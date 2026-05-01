#include "TeamServer.hpp"

#include "TeamServerAuth.hpp"
#include "TeamServerBootstrap.hpp"
#include "TeamServerCommandPreparationService.hpp"
#include "TeamServerHelpService.hpp"
#include "TeamServerListenerArtifactService.hpp"
#include "TeamServerListenerSessionService.hpp"
#include "TeamServerModuleLoader.hpp"
#include "TeamServerSocksService.hpp"
#include "TeamServerTermLocalService.hpp"
#include "TeamServerRuntimeConfig.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace std::placeholders;

using json = nlohmann::json;

inline bool port_in_use(unsigned short port)
{

    return 0;
}

std::string getIPAddress(const std::string& interface);

grpc::Status TeamServer::ensureAuthenticated(grpc::ServerContext* context)
{
    return m_authManager->ensureAuthenticated(context->client_metadata());
}

TeamServer::TeamServer(const nlohmann::json& config)
    : m_config(config)
{
    m_logger = createTeamServerLogger(config);

    TeamServerRuntimeConfig runtimeConfig = TeamServerRuntimeConfig::fromJson(config);
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
        [this](const std::string& input, C2Message& c2Message, bool isWindows, const std::string& windowsArch)
        { return this->prepMsg(input, c2Message, isWindows, windowsArch); });
    m_listenerArtifactService = std::make_unique<TeamServerListenerArtifactService>(
        m_logger,
        m_config,
        runtimeConfig,
        m_listeners,
        [](const std::string& interface)
        {
            return getIPAddress(interface);
        });
    m_moduleLoader = std::make_unique<TeamServerModuleLoader>(m_logger, runtimeConfig);
    m_socksService = std::make_unique<TeamServerSocksService>(m_logger, m_listeners);
    m_commandPreparationService = std::make_unique<TeamServerCommandPreparationService>(
        m_logger,
        runtimeConfig.teamServerModulesDirectoryPath,
        m_commonCommands,
        m_moduleCmd);
    m_termLocalService = std::make_unique<TeamServerTermLocalService>(
        m_logger,
        m_config,
        runtimeConfig,
        m_listeners,
        m_credentials,
        m_moduleCmd,
        [this]()
        { return m_moduleLoader->loadModules(); });

    m_moduleCmd = m_moduleLoader->loadModules();

    m_handleCmdResponseThreadRuning = true;
    m_handleCmdResponseThread = std::make_unique<std::thread>(&TeamServer::handleCmdResponse, this);
}

TeamServer::~TeamServer()
{
    m_handleCmdResponseThreadRuning = false;
    m_handleCmdResponseThread->join();
    m_socksService->shutdown();
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

std::string getIPAddress(const std::string& interface)
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
    if (m_listenerArtifactService->canHandle(instruction))
    {
        return m_listenerArtifactService->handleCommand(instruction, splitedCmd, *command, response);
    }
    else if (m_termLocalService->canHandle(instruction))
    {
        return m_termLocalService->handleCommand(instruction, splitedCmd, *command, response);
    }
    else if (instruction == SocksInstruction_)
    {
        m_logger->debug("socks {0}", cmd);
        return m_socksService->handleCommand(splitedCmd, response);
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

int TeamServer::prepMsg(const std::string& input, C2Message& c2Message, bool isWindows, const std::string& windowsArch)
{
    return m_commandPreparationService->prepareMessage(input, c2Message, isWindows, windowsArch);
}
