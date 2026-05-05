#include "TeamServer.hpp"

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerArtifactService.hpp"
#include "TeamServerAssemblyExecCommandPreparer.hpp"
#include "TeamServerAuth.hpp"
#include "TeamServerBootstrap.hpp"
#include "TeamServerCommandCatalog.hpp"
#include "TeamServerCommandCatalogService.hpp"
#include "TeamServerCommandPreparationService.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "TeamServerHelpService.hpp"
#include "TeamServerListenerArtifactService.hpp"
#include "TeamServerListenerSessionService.hpp"
#include "TeamServerModuleLoader.hpp"
#include "TeamServerShellcodeService.hpp"
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
    m_generatedArtifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    m_shellcodeService = std::make_shared<TeamServerShellcodeService>(m_logger);
    m_artifactService = std::make_unique<TeamServerArtifactService>(
        m_logger,
        TeamServerArtifactCatalog(runtimeConfig));
    m_commandCatalogService = std::make_unique<TeamServerCommandCatalogService>(
        m_logger,
        TeamServerCommandCatalog(runtimeConfig));
    m_helpService = std::make_unique<TeamServerHelpService>(
        m_logger,
        m_listeners,
        m_moduleCmd,
        m_commonCommands,
        TeamServerCommandCatalog(runtimeConfig));
    m_listenerSessionService = std::make_unique<TeamServerListenerSessionService>(
        m_logger,
        m_config,
        m_listeners,
        m_moduleCmd,
        m_commonCommands,
        m_cmdResponses,
        m_sentResponses,
        m_sentCommands,
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
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> commandPreparers;
    commandPreparers.push_back(std::make_unique<TeamServerAssemblyExecCommandPreparer>(
        m_logger,
        runtimeConfig,
        m_shellcodeService,
        m_generatedArtifactStore,
        m_moduleCmd));
    m_commandPreparationService = std::make_unique<TeamServerCommandPreparationService>(
        m_logger,
        runtimeConfig,
        m_commonCommands,
        m_moduleCmd,
        std::move(commandPreparers));
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
grpc::Status TeamServer::ListListeners(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Listener>* writer)
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
grpc::Status TeamServer::AddListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToCreate, teamserverapi::OperationAck* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->addListener(*listenerToCreate, response);
}

grpc::Status TeamServer::StopListener(grpc::ServerContext* context, const teamserverapi::ListenerSelector* listenerToStop, teamserverapi::OperationAck* response)
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
grpc::Status TeamServer::ListSessions(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer)
{
    (void)empty;
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->streamSessions([&](const teamserverapi::Session& session)
        { return writer->Write(session); });
}

grpc::Status TeamServer::StopSession(grpc::ServerContext* context, const teamserverapi::SessionSelector* sessionToStop, teamserverapi::OperationAck* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->stopSession(*sessionToStop, response);
}

grpc::Status TeamServer::ListArtifacts(grpc::ServerContext* context, const teamserverapi::ArtifactQuery* query, grpc::ServerWriter<teamserverapi::ArtifactSummary>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_artifactService->listArtifacts(*query, [&](const teamserverapi::ArtifactSummary& artifact)
        { return writer->Write(artifact); });
}

grpc::Status TeamServer::ListCommands(grpc::ServerContext* context, const teamserverapi::CommandQuery* query, grpc::ServerWriter<teamserverapi::CommandSpec>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_commandCatalogService->listCommands(*query, [&](const teamserverapi::CommandSpec& command)
        { return writer->Write(command); });
}

grpc::Status TeamServer::ListModules(grpc::ServerContext* context, const teamserverapi::SessionSelector* session, grpc::ServerWriter<teamserverapi::LoadedModule>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->streamModulesForSession(*session, [&](const teamserverapi::LoadedModule& module)
        { return writer->Write(module); });
}

grpc::Status TeamServer::SendSessionCommand(grpc::ServerContext* context, const teamserverapi::SessionCommandRequest* command, teamserverapi::CommandAck* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->sendSessionCommand(*command, response);
}

int TeamServer::handleCmdResponse()
{
    while (m_handleCmdResponseThreadRuning)
        m_listenerSessionService->handleCmdResponse();
    return 0;
}

grpc::Status TeamServer::StreamSessionCommandResults(grpc::ServerContext* context, const teamserverapi::SessionSelector* session, grpc::ServerWriter<teamserverapi::CommandResult>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_listenerSessionService->streamResponsesForSession(
        *session,
        context->client_metadata(),
        [&](const teamserverapi::CommandResult& commandResponse)
        { return writer->Write(commandResponse); });
}

grpc::Status TeamServer::GetCommandHelp(grpc::ServerContext* context, const teamserverapi::CommandHelpRequest* command, teamserverapi::CommandHelpResponse* commandResponse)
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

grpc::Status TeamServer::ExecuteTerminalCommand(grpc::ServerContext* context, const teamserverapi::TerminalCommandRequest* command, teamserverapi::TerminalCommandResponse* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;

    m_logger->trace("ExecuteTerminalCommand");

    std::string cmd = command->command();
    m_logger->debug("ExecuteTerminalCommand {0}", cmd);

    std::vector<std::string> splitedCmd;
    splitInputCmd(cmd, splitedCmd);

    teamserverapi::TerminalCommandResponse responseTmp;
    std::string none = "";
    responseTmp.set_status(teamserverapi::KO);
    responseTmp.set_command(cmd);
    responseTmp.set_result(none);
    responseTmp.set_data(none);

    if (splitedCmd.empty())
    {
        responseTmp.set_result("Error: empty command.");
        responseTmp.set_message("Empty terminal command.");
        *response = responseTmp;
        return grpc::Status::OK;
    }

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
        responseTmp.set_message("Terminal command not implemented.");
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
