#include <unordered_map>
#include <mutex>
#include <chrono>
#include <string>

#include "listener/ListenerTcp.hpp"
#include "listener/ListenerHttp.hpp"
#include "listener/ListenerGithub.hpp"
#include "listener/ListenerDns.hpp"

#include "modules/ModuleCmd/ModuleCmd.hpp"

#include "SocksServer.hpp"

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "TeamServerApi.pb.h"
#include "TeamServerApi.grpc.pb.h"
#include "TeamServerCommandTracking.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "nlohmann/json.hpp"

class TeamServerAuthManager;
class TeamServerArtifactService;
class TeamServerHelpService;
class TeamServerListenerSessionService;
class TeamServerListenerArtifactService;
class TeamServerModuleLoader;
class TeamServerSocksService;
class TeamServerCommandPreparationService;
class TeamServerTermLocalService;

class TeamServer final : public teamserverapi::TeamServerApi::Service
{

public:
    explicit TeamServer(const nlohmann::json& config);
    ~TeamServer();

    grpc::Status Authenticate(grpc::ServerContext* context, const teamserverapi::AuthRequest* request, teamserverapi::AuthResponse* response) override;
    grpc::Status ListListeners(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Listener>* writer) override;
    grpc::Status AddListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToCreate, teamserverapi::OperationAck* response) override;
    grpc::Status StopListener(grpc::ServerContext* context, const teamserverapi::ListenerSelector* listenerToStop, teamserverapi::OperationAck* response) override;

    grpc::Status ListSessions(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer) override;
    grpc::Status StopSession(grpc::ServerContext* context, const teamserverapi::SessionSelector* sessionToStop, teamserverapi::OperationAck* response) override;

    grpc::Status ListArtifacts(grpc::ServerContext* context, const teamserverapi::ArtifactQuery* query, grpc::ServerWriter<teamserverapi::ArtifactSummary>* writer) override;

    grpc::Status SendSessionCommand(grpc::ServerContext* context, const teamserverapi::SessionCommandRequest* command, teamserverapi::CommandAck* response) override;
    grpc::Status StreamSessionCommandResults(grpc::ServerContext* context, const teamserverapi::SessionSelector* session, grpc::ServerWriter<teamserverapi::CommandResult>* writer) override;

    grpc::Status GetCommandHelp(grpc::ServerContext* context, const teamserverapi::CommandHelpRequest* command, teamserverapi::CommandHelpResponse* commandResponse) override;

    grpc::Status ExecuteTerminalCommand(grpc::ServerContext* context, const teamserverapi::TerminalCommandRequest* command, teamserverapi::TerminalCommandResponse* response) override;

protected:
    int handleCmdResponse();
    bool isListenerAlive(const std::string& listenerHash);
    int prepMsg(
        const std::string& input,
        C2Message& c2Message,
        bool isWindows = true,
        const std::string& windowsArch = "x64");

private:
    grpc::Status ensureAuthenticated(grpc::ServerContext* context);

    nlohmann::json m_config;

    std::shared_ptr<spdlog::logger> m_logger;

    std::vector<std::shared_ptr<Listener>> m_listeners;
    nlohmann::json m_credentials = nlohmann::json::array();

    std::vector<std::unique_ptr<ModuleCmd>> m_moduleCmd;
    CommonCommands m_commonCommands;

    bool m_handleCmdResponseThreadRuning;
    std::unique_ptr<std::thread> m_handleCmdResponseThread;
    std::vector<teamserverapi::CommandResult> m_cmdResponses;
    std::unordered_map<std::string, std::vector<int>> m_sentResponses;

    std::vector<BeaconCommandContext> m_sentCommands;

    std::unique_ptr<TeamServerAuthManager> m_authManager;
    std::unique_ptr<TeamServerArtifactService> m_artifactService;
    std::unique_ptr<TeamServerHelpService> m_helpService;
    std::unique_ptr<TeamServerListenerSessionService> m_listenerSessionService;
    std::unique_ptr<TeamServerListenerArtifactService> m_listenerArtifactService;
    std::unique_ptr<TeamServerModuleLoader> m_moduleLoader;
    std::unique_ptr<TeamServerSocksService> m_socksService;
    std::unique_ptr<TeamServerCommandPreparationService> m_commandPreparationService;
    std::unique_ptr<TeamServerTermLocalService> m_termLocalService;
};
