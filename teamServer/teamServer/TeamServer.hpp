#include <unordered_map>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <string>

#include "listener/ListenerTcp.hpp"
#include "listener/ListenerHttp.hpp"
#include "listener/ListenerDns.hpp"
#ifdef C2_ENABLE_GITHUB_TRANSPORT
#include "listener/ListenerGithub.hpp"
#endif

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
class TeamServerCommandCatalogService;
class TeamServerCredentialVaultService;
class TeamServerFileArtifactService;
class TeamServerGeneratedArtifactStore;
class TeamServerHelpService;
class TeamServerListenerSessionService;
class TeamServerListenerArtifactService;
class TeamServerModuleLoader;
class TeamServerSocksService;
class TeamServerCommandPreparationService;
class TeamServerShellcodeService;
class TeamServerLocalOperationService;
class JobApplicationService;
class SqliteJobRepository;

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
    grpc::Status ListSessionHistory(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer) override;
    grpc::Status StopSession(grpc::ServerContext* context, const teamserverapi::SessionSelector* sessionToStop, teamserverapi::OperationAck* response) override;

    grpc::Status ListArtifacts(grpc::ServerContext* context, const teamserverapi::ArtifactQuery* query, grpc::ServerWriter<teamserverapi::ArtifactSummary>* writer) override;
    grpc::Status DownloadArtifact(grpc::ServerContext* context, const teamserverapi::ArtifactSelector* selector, teamserverapi::ArtifactContent* response) override;
    grpc::Status UploadArtifact(grpc::ServerContext* context, const teamserverapi::ArtifactUploadRequest* request, teamserverapi::OperationAck* response) override;
    grpc::Status DeleteGeneratedArtifact(grpc::ServerContext* context, const teamserverapi::ArtifactSelector* selector, teamserverapi::OperationAck* response) override;
    grpc::Status ListCredentials(grpc::ServerContext* context, const teamserverapi::CredentialQuery* query, grpc::ServerWriter<teamserverapi::CredentialSummary>* writer) override;
    grpc::Status GetCredential(grpc::ServerContext* context, const teamserverapi::CredentialSelector* selector, teamserverapi::CredentialDetail* response) override;
    grpc::Status AddCredential(grpc::ServerContext* context, const teamserverapi::CredentialUpsertRequest* request, teamserverapi::OperationAck* response) override;
    grpc::Status UpdateCredential(grpc::ServerContext* context, const teamserverapi::CredentialUpsertRequest* request, teamserverapi::OperationAck* response) override;
    grpc::Status DeleteCredential(grpc::ServerContext* context, const teamserverapi::CredentialSelector* selector, teamserverapi::OperationAck* response) override;
    grpc::Status ListCommands(grpc::ServerContext* context, const teamserverapi::CommandQuery* query, grpc::ServerWriter<teamserverapi::CommandSpec>* writer) override;
    grpc::Status ListModules(grpc::ServerContext* context, const teamserverapi::SessionSelector* session, grpc::ServerWriter<teamserverapi::LoadedModule>* writer) override;

    grpc::Status SubmitJob(grpc::ServerContext* context, const teamserverapi::SubmitJobRequest* request, teamserverapi::JobExecutionRecord* response) override;
    grpc::Status GetJobExecution(grpc::ServerContext* context, const teamserverapi::GetJobExecutionRequest* request, teamserverapi::JobExecutionRecord* response) override;
    grpc::Status GetJobOutputChunk(grpc::ServerContext* context, const teamserverapi::GetJobOutputChunkRequest* request, teamserverapi::GetJobOutputChunkResponse* response) override;
    grpc::Status ListJobExecutions(grpc::ServerContext* context, const teamserverapi::ListJobExecutionsRequest* request, teamserverapi::ListJobExecutionsResponse* response) override;
    grpc::Status SubscribeJobEvents(grpc::ServerContext* context, const teamserverapi::SubscribeJobEventsRequest* request, grpc::ServerWriter<teamserverapi::JobEventRecord>* writer) override;

    grpc::Status GetCommandHelp(grpc::ServerContext* context, const teamserverapi::CommandHelpRequest* command, teamserverapi::CommandHelpResponse* commandResponse) override;

    grpc::Status HostArtifact(grpc::ServerContext* context, const teamserverapi::HostArtifactRequest* request,
        teamserverapi::JobExecutionRecord* response) override;
    grpc::Status ControlSocks(grpc::ServerContext* context, const teamserverapi::SocksControlRequest* request,
        teamserverapi::JobExecutionRecord* response) override;
    grpc::Status ReloadModules(grpc::ServerContext* context, const teamserverapi::OperationRequest* request,
        teamserverapi::JobExecutionRecord* response) override;

    grpc::Status GetListenerInfo(grpc::ServerContext* context, const teamserverapi::ListenerSelector* request,
        teamserverapi::ListenerInfoResponse* response) override;
    grpc::Status GetBeaconBinary(grpc::ServerContext* context, const teamserverapi::BeaconBinaryRequest* request,
        teamserverapi::BeaconBinaryResponse* response) override;
    grpc::Status UploadListenerFile(grpc::ServerContext* context, const teamserverapi::ListenerFileRequest* request,
        teamserverapi::OperationAck* response) override;
    grpc::Status InstallTool(grpc::ServerContext* context, const teamserverapi::ToolFile* request,
        teamserverapi::OperationAck* response) override;
    grpc::Status InstallToolBundle(grpc::ServerContext* context, const teamserverapi::ToolBundleRequest* request,
        teamserverapi::OperationAck* response) override;

protected:
    int handleCmdResponse();
    void syncSessionHistory();
    bool isListenerAlive(const std::string& listenerHash);
    int prepMsg(
        const std::string& input,
        C2Message& c2Message,
        bool isWindows = true,
        const std::string& windowsArch = "x64");

private:
    grpc::Status ensureAuthenticated(grpc::ServerContext* context);
    void writeAudit(grpc::ServerContext* context, const std::string& actor,
        const std::string& action, const std::string& outcome, const nlohmann::json& details = {});

    nlohmann::json m_config;

    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<spdlog::logger> m_auditLogger;

    std::vector<std::shared_ptr<Listener>> m_listeners;
    mutable std::shared_mutex m_listenersMutex;
    nlohmann::json m_credentials = nlohmann::json::array();

    std::vector<std::unique_ptr<ModuleCmd>> m_moduleCmd;
    mutable std::shared_mutex m_moduleCmdMutex;
    CommonCommands m_commonCommands;

    std::atomic_bool m_handleCmdResponseThreadRuning{false};
    std::unique_ptr<std::thread> m_handleCmdResponseThread;
    std::vector<BeaconCommandContext> m_sentCommands;

    std::unique_ptr<TeamServerAuthManager> m_authManager;
    std::unique_ptr<TeamServerArtifactService> m_artifactService;
    std::unique_ptr<TeamServerCommandCatalogService> m_commandCatalogService;
    std::shared_ptr<TeamServerCredentialVaultService> m_credentialVaultService;
    std::shared_ptr<TeamServerFileArtifactService> m_fileArtifactService;
    std::shared_ptr<TeamServerGeneratedArtifactStore> m_generatedArtifactStore;
    std::unique_ptr<TeamServerHelpService> m_helpService;
    std::unique_ptr<TeamServerListenerSessionService> m_listenerSessionService;
    std::unique_ptr<TeamServerListenerArtifactService> m_listenerArtifactService;
    std::unique_ptr<TeamServerModuleLoader> m_moduleLoader;
    std::unique_ptr<TeamServerSocksService> m_socksService;
    std::unique_ptr<TeamServerCommandPreparationService> m_commandPreparationService;
    std::shared_ptr<TeamServerShellcodeService> m_shellcodeService;
    std::unique_ptr<TeamServerLocalOperationService> m_localOperationService;
    std::shared_ptr<SqliteJobRepository> m_jobRepository;
    std::shared_ptr<JobApplicationService> m_jobApplication;
};
