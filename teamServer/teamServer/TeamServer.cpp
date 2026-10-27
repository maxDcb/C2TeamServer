#include "TeamServer.hpp"

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerArtifactService.hpp"
#include "TeamServerAssemblyExecCommandPreparer.hpp"
#include "TeamServerAuth.hpp"
#include "TeamServerBootstrap.hpp"
#include "TeamServerChiselCommandPreparer.hpp"
#include "TeamServerCommandCatalog.hpp"
#include "TeamServerCommandCatalogService.hpp"
#include "TeamServerCommandPreparationService.hpp"
#include "TeamServerCredentialVaultService.hpp"
#include "TeamServerFileArtifactService.hpp"
#include "TeamServerFileTransferCommandPreparer.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "TeamServerHelpService.hpp"
#include "TeamServerInjectCommandPreparer.hpp"
#include "TeamServerListenerArtifactService.hpp"
#include "TeamServerListenerSessionService.hpp"
#include "TeamServerMiniDumpCommandPreparer.hpp"
#include "TeamServerModuleLoader.hpp"
#include "TeamServerModuleArtifactCommandPreparer.hpp"
#include "TeamServerScriptCommandPreparer.hpp"
#include "TeamServerShellcodeService.hpp"
#include "TeamServerSocksService.hpp"
#include "TeamServerLocalOperationService.hpp"
#include "TeamServerRuntimeConfig.hpp"
#include "JobApplicationService.hpp"
#include "SqliteJobRepository.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <chrono>
#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace std;
using namespace std::placeholders;

using json = nlohmann::json;

inline bool port_in_use(unsigned short port)
{

    return 0;
}

namespace
{
std::string trimTrailingPathSeparators(std::string path)
{
    while (!path.empty() && (path.back() == '/' || path.back() == '\\'))
        path.pop_back();
    return path;
}

void configureHostedDownloadFolders(nlohmann::json& config, const TeamServerRuntimeConfig& runtimeConfig)
{
    const std::string hostedPath = trimTrailingPathSeparators(runtimeConfig.hostedArtifactsDirectoryPath);
    if (hostedPath.empty())
        return;

    for (const char* section : {"ListenerHttpConfig", "ListenerHttpsConfig"})
    {
        if (!config[section].is_object())
            config[section] = nlohmann::json::object();
        config[section]["downloadFolder"] = hostedPath;
    }
}

void copyJob(const JobExecution& job, teamserverapi::JobExecutionRecord* response, std::size_t previewBytes)
{
    response->set_job_id(job.jobId);
    response->set_operation(job.operation);
    response->set_normalized_input(job.normalizedInput);
    response->set_request_hash(job.requestHash);
    response->set_state(job.state);
    response->set_created_at(job.createdAt);
    response->set_queued_at(job.queuedAt);
    response->set_completed_at(job.completedAt);
    response->set_error_code(job.errorCode);
    response->set_error_message(job.errorMessage);
    response->set_output_inline(job.outputInline.substr(0, previewBytes));
    response->set_output_size(job.outputSize);
    response->set_operator_username(job.operatorUsername);
    response->set_origin(job.origin);
}

grpc::Status jobStatus(const JobError& error)
{
    switch (error.code())
    {
    case JobErrorCode::invalid_argument: return {grpc::StatusCode::INVALID_ARGUMENT, error.what()};
    case JobErrorCode::conflict: return {grpc::StatusCode::ALREADY_EXISTS, error.what()};
    case JobErrorCode::not_found: return {grpc::StatusCode::NOT_FOUND, error.what()};
    case JobErrorCode::invalid_transition: return {grpc::StatusCode::FAILED_PRECONDITION, error.what()};
    case JobErrorCode::storage: return {grpc::StatusCode::INTERNAL, error.what()};
    }
    return {grpc::StatusCode::INTERNAL, error.what()};
}

std::string auditOutcome(const grpc::Status& status, teamserverapi::Status responseStatus)
{
    if (!status.ok()) return "error";
    return responseStatus == teamserverapi::OK ? "accepted" : "rejected";
}
} // namespace

std::string getIPAddress(const std::string& interface);

grpc::Status TeamServer::ensureAuthenticated(grpc::ServerContext* context)
{
    return m_authManager->ensureAuthenticated(context->client_metadata());
}

void TeamServer::writeAudit(grpc::ServerContext* context, const std::string& actor,
    const std::string& action, const std::string& outcome, const nlohmann::json& details)
{
    try
    {
        json record = {
            {"timestamp_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
            {"actor", actor}, {"action", action}, {"outcome", outcome}, {"details", details}
        };
        if (context)
        {
            record["peer"] = context->peer();
            const auto& metadata = context->client_metadata();
            const auto clientId = metadata.find("clientid");
            if (clientId != metadata.end())
                record["client_id"] = std::string(clientId->second.data(),
                    std::min<std::size_t>(clientId->second.size(), 64));
        }
        m_auditLogger->info("{}", record.dump());
#ifndef _WIN32
        if (::chmod("logs/TeamServer.audit.jsonl", S_IRUSR | S_IWUSR) != 0)
            std::fprintf(stderr, "TeamServer audit log permissions could not be updated\n");
#endif
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "TeamServer audit write failed: %s\n", error.what());
    }
}

TeamServer::TeamServer(const nlohmann::json& config)
    : m_config(config)
{
    m_logger = createTeamServerLogger(config);
    m_auditLogger = createTeamServerAuditLogger();

    TeamServerRuntimeConfig runtimeConfig = TeamServerRuntimeConfig::fromJson(config);
    runtimeConfig.validateDirectories(m_logger);
    runtimeConfig.configureCommonCommands(m_commonCommands);
    configureHostedDownloadFolders(m_config, runtimeConfig);

    m_authManager = std::make_unique<TeamServerAuthManager>(m_logger);
    m_authManager->configure(config);
    m_generatedArtifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    m_fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        m_logger,
        runtimeConfig,
        m_generatedArtifactStore);
    m_shellcodeService = std::make_shared<TeamServerShellcodeService>(m_logger);
    m_artifactService = std::make_unique<TeamServerArtifactService>(
        m_logger,
        TeamServerArtifactCatalog(runtimeConfig));
        m_commandCatalogService = std::make_unique<TeamServerCommandCatalogService>(
        m_logger,
        TeamServerCommandCatalog(runtimeConfig));
        m_credentialVaultService = std::make_shared<TeamServerCredentialVaultService>(
            m_logger,
            runtimeConfig);
    m_helpService = std::make_unique<TeamServerHelpService>(
        m_logger,
        m_listeners,
        m_moduleCmd,
        m_commonCommands,
        TeamServerCommandCatalog(runtimeConfig),
        &m_listenersMutex);
    m_listenerSessionService = std::make_unique<TeamServerListenerSessionService>(
        m_logger,
        m_config,
        m_listeners,
        m_moduleCmd,
        m_commonCommands,
        m_sentCommands,
        m_fileArtifactService,
        [this](const std::string& input, C2Message& c2Message, bool isWindows, const std::string& windowsArch)
        { return this->prepMsg(input, c2Message, isWindows, windowsArch); },
        &m_listenersMutex);
    m_jobRepository = std::make_shared<SqliteJobRepository>(runtimeConfig.jobDatabasePath);
    m_jobRepository->syncSessions({});
    const std::size_t recovered = m_jobRepository->recoverInFlight();
    if (recovered)
        m_logger->warn("Marked {} unfinished jobs as outcome_unknown after restart", recovered);
    m_jobApplication = std::make_shared<JobApplicationService>(m_jobRepository,
        runtimeConfig.maxJobOutputBytes,
        [this](const JobExecution& job) -> std::string
        {
            const auto input = json::parse(job.normalizedInput);
            teamserverapi::SessionCommandRequest command;
            command.set_command_id(job.jobId);
            command.set_command(input.at("command").get<std::string>());
            command.mutable_session()->set_beacon_hash(input.at("beacon_hash").get<std::string>());
            command.mutable_session()->set_listener_hash(input.at("listener_hash").get<std::string>());
            teamserverapi::CommandAck ack;
            const auto status = m_listenerSessionService->sendSessionCommand(command, &ack);
            if (!status.ok()) return status.error_message();
            return ack.status() == teamserverapi::OK ? std::string{} : ack.message();
        },
        [this](const JobExecution& job) -> TeamServerOperationResult
        {
            const auto input = json::parse(job.normalizedInput);
            if (job.operation == "host_artifact")
                return m_localOperationService->hostArtifact(
                    input.at("listener_hash").get<std::string>(),
                    input.at("artifact_reference").get<std::string>(),
                    input.at("hosted_filename").get<std::string>());
            if (job.operation == "reload_modules")
                return m_localOperationService->reloadModules();
            if (job.operation == "socks_control")
                return m_socksService->control(
                    input.at("action").get<std::string>(),
                    input.at("beacon_hash").get<std::string>());
            return {false, "Unknown local operation."};
        });
    m_listenerSessionService->setJobResultHandler([this](const teamserverapi::CommandResult& result)
    {
        if (result.command_id().empty()) return;
        try
        {
            const auto completed = m_jobApplication->complete(result.command_id(), result.status() == teamserverapi::OK,
                result.output(), result.status() == teamserverapi::OK ? "" : "command_failed", result.message());
            writeAudit(nullptr, completed.operatorUsername, "JobCompleted", completed.state,
                {{"job_id", completed.jobId}, {"operation", completed.operation}});
        }
        catch (const JobError& error)
        {
            if (error.code() != JobErrorCode::not_found && error.code() != JobErrorCode::invalid_transition)
                throw;
            m_logger->warn("Ignored late or untracked command result {}: {}", result.command_id(), error.what());
        }
    });
    m_listenerArtifactService = std::make_unique<TeamServerListenerArtifactService>(
        m_logger,
        m_config,
        runtimeConfig,
        m_listeners,
        [](const std::string& interface)
        {
            return getIPAddress(interface);
        },
        &m_listenersMutex);
    m_moduleLoader = std::make_unique<TeamServerModuleLoader>(m_logger, runtimeConfig);
    m_socksService = std::make_unique<TeamServerSocksService>(
        m_logger, m_listeners, TeamServerSocksService::PortInUseCallback{},
        TeamServerSocksService::ServerFactory{}, std::chrono::minutes(2), &m_listenersMutex);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> commandPreparers;
    commandPreparers.push_back(std::make_unique<TeamServerAssemblyExecCommandPreparer>(
        m_logger,
        runtimeConfig,
        m_shellcodeService,
        m_generatedArtifactStore,
        m_moduleCmd));
    commandPreparers.push_back(std::make_unique<TeamServerInjectCommandPreparer>(
        m_logger,
        runtimeConfig,
        m_shellcodeService,
        m_generatedArtifactStore,
        m_moduleCmd));
    commandPreparers.push_back(std::make_unique<TeamServerChiselCommandPreparer>(
        m_logger,
        runtimeConfig,
        m_shellcodeService,
        m_generatedArtifactStore,
        m_moduleCmd));
    commandPreparers.push_back(std::make_unique<TeamServerFileTransferCommandPreparer>(
        m_logger,
        m_fileArtifactService,
        m_moduleCmd));
    commandPreparers.push_back(std::make_unique<TeamServerScriptCommandPreparer>(
        m_logger,
        m_fileArtifactService,
        m_moduleCmd));
    commandPreparers.push_back(std::make_unique<TeamServerMiniDumpCommandPreparer>(
        m_logger,
        m_fileArtifactService,
        m_moduleCmd));
    commandPreparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(
        m_logger,
        m_fileArtifactService,
        m_moduleCmd));
    m_commandPreparationService = std::make_unique<TeamServerCommandPreparationService>(
        m_logger,
        runtimeConfig,
        m_commonCommands,
        m_moduleCmd,
        std::move(commandPreparers),
        m_credentialVaultService);
    m_localOperationService = std::make_unique<TeamServerLocalOperationService>(
        m_logger,
        m_config,
        runtimeConfig,
        m_moduleCmd,
        [this]()
        { return m_moduleLoader->loadModules(); },
        m_listenerArtifactService.get(),
        &m_moduleCmdMutex);

    m_moduleCmd = m_moduleLoader->loadModules();

    m_handleCmdResponseThreadRuning = true;
    m_handleCmdResponseThread = std::make_unique<std::thread>(&TeamServer::handleCmdResponse, this);
}

TeamServer::~TeamServer()
{
    m_handleCmdResponseThreadRuning.store(false);
    if (m_handleCmdResponseThread && m_handleCmdResponseThread->joinable())
        m_handleCmdResponseThread->join();
    m_socksService->shutdown();
}

grpc::Status TeamServer::Authenticate(grpc::ServerContext* context, const teamserverapi::AuthRequest* request, teamserverapi::AuthResponse* response)
{
    auto status = m_authManager->authenticate(*request, *response);
    writeAudit(context, request->username(), "Authenticate", auditOutcome(status, response->status()));
    if (status.ok() && response->status() == teamserverapi::OK)
    {
        response->add_available_listener_types(ListenerHttpType);
        response->add_available_listener_types(ListenerHttpsType);
        response->add_available_listener_types(ListenerTcpType);
        response->add_available_listener_types(ListenerDnsType);
#ifdef C2_ENABLE_GITHUB_TRANSPORT
        response->add_available_listener_types(ListenerGithubType);
#endif
    }
    return status;
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
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "AddListener", "denied");
        return authStatus;
    }
    writeAudit(context, actor, "AddListener", "requested",
        {{"type", listenerToCreate->type()}, {"ip", listenerToCreate->ip()}, {"port", listenerToCreate->port()}});
    const auto status = m_listenerSessionService->addListener(*listenerToCreate, response);
    writeAudit(context, actor, "AddListener", auditOutcome(status, response->status()),
        {{"type", listenerToCreate->type()}, {"ip", listenerToCreate->ip()},
         {"port", listenerToCreate->port()}, {"listener_hash", response->listener_hash()}});
    return status;
}

grpc::Status TeamServer::StopListener(grpc::ServerContext* context, const teamserverapi::ListenerSelector* listenerToStop, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "StopListener", "denied", {{"listener_hash", listenerToStop->listener_hash()}});
        return authStatus;
    }
    writeAudit(context, actor, "StopListener", "requested", {{"listener_hash", listenerToStop->listener_hash()}});
    const auto status = m_listenerSessionService->stopListener(*listenerToStop, response);
    writeAudit(context, actor, "StopListener", auditOutcome(status, response->status()),
        {{"listener_hash", listenerToStop->listener_hash()}});
    return status;
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

grpc::Status TeamServer::ListSessionHistory(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer)
{
    (void)empty;
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok()) return authStatus;
    try
    {
        syncSessionHistory();
        for (const auto& session : m_jobRepository->listSessions())
            if (!writer->Write(session)) break;
    }
    catch (const JobError& error) { return jobStatus(error); }
    return grpc::Status::OK;
}

grpc::Status TeamServer::StopSession(grpc::ServerContext* context, const teamserverapi::SessionSelector* sessionToStop, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "StopSession", "denied",
            {{"beacon_hash", sessionToStop->beacon_hash()}, {"listener_hash", sessionToStop->listener_hash()}});
        return authStatus;
    }
    writeAudit(context, actor, "StopSession", "requested",
        {{"beacon_hash", sessionToStop->beacon_hash()}, {"listener_hash", sessionToStop->listener_hash()}});
    const auto status = m_listenerSessionService->stopSession(*sessionToStop, response);
    writeAudit(context, actor, "StopSession", auditOutcome(status, response->status()),
        {{"beacon_hash", sessionToStop->beacon_hash()}, {"listener_hash", sessionToStop->listener_hash()},
         {"resolved_beacon_hash", response->session_beacon_hash()},
         {"resolved_listener_hash", response->session_listener_hash()},
         {"session_state", response->session_state()}});
    return status;
}

grpc::Status TeamServer::ListArtifacts(grpc::ServerContext* context, const teamserverapi::ArtifactQuery* query, grpc::ServerWriter<teamserverapi::ArtifactSummary>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_artifactService->listArtifacts(*query, [&](const teamserverapi::ArtifactSummary& artifact)
        { return writer->Write(artifact); });
}

grpc::Status TeamServer::DownloadArtifact(grpc::ServerContext* context, const teamserverapi::ArtifactSelector* selector, teamserverapi::ArtifactContent* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "DownloadArtifact", "denied", {{"artifact_id", selector->artifact_id()}});
        return authStatus;
    }
    const auto status = m_artifactService->downloadArtifact(*selector, response);
    writeAudit(context, actor, "DownloadArtifact", auditOutcome(status, response->status()),
        {{"artifact_id", selector->artifact_id()}, {"size", response->data().size()}});
    return status;
}

grpc::Status TeamServer::UploadArtifact(grpc::ServerContext* context, const teamserverapi::ArtifactUploadRequest* request, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "UploadArtifact", "denied");
        return authStatus;
    }
    const auto status = m_artifactService->uploadArtifact(*request, response);
    writeAudit(context, actor, "UploadArtifact", auditOutcome(status, response->status()),
        {{"name", request->name()}, {"platform", request->platform()}, {"arch", request->arch()},
         {"size", request->data().size()}});
    return status;
}

grpc::Status TeamServer::DeleteGeneratedArtifact(grpc::ServerContext* context, const teamserverapi::ArtifactSelector* selector, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "DeleteGeneratedArtifact", "denied", {{"artifact_id", selector->artifact_id()}});
        return authStatus;
    }
    const auto status = m_artifactService->deleteGeneratedArtifact(*selector, response);
    writeAudit(context, actor, "DeleteGeneratedArtifact", auditOutcome(status, response->status()),
        {{"artifact_id", selector->artifact_id()}});
    return status;
}

grpc::Status TeamServer::ListCredentials(grpc::ServerContext* context, const teamserverapi::CredentialQuery* query, grpc::ServerWriter<teamserverapi::CredentialSummary>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    return m_credentialVaultService->listCredentials(*query, [&](const teamserverapi::CredentialSummary& credential)
        { return writer->Write(credential); });
}

grpc::Status TeamServer::GetCredential(grpc::ServerContext* context, const teamserverapi::CredentialSelector* selector, teamserverapi::CredentialDetail* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        if (selector->reveal_secret())
            writeAudit(context, actor, "RevealCredential", "denied", {{"credential_id", selector->credential_id()}});
        return authStatus;
    }
    const auto status = m_credentialVaultService->getCredential(*selector, response);
    if (selector->reveal_secret())
        writeAudit(context, actor, "RevealCredential", auditOutcome(status, response->status()),
            {{"credential_id", selector->credential_id()}});
    return status;
}

grpc::Status TeamServer::AddCredential(grpc::ServerContext* context, const teamserverapi::CredentialUpsertRequest* request, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "AddCredential", "denied");
        return authStatus;
    }
    const auto status = m_credentialVaultService->addCredential(*request, response);
    writeAudit(context, actor, "AddCredential", auditOutcome(status, response->status()),
        {{"credential_id", request->credential_id()}, {"type", request->type()}});
    return status;
}

grpc::Status TeamServer::UpdateCredential(grpc::ServerContext* context, const teamserverapi::CredentialUpsertRequest* request, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "UpdateCredential", "denied", {{"credential_id", request->credential_id()}});
        return authStatus;
    }
    const auto status = m_credentialVaultService->updateCredential(*request, response);
    writeAudit(context, actor, "UpdateCredential", auditOutcome(status, response->status()),
        {{"credential_id", request->credential_id()}});
    return status;
}

grpc::Status TeamServer::DeleteCredential(grpc::ServerContext* context, const teamserverapi::CredentialSelector* selector, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "DeleteCredential", "denied", {{"credential_id", selector->credential_id()}});
        return authStatus;
    }
    const auto status = m_credentialVaultService->deleteCredential(*selector, response);
    writeAudit(context, actor, "DeleteCredential", auditOutcome(status, response->status()),
        {{"credential_id", selector->credential_id()}});
    return status;
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

grpc::Status TeamServer::SubmitJob(grpc::ServerContext* context, const teamserverapi::SubmitJobRequest* request, teamserverapi::JobExecutionRecord* response)
{
    json details = {{"job_id", request->job_id()}, {"operation", request->operation()}};
    std::string operatorUsername;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &operatorUsername);
    if (!authStatus.ok())
    {
        writeAudit(context, operatorUsername, "SubmitJob", "denied", details);
        return authStatus;
    }
    if (request->operation() != "echo" && request->operation() != "session_command")
    {
        writeAudit(context, operatorUsername, "SubmitJob", "rejected", details);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Use the typed RPC for this operation.");
    }
    if (request->operation() == "session_command")
    {
        const json input = json::parse(request->input(), nullptr, false);
        if (input.is_object())
        {
            if (input.contains("beacon_hash") && input["beacon_hash"].is_string())
                details["beacon_hash"] = input["beacon_hash"];
            if (input.contains("listener_hash") && input["listener_hash"].is_string())
                details["listener_hash"] = input["listener_hash"];
        }
    }
    writeAudit(context, operatorUsername, "SubmitJob", "requested", details);
    try
    {
        copyJob(m_jobApplication->submit(request->job_id(), request->operation(), request->input(),
            operatorUsername, request->origin()), response, m_jobApplication->outputPreviewBytes());
    }
    catch (const JobError& error)
    {
        writeAudit(context, operatorUsername, "SubmitJob", "error", details);
        return jobStatus(error);
    }
    details["state"] = response->state();
    writeAudit(context, operatorUsername, "SubmitJob",
        response->state() == "failed" ? "rejected" : "accepted", details);
    return grpc::Status::OK;
}

int TeamServer::handleCmdResponse()
{
    while (m_handleCmdResponseThreadRuning.load())
    {
        try
        {
            {
                std::shared_lock<std::shared_mutex> lock(m_moduleCmdMutex);
                m_listenerSessionService->handleCmdResponse();
            }
            syncSessionHistory();
        }
        catch (const std::exception& ex)
        {
            m_logger->error("Command response worker recovered from an exception: {}", ex.what());
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        catch (...)
        {
            m_logger->error("Command response worker recovered from an unknown exception");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    return 0;
}

void TeamServer::syncSessionHistory()
{
    std::vector<teamserverapi::Session> live;
    m_listenerSessionService->streamSessions([&](const teamserverapi::Session& session)
    {
        live.push_back(session);
        return true;
    });
    m_jobRepository->syncSessions(live);
}

grpc::Status TeamServer::GetJobExecution(grpc::ServerContext* context, const teamserverapi::GetJobExecutionRequest* request, teamserverapi::JobExecutionRecord* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    try { copyJob(m_jobApplication->get(request->job_id()), response, m_jobApplication->outputPreviewBytes()); }
    catch (const JobError& error) { return jobStatus(error); }
    return grpc::Status::OK;
}

grpc::Status TeamServer::GetJobOutputChunk(grpc::ServerContext* context,
    const teamserverapi::GetJobOutputChunkRequest* request,
    teamserverapi::GetJobOutputChunkResponse* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok()) return authStatus;
    constexpr std::size_t MaxChunkBytes = 64 * 1024;
    if (request->offset() < 0 || request->max_bytes() == 0 || request->max_bytes() > MaxChunkBytes)
        return {grpc::StatusCode::INVALID_ARGUMENT, "Invalid output chunk offset or size."};
    try
    {
        const auto offset = static_cast<std::size_t>(request->offset());
        const JobOutputChunk chunk = m_jobApplication->outputChunk(
            request->job_id(), offset, request->max_bytes());
        response->set_data(chunk.data);
        response->set_total_size(chunk.totalSize);
        response->set_next_offset(static_cast<std::int64_t>(offset + chunk.data.size()));
        response->set_complete(response->next_offset() == chunk.totalSize);
    }
    catch (const JobError& error)
    {
        if (error.code() == JobErrorCode::invalid_argument)
            return {grpc::StatusCode::OUT_OF_RANGE, error.what()};
        return jobStatus(error);
    }
    return grpc::Status::OK;
}

grpc::Status TeamServer::ListJobExecutions(grpc::ServerContext* context, const teamserverapi::ListJobExecutionsRequest* request, teamserverapi::ListJobExecutionsResponse* response)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok()) return authStatus;
    try
    {
        auto page = m_jobApplication->list(request->after_created_at(), request->after_job_id(),
            request->page_size() ? request->page_size() : 100);
        for (const auto& job : page.jobs) copyJob(job, response->add_jobs(), m_jobApplication->outputPreviewBytes());
        response->set_next_created_at(page.nextCreatedAt);
        response->set_next_job_id(page.nextJobId);
    }
    catch (const JobError& error) { return jobStatus(error); }
    return grpc::Status::OK;
}

grpc::Status TeamServer::SubscribeJobEvents(grpc::ServerContext* context, const teamserverapi::SubscribeJobEventsRequest* request, grpc::ServerWriter<teamserverapi::JobEventRecord>* writer)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok()) return authStatus;
    const JobEventFilter filter{request->job_id(), request->state()};
    std::int64_t cursor = request->after_event_id();
    const std::size_t pageSize = request->page_size() ? request->page_size() : 100;
    try
    {
        while (!context->IsCancelled())
        {
            const auto page = m_jobApplication->events(cursor, filter, pageSize);
            for (const auto& event : page)
            {
                teamserverapi::JobEventRecord response;
                response.set_event_id(event.eventId);
                response.set_job_id(event.jobId);
                response.set_event_type(event.eventType);
                response.set_created_at(event.createdAt);
                response.set_payload_json(event.payloadJson);
                if (!writer->Write(response)) return grpc::Status::OK;
                cursor = event.eventId;
            }
            if (!request->follow()) return grpc::Status::OK;
            if (page.size() == pageSize) continue;
            m_jobApplication->waitForEvents(cursor, filter,
                [context] { return context->IsCancelled(); }, std::chrono::milliseconds(1000));
        }
    }
    catch (const JobError& error) { return jobStatus(error); }
    return grpc::Status::OK;
}

grpc::Status TeamServer::GetCommandHelp(grpc::ServerContext* context, const teamserverapi::CommandHelpRequest* command, teamserverapi::CommandHelpResponse* commandResponse)
{
    auto authStatus = ensureAuthenticated(context);
    if (!authStatus.ok())
        return authStatus;
    std::shared_lock<std::shared_mutex> lock(m_moduleCmdMutex);
    return m_helpService->getHelp(*command, commandResponse);
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


grpc::Status TeamServer::HostArtifact(grpc::ServerContext* context,
    const teamserverapi::HostArtifactRequest* request, teamserverapi::JobExecutionRecord* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "HostArtifact", "denied");
        return authStatus;
    }
    const json details = {{"job_id", request->job_id()}, {"listener_hash", request->listener_hash()},
        {"artifact_reference", request->artifact_reference()}};
    writeAudit(context, actor, "HostArtifact", "requested", details);
    try
    {
        const json input = {{"listener_hash", request->listener_hash()},
            {"artifact_reference", request->artifact_reference()},
            {"hosted_filename", request->hosted_filename()}};
        copyJob(m_jobApplication->submit(request->job_id(), "host_artifact",
            input.dump(), actor, request->origin()), response, m_jobApplication->outputPreviewBytes());
    }
    catch (const JobError& error)
    {
        writeAudit(context, actor, "HostArtifact", "error", details);
        return jobStatus(error);
    }
    writeAudit(context, actor, "HostArtifact", response->state(), details);
    return grpc::Status::OK;
}

grpc::Status TeamServer::ControlSocks(grpc::ServerContext* context,
    const teamserverapi::SocksControlRequest* request, teamserverapi::JobExecutionRecord* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "ControlSocks", "denied");
        return authStatus;
    }
    const json details = {{"job_id", request->job_id()}, {"action", request->action()},
        {"beacon_hash", request->beacon_hash()}};
    writeAudit(context, actor, "ControlSocks", "requested", details);
    try
    {
        const json input = {{"action", request->action()}, {"beacon_hash", request->beacon_hash()}};
        copyJob(m_jobApplication->submit(request->job_id(), "socks_control",
            input.dump(), actor, request->origin()), response, m_jobApplication->outputPreviewBytes());
    }
    catch (const JobError& error)
    {
        writeAudit(context, actor, "ControlSocks", "error", details);
        return jobStatus(error);
    }
    writeAudit(context, actor, "ControlSocks", response->state(), details);
    return grpc::Status::OK;
}

grpc::Status TeamServer::ReloadModules(grpc::ServerContext* context,
    const teamserverapi::OperationRequest* request, teamserverapi::JobExecutionRecord* response)
{
    std::string actor;
    auto authStatus = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!authStatus.ok())
    {
        writeAudit(context, actor, "ReloadModules", "denied");
        return authStatus;
    }
    const json details = {{"job_id", request->job_id()}};
    writeAudit(context, actor, "ReloadModules", "requested", details);
    try
    {
        copyJob(m_jobApplication->submit(request->job_id(), "reload_modules", "{}",
            actor, request->origin()), response, m_jobApplication->outputPreviewBytes());
    }
    catch (const JobError& error)
    {
        writeAudit(context, actor, "ReloadModules", "error", details);
        return jobStatus(error);
    }
    writeAudit(context, actor, "ReloadModules", response->state(), details);
    return grpc::Status::OK;
}

grpc::Status TeamServer::GetListenerInfo(grpc::ServerContext* context,
    const teamserverapi::ListenerSelector* request, teamserverapi::ListenerInfoResponse* response)
{
    std::string actor;
    auto auth = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!auth.ok())
    {
        writeAudit(context, actor, "GetListenerInfo", "denied");
        return auth;
    }
    m_listenerArtifactService->getListenerInfo(request->listener_hash(), response);
    writeAudit(context, actor, "GetListenerInfo", response->status() == teamserverapi::OK ? "succeeded" : "failed");
    return grpc::Status::OK;
}

grpc::Status TeamServer::GetBeaconBinary(grpc::ServerContext* context,
    const teamserverapi::BeaconBinaryRequest* request, teamserverapi::BeaconBinaryResponse* response)
{
    std::string actor;
    auto auth = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!auth.ok())
    {
        writeAudit(context, actor, "GetBeaconBinary", "denied");
        return auth;
    }
    m_listenerArtifactService->getBeaconBinary(request->listener_hash(), request->target_os(),
        request->target_arch(), response);
    writeAudit(context, actor, "GetBeaconBinary", response->status() == teamserverapi::OK ? "succeeded" : "failed");
    return grpc::Status::OK;
}

grpc::Status TeamServer::UploadListenerFile(grpc::ServerContext* context,
    const teamserverapi::ListenerFileRequest* request, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto auth = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!auth.ok())
    {
        writeAudit(context, actor, "UploadListenerFile", "denied");
        return auth;
    }
    const auto result = m_localOperationService->uploadListenerFile(request->listener_hash(), request->filename(), request->data());
    response->set_status(result.ok ? teamserverapi::OK : teamserverapi::KO);
    response->set_message(result.output);
    writeAudit(context, actor, "UploadListenerFile", result.ok ? "succeeded" : "failed");
    return grpc::Status::OK;
}

grpc::Status TeamServer::InstallTool(grpc::ServerContext* context,
    const teamserverapi::ToolFile* request, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto auth = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!auth.ok())
    {
        writeAudit(context, actor, "InstallTool", "denied");
        return auth;
    }
    const auto result = m_localOperationService->installTool(request->filename(), request->data());
    response->set_status(result.ok ? teamserverapi::OK : teamserverapi::KO);
    response->set_message(result.output);
    writeAudit(context, actor, "InstallTool", result.ok ? "succeeded" : "failed");
    return grpc::Status::OK;
}

grpc::Status TeamServer::InstallToolBundle(grpc::ServerContext* context,
    const teamserverapi::ToolBundleRequest* request, teamserverapi::OperationAck* response)
{
    std::string actor;
    auto auth = m_authManager->ensureAuthenticated(context->client_metadata(), &actor);
    if (!auth.ok())
    {
        writeAudit(context, actor, "InstallToolBundle", "denied");
        return auth;
    }
    std::vector<std::pair<std::string, std::string>> files;
    files.reserve(static_cast<std::size_t>(request->files_size()));
    for (const auto& file : request->files())
        files.emplace_back(file.filename(), file.data());
    const auto result = m_localOperationService->installToolBundle(files);
    response->set_status(result.ok ? teamserverapi::OK : teamserverapi::KO);
    response->set_message(result.output);
    writeAudit(context, actor, "InstallToolBundle", result.ok ? "succeeded" : "failed");
    return grpc::Status::OK;
}

int TeamServer::prepMsg(const std::string& input, C2Message& c2Message, bool isWindows, const std::string& windowsArch)
{
    std::shared_lock<std::shared_mutex> lock(m_moduleCmdMutex);
    return m_commandPreparationService->prepareMessage(input, c2Message, isWindows, windowsArch);
}
