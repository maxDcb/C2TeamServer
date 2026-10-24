#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <unistd.h>

#include <grpcpp/support/string_ref.h>

#include "TeamServerFileArtifactService.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "JobApplicationService.hpp"
#include "SqliteJobRepository.hpp"
#include "TeamServerListenerSessionService.hpp"

namespace fs = std::filesystem;

namespace
{
class ScopedPath
{
public:
    explicit ScopedPath(fs::path path)
        : m_path(std::move(path))
    {
    }

    ~ScopedPath()
    {
        std::error_code ec;
        fs::remove_all(m_path, ec);
    }

    const fs::path& path() const
    {
        return m_path;
    }

private:
    fs::path m_path;
};

class TestListener final : public Listener
{
public:
    TestListener(const std::string& param1, const std::string& param2, const std::string& type, const std::string& hash)
        : Listener(param1, param2, type)
    {
        m_listenerHash = hash;
        setState(State::Running);
    }

    std::shared_ptr<Session> addSession(
        const std::string& listenerHash,
        const std::string& beaconHash,
        const std::string& hostname,
        const std::string& username,
        const std::string& arch,
        const std::string& privilege,
        const std::string& os)
    {
        auto session = std::make_shared<Session>(listenerHash, beaconHash, hostname, username, arch, privilege, os);
        m_sessions.push_back(session);
        return session;
    }
};

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

fs::path makeTempDirectory(const std::string& name)
{
    fs::path root = fs::temp_directory_path() / ("c2teamserver-listener-session-" + name + "-" + std::to_string(::getpid()));
    fs::create_directories(root);
    return root;
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.generatedArtifactsDirectoryPath = (root / "GeneratedArtifacts").string() + "/";
    runtimeConfig.defaultWindowsArch = "x64";
    runtimeConfig.defaultLinuxArch = "x64";
    return runtimeConfig;
}

std::string readFile(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), {});
}

void testCollectListenersAndSessions()
{
    nlohmann::json config = {
        {"LogLevel", "off"},
        {"HttpsListener", {{"PortBind", 0}}},
        {"HttpListener", {{"PortBind", 0}}},
        {"SmbListener", {{"Pipename", "pipe"}}},
        {"DnsListener", {{"PortBind", 0}}}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    auto primaryListener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    auto session = primaryListener->addSession("listener-primary", "ABCDEFGH12345678ABCDEFGH12345678", "host", "user", "x64", "admin", "Linux");
    session->addListener("listener-child", ListenerTcpType, "10.0.0.1", "9001");
    listeners.push_back(primaryListener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::vector<BeaconCommandContext> sentCommands;

    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        sentCommands,
        nullptr,
        [](const std::string&, C2Message& c2Message, bool, const std::string&)
        {
            c2Message.set_instruction("noop");
            return 0;
        });

    std::vector<teamserverapi::Listener> streamedListeners;
    assert(service.streamListeners([&](const teamserverapi::Listener& listener)
               {
                   streamedListeners.push_back(listener);
                   return true;
               })
               .ok());
    assert(streamedListeners.size() == 2);
    assert(streamedListeners[0].listener_hash() == "listener-primary");
    assert(streamedListeners[1].listener_hash() == "listener-child");

    std::vector<teamserverapi::Session> streamedSessions;
    assert(service.streamSessions([&](const teamserverapi::Session& sessionInfo)
               {
                   streamedSessions.push_back(sessionInfo);
                   return true;
               })
               .ok());
    assert(streamedSessions.size() == 1);
    assert(streamedSessions[0].beacon_hash() == "ABCDEFGH12345678ABCDEFGH12345678");
}

void testQueueStopAndResponseDelivery()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    auto primaryListener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    const std::string beaconHash(SizeBeaconHash, 'A');
    primaryListener->addSession("listener-primary", beaconHash, "host", "user", "arm64", "admin", "Windows");
    listeners.push_back(primaryListener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::vector<BeaconCommandContext> sentCommands;

    std::string preparedArch;
    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        sentCommands,
        nullptr,
        [&preparedArch](const std::string& input, C2Message& c2Message, bool, const std::string& windowsArch)
        {
            preparedArch = windowsArch;
            c2Message.set_instruction("instruction");
            c2Message.set_cmd(input);
            c2Message.set_returnvalue("");
            return 0;
        });

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash(beaconHash);
    command.mutable_session()->set_listener_hash("listener-primary");
    command.set_command("whoami");
    command.set_command_id("cmd-0001");

    teamserverapi::CommandAck response;
    assert(service.sendSessionCommand(command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.command_id() == "cmd-0001");
    assert(preparedArch == "arm64");
    C2Message queuedTask = primaryListener->getTask(beaconHash);
    assert(queuedTask.instruction() == "instruction");
    assert(queuedTask.uuid() == "cmd-0001");

    C2Message emptyResult;
    emptyResult.set_instruction("instruction");
    emptyResult.set_uuid("cmd-0001");
    emptyResult.set_cmd("internal command payload");
    emptyResult.set_returnvalue("");
    assert(primaryListener->addTaskResult(emptyResult, beaconHash));
    service.setJobResultHandler([&](const teamserverapi::CommandResult& result) { cmdResponses.push_back(result); });
    service.handleCmdResponse();
    assert(cmdResponses.size() == 1);
    assert(cmdResponses[0].session().listener_hash() == "listener-primary");
    assert(cmdResponses[0].command_id() == "cmd-0001");
    assert(cmdResponses[0].command() == "whoami");
    assert(cmdResponses[0].output().empty());

    teamserverapi::SessionSelector sessionToStop;
    sessionToStop.set_beacon_hash(beaconHash);
    sessionToStop.set_listener_hash("listener-primary");
    teamserverapi::OperationAck stopResponse;
    assert(service.stopSession(sessionToStop, &stopResponse).ok());
    assert(stopResponse.status() == teamserverapi::OK);
    C2Message stopTask = primaryListener->getTask(beaconHash);
    assert(stopTask.instruction() == "instruction");


}

void testAddListenerRejectsTcpBoundPortConflicts()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    listeners.push_back(std::make_shared<TestListener>("0.0.0.0", "8443", ListenerHttpsType, "listener-primary"));

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::vector<BeaconCommandContext> sentCommands;

    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        sentCommands,
        nullptr,
        [](const std::string&, C2Message&, bool, const std::string&)
        {
            return 0;
        });

    teamserverapi::Listener tcpListener;
    tcpListener.set_type(ListenerTcpType);
    tcpListener.set_ip("0.0.0.0");
    tcpListener.set_port(8443);

    teamserverapi::OperationAck response;
    assert(service.addListener(tcpListener, &response).ok());
    assert(response.status() == teamserverapi::KO);
    assert(response.message() == "Port 8443 is already used by https listener.");
    assert(listeners.size() == 1);
}

#ifndef C2_ENABLE_GITHUB_TRANSPORT
void testAddListenerRejectsDisabledGithubTransport()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;

    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        sentCommands,
        nullptr,
        [](const std::string&, C2Message&, bool, const std::string&)
        {
            return 0;
        });

    teamserverapi::Listener githubListener;
    githubListener.set_type(ListenerGithubType);
    githubListener.set_project("owner/repository");
    githubListener.set_token("token");

    teamserverapi::OperationAck response;
    assert(service.addListener(githubListener, &response).ok());
    assert(response.status() == teamserverapi::KO);
    assert(response.message() == "GitHub transport is disabled in this build.");
    assert(listeners.empty());
}
#endif

void testModuleTrackingBlocksDuplicateLoadsAndListsLoadedModules()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    auto primaryListener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    primaryListener->addSession("listener-primary", "ABCDEFGH12345678ABCDEFGH12345678", "host", "user", "x64", "admin", "Linux");
    listeners.push_back(primaryListener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::vector<BeaconCommandContext> sentCommands;

    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        sentCommands,
        nullptr,
        [](const std::string& input, C2Message& c2Message, bool, const std::string&)
        {
            if (input.rfind("loadModule", 0) == 0)
            {
                c2Message.set_instruction(LoadC2ModuleCmd);
                c2Message.set_inputfile("libPrintWorkingDirectory.so");
                c2Message.set_data("module-bytes");
            }
            else if (input.rfind("unloadModule", 0) == 0)
            {
                c2Message.set_instruction(UnloadC2ModuleCmd);
                c2Message.set_cmd("pwd");
            }
            else
            {
                c2Message.set_instruction("instruction");
                c2Message.set_cmd(input);
            }
            return 0;
        });

    teamserverapi::SessionCommandRequest loadCommand;
    loadCommand.mutable_session()->set_beacon_hash("ABCDEFGH12345678ABCDEFGH12345678");
    loadCommand.mutable_session()->set_listener_hash("listener-primary");
    loadCommand.set_command("loadModule pwd");
    loadCommand.set_command_id("load-0001");

    teamserverapi::CommandAck loadResponse;
    assert(service.sendSessionCommand(loadCommand, &loadResponse).ok());
    assert(loadResponse.status() == teamserverapi::OK);

    std::vector<teamserverapi::LoadedModule> modules;
    teamserverapi::SessionSelector sessionSelector;
    sessionSelector.set_beacon_hash("ABCDEFGH12345678ABCDEFGH12345678");
    sessionSelector.set_listener_hash("listener-primary");
    assert(service.streamModulesForSession(
               sessionSelector,
               [&](const teamserverapi::LoadedModule& module)
               {
                   modules.push_back(module);
                   return true;
               })
               .ok());
    assert(modules.size() == 1);
    assert(modules[0].name() == "pwd");
    assert(modules[0].state() == "loading");

    teamserverapi::CommandAck duplicateLoadResponse;
    assert(service.sendSessionCommand(loadCommand, &duplicateLoadResponse).ok());
    assert(duplicateLoadResponse.status() == teamserverapi::KO);
    assert(duplicateLoadResponse.message().find("already tracked") != std::string::npos);

    C2Message loadResult;
    loadResult.set_instruction(LoadC2ModuleCmd);
    loadResult.set_uuid("load-0001");
    loadResult.set_returnvalue(CmdStatusSuccess);
    assert(primaryListener->addTaskResult(loadResult, "ABCDEFGH12345678ABCDEFGH12345678"));
    service.setJobResultHandler([&](const teamserverapi::CommandResult& result) { cmdResponses.push_back(result); });
    service.handleCmdResponse();

    modules.clear();
    assert(service.streamModulesForSession(
               sessionSelector,
               [&](const teamserverapi::LoadedModule& module)
               {
                   modules.push_back(module);
                   return true;
               })
               .ok());
    assert(modules.size() == 1);
    assert(modules[0].name() == "pwd");
    assert(modules[0].state() == "loaded");
    assert(modules[0].load_count() == 1);

    teamserverapi::SessionCommandRequest unloadCommand;
    unloadCommand.mutable_session()->set_beacon_hash("ABCDEFGH12345678ABCDEFGH12345678");
    unloadCommand.mutable_session()->set_listener_hash("listener-primary");
    unloadCommand.set_command("unloadModule pwd");
    unloadCommand.set_command_id("unload-0001");

    teamserverapi::CommandAck unloadResponse;
    assert(service.sendSessionCommand(unloadCommand, &unloadResponse).ok());
    assert(unloadResponse.status() == teamserverapi::OK);

    modules.clear();
    assert(service.streamModulesForSession(
               sessionSelector,
               [&](const teamserverapi::LoadedModule& module)
               {
                   modules.push_back(module);
                   return true;
               })
               .ok());
    assert(modules.size() == 1);
    assert(modules[0].state() == "unloading");

    C2Message unloadResult;
    unloadResult.set_instruction(UnloadC2ModuleCmd);
    unloadResult.set_uuid("unload-0001");
    unloadResult.set_returnvalue(CmdStatusSuccess);
    assert(primaryListener->addTaskResult(unloadResult, "ABCDEFGH12345678ABCDEFGH12345678"));
    service.setJobResultHandler([&](const teamserverapi::CommandResult& result) { cmdResponses.push_back(result); });
    service.handleCmdResponse();

    modules.clear();
    assert(service.streamModulesForSession(
               sessionSelector,
               [&](const teamserverapi::LoadedModule& module)
               {
                   modules.push_back(module);
                   return true;
               })
               .ok());
    assert(modules.empty());
}

void testPendingGeneratedArtifactChunksDoNotEmitIntermediateResponses()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    auto primaryListener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    primaryListener->addSession("listener-primary", "ABCDEFGH12345678ABCDEFGH12345678", "host", "user", "x64", "admin", "Windows");
    listeners.push_back(primaryListener);

    ScopedPath tempRoot(makeTempDirectory("pending-artifact"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        logger,
        runtimeConfig,
        artifactStore);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::vector<BeaconCommandContext> sentCommands;

    std::string preparedOutputFile;
    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        sentCommands,
        fileArtifactService,
        [&](const std::string& input, C2Message& c2Message, bool, const std::string&)
        {
            TeamServerGeneratedFileArtifactSpec spec;
            spec.remotePath = input;
            spec.nameHint = "desktop.png";
            spec.category = "screenshot";
            spec.source = "beacon";
            spec.target = "teamserver";
            spec.runtime = "file";
            spec.format = "png";
            spec.isWindows = true;
            spec.arch = "x64";
            spec.writeResultData = true;
            const TeamServerPreparedDownloadArtifact artifact = fileArtifactService->prepareGeneratedFileArtifact(spec);
            assert(artifact.ok);

            preparedOutputFile = artifact.path;
            c2Message.set_instruction("screenShot");
            c2Message.set_outputfile(artifact.path);
            c2Message.set_cmd(input);
            return 0;
        });

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash("ABCDEFGH12345678ABCDEFGH12345678");
    command.mutable_session()->set_listener_hash("listener-primary");
    command.set_command("screenShot desktop.png");
    command.set_command_id("shot-0001");

    teamserverapi::CommandAck response;
    assert(service.sendSessionCommand(command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(!preparedOutputFile.empty());

    C2Message queuedTask = primaryListener->getTask("ABCDEFGH12345678ABCDEFGH12345678");
    assert(queuedTask.instruction() == "screenShot");
    assert(queuedTask.uuid() == "shot-0001");

    C2Message firstChunk;
    firstChunk.set_instruction("screenShot");
    firstChunk.set_outputfile(preparedOutputFile);
    firstChunk.set_args("0");
    firstChunk.set_data("AA");
    firstChunk.set_returnvalue("2/4");
    assert(primaryListener->addTaskResult(firstChunk, "ABCDEFGH12345678ABCDEFGH12345678"));
    service.setJobResultHandler([&](const teamserverapi::CommandResult& result) { cmdResponses.push_back(result); });
    service.handleCmdResponse();
    assert(cmdResponses.empty());
    assert(sentCommands.size() == 1);
    assert(readFile(preparedOutputFile) == "AA");

    C2Message finalChunk;
    finalChunk.set_instruction("screenShot");
    finalChunk.set_outputfile(preparedOutputFile);
    finalChunk.set_args("1");
    finalChunk.set_data("BB");
    finalChunk.set_returnvalue("Success");
    assert(primaryListener->addTaskResult(finalChunk, "ABCDEFGH12345678ABCDEFGH12345678"));
    service.handleCmdResponse();

    assert(sentCommands.empty());
    assert(cmdResponses.size() == 1);
    assert(cmdResponses[0].command_id() == "shot-0001");
    assert(cmdResponses[0].command() == "screenShot desktop.png");
    assert(cmdResponses[0].output().find("Generated artifact stored:") != std::string::npos);
    assert(readFile(preparedOutputFile) == "AABB");
    assert(fs::exists(preparedOutputFile + ".artifact.json"));
    assert(!fs::exists(preparedOutputFile + ".artifact.pending.json"));
}

void testDurableSessionCommandBridge()
{
    const auto requireBridge = [](bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    };
    ScopedPath temp(makeTempDirectory("job-bridge"));
    auto repository = std::make_shared<SqliteJobRepository>((temp.path() / "jobs.sqlite").string());
    auto logger = makeLogger();
    nlohmann::json config = {{"LogLevel", "off"}};
    std::vector<std::shared_ptr<Listener>> listeners;
    auto listener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    listener->addSession("listener-primary", "ABCDEFGH12345678ABCDEFGH12345678", "host", "user", "x64", "admin", "Linux");
    listeners.push_back(listener);
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService service(logger, config, listeners, modules, commonCommands,
        sentCommands, nullptr,
        [](const std::string& input, C2Message& message, bool, const std::string&)
        {
            message.set_instruction(input == EndInstruction ? EndCmd : "whoami");
            message.set_cmd(input);
            return 0;
        });
    auto application = std::make_shared<JobApplicationService>(repository, 65536,
        [&](const JobExecution& job) -> std::string
        {
            teamserverapi::SessionCommandRequest request;
            request.set_command_id(job.jobId);
            request.set_command("whoami");
            request.mutable_session()->set_beacon_hash("ABCDEFGH12345678ABCDEFGH12345678");
            request.mutable_session()->set_listener_hash("listener-primary");
            teamserverapi::CommandAck ack;
            service.sendSessionCommand(request, &ack);
            return ack.status() == teamserverapi::OK ? std::string{} : ack.message();
        });
    service.setJobResultHandler([&](const teamserverapi::CommandResult& result)
    {
        application->complete(result.command_id(), result.status() == teamserverapi::OK, result.output(),
            result.status() == teamserverapi::OK ? "" : "command_failed", result.message());
    });

    const auto queued = application->submit("job-bridge-1", "session_command",
        R"({"command":"whoami","beacon_hash":"ABCDEFGH12345678ABCDEFGH12345678","listener_hash":"listener-primary"})");
    requireBridge(queued.state == "queued", "Session job was not queued");
    auto task = listener->getTask("ABCDEFGH12345678ABCDEFGH12345678");
    requireBridge(task.uuid() == "job-bridge-1", "Beacon task lost its job ID");
    task.set_returnvalue(std::string("A\0\xff", 3));
    requireBridge(listener->addTaskResult(task, "ABCDEFGH12345678ABCDEFGH12345678"), "Could not enqueue beacon result");
    service.handleCmdResponse();
    const auto completed = application->get("job-bridge-1");
    requireBridge(completed.state == "succeeded", "Session job did not complete");
    requireBridge(completed.outputInline == std::string("A\0\xff", 3), "Beacon result bytes changed");
    const auto events = application->events(0, {}, 10);
    requireBridge(events.size() == 3, "Session job event count incorrect");
    requireBridge(events[0].eventType == "accepted" && events[1].eventType == "queued"
        && events[2].eventType == "succeeded", "Session job event order incorrect");
    auto reopened = std::make_shared<SqliteJobRepository>((temp.path() / "jobs.sqlite").string());
    requireBridge(reopened->get("job-bridge-1").outputInline == std::string("A\0\xff", 3),
        "Reopen lost beacon result");

    const auto queuedMissingModule = application->submit("job-bridge-missing-module", "session_command",
        R"({"command":"whoami","beacon_hash":"ABCDEFGH12345678ABCDEFGH12345678","listener_hash":"listener-primary"})");
    requireBridge(queuedMissingModule.state == "queued", "Missing-module job was not queued");
    auto missingModuleTask = listener->getTask("ABCDEFGH12345678ABCDEFGH12345678");
    requireBridge(missingModuleTask.uuid() == "job-bridge-missing-module", "Missing-module task lost its job ID");
    missingModuleTask.set_returnvalue(CmdModuleNotFound);
    requireBridge(listener->addTaskResult(missingModuleTask, "ABCDEFGH12345678ABCDEFGH12345678"),
        "Could not enqueue missing-module result");
    service.handleCmdResponse();
    const auto failed = application->get("job-bridge-missing-module");
    requireBridge(failed.state == "failed", "Old beacon missing-module result was classified as success");
    requireBridge(failed.errorMessage == "Error: Module not loaded", "Missing-module error message was lost");
    const auto failureEvents = application->events(0, {}, 10);
    requireBridge(failureEvents.size() == 6 && failureEvents.back().eventType == "failed",
        "Missing-module failure event was not persisted");

    const auto queuedCodedFailure = application->submit("job-bridge-missing-module-code", "session_command",
        R"({"command":"whoami","beacon_hash":"ABCDEFGH12345678ABCDEFGH12345678","listener_hash":"listener-primary"})");
    requireBridge(queuedCodedFailure.state == "queued", "Coded missing-module job was not queued");
    auto codedFailureTask = listener->getTask("ABCDEFGH12345678ABCDEFGH12345678");
    codedFailureTask.set_errorCode(ERROR_MODULE_NOT_FOUND);
    codedFailureTask.set_returnvalue("");
    requireBridge(listener->addTaskResult(codedFailureTask, "ABCDEFGH12345678ABCDEFGH12345678"),
        "Could not enqueue coded missing-module result");
    service.handleCmdResponse();
    requireBridge(application->get("job-bridge-missing-module-code").state == "failed",
        "Coded missing-module result was classified as success");

    teamserverapi::SessionSelector stopSelector;
    stopSelector.set_beacon_hash("ABCDEFGH12345678ABCDEFGH12345678");
    stopSelector.set_listener_hash("listener-primary");
    teamserverapi::OperationAck stopAck;
    requireBridge(service.stopSession(stopSelector, &stopAck).ok() && stopAck.status() == teamserverapi::OK,
        "Stop command was not accepted");
    requireBridge(listener->getTask("ABCDEFGH12345678ABCDEFGH12345678").instruction() == EndCmd,
        "Stop task was not queued");

    const auto afterStop = application->submit("job-bridge-after-stop", "session_command",
        R"({"command":"whoami","beacon_hash":"ABCDEFGH12345678ABCDEFGH12345678","listener_hash":"listener-primary"})");
    requireBridge(afterStop.state == "failed" && afterStop.errorCode == "dispatch_failed",
        "Command after stop should fail during dispatch");
    requireBridge(afterStop.errorMessage == "Session is stopped.",
        "Command after stop should explain why it was rejected");
    requireBridge(listener->getTask("ABCDEFGH12345678ABCDEFGH12345678").instruction().empty(),
        "Command after stop must not be queued");
    const auto afterStopEvents = application->events(0, {}, 20);
    requireBridge(afterStopEvents.back().eventType == "failed",
        "Rejected command should emit a failed event");

    teamserverapi::OperationAck secondStopAck;
    requireBridge(service.stopSession(stopSelector, &secondStopAck).ok()
        && secondStopAck.status() == teamserverapi::KO,
        "Duplicate stop command should be rejected");
    requireBridge(listener->getTask("ABCDEFGH12345678ABCDEFGH12345678").instruction().empty(),
        "Duplicate stop task must not be queued");
}

void testStopDuringPreparationRejectsCommand()
{
    const auto requireStop = [](bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    };
    const std::string beaconHash = "ABCDEFGH12345678ABCDEFGH12345678";
    nlohmann::json config = {{"LogLevel", "off"}};
    std::vector<std::shared_ptr<Listener>> listeners;
    auto listener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    listener->addSession("listener-primary", beaconHash, "host", "user", "x64", "admin", "Linux");
    listeners.push_back(listener);
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService* servicePtr = nullptr;
    teamserverapi::OperationAck stopAck;
    TeamServerListenerSessionService service(makeLogger(), config, listeners, modules, commonCommands,
        sentCommands, nullptr,
        [&](const std::string& input, C2Message& message, bool, const std::string&)
        {
            if (input == EndInstruction)
            {
                message.set_instruction(EndCmd);
                return 0;
            }
            teamserverapi::SessionSelector selector;
            selector.set_beacon_hash(beaconHash);
            selector.set_listener_hash("listener-primary");
            servicePtr->stopSession(selector, &stopAck);
            message.set_instruction("whoami");
            return 0;
        });
    servicePtr = &service;

    teamserverapi::SessionCommandRequest request;
    request.mutable_session()->set_beacon_hash(beaconHash);
    request.mutable_session()->set_listener_hash("listener-primary");
    request.set_command("whoami");
    request.set_command_id("command-during-stop");
    teamserverapi::CommandAck ack;
    requireStop(service.sendSessionCommand(request, &ack).ok(), "Session command RPC failed");
    requireStop(stopAck.status() == teamserverapi::OK, "Stop during preparation was not accepted");
    requireStop(ack.status() == teamserverapi::KO && ack.message() == "Session is stopped.",
        "Command prepared before stop should be rejected at enqueue");
    requireStop(listener->getTask(beaconHash).instruction() == EndCmd,
        "Stop task should be the only queued task");
    requireStop(listener->getTask(beaconHash).instruction().empty(),
        "Command must not be queued after stop");
}
} // namespace

int main()
{
    testCollectListenersAndSessions();
    testQueueStopAndResponseDelivery();
    testAddListenerRejectsTcpBoundPortConflicts();
#ifndef C2_ENABLE_GITHUB_TRANSPORT
    testAddListenerRejectsDisabledGithubTransport();
#endif
    testModuleTrackingBlocksDuplicateLoadsAndListsLoadedModules();
    testPendingGeneratedArtifactChunksDoNotEmitIntermediateResponses();
    testDurableSessionCommandBridge();
    testStopDuringPreparationRejectsCommand();
    return 0;
}
