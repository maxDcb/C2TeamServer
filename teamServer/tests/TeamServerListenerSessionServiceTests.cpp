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

    void fail() { setState(State::Failed); }

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
    assert(streamedListeners[0].state() == teamserverapi::LISTENER_STATE_RUNNING);
    assert(streamedListeners[1].listener_hash() == "listener-child");
    assert(streamedListeners[1].parent_listener_hash() == "listener-primary");
    assert(streamedListeners[1].state() == teamserverapi::LISTENER_STATE_RUNNING);

    std::vector<teamserverapi::Session> streamedSessions;
    assert(service.streamSessions([&](const teamserverapi::Session& sessionInfo)
               {
                   streamedSessions.push_back(sessionInfo);
                   return true;
               })
               .ok());
    assert(streamedSessions.size() == 1);
    assert(streamedSessions[0].beacon_hash() == "ABCDEFGH12345678ABCDEFGH12345678");
    assert(streamedSessions[0].state() == teamserverapi::SESSION_STATE_RUNNING);

    primaryListener->fail();
    streamedListeners.clear();
    assert(service.streamListeners([&](const teamserverapi::Listener& listener)
               {
                   streamedListeners.push_back(listener);
                   return true;
               }).ok());
    assert(streamedListeners[0].state() == teamserverapi::LISTENER_STATE_FAILED);
    assert(streamedListeners[1].state() == teamserverapi::LISTENER_STATE_FAILED);
}

void testChildListenerMetadataAndLiveness()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    std::vector<std::shared_ptr<Listener>> listeners;
    auto primary = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "primary-route");
    const std::string parentHash(SizeBeaconHash, 'P');
    const std::string childHash(SizeBeaconHash, 'C');
    auto parent = primary->addSession("primary-route", parentHash, "parent", "user", "x64", "user", "Linux");
    primary->addSession("child-route", childHash, "child", "user", "x64", "user", "Linux");
    parent->addListener("child-route", ListenerTcpType, "127.0.0.1", "9001",
        std::chrono::steady_clock::now() - std::chrono::seconds(31));
    parent->addListener("invalid-port", ListenerTcpType, "127.0.0.1", "not-a-port");
    parent->addListener("invalid-type", ListenerHttpType, "127.0.0.1", "9002");
    listeners.push_back(primary);
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    CommonCommands commands;
    std::vector<BeaconCommandContext> sent;
    TeamServerListenerSessionService service(makeLogger(), config, listeners, modules, commands, sent, nullptr,
        [](const std::string&, C2Message& message, bool, const std::string&)
        {
            message.set_instruction("instruction");
            return 0;
        });

    std::vector<teamserverapi::Listener> snapshot;
    assert(service.streamListeners([&](const teamserverapi::Listener& item)
        { snapshot.push_back(item); return true; }).ok());
    assert(snapshot.size() == 2);
    assert(snapshot[1].listener_hash() == "child-route");
    assert(snapshot[1].state() == teamserverapi::LISTENER_STATE_UNAVAILABLE);
    assert(service.isListenerAlive("child-route"));
    std::vector<teamserverapi::Session> sessions;
    assert(service.streamSessions([&](const teamserverapi::Session& item)
        { sessions.push_back(item); return true; }).ok());
    assert(sessions.size() == 2); // Stale routes remain visible for audit/history.

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash(childHash);
    command.mutable_session()->set_listener_hash("child-route");
    command.set_command("ls");
    command.set_command_id("stale-child-command");
    teamserverapi::CommandAck rejected;
    assert(service.sendSessionCommand(command, &rejected).ok());
    assert(rejected.status() == teamserverapi::KO);
    assert(sent.empty());

    assert(!parent->addListener("child-route", ListenerTcpType, "127.0.0.1", "9001"));
    snapshot.clear();
    assert(service.streamListeners([&](const teamserverapi::Listener& item)
        { snapshot.push_back(item); return true; }).ok());
    assert(snapshot[1].state() == teamserverapi::LISTENER_STATE_RUNNING);
    teamserverapi::CommandAck accepted;
    assert(service.sendSessionCommand(command, &accepted).ok());
    assert(accepted.status() == teamserverapi::OK);
    assert(primary->getTask(childHash, "child-route").uuid() == "stale-child-command");

    std::vector<teamserverapi::CommandResult> reported;
    service.setJobResultHandler([&](const teamserverapi::CommandResult& result)
        { reported.push_back(result); });
    C2Message routeFailure;
    routeFailure.set_instruction(ListenerCmd);
    routeFailure.set_uuid("lost-child-command");
    routeFailure.set_data(RouteFailureReportTag);
    routeFailure.set_errorCode(ERROR_HASH_NOT_FOUND);
    routeFailure.set_returnvalue("Child listener route is unavailable.");
    assert(primary->addTaskResult(routeFailure, childHash, "child-route"));
    service.handleCmdResponse();
    assert(reported.size() == 1);
    assert(reported[0].status() == teamserverapi::KO);
    assert(reported[0].command_id() == "lost-child-command");
    assert(reported[0].output() == "Child listener route is unavailable.");

    assert(parent->updateProofOfLife("31"));
    snapshot.clear();
    assert(service.streamListeners([&](const teamserverapi::Listener& item)
        { snapshot.push_back(item); return true; }).ok());
    assert(snapshot[1].state() == teamserverapi::LISTENER_STATE_UNAVAILABLE);
}

void testChildCommandSelectsTheReachableUpstreamPath()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    const std::string parentHash(SizeBeaconHash, 'P');
    const std::string childHash(SizeBeaconHash, 'C');
    std::vector<std::shared_ptr<Listener>> listeners;
    auto stale = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "primary-a");
    auto healthy = std::make_shared<TestListener>("127.0.0.1", "8444", ListenerHttpsType, "primary-b");
    auto staleParent = stale->addSession("primary-a", parentHash, "parent", "user", "x64", "user", "Linux");
    auto healthyParent = healthy->addSession("primary-b", parentHash, "parent", "user", "x64", "user", "Linux");
    staleParent->addListener("shared-child-route", ListenerTcpType, "127.0.0.1", "9001");
    healthyParent->addListener("shared-child-route", ListenerTcpType, "127.0.0.1", "9001");
    stale->addSession("shared-child-route", childHash, "child", "user", "x64", "user", "Linux");
    healthy->addSession("shared-child-route", childHash, "child", "user", "x64", "user", "Linux");
    assert(staleParent->updateProofOfLife("31"));
    listeners.push_back(stale);
    listeners.push_back(healthy);
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    CommonCommands commands;
    std::vector<BeaconCommandContext> sent;
    TeamServerListenerSessionService service(makeLogger(), config, listeners, modules, commands, sent, nullptr,
        [](const std::string&, C2Message& message, bool, const std::string&)
        {
            message.set_instruction("instruction");
            return 0;
        });

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash(childHash);
    command.mutable_session()->set_listener_hash("shared-child-route");
    command.set_command("ls");
    command.set_command_id("healthy-path-command");
    teamserverapi::CommandAck response;
    assert(service.sendSessionCommand(command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(stale->getTask(childHash, "shared-child-route").instruction().empty());
    assert(healthy->getTask(childHash, "shared-child-route").uuid() == "healthy-path-command");
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

void testServerValidatesListenerRequests()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService service(
        logger, config, listeners, moduleCmd, commonCommands, sentCommands, nullptr,
        [](const std::string&, C2Message&, bool, const std::string&) { return 0; });

    const std::vector<std::pair<teamserverapi::Listener, std::string>> invalid = []
    {
        std::vector<std::pair<teamserverapi::Listener, std::string>> cases;
        teamserverapi::Listener unknown;
        unknown.set_type("unknown");
        cases.emplace_back(unknown, "Unknown listener type.");
        teamserverapi::Listener invalidIp;
        invalidIp.set_type(ListenerHttpType);
        invalidIp.set_ip("999.0.0.1");
        invalidIp.set_port(8080);
        cases.emplace_back(invalidIp, "IP must be a valid IPv4 or IPv6 address.");
        teamserverapi::Listener missingIp;
        missingIp.set_type(ListenerTcpType);
        missingIp.set_port(4444);
        cases.emplace_back(missingIp, "IP is required.");
        teamserverapi::Listener invalidPort;
        invalidPort.set_type(ListenerHttpsType);
        invalidPort.set_ip("127.0.0.1");
        invalidPort.set_port(0);
        cases.emplace_back(invalidPort, "Port must be a number between 1 and 65535.");
        invalidPort.set_port(65536);
        cases.emplace_back(invalidPort, "Port must be a number between 1 and 65535.");
        teamserverapi::Listener invalidDomain;
        invalidDomain.set_type(ListenerDnsType);
        invalidDomain.set_domain("https://example.com");
        invalidDomain.set_port(53);
        cases.emplace_back(invalidDomain, "Domain must be a valid DNS name.");
        return cases;
    }();
    for (const auto& [request, expectedMessage] : invalid)
    {
        teamserverapi::OperationAck response;
        assert(service.addListener(request, &response).ok());
        assert(response.status() == teamserverapi::KO);
        assert(response.message() == expectedMessage);
        assert(response.listener_hash().empty());
        assert(listeners.empty());
    }
}

void testChildStopIsPendingUntilListenerDisappears()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    auto primary = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "primary");
    const std::string beaconHash(SizeBeaconHash, 'A');
    auto session = primary->addSession("primary", beaconHash, "host", "user", "x64", "admin", "Linux");
    session->addListener("child", ListenerTcpType, "127.0.0.1", "9001");
    listeners.push_back(primary);
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService service(
        logger, config, listeners, moduleCmd, commonCommands, sentCommands, nullptr,
        [](const std::string&, C2Message& message, bool, const std::string&)
        {
            message.set_instruction("noop");
            return 0;
        });

    teamserverapi::ListenerSelector selector;
    selector.set_listener_hash("child");
    teamserverapi::OperationAck response;
    assert(service.stopListener(selector, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.listener_hash() == "child");
    assert(response.listener_state() == teamserverapi::LISTENER_STATE_STOPPING);
    teamserverapi::OperationAck duplicate;
    assert(service.stopListener(selector, &duplicate).ok());
    assert(duplicate.message() == "Listener stop is already pending.");

    std::vector<teamserverapi::Listener> snapshot;
    assert(service.streamListeners([&](const teamserverapi::Listener& listener)
               {
                   snapshot.push_back(listener);
                   return true;
               }).ok());
    assert(snapshot.size() == 2);
    assert(snapshot[1].state() == teamserverapi::LISTENER_STATE_STOPPING);

    assert(session->rmListener("child"));
    teamserverapi::OperationAck afterRemoval;
    assert(service.stopListener(selector, &afterRemoval).ok());
    assert(afterRemoval.status() == teamserverapi::KO);
    snapshot.clear();
    assert(service.streamListeners([&](const teamserverapi::Listener& listener)
               {
                   snapshot.push_back(listener);
                   return true;
               }).ok());
    assert(snapshot.size() == 1);
}

void testListenerListingDoesNotExposeGithubToken()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    listeners.push_back(std::make_shared<TestListener>(
        "owner/repo", "secret-token", ListenerGithubType, "github-listener"));
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService service(
        logger, config, listeners, moduleCmd, commonCommands, sentCommands, nullptr,
        [](const std::string&, C2Message&, bool, const std::string&) { return 0; });
    std::vector<teamserverapi::Listener> snapshot;
    assert(service.streamListeners([&](const teamserverapi::Listener& listener)
               {
                   snapshot.push_back(listener);
                   return true;
               }).ok());
    assert(snapshot.size() == 1);
    assert(snapshot[0].token().empty());
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
    requireBridge(afterStop.errorMessage == "Session stop in progress.",
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
    requireStop(ack.status() == teamserverapi::KO && ack.message() == "Session stop in progress.",
        "Command prepared before stop should be rejected at enqueue");
    requireStop(listener->getTask(beaconHash).instruction() == EndCmd,
        "Stop task should be the only queued task");
    requireStop(listener->getTask(beaconHash).instruction().empty(),
        "Command must not be queued after stop");
}

void testStaleListenerRouteUsesUniqueActiveSession()
{
    const auto requireRoute = [](bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    };
    const std::string beaconHash(SizeBeaconHash, 'R');
    nlohmann::json config = {{"LogLevel", "off"}};
    std::vector<std::shared_ptr<Listener>> listeners;
    auto current = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "current-listener");
    current->addSession("current-listener", beaconHash, "host", "user", "x64", "user", "Linux");
    listeners.push_back(current);
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService service(makeLogger(), config, listeners, modules, commonCommands,
        sentCommands, nullptr,
        [](const std::string& input, C2Message& message, bool, const std::string&)
        {
            message.set_instruction(input == EndInstruction ? EndCmd : "instruction");
            return 0;
        });

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash(beaconHash);
    command.mutable_session()->set_listener_hash("stale-listener");
    command.set_command("ls");
    command.set_command_id("rerouted-command");
    teamserverapi::CommandAck response;
    requireRoute(service.sendSessionCommand(command, &response).ok(), "Rerouted command RPC failed");
    requireRoute(response.status() == teamserverapi::OK, "Rerouted command was rejected");
    requireRoute(sentCommands.size() == 1 && sentCommands[0].listenerHash == "current-listener",
        "Rerouted command recorded the stale listener");
    requireRoute(current->getTask(beaconHash).uuid() == "rerouted-command",
        "Rerouted command was not queued on the active listener");

    teamserverapi::SessionSelector stop;
    stop.set_beacon_hash(beaconHash);
    stop.set_listener_hash("stale-listener");
    teamserverapi::OperationAck stopResponse;
    requireRoute(service.stopSession(stop, &stopResponse).ok(), "Rerouted stop RPC failed");
    requireRoute(stopResponse.status() == teamserverapi::OK, "Rerouted stop was rejected");
    requireRoute(stopResponse.session_beacon_hash() == beaconHash
        && stopResponse.session_listener_hash() == "current-listener"
        && stopResponse.session_state() == teamserverapi::SESSION_STATE_STOPPING,
        "Rerouted stop acknowledgement did not identify the active route and state");
    std::vector<teamserverapi::Session> stoppingSessions;
    requireRoute(service.streamSessions([&](const teamserverapi::Session& item)
        { stoppingSessions.push_back(item); return true; }).ok(), "Stopping session listing failed");
    requireRoute(stoppingSessions.size() == 1
        && stoppingSessions[0].state() == teamserverapi::SESSION_STATE_STOPPING
        && !stoppingSessions[0].killed(), "Queued stop disappeared before confirmation");
    requireRoute(current->getTask(beaconHash).instruction() == EndCmd,
        "Rerouted stop was not queued on the active listener");
    requireRoute(current->markSessionKilled(beaconHash, "current-listener"), "Confirmation was not recorded");
    stoppingSessions.clear();
    requireRoute(service.streamSessions([&](const teamserverapi::Session& item)
        { stoppingSessions.push_back(item); return true; }).ok(), "Confirmed session listing failed");
    requireRoute(stoppingSessions.size() == 1
        && stoppingSessions[0].state() == teamserverapi::SESSION_STATE_STOPPED
        && stoppingSessions[0].killed(), "Confirmed stop was not visible");
}

void testStaleListenerRouteDoesNotGuessBetweenActivePaths()
{
    const auto requireRoute = [](bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    };
    const std::string beaconHash(SizeBeaconHash, 'R');
    nlohmann::json config = {{"LogLevel", "off"}};
    std::vector<std::shared_ptr<Listener>> listeners;
    for (const std::string& hash : {"route-one", "route-two"})
    {
        auto listener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, hash);
        listener->addSession(hash, beaconHash, "host", "user", "x64", "user", "Linux");
        listeners.push_back(listener);
    }
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    CommonCommands commonCommands;
    std::vector<BeaconCommandContext> sentCommands;
    TeamServerListenerSessionService service(makeLogger(), config, listeners, modules, commonCommands,
        sentCommands, nullptr,
        [](const std::string&, C2Message& message, bool, const std::string&)
        {
            message.set_instruction("instruction");
            return 0;
        });

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash(beaconHash);
    command.mutable_session()->set_listener_hash("stale-listener");
    command.set_command("ls");
    teamserverapi::CommandAck response;
    requireRoute(service.sendSessionCommand(command, &response).ok(), "Ambiguous route RPC failed");
    requireRoute(response.status() == teamserverapi::KO, "Ambiguous route was accepted");
    requireRoute(response.message().find("Multiple active routes") != std::string::npos,
        "Ambiguous route did not explain the conflict");
    requireRoute(sentCommands.empty(), "Ambiguous route queued a command");

    teamserverapi::SessionSelector stop;
    stop.set_beacon_hash(beaconHash);
    stop.set_listener_hash("stale-listener");
    teamserverapi::OperationAck stopResponse;
    requireRoute(service.stopSession(stop, &stopResponse).ok(), "Ambiguous stop RPC failed");
    requireRoute(stopResponse.status() == teamserverapi::KO
        && stopResponse.message().find("Multiple active routes") != std::string::npos,
        "Ambiguous stop did not reject the request");
    for (const auto& listener : listeners)
        requireRoute(listener->getTask(beaconHash).instruction().empty(),
            "Ambiguous stop queued a task on a route");

    command.mutable_session()->set_listener_hash("route-two");
    teamserverapi::CommandAck exactResponse;
    requireRoute(service.sendSessionCommand(command, &exactResponse).ok(), "Exact route RPC failed");
    requireRoute(exactResponse.status() == teamserverapi::OK,
        "Exact active route was rejected because another path exists");
    requireRoute(sentCommands.size() == 1 && sentCommands[0].listenerHash == "route-two",
        "Exact route command was queued on the wrong listener");
}
} // namespace

int main()
{
    testCollectListenersAndSessions();
    testChildListenerMetadataAndLiveness();
    testChildCommandSelectsTheReachableUpstreamPath();
    testQueueStopAndResponseDelivery();
    testAddListenerRejectsTcpBoundPortConflicts();
    testServerValidatesListenerRequests();
    testChildStopIsPendingUntilListenerDisappears();
    testListenerListingDoesNotExposeGithubToken();
#ifndef C2_ENABLE_GITHUB_TRANSPORT
    testAddListenerRejectsDisabledGithubTransport();
#endif
    testModuleTrackingBlocksDuplicateLoadsAndListsLoadedModules();
    testPendingGeneratedArtifactChunksDoNotEmitIntermediateResponses();
    testDurableSessionCommandBridge();
    testStopDuringPreparationRejectsCommand();
    testStaleListenerRouteUsesUniqueActiveSession();
    testStaleListenerRouteDoesNotGuessBetweenActivePaths();
    return 0;
}
