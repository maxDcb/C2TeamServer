#include <cassert>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <grpcpp/support/string_ref.h>

#include "TeamServerListenerSessionService.hpp"

namespace
{
class TestListener final : public Listener
{
public:
    TestListener(const std::string& param1, const std::string& param2, const std::string& type, const std::string& hash)
        : Listener(param1, param2, type)
    {
        m_listenerHash = hash;
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

std::multimap<grpc::string_ref, grpc::string_ref> makeMetadata(std::string& clientIdKey, std::string& clientIdValue)
{
    std::multimap<grpc::string_ref, grpc::string_ref> metadata;
    metadata.emplace(
        grpc::string_ref(clientIdKey.data(), clientIdKey.size()),
        grpc::string_ref(clientIdValue.data(), clientIdValue.size()));
    return metadata;
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
    auto session = primaryListener->addSession("listener-primary", "ABCDEFGH12345678", "host", "user", "x64", "admin", "Linux");
    session->addListener("listener-child", ListenerTcpType, "10.0.0.1", "9001");
    listeners.push_back(primaryListener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::unordered_map<std::string, std::vector<int>> sentResponses;
    std::vector<BeaconCommandContext> sentCommands;

    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        cmdResponses,
        sentResponses,
        sentCommands,
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
    assert(streamedSessions[0].beacon_hash() == "ABCDEFGH12345678");
}

void testQueueStopAndResponseDeduplication()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    auto primaryListener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    primaryListener->addSession("listener-primary", "ABCDEFGH12345678", "host", "user", "arm64", "admin", "Windows");
    listeners.push_back(primaryListener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::unordered_map<std::string, std::vector<int>> sentResponses;
    std::vector<BeaconCommandContext> sentCommands;

    std::string preparedArch;
    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        cmdResponses,
        sentResponses,
        sentCommands,
        [&preparedArch](const std::string& input, C2Message& c2Message, bool, const std::string& windowsArch)
        {
            preparedArch = windowsArch;
            c2Message.set_instruction("instruction");
            c2Message.set_cmd(input);
            c2Message.set_returnvalue("");
            return 0;
        });

    teamserverapi::SessionCommandRequest command;
    command.mutable_session()->set_beacon_hash("ABCDEFGH12345678");
    command.mutable_session()->set_listener_hash("listener-primary");
    command.set_command("whoami");
    command.set_command_id("cmd-0001");

    teamserverapi::CommandAck response;
    assert(service.sendSessionCommand(command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.command_id() == "cmd-0001");
    assert(preparedArch == "arm64");
    C2Message queuedTask = primaryListener->getTask("ABCDEFGH12345678");
    assert(queuedTask.instruction() == "instruction");
    assert(queuedTask.uuid() == "cmd-0001");

    C2Message emptyResult;
    emptyResult.set_instruction("instruction");
    emptyResult.set_uuid("cmd-0001");
    emptyResult.set_cmd("internal command payload");
    emptyResult.set_returnvalue("");
    assert(primaryListener->addTaskResult(emptyResult, "ABCDEFGH12345678"));
    service.handleCmdResponse();
    assert(cmdResponses.size() == 1);
    assert(cmdResponses[0].session().listener_hash() == "listener-primary");
    assert(cmdResponses[0].command_id() == "cmd-0001");
    assert(cmdResponses[0].command() == "whoami");
    assert(cmdResponses[0].output().empty());

    teamserverapi::SessionSelector sessionToStop;
    sessionToStop.set_beacon_hash("ABCDEFGH12345678");
    sessionToStop.set_listener_hash("listener-primary");
    teamserverapi::OperationAck stopResponse;
    assert(service.stopSession(sessionToStop, &stopResponse).ok());
    assert(stopResponse.status() == teamserverapi::OK);
    C2Message stopTask = primaryListener->getTask("ABCDEFGH12345678");
    assert(stopTask.instruction() == "instruction");

    std::string clientIdKey = "clientid";
    std::string firstClientId = "client-a";
    auto firstMetadata = makeMetadata(clientIdKey, firstClientId);

    std::vector<teamserverapi::CommandResult> streamedResponses;
    assert(service.streamResponsesForSession(
               sessionToStop,
               firstMetadata,
               [&](const teamserverapi::CommandResult& responseInfo)
               {
                   streamedResponses.push_back(responseInfo);
                   return true;
               })
               .ok());
    assert(streamedResponses.size() == 1);
    assert(streamedResponses[0].session().listener_hash() == "listener-primary");
    assert(streamedResponses[0].command_id() == "cmd-0001");
    assert(streamedResponses[0].command() == "whoami");

    assert(service.streamResponsesForSession(
               sessionToStop,
               firstMetadata,
               [&](const teamserverapi::CommandResult&)
               {
                   return false;
               })
               .ok());

    std::string secondClientId = "client-b";
    auto secondMetadata = makeMetadata(clientIdKey, secondClientId);
    std::vector<teamserverapi::CommandResult> secondClientResponses;
    assert(service.streamResponsesForSession(
               sessionToStop,
               secondMetadata,
               [&](const teamserverapi::CommandResult& responseInfo)
               {
                   secondClientResponses.push_back(responseInfo);
                   return true;
               })
               .ok());
    assert(secondClientResponses.size() == 1);
}

void testModuleTrackingBlocksDuplicateLoadsAndListsLoadedModules()
{
    nlohmann::json config = {{"LogLevel", "off"}};
    auto logger = makeLogger();

    std::vector<std::shared_ptr<Listener>> listeners;
    auto primaryListener = std::make_shared<TestListener>("127.0.0.1", "8443", ListenerHttpsType, "listener-primary");
    primaryListener->addSession("listener-primary", "ABCDEFGH12345678", "host", "user", "x64", "admin", "Linux");
    listeners.push_back(primaryListener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    CommonCommands commonCommands;
    std::vector<teamserverapi::CommandResult> cmdResponses;
    std::unordered_map<std::string, std::vector<int>> sentResponses;
    std::vector<BeaconCommandContext> sentCommands;

    TeamServerListenerSessionService service(
        logger,
        config,
        listeners,
        moduleCmd,
        commonCommands,
        cmdResponses,
        sentResponses,
        sentCommands,
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
    loadCommand.mutable_session()->set_beacon_hash("ABCDEFGH12345678");
    loadCommand.mutable_session()->set_listener_hash("listener-primary");
    loadCommand.set_command("loadModule pwd");
    loadCommand.set_command_id("load-0001");

    teamserverapi::CommandAck loadResponse;
    assert(service.sendSessionCommand(loadCommand, &loadResponse).ok());
    assert(loadResponse.status() == teamserverapi::OK);

    std::vector<teamserverapi::LoadedModule> modules;
    teamserverapi::SessionSelector sessionSelector;
    sessionSelector.set_beacon_hash("ABCDEFGH12345678");
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
    assert(primaryListener->addTaskResult(loadResult, "ABCDEFGH12345678"));
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
    unloadCommand.mutable_session()->set_beacon_hash("ABCDEFGH12345678");
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
    assert(primaryListener->addTaskResult(unloadResult, "ABCDEFGH12345678"));
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
} // namespace

int main()
{
    testCollectListenersAndSessions();
    testQueueStopAndResponseDeduplication();
    testModuleTrackingBlocksDuplicateLoadsAndListsLoadedModules();
    return 0;
}
