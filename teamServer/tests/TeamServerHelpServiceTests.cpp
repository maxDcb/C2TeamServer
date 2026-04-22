#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include "TeamServerHelpService.hpp"

namespace
{
class TestListener final : public Listener
{
public:
    explicit TestListener(const std::string& hash)
        : Listener("127.0.0.1", "8443", ListenerHttpsType)
    {
        m_listenerHash = hash;
    }

    std::shared_ptr<Session> addSession(
        const std::string& listenerHash,
        const std::string& beaconHash,
        const std::string& os)
    {
        auto session = std::make_shared<Session>(listenerHash, beaconHash, "host", "user", "x64", "admin", os);
        m_sessions.push_back(session);
        return session;
    }
};

class FakeModule final : public ModuleCmd
{
public:
    FakeModule(std::string name, std::string info, int compatibility)
        : ModuleCmd(std::move(name)),
          m_info(std::move(info)),
          m_compatibility(compatibility)
    {
    }

    std::string getInfo() override
    {
        return m_info;
    }

    int init(std::vector<std::string>&, C2Message&) override
    {
        return 0;
    }

    int process(C2Message&, C2Message&) override
    {
        return 0;
    }

    int osCompatibility() override
    {
        return m_compatibility;
    }

private:
    std::string m_info;
    int m_compatibility;
};

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("help-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

void testGeneralHelpUsesSessionPlatform()
{
    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    auto listener = std::make_shared<TestListener>("listener-primary");
    listener->addSession("listener-primary", "ABCDEFGH12345678", "Windows");
    listeners.push_back(listener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    moduleCmd.push_back(std::make_unique<FakeModule>("winmod", "windows module info", OS_WINDOWS));
    moduleCmd.push_back(std::make_unique<FakeModule>("linmod", "linux module info", OS_LINUX));

    CommonCommands commonCommands;
    TeamServerHelpService service(logger, listeners, moduleCmd, commonCommands);

    teamserverapi::Command command;
    command.set_cmd("help");
    command.set_beaconhash("ABCDEFGH12345678");
    command.set_listenerhash("listener-primary");

    teamserverapi::CommandResponse response;
    assert(service.getHelp(command, &response).ok());
    assert(response.response().find("- Modules Commands Windows:") != std::string::npos);
    assert(response.response().find("winmod") != std::string::npos);
    assert(response.response().find("linmod") == std::string::npos);
}

void testSpecificHelpResolvesModuleInfoAndMissingModule()
{
    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    moduleCmd.push_back(std::make_unique<FakeModule>("winmod", "windows module info", OS_WINDOWS));

    CommonCommands commonCommands;
    TeamServerHelpService service(logger, listeners, moduleCmd, commonCommands);

    teamserverapi::Command moduleCommand;
    moduleCommand.set_cmd("help winmod");
    teamserverapi::CommandResponse moduleResponse;
    assert(service.getHelp(moduleCommand, &moduleResponse).ok());
    assert(moduleResponse.response().find("windows module info") != std::string::npos);

    teamserverapi::Command missingCommand;
    missingCommand.set_cmd("help nope");
    teamserverapi::CommandResponse missingResponse;
    assert(service.getHelp(missingCommand, &missingResponse).ok());
    assert(missingResponse.response() == "Module nope not found.\n");
}
} // namespace

int main()
{
    testGeneralHelpUsesSessionPlatform();
    testSpecificHelpResolvesModuleInfoAndMissingModule();
    return 0;
}
