#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "TeamServerCommandCatalog.hpp"
#include "TeamServerHelpService.hpp"
#include "TeamServerRuntimeConfig.hpp"

namespace fs = std::filesystem;

namespace
{
class ScopedPath
{
public:
    explicit ScopedPath(fs::path path)
        : m_path(std::move(path))
    {
        std::error_code ec;
        fs::remove_all(m_path, ec);
        fs::create_directories(m_path);
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

fs::path makeTempDirectory(const std::string& name)
{
    return fs::temp_directory_path() / ("c2teamserver-help-service-" + name + "-" + std::to_string(::getpid()));
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("help-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.commandSpecsDirectoryPath = (root / "CommandSpecs").string();
    fs::create_directories(runtimeConfig.commandSpecsDirectoryPath);
    return runtimeConfig;
}

void writeFile(const fs::path& path, const std::string& content)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << content;
}

void seedCommandSpecs(const TeamServerRuntimeConfig& runtimeConfig)
{
    writeFile(
        fs::path(runtimeConfig.commandSpecsDirectoryPath) / "common" / "sleep.json",
        R"JSON({
  "name": "sleep",
  "display_name": "sleep",
  "kind": "common",
  "description": "Set the beacon sleep interval in seconds.",
  "target": "beacon",
  "requires_session": true,
  "platforms": ["windows", "linux"],
  "archs": ["any"],
  "args": [
    {
      "name": "seconds",
      "type": "number",
      "required": true,
      "description": "Sleep interval in seconds."
    }
  ],
  "examples": ["sleep 0.5"],
  "source": "manifest"
})JSON");
    writeFile(
        fs::path(runtimeConfig.commandSpecsDirectoryPath) / "common" / "help.json",
        R"JSON({
  "name": "help",
  "kind": "common",
  "description": "Show available commands.",
  "target": "operator",
  "requires_session": false,
  "platforms": ["any"],
  "archs": ["any"],
  "args": [
    {
      "name": "command",
      "type": "text",
      "required": false,
      "description": "Optional command name."
    }
  ],
  "examples": ["help", "help sleep"],
  "source": "manifest"
})JSON");
    writeFile(
        fs::path(runtimeConfig.commandSpecsDirectoryPath) / "modules" / "winmod.json",
        R"JSON({
  "name": "winmod",
  "kind": "module",
  "description": "Windows-only module.",
  "target": "beacon",
  "requires_session": true,
  "platforms": ["windows"],
  "archs": ["any"],
  "args": [],
  "examples": ["winmod"],
  "source": "manifest"
})JSON");
    writeFile(
        fs::path(runtimeConfig.commandSpecsDirectoryPath) / "modules" / "linmod.json",
        R"JSON({
  "name": "linmod",
  "kind": "module",
  "description": "Linux-only module.",
  "target": "beacon",
  "requires_session": true,
  "platforms": ["linux"],
  "archs": ["any"],
  "args": [],
  "examples": ["linmod"],
  "source": "manifest"
})JSON");
}

void testGeneralHelpUsesSessionPlatform()
{
    ScopedPath tempRoot(makeTempDirectory("general"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedCommandSpecs(runtimeConfig);

    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    auto listener = std::make_shared<TestListener>("listener-primary");
    listener->addSession("listener-primary", "ABCDEFGH12345678", "Windows");
    listeners.push_back(listener);

    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    moduleCmd.push_back(std::make_unique<FakeModule>("winmod", "windows module info", OS_WINDOWS));
    moduleCmd.push_back(std::make_unique<FakeModule>("linmod", "linux module info", OS_LINUX));

    CommonCommands commonCommands;
    TeamServerHelpService service(
        logger,
        listeners,
        moduleCmd,
        commonCommands,
        TeamServerCommandCatalog(runtimeConfig));

    teamserverapi::CommandHelpRequest command;
    command.set_command("help");
    command.mutable_session()->set_beacon_hash("ABCDEFGH12345678");
    command.mutable_session()->set_listener_hash("listener-primary");

    teamserverapi::CommandHelpResponse response;
    assert(service.getHelp(command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.help().find("Available commands for windows:") != std::string::npos);
    assert(response.help().find("- Common Commands:") != std::string::npos);
    assert(response.help().find("sleep - Set the beacon sleep interval") != std::string::npos);
    assert(response.help().find("- Module Commands:") != std::string::npos);
    assert(response.help().find("winmod") != std::string::npos);
    assert(response.help().find("linmod") == std::string::npos);
}

void testSpecificHelpUsesCommandSpec()
{
    ScopedPath tempRoot(makeTempDirectory("specific"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedCommandSpecs(runtimeConfig);

    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;

    CommonCommands commonCommands;
    TeamServerHelpService service(
        logger,
        listeners,
        moduleCmd,
        commonCommands,
        TeamServerCommandCatalog(runtimeConfig));

    teamserverapi::CommandHelpRequest sleepCommand;
    sleepCommand.set_command("help sleep");
    teamserverapi::CommandHelpResponse sleepResponse;
    assert(service.getHelp(sleepCommand, &sleepResponse).ok());
    assert(sleepResponse.status() == teamserverapi::OK);
    assert(sleepResponse.help().find("sleep\n") == 0);
    assert(sleepResponse.help().find("Usage: sleep <seconds>") != std::string::npos);
    assert(sleepResponse.help().find("<seconds> (number, required) - Sleep interval in seconds.") != std::string::npos);
    assert(sleepResponse.help().find("Examples:") != std::string::npos);
    assert(sleepResponse.help().find("sleep 0.5") != std::string::npos);

    teamserverapi::CommandHelpRequest missingCommand;
    missingCommand.set_command("help nope");
    teamserverapi::CommandHelpResponse missingResponse;
    assert(service.getHelp(missingCommand, &missingResponse).ok());
    assert(missingResponse.status() == teamserverapi::KO);
    assert(missingResponse.message() == "No help available.");
}

void testSpecificHelpFallsBackToLegacyInfoWithoutSpec()
{
    ScopedPath tempRoot(makeTempDirectory("fallback"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    auto logger = makeLogger();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> moduleCmd;
    moduleCmd.push_back(std::make_unique<FakeModule>("legacyMod", "legacy module info", OS_WINDOWS));

    CommonCommands commonCommands;
    TeamServerHelpService service(
        logger,
        listeners,
        moduleCmd,
        commonCommands,
        TeamServerCommandCatalog(runtimeConfig));

    teamserverapi::CommandHelpRequest moduleCommand;
    moduleCommand.set_command("help legacyMod");
    teamserverapi::CommandHelpResponse moduleResponse;
    assert(service.getHelp(moduleCommand, &moduleResponse).ok());
    assert(moduleResponse.status() == teamserverapi::OK);
    assert(moduleResponse.help().find("legacy module info") != std::string::npos);
}
} // namespace

int main()
{
    testGeneralHelpUsesSessionPlatform();
    testSpecificHelpUsesCommandSpec();
    testSpecificHelpFallsBackToLegacyInfoWithoutSpec();
    return 0;
}
