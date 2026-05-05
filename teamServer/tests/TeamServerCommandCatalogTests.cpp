#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "TeamServerCommandCatalog.hpp"
#include "TeamServerCommandCatalogService.hpp"
#include "spdlog/logger.h"

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

fs::path makeTempDirectory(const std::string& name)
{
    return fs::temp_directory_path() / ("c2teamserver-command-catalog-" + name + "-" + std::to_string(::getpid()));
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("command-catalog-tests");
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
  "description": "Set beacon sleep interval.",
  "target": "beacon",
  "requires_session": true,
  "platforms": ["windows", "linux"],
  "archs": ["any"],
  "args": [
    {
      "name": "seconds",
      "type": "number",
      "required": true,
      "description": "Sleep interval."
    }
  ],
  "examples": ["sleep 0.5"],
  "source": "manifest"
})JSON");
    writeFile(
        fs::path(runtimeConfig.commandSpecsDirectoryPath) / "common" / "end.json",
        R"JSON({
  "name": "end",
  "kind": "common",
  "description": "Terminate beacon.",
  "target": "beacon",
  "requires_session": true,
  "platforms": ["windows", "linux"],
  "archs": ["any"],
  "args": [],
  "examples": ["end"],
  "source": "manifest"
})JSON");
    writeFile(fs::path(runtimeConfig.commandSpecsDirectoryPath) / "common" / "broken.json", "{");
}

const TeamServerCommandSpecRecord* findCommand(
    const std::vector<TeamServerCommandSpecRecord>& commands,
    const std::string& name)
{
    for (const TeamServerCommandSpecRecord& command : commands)
    {
        if (command.name == name)
            return &command;
    }
    return nullptr;
}

void testCommandCatalogLoadsManifestSpecs()
{
    ScopedPath tempRoot(makeTempDirectory("loads"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedCommandSpecs(runtimeConfig);

    TeamServerCommandCatalog catalog(runtimeConfig);
    const std::vector<TeamServerCommandSpecRecord> commands = catalog.listCommands();

    assert(commands.size() == 2);

    const TeamServerCommandSpecRecord* sleep = findCommand(commands, "sleep");
    assert(sleep != nullptr);
    assert(sleep->kind == "common");
    assert(sleep->target == "beacon");
    assert(sleep->requiresSession);
    assert(sleep->platforms.size() == 2);
    assert(sleep->args.size() == 1);
    assert(sleep->args[0].name == "seconds");
    assert(sleep->args[0].type == "number");
    assert(sleep->args[0].required);
    assert(sleep->examples.size() == 1);

    const TeamServerCommandSpecRecord* end = findCommand(commands, "end");
    assert(end != nullptr);
    assert(end->args.empty());
}

void testCommandCatalogFiltersSpecs()
{
    ScopedPath tempRoot(makeTempDirectory("filters"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedCommandSpecs(runtimeConfig);

    TeamServerCommandCatalog catalog(runtimeConfig);
    TeamServerCommandQuery query;
    query.kind = "common";
    query.platform = "windows";
    query.nameContains = "sle";

    const std::vector<TeamServerCommandSpecRecord> commands = catalog.listCommands(query);
    assert(commands.size() == 1);
    assert(commands[0].name == "sleep");

    query.platform = "macos";
    assert(catalog.listCommands(query).empty());
}

void testCommandCatalogServiceStreamsProto()
{
    ScopedPath tempRoot(makeTempDirectory("service"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedCommandSpecs(runtimeConfig);

    TeamServerCommandCatalogService service(makeLogger(), TeamServerCommandCatalog(runtimeConfig));
    teamserverapi::CommandQuery query;
    query.set_name_contains("sleep");

    std::vector<teamserverapi::CommandSpec> commands;
    assert(service.listCommands(query, [&](const teamserverapi::CommandSpec& command)
    {
        commands.push_back(command);
        return true;
    }).ok());

    assert(commands.size() == 1);
    assert(commands[0].name() == "sleep");
    assert(commands[0].kind() == "common");
    assert(commands[0].requires_session());
    assert(commands[0].args_size() == 1);
    assert(commands[0].args(0).name() == "seconds");
    assert(commands[0].args(0).type() == "number");
    assert(commands[0].DebugString().find(tempRoot.path().string()) == std::string::npos);
}
} // namespace

int main()
{
    testCommandCatalogLoadsManifestSpecs();
    testCommandCatalogFiltersSpecs();
    testCommandCatalogServiceStreamsProto();
    return 0;
}
