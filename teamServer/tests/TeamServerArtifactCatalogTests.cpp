#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerArtifactService.hpp"
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
    return fs::temp_directory_path() / ("c2teamserver-artifact-catalog-" + name + "-" + std::to_string(::getpid()));
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("artifact-catalog-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.teamServerModulesDirectoryPath = (root / "TeamServerModules").string();
    runtimeConfig.linuxModulesDirectoryPath = (root / "LinuxModules").string();
    runtimeConfig.windowsModulesDirectoryPath = (root / "WindowsModules").string();
    runtimeConfig.linuxBeaconsDirectoryPath = (root / "LinuxBeacons").string();
    runtimeConfig.windowsBeaconsDirectoryPath = (root / "WindowsBeacons").string();
    runtimeConfig.toolsDirectoryPath = (root / "Tools").string();
    runtimeConfig.scriptsDirectoryPath = (root / "Scripts").string();

    fs::create_directories(runtimeConfig.teamServerModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxModulesDirectoryPath);
    fs::create_directories(runtimeConfig.windowsModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.windowsBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.toolsDirectoryPath);
    fs::create_directories(runtimeConfig.scriptsDirectoryPath);
    for (const std::string& arch : runtimeConfig.supportedWindowsArchs)
    {
        fs::create_directories(fs::path(runtimeConfig.windowsModulesDirectoryPath) / arch);
        fs::create_directories(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / arch);
    }

    return runtimeConfig;
}

void writeFile(const fs::path& path, const std::string& content)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << content;
}

void seedArtifacts(const TeamServerRuntimeConfig& runtimeConfig)
{
    writeFile(fs::path(runtimeConfig.teamServerModulesDirectoryPath) / "libServerModule.so", "teamserver-module");
    writeFile(fs::path(runtimeConfig.linuxModulesDirectoryPath) / "linuxmod.so", "linux-module");
    writeFile(fs::path(runtimeConfig.windowsModulesDirectoryPath) / "x64" / "winmod64.dll", "windows-module-x64");
    writeFile(fs::path(runtimeConfig.windowsModulesDirectoryPath) / "x86" / "winmod86.dll", "windows-module-x86");
    writeFile(fs::path(runtimeConfig.linuxBeaconsDirectoryPath) / "BeaconHttp", "linux-beacon");
    writeFile(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / "x64" / "BeaconHttp.exe", "windows-beacon-x64");
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "batcave.zip", "tool-archive");
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / "startup.py", "script");
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / ".ignored.py", "hidden-script");
}

const TeamServerArtifactRecord* findArtifact(
    const std::vector<TeamServerArtifactRecord>& artifacts,
    const std::string& name,
    const std::string& category,
    const std::string& platform,
    const std::string& arch)
{
    for (const TeamServerArtifactRecord& artifact : artifacts)
    {
        if (artifact.name == name
            && artifact.category == category
            && artifact.platform == platform
            && artifact.arch == arch)
        {
            return &artifact;
        }
    }
    return nullptr;
}

void testCatalogIndexesReleaseRoots()
{
    ScopedPath tempRoot(makeTempDirectory("indexes"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedArtifacts(runtimeConfig);

    TeamServerArtifactCatalog catalog(runtimeConfig);
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts();

    assert(artifacts.size() == 8);
    assert(findArtifact(artifacts, ".ignored.py", "script", "any", "any") == nullptr);

    const TeamServerArtifactRecord* windowsModule = findArtifact(artifacts, "winmod64.dll", "module", "windows", "x64");
    assert(windowsModule != nullptr);
    assert(windowsModule->scope == "beacon");
    assert(windowsModule->format == "dll");
    assert(windowsModule->source == "release");
    assert(windowsModule->size == 18);
    assert(windowsModule->sha256.size() == 64);
    assert(windowsModule->artifactId.size() == 64);
    assert(windowsModule->internalPath.find(tempRoot.path().string()) != std::string::npos);

    const TeamServerArtifactRecord* linuxBeacon = findArtifact(artifacts, "BeaconHttp", "beacon", "linux", "any");
    assert(linuxBeacon != nullptr);
    assert(linuxBeacon->format == "binary");
    assert(linuxBeacon->scope == "implant");

    const TeamServerArtifactRecord* script = findArtifact(artifacts, "startup.py", "script", "any", "any");
    assert(script != nullptr);
    assert(script->scope == "teamserver");
    assert(script->format == "py");
}

void testCatalogFiltersArtifacts()
{
    ScopedPath tempRoot(makeTempDirectory("filters"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedArtifacts(runtimeConfig);

    TeamServerArtifactCatalog catalog(runtimeConfig);

    TeamServerArtifactQuery windowsX64Modules;
    windowsX64Modules.category = "module";
    windowsX64Modules.platform = "windows";
    windowsX64Modules.arch = "x64";
    std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(windowsX64Modules);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "winmod64.dll");

    TeamServerArtifactQuery toolQuery;
    toolQuery.category = "tool";
    toolQuery.nameContains = "BATCAVE";
    artifacts = catalog.listArtifacts(toolQuery);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "batcave.zip");

    TeamServerArtifactQuery linuxModules;
    linuxModules.category = "module";
    linuxModules.platform = "linux";
    artifacts = catalog.listArtifacts(linuxModules);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "linuxmod.so");
}

void testArtifactServiceStreamsPublicMetadataOnly()
{
    ScopedPath tempRoot(makeTempDirectory("service"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedArtifacts(runtimeConfig);

    TeamServerArtifactService service(makeLogger(), TeamServerArtifactCatalog(runtimeConfig));

    teamserverapi::ArtifactQuery query;
    query.set_category("script");
    std::vector<teamserverapi::ArtifactSummary> summaries;
    assert(service.listArtifacts(query, [&](const teamserverapi::ArtifactSummary& artifact)
    {
        summaries.push_back(artifact);
        return true;
    }).ok());

    assert(summaries.size() == 1);
    assert(summaries[0].name() == "startup.py");
    assert(summaries[0].category() == "script");
    assert(summaries[0].scope() == "teamserver");
    assert(summaries[0].sha256().size() == 64);
    assert(summaries[0].DebugString().find(tempRoot.path().string()) == std::string::npos);
}
} // namespace

int main()
{
    testCatalogIndexesReleaseRoots();
    testCatalogFiltersArtifacts();
    testArtifactServiceStreamsPublicMetadataOnly();
    return 0;
}
