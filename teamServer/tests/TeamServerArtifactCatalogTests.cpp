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
#include "TeamServerGeneratedArtifactStore.hpp"
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
    runtimeConfig.uploadedArtifactsDirectoryPath = (root / "UploadedArtifacts").string();
    runtimeConfig.generatedArtifactsDirectoryPath = (root / "GeneratedArtifacts").string();
    runtimeConfig.hostedArtifactsDirectoryPath = (root / "GeneratedArtifacts" / "hosted").string();

    fs::create_directories(runtimeConfig.teamServerModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxModulesDirectoryPath);
    fs::create_directories(runtimeConfig.windowsModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.windowsBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.toolsDirectoryPath);
    fs::create_directories(runtimeConfig.scriptsDirectoryPath);
    fs::create_directories(runtimeConfig.uploadedArtifactsDirectoryPath);
    fs::create_directories(runtimeConfig.generatedArtifactsDirectoryPath);
    fs::create_directories(runtimeConfig.hostedArtifactsDirectoryPath);
    for (const std::string& arch : runtimeConfig.supportedLinuxArchs)
    {
        fs::create_directories(fs::path(runtimeConfig.linuxModulesDirectoryPath) / arch);
        fs::create_directories(fs::path(runtimeConfig.linuxBeaconsDirectoryPath) / arch);
        fs::create_directories(fs::path(runtimeConfig.toolsDirectoryPath) / "Linux" / arch);
        fs::create_directories(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Linux" / arch);
    }
    for (const std::string& arch : runtimeConfig.supportedWindowsArchs)
    {
        fs::create_directories(fs::path(runtimeConfig.windowsModulesDirectoryPath) / arch);
        fs::create_directories(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / arch);
        fs::create_directories(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / arch);
        fs::create_directories(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Windows" / arch);
    }
    fs::create_directories(fs::path(runtimeConfig.scriptsDirectoryPath) / "Windows");
    fs::create_directories(fs::path(runtimeConfig.scriptsDirectoryPath) / "Linux");
    fs::create_directories(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any");

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
    writeFile(fs::path(runtimeConfig.linuxModulesDirectoryPath) / "x64" / "linuxmod.so", "linux-module");
    writeFile(fs::path(runtimeConfig.windowsModulesDirectoryPath) / "x64" / "winmod64.dll", "windows-module-x64");
    writeFile(fs::path(runtimeConfig.windowsModulesDirectoryPath) / "x86" / "winmod86.dll", "windows-module-x86");
    writeFile(fs::path(runtimeConfig.linuxBeaconsDirectoryPath) / "x64" / "BeaconHttp", "linux-beacon");
    writeFile(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / "x64" / "BeaconHttp.exe", "windows-beacon-x64");
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "batcave.zip", "tool-archive");
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / "Windows" / "startup.ps1", "script");
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / "Windows" / ".ignored.ps1", "hidden-script");
    writeFile(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any" / "operator-note.txt", "upload");
    writeFile(fs::path(runtimeConfig.hostedArtifactsDirectoryPath) / "payload.bin", "hosted-file");
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

    assert(artifacts.size() == 10);
    assert(findArtifact(artifacts, ".ignored.ps1", "script", "windows", "any") == nullptr);

    const TeamServerArtifactRecord* windowsModule = findArtifact(artifacts, "winmod64.dll", "module", "windows", "x64");
    assert(windowsModule != nullptr);
    assert(windowsModule->scope == "beacon");
    assert(windowsModule->target == "beacon");
    assert(windowsModule->format == "dll");
    assert(windowsModule->runtime == "native");
    assert(windowsModule->source == "release");
    assert(windowsModule->size == 18);
    assert(windowsModule->sha256.size() == 64);
    assert(windowsModule->artifactId.size() == 64);
    assert(windowsModule->internalPath.find(tempRoot.path().string()) != std::string::npos);

    const TeamServerArtifactRecord* linuxBeacon = findArtifact(artifacts, "BeaconHttp", "beacon", "linux", "x64");
    assert(linuxBeacon != nullptr);
    assert(linuxBeacon->format == "binary");
    assert(linuxBeacon->scope == "implant");
    assert(linuxBeacon->target == "listener");

    const TeamServerArtifactRecord* script = findArtifact(artifacts, "startup.ps1", "script", "windows", "any");
    assert(script != nullptr);
    assert(script->scope == "server");
    assert(script->target == "beacon");
    assert(script->format == "ps1");
    assert(script->runtime == "script");

    const TeamServerArtifactRecord* upload = findArtifact(artifacts, "operator-note.txt", "upload", "any", "any");
    assert(upload != nullptr);
    assert(upload->scope == "operator");
    assert(upload->target == "beacon");
    assert(upload->runtime == "file");

    const TeamServerArtifactRecord* hosted = findArtifact(artifacts, "payload.bin", "hosted", "any", "any");
    assert(hosted != nullptr);
    assert(hosted->scope == "generated");
    assert(hosted->target == "listener");
    assert(hosted->runtime == "file");
    assert(hosted->source == "operator");
    assert(hosted->size == 11);
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
    toolQuery.platform = "windows";
    toolQuery.arch = "x64";
    toolQuery.nameContains = "BATCAVE";
    artifacts = catalog.listArtifacts(toolQuery);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "batcave.zip");

    TeamServerArtifactQuery linuxModules;
    linuxModules.category = "module";
    linuxModules.platform = "linux";
    linuxModules.arch = "x64";
    artifacts = catalog.listArtifacts(linuxModules);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "linuxmod.so");

    TeamServerArtifactQuery hostedFiles;
    hostedFiles.category = "hosted";
    hostedFiles.target = "listener";
    artifacts = catalog.listArtifacts(hostedFiles);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "payload.bin");
}

void testCatalogIndexesAndDeletesGeneratedArtifacts()
{
    ScopedPath tempRoot(makeTempDirectory("generated"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    TeamServerGeneratedArtifactStore store(runtimeConfig);
    TeamServerGeneratedArtifactRequest request;
    request.nameHint = "Rubeus.exe.bin";
    request.bytes = "generated-shellcode";
    request.category = "payload";
    request.scope = "generated";
    request.target = "beacon";
    request.platform = "windows";
    request.arch = "x64";
    request.format = "bin";
    request.runtime = "shellcode";
    request.source = "donut";
    request.description = "Generated shellcode for assemblyExec.";
    const TeamServerGeneratedArtifactRecord record = store.store(request);
    assert(!record.artifactId.empty());

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "payload";
    query.scope = "generated";
    query.runtime = "shellcode";
    std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);

    assert(artifacts.size() == 1);
    assert(artifacts[0].artifactId == record.artifactId);
    assert(artifacts[0].displayName == "Rubeus.exe.bin");
    assert(artifacts[0].source == "donut");
    assert(artifacts[0].size == static_cast<std::int64_t>(request.bytes.size()));
    assert(artifacts[0].sha256 == record.sha256);

    std::string message;
    assert(catalog.deleteGeneratedArtifact(record.artifactId, message));
    assert(message == "Generated artifact deleted.");
    assert(!fs::exists(record.path));
    assert(!fs::exists(record.path + ".artifact.json"));

    artifacts = catalog.listArtifacts(query);
    assert(artifacts.empty());
    assert(!catalog.deleteGeneratedArtifact(record.artifactId, message));
    assert(message == "Generated artifact not found.");
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
    assert(summaries[0].name() == "startup.ps1");
    assert(summaries[0].category() == "script");
    assert(summaries[0].scope() == "server");
    assert(summaries[0].target() == "beacon");
    assert(summaries[0].runtime() == "script");
    assert(summaries[0].sha256().size() == 64);
    assert(summaries[0].DebugString().find(tempRoot.path().string()) == std::string::npos);
}

void testArtifactServiceDownloadsArtifactPayload()
{
    ScopedPath tempRoot(makeTempDirectory("service-download"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    seedArtifacts(runtimeConfig);

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "upload";
    query.nameContains = "operator-note";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    assert(artifacts.size() == 1);

    TeamServerArtifactService service(makeLogger(), TeamServerArtifactCatalog(runtimeConfig));
    teamserverapi::ArtifactSelector selector;
    selector.set_artifact_id(artifacts[0].artifactId);
    teamserverapi::ArtifactContent response;
    assert(service.downloadArtifact(selector, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.name() == "operator-note.txt");
    assert(response.display_name() == "operator-note.txt");
    assert(response.data() == "upload");
    assert(response.DebugString().find(tempRoot.path().string()) == std::string::npos);

    teamserverapi::ArtifactSelector missingSelector;
    missingSelector.set_artifact_id("missing");
    teamserverapi::ArtifactContent missingResponse;
    assert(service.downloadArtifact(missingSelector, &missingResponse).ok());
    assert(missingResponse.status() == teamserverapi::KO);
    assert(missingResponse.message() == "Artifact not found.");
}

void testArtifactServiceUploadsOperatorArtifact()
{
    ScopedPath tempRoot(makeTempDirectory("service-upload"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    TeamServerArtifactService service(makeLogger(), TeamServerArtifactCatalog(runtimeConfig));
    teamserverapi::ArtifactUploadRequest request;
    request.set_name("../payload v1.exe");
    request.set_platform("windows");
    request.set_arch("amd64");
    request.set_data("uploaded-bytes");

    teamserverapi::OperationAck response;
    assert(service.uploadArtifact(request, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.message() == "Uploaded artifact stored: payload_v1.exe");
    assert((fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Windows" / "x64" / "payload_v1.exe").is_regular_file());

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "upload";
    query.platform = "windows";
    query.arch = "x64";
    query.nameContains = "payload";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    assert(artifacts.size() == 1);
    assert(artifacts[0].name == "payload_v1.exe");
    assert(artifacts[0].scope == "operator");
    assert(artifacts[0].target == "beacon");
    assert(artifacts[0].runtime == "file");
}

void testArtifactServiceDeletesGeneratedArtifacts()
{
    ScopedPath tempRoot(makeTempDirectory("service-delete"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    TeamServerGeneratedArtifactStore store(runtimeConfig);
    TeamServerGeneratedArtifactRequest request;
    request.nameHint = "Seatbelt.exe.bin";
    request.bytes = "service-generated-shellcode";
    request.source = "donut";
    const TeamServerGeneratedArtifactRecord record = store.store(request);
    assert(!record.artifactId.empty());

    TeamServerArtifactService service(makeLogger(), TeamServerArtifactCatalog(runtimeConfig));
    teamserverapi::ArtifactSelector selector;
    selector.set_artifact_id(record.artifactId);
    teamserverapi::OperationAck response;
    assert(service.deleteGeneratedArtifact(selector, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.message() == "Generated artifact deleted.");
    assert(!fs::exists(record.path));

    teamserverapi::OperationAck missingResponse;
    assert(service.deleteGeneratedArtifact(selector, &missingResponse).ok());
    assert(missingResponse.status() == teamserverapi::KO);
    assert(missingResponse.message() == "Generated artifact not found.");
}
} // namespace

int main()
{
    testCatalogIndexesReleaseRoots();
    testCatalogFiltersArtifacts();
    testCatalogIndexesAndDeletesGeneratedArtifacts();
    testArtifactServiceStreamsPublicMetadataOnly();
    testArtifactServiceDownloadsArtifactPayload();
    testArtifactServiceUploadsOperatorArtifact();
    testArtifactServiceDeletesGeneratedArtifacts();
    return 0;
}
