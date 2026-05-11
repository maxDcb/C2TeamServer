#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerTermLocalService.hpp"

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
    explicit TestListener(const std::string& hash)
        : Listener("127.0.0.1", "8443", ListenerHttpsType)
    {
        m_listenerHash = hash;
    }
};

class FakeModule final : public ModuleCmd
{
public:
    explicit FakeModule(std::string name)
        : ModuleCmd(std::move(name))
    {
    }

    std::string getInfo() override
    {
        return "fake module";
    }

    int init(std::vector<std::string>&, C2Message&) override
    {
        return 0;
    }

    int process(C2Message&, C2Message&) override
    {
        return 0;
    }
};

fs::path makeTempDirectory(const std::string& name)
{
    fs::path root = fs::temp_directory_path() / ("c2teamserver-term-local-" + name + "-" + std::to_string(::getpid()));
    fs::create_directories(root);
    return root;
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("term-local-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.teamServerModulesDirectoryPath = (root / "modules").string();
    runtimeConfig.linuxModulesDirectoryPath = (root / "linux-modules").string();
    runtimeConfig.windowsModulesDirectoryPath = (root / "windows-modules").string();
    runtimeConfig.linuxBeaconsDirectoryPath = (root / "linux-beacons").string();
    runtimeConfig.windowsBeaconsDirectoryPath = (root / "windows-beacons").string();
    runtimeConfig.toolsDirectoryPath = (root / "tools").string();
    runtimeConfig.scriptsDirectoryPath = (root / "scripts").string();
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
    fs::create_directories(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any");
    fs::create_directories(runtimeConfig.generatedArtifactsDirectoryPath);
    fs::create_directories(runtimeConfig.hostedArtifactsDirectoryPath);

    return runtimeConfig;
}

void writeFile(const fs::path& path, const std::string& content)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << content;
}

std::string readFile(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

void testUploadCommands()
{
    ScopedPath tempRoot(makeTempDirectory("upload"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    fs::path downloadDir = tempRoot.path() / "downloads";
    fs::create_directories(downloadDir);

    nlohmann::json config = {
        {"ListenerHttpsConfig", {{"downloadFolder", downloadDir.string()}}}};
    std::vector<std::shared_ptr<Listener>> listeners;
    listeners.push_back(std::make_shared<TestListener>("listener-primary"));
    nlohmann::json credentials = nlohmann::json::array();
    std::vector<std::unique_ptr<ModuleCmd>> modules;

    TeamServerTermLocalService service(
        makeLogger(),
        config,
        runtimeConfig,
        listeners,
        credentials,
        modules);

    teamserverapi::TerminalCommandRequest uploadCommand;
    uploadCommand.set_command("putIntoUploadDir listener-pri hello.bin");
    uploadCommand.set_data("PAYLOAD");

    teamserverapi::TerminalCommandResponse response;
    assert(service.handleCommand("putIntoUploadDir", {"putIntoUploadDir", "listener-pri", "hello.bin"}, uploadCommand, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.result() == "ok");
    assert(response.message().empty());
    assert(readFile(downloadDir / "hello.bin") == "PAYLOAD");

    assert(service.handleCommand("putIntoUploadDir", {"putIntoUploadDir", "listener-pri", "../bad.bin"}, uploadCommand, &response).ok());
    assert(response.status() == teamserverapi::KO);
    assert(response.result() == "Error: filename not allowed.");
    assert(response.message() == "Error: filename not allowed.");

    teamserverapi::TerminalCommandRequest batcaveCommand;
    batcaveCommand.set_command("batcaveUpload tool.bin");
    batcaveCommand.set_data("TOOL");
    assert(service.handleCommand("batcaveUpload", {"batcaveUpload", "tool.bin"}, batcaveCommand, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.result() == "ok");
    assert(response.message().empty());
    assert(readFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Any" / "any" / "tool.bin") == "TOOL");
}

void testHostArtifactCommand()
{
    ScopedPath tempRoot(makeTempDirectory("host-artifact"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    fs::path downloadDir = tempRoot.path() / "downloads";
    fs::create_directories(downloadDir);
    writeFile(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any" / "operator_payload.bin", "PAYLOAD");

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "upload";
    query.nameContains = "operator_payload";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    assert(artifacts.size() == 1);

    nlohmann::json config = {
        {"ListenerHttpsConfig", {{"downloadFolder", downloadDir.string()}}}};
    std::vector<std::shared_ptr<Listener>> listeners;
    listeners.push_back(std::make_shared<TestListener>("listener-primary"));
    nlohmann::json credentials = nlohmann::json::array();
    std::vector<std::unique_ptr<ModuleCmd>> modules;

    TeamServerTermLocalService service(
        makeLogger(),
        config,
        runtimeConfig,
        listeners,
        credentials,
        modules);

    teamserverapi::TerminalCommandRequest command;
    command.set_command("hostArtifact listener-pri " + artifacts[0].artifactId);
    teamserverapi::TerminalCommandResponse response;
    assert(service.handleCommand("hostArtifact", {"hostArtifact", "listener-pri", artifacts[0].artifactId}, command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.result() == "operator_payload.bin");
    assert(response.message().empty());
    assert(readFile(downloadDir / "operator_payload.bin") == "PAYLOAD");

    command.set_command("hostArtifact listener-pri " + artifacts[0].artifactId + " hosted.bin");
    assert(service.handleCommand("hostArtifact", {"hostArtifact", "listener-pri", artifacts[0].artifactId, "hosted.bin"}, command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.result() == "hosted.bin");
    assert(readFile(downloadDir / "hosted.bin") == "PAYLOAD");

    assert(service.handleCommand("hostArtifact", {"hostArtifact", "listener-pri", "missing"}, command, &response).ok());
    assert(response.status() == teamserverapi::KO);
    assert(response.result() == "Error: artifact not found.");
}

void testCredentialCommands()
{
    ScopedPath tempRoot(makeTempDirectory("cred"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    nlohmann::json config = nlohmann::json::object();
    std::vector<std::shared_ptr<Listener>> listeners;
    nlohmann::json credentials = nlohmann::json::array();
    std::vector<std::unique_ptr<ModuleCmd>> modules;

    TeamServerTermLocalService service(
        makeLogger(),
        config,
        runtimeConfig,
        listeners,
        credentials,
        modules);

    teamserverapi::TerminalCommandRequest addCommand;
    addCommand.set_command("addCred");
    addCommand.set_data(R"({"username":"alice","password":"secret"})");

    teamserverapi::TerminalCommandResponse response;
    assert(service.handleCommand("addCred", {"addCred"}, addCommand, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.result() == "ok");
    assert(credentials.size() == 1);

    addCommand.set_data("{not-json}");
    assert(service.handleCommand("addCred", {"addCred"}, addCommand, &response).ok());
    assert(response.status() == teamserverapi::KO);
    assert(response.result() == "Error: invalid credential payload.");

    teamserverapi::TerminalCommandRequest getCommand;
    getCommand.set_command("getCred");
    assert(service.handleCommand("getCred", {"getCred"}, getCommand, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(response.result().find("alice") != std::string::npos);
    assert(response.message().empty());
}

void testReloadModulesUsesInjectedLoader()
{
    ScopedPath tempRoot(makeTempDirectory("reload"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    nlohmann::json config = nlohmann::json::object();
    std::vector<std::shared_ptr<Listener>> listeners;
    nlohmann::json credentials = nlohmann::json::array();
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("OldModule"));

    TeamServerTermLocalService service(
        makeLogger(),
        config,
        runtimeConfig,
        listeners,
        credentials,
        modules,
        []()
        {
            std::vector<std::unique_ptr<ModuleCmd>> loaded;
            loaded.push_back(std::make_unique<FakeModule>("ReloadedModule"));
            return loaded;
        });

    teamserverapi::TerminalCommandRequest command;
    command.set_command("reloadModules");
    teamserverapi::TerminalCommandResponse response;
    assert(service.handleCommand("reloadModules", {"reloadModules"}, command, &response).ok());
    assert(response.status() == teamserverapi::OK);
    assert(modules.size() == 1);
    assert(modules.front()->getName() == "ReloadedModule");
    assert(response.result().empty());
}
} // namespace

int main()
{
    testUploadCommands();
    testHostArtifactCommand();
    testCredentialCommands();
    testReloadModulesUsesInjectedLoader();
    return 0;
}
