#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

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

    fs::create_directories(runtimeConfig.teamServerModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxModulesDirectoryPath);
    fs::create_directories(runtimeConfig.windowsModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.windowsBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.toolsDirectoryPath);
    fs::create_directories(runtimeConfig.scriptsDirectoryPath);

    return runtimeConfig;
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

    teamserverapi::TermCommand uploadCommand;
    uploadCommand.set_cmd("putIntoUploadDir listener-pri hello.bin");
    uploadCommand.set_data("PAYLOAD");

    teamserverapi::TermCommand response;
    assert(service.handleCommand("putIntoUploadDir", {"putIntoUploadDir", "listener-pri", "hello.bin"}, uploadCommand, &response).ok());
    assert(response.result() == "ok");
    assert(readFile(downloadDir / "hello.bin") == "PAYLOAD");

    teamserverapi::TermCommand batcaveCommand;
    batcaveCommand.set_cmd("batcaveUpload tool.bin");
    batcaveCommand.set_data("TOOL");
    assert(service.handleCommand("batcaveUpload", {"batcaveUpload", "tool.bin"}, batcaveCommand, &response).ok());
    assert(response.result() == "ok");
    assert(readFile(fs::path(runtimeConfig.toolsDirectoryPath) / "tool.bin") == "TOOL");
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

    teamserverapi::TermCommand addCommand;
    addCommand.set_cmd("addCred");
    addCommand.set_data(R"({"username":"alice","password":"secret"})");

    teamserverapi::TermCommand response;
    assert(service.handleCommand("addCred", {"addCred"}, addCommand, &response).ok());
    assert(response.result() == "ok");
    assert(credentials.size() == 1);

    teamserverapi::TermCommand getCommand;
    getCommand.set_cmd("getCred");
    assert(service.handleCommand("getCred", {"getCred"}, getCommand, &response).ok());
    assert(response.result().find("alice") != std::string::npos);
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

    teamserverapi::TermCommand command;
    command.set_cmd("reloadModules");
    teamserverapi::TermCommand response;
    assert(service.handleCommand("reloadModules", {"reloadModules"}, command, &response).ok());
    assert(modules.size() == 1);
    assert(modules.front()->getName() == "ReloadedModule");
    assert(response.result().empty());
}
} // namespace

int main()
{
    testUploadCommands();
    testCredentialCommands();
    testReloadModulesUsesInjectedLoader();
    return 0;
}
