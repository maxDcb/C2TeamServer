#include <cassert>
#include <filesystem>
#include <fstream>
#include <atomic>
#include <chrono>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerListenerArtifactService.hpp"
#include "TeamServerLocalOperationService.hpp"

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
    explicit TestListener(const std::string& hash, const std::string& type = ListenerHttpsType)
        : Listener("127.0.0.1", "8443", type)
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
        {"ListenerHttpsConfig", {{"downloadFolder", downloadDir.string()}, {"uriFileDownload", "/downloads/"}}}};
    std::vector<std::shared_ptr<Listener>> listeners;
    listeners.push_back(std::make_shared<TestListener>("listener-primary"));
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerListenerArtifactService listenerService(makeLogger(), config, runtimeConfig, listeners);

    TeamServerLocalOperationService service(
        makeLogger(),
        config,
        runtimeConfig,
        modules,
        {}, &listenerService);

    TeamServerOperationResult response;
    response = service.uploadListenerFile("listener-pri", "hello.bin", "PAYLOAD");
    assert(response.ok);
    assert(response.output == "ok");
    assert(readFile(downloadDir / "hello.bin") == "PAYLOAD");

    response = service.uploadListenerFile("listener-pri", "../bad.bin", "PAYLOAD");
    assert(!response.ok);
    assert(response.output == "Error: filename not allowed.");

    listeners.push_back(std::make_shared<TestListener>("listener-primary-other"));
    response = service.uploadListenerFile("listener-pri", "ambiguous.bin", "PAYLOAD");
    assert(!response.ok);
    assert(response.output == "Error: Listener reference is ambiguous.");
    assert(!fs::exists(downloadDir / "ambiguous.bin"));

    response = service.uploadListenerFile("primary", "substring.bin", "PAYLOAD");
    assert(!response.ok);
    assert(response.output == "Error: Listener not found.");

    response = service.uploadListenerFile("listener-primary", "exact.bin", "PAYLOAD");
    assert(response.ok);
    assert(readFile(downloadDir / "exact.bin") == "PAYLOAD");

    fs::create_directories(downloadDir / "blocked.bin");
    response = service.uploadListenerFile("listener-primary", "blocked.bin", "PAYLOAD");
    assert(!response.ok);
    assert(fs::is_directory(downloadDir / "blocked.bin"));

    response = service.installTool("tool.bin", "TOOL");
    assert(response.ok);
    assert(response.output == "ok");
    assert(readFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Any" / "any" / "tool.bin") == "TOOL");
}

void testBatcaveBundleIsAllOrNothing()
{
    ScopedPath tempRoot(makeTempDirectory("batcave-bundle"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    nlohmann::json config = nlohmann::json::object();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerLocalOperationService service(makeLogger(), config, runtimeConfig, modules);

    const fs::path tools = fs::path(runtimeConfig.toolsDirectoryPath) / "Any" / "any";
    writeFile(tools / "first.bin", "OLD");
    fs::create_directories(tools / "blocked.bin");

    std::vector<std::pair<std::string, std::string>> bundle = {
        {"first.bin", "NEW"}, {"blocked.bin", "SECOND"}};
    auto response = service.installToolBundle(bundle);
    assert(!response.ok);
    assert(readFile(tools / "first.bin") == "OLD");
    assert(fs::is_directory(tools / "blocked.bin"));

    bundle[1].first = "second.bin";
    response = service.installToolBundle(bundle);
    assert(response.ok);
    assert(readFile(tools / "first.bin") == "NEW");
    assert(readFile(tools / "second.bin") == "SECOND");

    bundle[0].first = "../bad.bin";
    response = service.installToolBundle(bundle);
    assert(!response.ok);
    assert(readFile(tools / "first.bin") == "NEW");
}

void testBatcaveBundleRecoveryAfterRestart()
{
    ScopedPath tempRoot(makeTempDirectory("batcave-recovery"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    const fs::path tools = fs::path(runtimeConfig.toolsDirectoryPath) / "Any" / "any";
    const fs::path staging = fs::path(runtimeConfig.toolsDirectoryPath) / ".batcave-staging";

    const fs::path interrupted = staging / ".bundle.c2tmp-interrupted";
    writeFile(tools / "old.bin", "NEW");
    writeFile(tools / "new.bin", "NEWFILE");
    writeFile(interrupted / "backups" / "old.bin", "ORIGINAL");
    writeFile(interrupted / "recovery.json", "[[\"old.bin\",true],[\"new.bin\",false]]");

    const fs::path committed = staging / ".bundle.c2tmp-committed";
    writeFile(tools / "done.bin", "COMMITTED");
    writeFile(committed / "backups" / "done.bin", "PREVIOUS");
    writeFile(committed / "recovery.json", "[[\"done.bin\",true]]");
    writeFile(committed / "committed", "");

    nlohmann::json config = nlohmann::json::object();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerLocalOperationService service(makeLogger(), config, runtimeConfig, modules);

    assert(readFile(tools / "old.bin") == "ORIGINAL");
    assert(!fs::exists(tools / "new.bin"));
    assert(!fs::exists(interrupted));
    assert(readFile(tools / "done.bin") == "COMMITTED");
    assert(!fs::exists(committed));
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
        {"DomainName", "team.example"},
        {"ListenerHttpsConfig", {{"downloadFolder", downloadDir.string()}, {"uriFileDownload", "/downloads/"}}}};
    std::vector<std::shared_ptr<Listener>> listeners;
    listeners.push_back(std::make_shared<TestListener>("listener-primary"));
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerListenerArtifactService listenerService(makeLogger(), config, runtimeConfig, listeners);

    TeamServerLocalOperationService service(
        makeLogger(),
        config,
        runtimeConfig,
        modules,
        {}, &listenerService);

    TeamServerOperationResult response;
    response = service.hostArtifact("listener-pri", artifacts[0].artifactId);
    assert(response.ok);
    assert(response.output == "https://team.example:8443/downloads/operator_payload.bin");
    assert(readFile(downloadDir / "operator_payload.bin") == "PAYLOAD");

    const auto typed = service.hostArtifact("listener-pri", artifacts[0].artifactId, "typed.bin");
    assert(typed.ok);
    assert(typed.output == "https://team.example:8443/downloads/typed.bin");
    assert(readFile(downloadDir / "typed.bin") == "PAYLOAD");

    response = service.hostArtifact("listener-pri", artifacts[0].artifactId, "hosted.bin");
    assert(response.ok);
    assert(response.output == "https://team.example:8443/downloads/hosted.bin");
    assert(readFile(downloadDir / "hosted.bin") == "PAYLOAD");

    response = service.hostArtifact("listener-pri", "missing");
    assert(!response.ok);
    assert(response.output == "Error: artifact not found.");

    config["ListenerHttpsConfig"].erase("uriFileDownload");
    response = service.hostArtifact("listener-pri", artifacts[0].artifactId, "no-url.bin");
    assert(!response.ok);
    assert(response.output == "Error: Listener has no public download URL configured.");
    assert(!fs::exists(downloadDir / "no-url.bin"));
}

void testReloadModulesUsesInjectedLoader()
{
    ScopedPath tempRoot(makeTempDirectory("reload"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    nlohmann::json config = nlohmann::json::object();
    std::vector<std::shared_ptr<Listener>> listeners;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("OldModule"));
    int reloadMode = 0;
    std::shared_mutex moduleMutex;

    TeamServerLocalOperationService service(
        makeLogger(),
        config,
        runtimeConfig,
        modules,
        [&reloadMode]()
        {
            if (reloadMode == 1)
                return std::vector<std::unique_ptr<ModuleCmd>>{};
            if (reloadMode == 2)
                throw std::runtime_error("loader failure");
            std::vector<std::unique_ptr<ModuleCmd>> loaded;
            loaded.push_back(std::make_unique<FakeModule>("ReloadedModule"));
            return loaded;
        }, nullptr, &moduleMutex);

    TeamServerOperationResult response = service.reloadModules();
    assert(response.ok);
    assert(modules.size() == 1);
    assert(modules.front()->getName() == "ReloadedModule");
    assert(response.output == "Reloaded 1 TeamServer module(s).");
    const auto typedReload = service.reloadModules();
    assert(typedReload.ok && typedReload.output == response.output);

    reloadMode = 1;
    response = service.reloadModules();
    assert(!response.ok);
    assert(modules.size() == 1);
    assert(modules.front()->getName() == "ReloadedModule");

    reloadMode = 2;
    response = service.reloadModules();
    assert(!response.ok);
    assert(modules.size() == 1);
    assert(modules.front()->getName() == "ReloadedModule");

    reloadMode = 0;
    std::atomic<bool> completed{false};
    TeamServerOperationResult concurrentResponse;
    std::shared_lock<std::shared_mutex> reader(moduleMutex);
    std::thread reloadThread([&]()
    {
        concurrentResponse = service.reloadModules();
        completed.store(true);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(!completed.load());
    reader.unlock();
    reloadThread.join();
    assert(completed.load());
    assert(concurrentResponse.ok);
}
} // namespace

int main()
{
    testUploadCommands();
    testBatcaveBundleIsAllOrNothing();
    testBatcaveBundleRecoveryAfterRestart();
    testHostArtifactCommand();
    testReloadModulesUsesInjectedLoader();
    return 0;
}
