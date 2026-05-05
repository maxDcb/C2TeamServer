#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

#include "TeamServerAssemblyExecCommandPreparer.hpp"
#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerCommandPreparationService.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "TeamServerInjectCommandPreparer.hpp"
#include "TeamServerShellcodeService.hpp"

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

class FakeModule final : public ModuleCmd
{
public:
    explicit FakeModule(std::string name)
        : ModuleCmd(std::move(name))
    {
    }

    std::string getInfo() override
    {
        return "fake";
    }

    int init(std::vector<std::string>&, C2Message& c2Message) override
    {
        c2Message.set_instruction("FAKE");
        c2Message.set_cmd(m_capturedWindowsArch);
        return 42;
    }

    int setWindowsArch(const std::string& windowsArch) override
    {
        m_capturedWindowsArch = windowsArch;
        return ModuleCmd::setWindowsArch(windowsArch);
    }

    int process(C2Message&, C2Message&) override
    {
        return 0;
    }

private:
    std::string m_capturedWindowsArch;
};

class FakeShellcodeModule final : public ModuleCmd
{
public:
    explicit FakeShellcodeModule(std::string name)
        : ModuleCmd(std::move(name))
    {
    }

    std::string getInfo() override
    {
        return "fake shellcode";
    }

    int init(std::vector<std::string>&, C2Message& c2Message) override
    {
        c2Message.set_returnvalue("plain init should not be used");
        return -1;
    }

    int initPreparedShellcode(const ModulePreparedShellcodeTask& task, C2Message& c2Message) override
    {
        c2Message.set_instruction(getName());
        c2Message.set_cmd(task.displayCommand);
        c2Message.set_args(task.executionMode);
        c2Message.set_pid(task.pid);
        c2Message.set_inputfile(task.inputFile);
        c2Message.set_data(task.payload);
        return 0;
    }

    int process(C2Message&, C2Message&) override
    {
        return 0;
    }
};

fs::path makeTempDirectory(const std::string& name)
{
    fs::path root = fs::temp_directory_path() / ("c2teamserver-prep-" + name + "-" + std::to_string(::getpid()));
    fs::create_directories(root);
    return root;
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("prep-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

void writeFile(const fs::path& path, const std::string& content)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << content;
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.teamServerModulesDirectoryPath = (root / "TeamServerModules").string();
    runtimeConfig.linuxModulesDirectoryPath = (root / "LinuxModules").string() + "/";
    runtimeConfig.windowsModulesDirectoryPath = (root / "WindowsModules").string() + "/";
    runtimeConfig.linuxBeaconsDirectoryPath = (root / "LinuxBeacons").string() + "/";
    runtimeConfig.windowsBeaconsDirectoryPath = (root / "WindowsBeacons").string() + "/";
    runtimeConfig.toolsDirectoryPath = (root / "Tools").string() + "/";
    runtimeConfig.scriptsDirectoryPath = (root / "Scripts").string() + "/";
    runtimeConfig.generatedArtifactsDirectoryPath = (root / "GeneratedArtifacts").string() + "/";
    return runtimeConfig;
}

void testPrepareCommonCommand()
{
    ScopedPath tempRoot(makeTempDirectory("common"));
    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerCommandPreparationService service(
        makeLogger(),
        makeRuntimeConfig(tempRoot.path()),
        commonCommands,
        modules);

    C2Message message;
    assert(service.prepareMessage("sleep 0.5", message, true) == 0);
    assert(message.instruction() == SleepCmd);
}

void testPrepareModuleCommandCaseInsensitive()
{
    ScopedPath tempRoot(makeTempDirectory("module"));
    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("FakeModule"));

    TeamServerCommandPreparationService service(
        makeLogger(),
        makeRuntimeConfig(tempRoot.path()),
        commonCommands,
        modules);

    C2Message message;
    assert(service.prepareMessage("fakemodule anything", message, true, "aarch64") == 42);
    assert(message.instruction() == "FAKE");
    assert(message.cmd() == "arm64");
}

void testPrepareMissingCommand()
{
    ScopedPath tempRoot(makeTempDirectory("missing"));
    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;

    TeamServerCommandPreparationService service(
        makeLogger(),
        makeRuntimeConfig(tempRoot.path()),
        commonCommands,
        modules);

    C2Message message;
    assert(service.prepareMessage("doesnotexist", message, true) == -1);
    assert(message.returnvalue() == "Module doesnotexist not found.");
}

void testPrepareLoadModuleUsesWindowsSessionArchitecture()
{
    ScopedPath tempRoot(makeTempDirectory("loadmodule-arch"));
    fs::path windowsModulesRoot = tempRoot.path() / "WindowsModules";
    fs::path linuxModulesRoot = tempRoot.path() / "LinuxModules";
    writeFile(windowsModulesRoot / "x86" / "Inject.dll", "X86DLL");
    writeFile(windowsModulesRoot / "x64" / "Inject.dll", "X64DLL");
    writeFile(windowsModulesRoot / "arm64" / "Inject.dll", "ARM64DLL");

    CommonCommands commonCommands;
    commonCommands.setDirectories(
        (tempRoot.path() / "TeamServerModules").string(),
        linuxModulesRoot.string() + "/",
        windowsModulesRoot.string() + "/",
        (tempRoot.path() / "LinuxBeacons").string() + "/",
        (tempRoot.path() / "WindowsBeacons").string() + "/",
        (tempRoot.path() / "Tools").string() + "/",
        (tempRoot.path() / "Scripts").string() + "/");

    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerCommandPreparationService service(
        makeLogger(),
        makeRuntimeConfig(tempRoot.path()),
        commonCommands,
        modules);

    C2Message message;
    assert(service.prepareMessage("loadModule Inject.dll", message, true, "x86") == 0);
    assert(message.instruction() == LoadC2ModuleCmd);
    assert(message.inputfile() == "Inject.dll");
    assert(message.data() == "X86DLL");
    assert(commonCommands.getLastResolvedModulePath() == (windowsModulesRoot / "x86" / "Inject.dll").string());

    C2Message aliasMessage;
    assert(service.prepareMessage("loadModule Inject.dll", aliasMessage, true, "amd64") == 0);
    assert(aliasMessage.data() == "X64DLL");
    assert(commonCommands.getLastResolvedModulePath() == (windowsModulesRoot / "x64" / "Inject.dll").string());

    C2Message armMessage;
    assert(service.prepareMessage("loadModule Inject.dll", armMessage, true, "arm64") == 0);
    assert(armMessage.data() == "ARM64DLL");
    assert(commonCommands.getLastResolvedModulePath() == (windowsModulesRoot / "arm64" / "Inject.dll").string());
}

void testPrepareAssemblyExecUsesShellcodeServiceAndGeneratedArtifactStore()
{
    ScopedPath tempRoot(makeTempDirectory("assemblyexec-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "payload.bin", "RAW-SHELLCODE");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeShellcodeModule>("assemblyExec"));

    auto shellcodeService = std::make_shared<TeamServerShellcodeService>(makeLogger());
    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerAssemblyExecCommandPreparer>(
        makeLogger(),
        runtimeConfig,
        shellcodeService,
        artifactStore,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    assert(service.prepareMessage("assemblyExec --mode thread --raw payload.bin", message, true, "amd64") == 0);
    assert(message.instruction() == "assemblyExec");
    assert(message.args() == "thread");
    assert(message.data() == "RAW-SHELLCODE");
    assert(message.cmd() == "--mode thread --raw payload.bin");
    assert(message.inputfile().find("GeneratedArtifacts") != std::string::npos);
    assert(fs::exists(message.inputfile()));
    assert(fs::exists(message.inputfile() + ".artifact.json"));

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "payload";
    query.scope = "generated";
    query.runtime = "shellcode";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    assert(artifacts.size() == 1);
    assert(artifacts[0].source == "raw");
    assert(artifacts[0].platform == "windows");
    assert(artifacts[0].arch == "x64");
}

void testPrepareAssemblyExecDonutReportsMissingSource()
{
    ScopedPath tempRoot(makeTempDirectory("assemblyexec-donut-missing"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeShellcodeModule>("assemblyExec"));

    auto shellcodeService = std::make_shared<TeamServerShellcodeService>(makeLogger());
    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerAssemblyExecCommandPreparer>(
        makeLogger(),
        runtimeConfig,
        shellcodeService,
        artifactStore,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    assert(service.prepareMessage("assemblyExec --mode thread --donut-exe missing.exe", message, true, "x64") == -1);
    assert(message.returnvalue().find("Couldn't open Donut source file.") != std::string::npos);
}

void testPrepareInjectUsesShellcodeServiceAndGeneratedArtifactStore()
{
    ScopedPath tempRoot(makeTempDirectory("inject-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "payload.bin", "INJECT-SHELLCODE");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeShellcodeModule>("inject"));

    auto shellcodeService = std::make_shared<TeamServerShellcodeService>(makeLogger());
    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerInjectCommandPreparer>(
        makeLogger(),
        runtimeConfig,
        shellcodeService,
        artifactStore,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    assert(service.prepareMessage("inject --raw payload.bin --pid 4321", message, true, "amd64") == 0);
    assert(message.instruction() == "inject");
    assert(message.pid() == 4321);
    assert(message.data() == "INJECT-SHELLCODE");
    assert(message.cmd() == "--raw payload.bin --pid 4321");
    assert(message.inputfile().find("GeneratedArtifacts") != std::string::npos);
    assert(fs::exists(message.inputfile()));
    assert(fs::exists(message.inputfile() + ".artifact.json"));

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "payload";
    query.scope = "generated";
    query.runtime = "shellcode";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    assert(artifacts.size() == 1);
    assert(artifacts[0].source == "raw");
    assert(artifacts[0].platform == "windows");
    assert(artifacts[0].arch == "x64");
    assert(artifacts[0].description == "Generated shellcode for inject.");
}

void testPrepareInjectDonutReportsMissingSource()
{
    ScopedPath tempRoot(makeTempDirectory("inject-donut-missing"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeShellcodeModule>("inject"));

    auto shellcodeService = std::make_shared<TeamServerShellcodeService>(makeLogger());
    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerInjectCommandPreparer>(
        makeLogger(),
        runtimeConfig,
        shellcodeService,
        artifactStore,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    assert(service.prepareMessage("inject --donut-exe missing.exe --pid 4321 -- arg1", message, true, "x64") == -1);
    assert(message.returnvalue().find("Couldn't open Donut source file.") != std::string::npos);
}
} // namespace

int main()
{
    testPrepareCommonCommand();
    testPrepareModuleCommandCaseInsensitive();
    testPrepareMissingCommand();
    testPrepareLoadModuleUsesWindowsSessionArchitecture();
    testPrepareAssemblyExecUsesShellcodeServiceAndGeneratedArtifactStore();
    testPrepareAssemblyExecDonutReportsMissingSource();
    testPrepareInjectUsesShellcodeServiceAndGeneratedArtifactStore();
    testPrepareInjectDonutReportsMissingSource();
    return 0;
}
