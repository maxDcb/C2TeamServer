#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include "TeamServerAssemblyExecCommandPreparer.hpp"
#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerChiselCommandPreparer.hpp"
#include "TeamServerCommandPreparationService.hpp"
#include "TeamServerFileArtifactService.hpp"
#include "TeamServerFileTransferCommandPreparer.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "TeamServerInjectCommandPreparer.hpp"
#include "TeamServerMiniDumpCommandPreparer.hpp"
#include "TeamServerModuleArtifactCommandPreparer.hpp"
#include "TeamServerScriptCommandPreparer.hpp"
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

class FakeShellcodeService final : public TeamServerShellcodeService
{
public:
    FakeShellcodeService()
        : TeamServerShellcodeService(makeLogger())
    {
        nextResult.ok = true;
        nextResult.bytes = "FAKE-SHELLCODE";
        nextResult.generator = "donut";
        nextResult.sourceType = "dotnet_exe";
        nextResult.sha256 = std::string(64, 'f');
    }

    TeamServerShellcodeResult generate(const TeamServerShellcodeRequest& request) const override
    {
        lastRequest = request;
        return nextResult;
    }

    mutable TeamServerShellcodeRequest lastRequest;
    TeamServerShellcodeResult nextResult;
};

void writeFile(const fs::path& path, const std::string& content)
{
    if (!path.parent_path().empty())
        fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << content;
}

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

std::vector<std::string> splitNullFields(const std::string& value)
{
    std::vector<std::string> fields;
    std::string current;
    for (char ch : value)
    {
        if (ch == '\0')
        {
            fields.push_back(current);
            current.clear();
        }
        else
        {
            current += ch;
        }
    }
    fields.push_back(current);
    return fields;
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
    runtimeConfig.uploadedArtifactsDirectoryPath = (root / "UploadedArtifacts").string() + "/";
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

void testPrepareLoadModuleUsesLinuxSessionArchitecture()
{
    ScopedPath tempRoot(makeTempDirectory("loadmodule-linux-arch"));
    fs::path windowsModulesRoot = tempRoot.path() / "WindowsModules";
    fs::path linuxModulesRoot = tempRoot.path() / "LinuxModules";
    writeFile(linuxModulesRoot / "x64" / "libInject.so", "LINUX-X64");

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
    assert(service.prepareMessage("loadModule libInject.so", message, false, "amd64") == 0);
    assert(message.instruction() == LoadC2ModuleCmd);
    assert(message.inputfile() == "libInject.so");
    assert(message.data() == "LINUX-X64");
    assert(commonCommands.getLastResolvedModulePath() == (linuxModulesRoot / "x64" / "libInject.so").string());
}

void testPrepareAssemblyExecUsesShellcodeServiceAndGeneratedArtifactStore()
{
    ScopedPath tempRoot(makeTempDirectory("assemblyexec-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "payload.bin", "RAW-SHELLCODE");

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
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "payload.bin", "INJECT-SHELLCODE");

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

void testPrepareUploadUsesUploadedArtifact()
{
    ScopedPath tempRoot(makeTempDirectory("upload-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any" / "operator.bin", "UPLOAD-BYTES");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("upload"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        makeLogger(),
        runtimeConfig,
        artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerFileTransferCommandPreparer>(
        makeLogger(),
        fileArtifactService,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    require(service.prepareMessage("upload operator.bin C:\\Temp\\operator.bin", message, true, "amd64") == 0, "upload prepare failed");
    require(message.instruction() == "upload", "upload instruction mismatch");
    require(message.inputfile() == "operator.bin", "upload input artifact mismatch");
    require(message.outputfile() == "C:\\Temp\\operator.bin", "upload remote path mismatch");
    require(message.data() == "UPLOAD-BYTES", "upload bytes mismatch");

    C2Message missingMessage;
    require(service.prepareMessage("upload missing.bin C:\\Temp\\missing.bin", missingMessage, true, "amd64") == -1, "missing upload artifact should fail");
    require(missingMessage.returnvalue().find("Upload artifact not found") != std::string::npos, "missing upload error mismatch");
}

void testPrepareDownloadCreatesGeneratedArtifactSlot()
{
    ScopedPath tempRoot(makeTempDirectory("download-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("download"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        makeLogger(),
        runtimeConfig,
        artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerFileTransferCommandPreparer>(
        makeLogger(),
        fileArtifactService,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    require(service.prepareMessage("download /tmp/loot.txt loot.txt", message, false, "amd64") == 0, "download prepare failed");
    require(message.instruction() == "download", "download instruction mismatch");
    require(message.inputfile() == "/tmp/loot.txt", "download input path mismatch");
    require(message.outputfile().find("GeneratedArtifacts/download/beacon") != std::string::npos, "download output path mismatch");
    require(fs::exists(message.outputfile() + ".artifact.pending.json"), "download pending metadata missing");

    writeFile(message.outputfile(), "LOOT");
    C2Message result;
    result.set_outputfile(message.outputfile());
    result.set_returnvalue("Success");
    std::string artifactMessage;
    require(fileArtifactService->handleCommandResult(result, artifactMessage), "download result was not handled");
    require(artifactMessage.find("Downloaded artifact stored:") != std::string::npos, "download artifact message mismatch");
    require(!fs::exists(message.outputfile() + ".artifact.pending.json"), "download pending metadata was not removed");
    require(fs::exists(message.outputfile() + ".artifact.json"), "download artifact metadata missing");

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "download";
    query.scope = "generated";
    query.target = "teamserver";
    query.runtime = "file";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    require(artifacts.size() == 1, "download artifact catalog count mismatch");
    require(artifacts[0].source == "beacon", "download artifact source mismatch");
    require(artifacts[0].platform == "linux", "download artifact platform mismatch");
    require(artifacts[0].arch == "x64", "download artifact arch mismatch");
    require(artifacts[0].displayName == "loot.txt", "download artifact display name mismatch");
}

void testPrepareChiselUsesFixedToolAndShellcodeService()
{
    ScopedPath tempRoot(makeTempDirectory("chisel-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    const fs::path chiselPath = fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "chisel.exe";
    writeFile(chiselPath, "CHISEL-EXE");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeShellcodeModule>("chisel"));

    auto shellcodeService = std::make_shared<FakeShellcodeService>();
    shellcodeService->nextResult.bytes = "CHISEL-SHELLCODE";
    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerChiselCommandPreparer>(
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
    require(service.prepareMessage("chisel client 127.0.0.1:9001 R:socks", message, true, "amd64") == 0, "chisel prepare failed");
    require(message.instruction() == "chisel", "chisel instruction mismatch");
    require(message.cmd() == "client 127.0.0.1:9001 R:socks", "chisel display command mismatch");
    require(message.data() == "CHISEL-SHELLCODE", "chisel shellcode payload mismatch");
    require(message.inputfile().find("GeneratedArtifacts") != std::string::npos, "chisel generated artifact path mismatch");
    require(shellcodeService->lastRequest.generator == "donut", "chisel generator mismatch");
    require(shellcodeService->lastRequest.sourcePath == chiselPath.string(), "chisel fixed source path mismatch");
    require(shellcodeService->lastRequest.arguments == "client 127.0.0.1:9001 R:socks", "chisel arguments mismatch");

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "payload";
    query.scope = "generated";
    query.runtime = "shellcode";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    require(artifacts.size() == 1, "chisel generated shellcode catalog count mismatch");
    require(artifacts[0].source == "donut", "chisel generated source mismatch");
    require(artifacts[0].arch == "x64", "chisel generated arch mismatch");
}

void testPrepareScriptAndPowershellUseScriptArtifacts()
{
    ScopedPath tempRoot(makeTempDirectory("script-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / "Linux" / "collect.sh", "id\n");
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / "Windows" / "collect.ps1", "Get-Process\n");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("script"));
    modules.push_back(std::make_unique<FakeModule>("powershell"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        makeLogger(),
        runtimeConfig,
        artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerScriptCommandPreparer>(
        makeLogger(),
        fileArtifactService,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message scriptMessage;
    require(service.prepareMessage("script collect.sh", scriptMessage, false, "amd64") == 0, "script prepare failed");
    require(scriptMessage.instruction() == "script", "script instruction mismatch");
    require(scriptMessage.inputfile() == "collect.sh", "script input artifact mismatch");
    require(scriptMessage.data() == "id\n", "script bytes mismatch");

    C2Message powershellMessage;
    require(service.prepareMessage("powershell -s collect.ps1", powershellMessage, true, "x64") == 0, "powershell script prepare failed");
    require(powershellMessage.instruction() == "powershell", "powershell instruction mismatch");
    require(powershellMessage.inputfile() == "collect.ps1", "powershell input artifact mismatch");
    require(powershellMessage.cmd() == "-s collect.ps1 ", "powershell cmd mismatch");
    require(powershellMessage.data().find("Invoke-Command -ScriptBlock") != std::string::npos, "powershell wrapper missing");
    require(powershellMessage.data().find("Get-Process") != std::string::npos, "powershell script content missing");

    C2Message inlineMessage;
    require(service.prepareMessage("powershell whoami", inlineMessage, true, "x86") == 42, "inline powershell should fall through to module init");
    require(inlineMessage.instruction() == "FAKE", "inline powershell fallback mismatch");
}

void testPrepareMiniDumpCreatesGeneratedArtifactSlotAndRegistersChunks()
{
    ScopedPath tempRoot(makeTempDirectory("minidump-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("miniDump"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        makeLogger(),
        runtimeConfig,
        artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerMiniDumpCommandPreparer>(
        makeLogger(),
        fileArtifactService,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    require(service.prepareMessage("miniDump dump lsass.xored", message, true, "amd64") == 0, "miniDump prepare failed");
    require(message.instruction() == "miniDump", "miniDump instruction mismatch");
    require(message.cmd() == "0", "miniDump command mismatch");
    require(message.outputfile().find("GeneratedArtifacts/minidump/beacon") != std::string::npos, "miniDump output path mismatch");
    require(fs::exists(message.outputfile() + ".artifact.pending.json"), "miniDump pending metadata missing");

    C2Message firstChunk;
    firstChunk.set_outputfile(message.outputfile());
    firstChunk.set_args("0");
    firstChunk.set_data("AA");
    firstChunk.set_returnvalue("2/4");
    std::string artifactMessage;
    require(fileArtifactService->handleCommandResult(firstChunk, artifactMessage), "miniDump first chunk was not handled");
    require(fileArtifactService->shouldKeepCommandContext(firstChunk), "miniDump first chunk should keep command context");
    require(!fs::exists(message.outputfile() + ".artifact.json"), "miniDump should not register before success");

    C2Message finalChunk;
    finalChunk.set_outputfile(message.outputfile());
    finalChunk.set_args("1");
    finalChunk.set_data("BB");
    finalChunk.set_returnvalue("Success");
    require(fileArtifactService->handleCommandResult(finalChunk, artifactMessage), "miniDump final chunk was not handled");
    require(artifactMessage.find("Generated artifact stored:") != std::string::npos, "miniDump artifact message mismatch");
    require(fs::exists(message.outputfile() + ".artifact.json"), "miniDump artifact metadata missing");

    std::ifstream payload(message.outputfile(), std::ios::binary);
    std::string payloadBytes(std::istreambuf_iterator<char>(payload), {});
    require(payloadBytes == "AABB", "miniDump assembled bytes mismatch");

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "minidump";
    query.scope = "generated";
    query.target = "teamserver";
    query.runtime = "file";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    require(artifacts.size() == 1, "miniDump artifact catalog count mismatch");
    require(artifacts[0].source == "beacon", "miniDump artifact source mismatch");
    require(artifacts[0].platform == "windows", "miniDump artifact platform mismatch");
    require(artifacts[0].arch == "x64", "miniDump artifact arch mismatch");
    require(artifacts[0].format == "xored", "miniDump artifact format mismatch");
}

void testPrepareScreenShotCreatesGeneratedArtifactSlot()
{
    ScopedPath tempRoot(makeTempDirectory("screenshot-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("screenShot"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(
        makeLogger(),
        runtimeConfig,
        artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(
        makeLogger(),
        fileArtifactService,
        modules));

    TeamServerCommandPreparationService service(
        makeLogger(),
        runtimeConfig,
        commonCommands,
        modules,
        std::move(preparers));

    C2Message message;
    require(service.prepareMessage("screenShot desktop.bmp", message, true, "amd64") == 0, "screenShot prepare failed");
    require(message.instruction() == "screenShot", "screenShot instruction mismatch");
    require(message.outputfile().find("GeneratedArtifacts/screenshot/beacon") != std::string::npos, "screenShot output path mismatch");
    require(fs::exists(message.outputfile() + ".artifact.pending.json"), "screenShot pending metadata missing");

    C2Message result;
    result.set_outputfile(message.outputfile());
    result.set_args("0");
    result.set_data("BMfake");
    result.set_returnvalue("Success");
    std::string artifactMessage;
    require(fileArtifactService->handleCommandResult(result, artifactMessage), "screenShot result was not handled");
    require(artifactMessage.find("Generated artifact stored:") != std::string::npos, "screenShot artifact message mismatch");

    TeamServerArtifactCatalog catalog(runtimeConfig);
    TeamServerArtifactQuery query;
    query.category = "screenshot";
    query.scope = "generated";
    query.target = "teamserver";
    query.runtime = "file";
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    require(artifacts.size() == 1, "screenShot artifact catalog count mismatch");
    require(artifacts[0].format == "bmp", "screenShot artifact format mismatch");
}

void testPrepareKerberosUseTicketUsesUploadedArtifact()
{
    ScopedPath tempRoot(makeTempDirectory("kerberos-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any" / "ticket.kirbi", "TICKET");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("kerberosUseTicket"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(makeLogger(), runtimeConfig, artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(makeLogger(), fileArtifactService, modules));

    TeamServerCommandPreparationService service(makeLogger(), runtimeConfig, commonCommands, modules, std::move(preparers));

    C2Message message;
    require(service.prepareMessage("kerberosUseTicket ticket.kirbi", message, true, "x64") == 0, "kerberosUseTicket prepare failed");
    require(message.instruction() == "kerberosUseTicket", "kerberosUseTicket instruction mismatch");
    require(message.inputfile() == "ticket.kirbi", "kerberosUseTicket input artifact mismatch");
    require(message.data() == "TICKET", "kerberosUseTicket data mismatch");
}

void testPreparePsExecUsesToolThenUploadedArtifact()
{
    ScopedPath tempRoot(makeTempDirectory("psexec-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "svc.exe", "TOOL-SVC");
    writeFile(fs::path(runtimeConfig.uploadedArtifactsDirectoryPath) / "Any" / "any" / "uploadSvc.exe", "UPLOAD-SVC");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("psExec"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(makeLogger(), runtimeConfig, artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(makeLogger(), fileArtifactService, modules));

    TeamServerCommandPreparationService service(makeLogger(), runtimeConfig, commonCommands, modules, std::move(preparers));

    C2Message credentialMessage;
    require(service.prepareMessage("psExec -u DOMAIN\\alice secret server01 svc.exe", credentialMessage, true, "amd64") == 0, "psExec tool prepare failed");
    require(credentialMessage.instruction() == "psExec", "psExec instruction mismatch");
    require(credentialMessage.inputfile() == "svc.exe", "psExec tool artifact mismatch");
    require(credentialMessage.data() == "TOOL-SVC", "psExec tool bytes mismatch");
    const std::vector<std::string> credentialFields = splitNullFields(credentialMessage.cmd());
    require(credentialFields.size() == 4, "psExec credential fields count mismatch");
    require(credentialFields[0] == "DOMAIN", "psExec domain mismatch");
    require(credentialFields[1] == "alice", "psExec username mismatch");
    require(credentialFields[2] == "secret", "psExec password mismatch");
    require(credentialFields[3] == "server01", "psExec target mismatch");

    C2Message uploadMessage;
    require(service.prepareMessage("psExec -n server01 uploadSvc.exe", uploadMessage, true, "amd64") == 0, "psExec upload fallback prepare failed");
    require(uploadMessage.inputfile() == "uploadSvc.exe", "psExec upload artifact mismatch");
    require(uploadMessage.data() == "UPLOAD-SVC", "psExec upload bytes mismatch");
    require(uploadMessage.cmd() == "server01", "psExec token target mismatch");
}

void testPrepareCoffLoaderUsesToolArtifact()
{
    ScopedPath tempRoot(makeTempDirectory("coffloader-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "whoami.x64.o", "COFF");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("coffLoader"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(makeLogger(), runtimeConfig, artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(makeLogger(), fileArtifactService, modules));

    TeamServerCommandPreparationService service(makeLogger(), runtimeConfig, commonCommands, modules, std::move(preparers));

    C2Message message;
    require(service.prepareMessage("coffLoader whoami.x64.o go Zs c:\\ 0", message, true, "x64") == 0, "coffLoader prepare failed");
    require(message.instruction() == "coffLoader", "coffLoader instruction mismatch");
    require(message.inputfile() == "whoami.x64.o", "coffLoader tool artifact mismatch");
    require(message.cmd() == "go", "coffLoader function mismatch");
    require(message.args() == "Zs c:\\ 0", "coffLoader arguments mismatch");
    require(message.data() == "COFF", "coffLoader bytes mismatch");
}

void testPrepareDotnetExecLoadUsesToolArtifact()
{
    ScopedPath tempRoot(makeTempDirectory("dotnetexec-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "Tool.exe", "EXE");
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "Library.dll", "DLL");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("dotnetExec"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(makeLogger(), runtimeConfig, artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(makeLogger(), fileArtifactService, modules));

    TeamServerCommandPreparationService service(makeLogger(), runtimeConfig, commonCommands, modules, std::move(preparers));

    C2Message exeMessage;
    require(service.prepareMessage("dotnetExec load tool Tool.exe", exeMessage, true, "amd64") == 0, "dotnetExec exe load prepare failed");
    require(exeMessage.instruction() == "dotnetExec", "dotnetExec instruction mismatch");
    require(exeMessage.cmd() == "00001", "dotnetExec load command mismatch");
    require(exeMessage.args() == "tool", "dotnetExec short name mismatch");
    require(exeMessage.returnvalue().empty(), "dotnetExec exe type mismatch");
    require(exeMessage.inputfile() == "Tool.exe", "dotnetExec exe artifact mismatch");
    require(exeMessage.data() == "EXE", "dotnetExec exe bytes mismatch");

    C2Message dllMessage;
    require(service.prepareMessage("dotnetExec load library Library.dll Namespace.Type", dllMessage, true, "amd64") == 0, "dotnetExec dll load prepare failed");
    require(dllMessage.returnvalue() == "Namespace.Type", "dotnetExec dll type mismatch");
    require(dllMessage.data() == "DLL", "dotnetExec dll bytes mismatch");

    C2Message runMessage;
    require(service.prepareMessage("dotnetExec runExe tool arg1", runMessage, true, "amd64") == 42, "dotnetExec run should fall through to module init");
    require(runMessage.instruction() == "FAKE", "dotnetExec run fallback mismatch");
}

void testPreparePwShUsesFixedRunnerAndScriptArtifacts()
{
    ScopedPath tempRoot(makeTempDirectory("pwsh-preparer"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / "x64" / "rdm.dll", "RUNNER");
    writeFile(fs::path(runtimeConfig.scriptsDirectoryPath) / "Windows" / "PowerView.ps1", "function Invoke-PowerView {}\n");

    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    modules.push_back(std::make_unique<FakeModule>("pwSh"));

    auto artifactStore = std::make_shared<TeamServerGeneratedArtifactStore>(runtimeConfig);
    auto fileArtifactService = std::make_shared<TeamServerFileArtifactService>(makeLogger(), runtimeConfig, artifactStore);
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers;
    preparers.push_back(std::make_unique<TeamServerModuleArtifactCommandPreparer>(makeLogger(), fileArtifactService, modules));

    TeamServerCommandPreparationService service(makeLogger(), runtimeConfig, commonCommands, modules, std::move(preparers));

    C2Message initMessage;
    require(service.prepareMessage("pwSh init", initMessage, true, "amd64") == 0, "pwSh init prepare failed");
    require(initMessage.instruction() == "pwSh", "pwSh init instruction mismatch");
    require(initMessage.cmd() == "00001", "pwSh init command mismatch");
    require(initMessage.args() == "rdm.rdm", "pwSh fixed type mismatch");
    require(initMessage.inputfile() == "rdm.dll", "pwSh fixed runner mismatch");
    require(initMessage.data() == "RUNNER", "pwSh runner bytes mismatch");

    C2Message runMessage;
    require(service.prepareMessage("pwSh run Get-Process", runMessage, true, "amd64") == 0, "pwSh run prepare failed");
    require(runMessage.cmd() == "00003", "pwSh run command mismatch");
    require(runMessage.args() == "Get-Process ", "pwSh run args mismatch");

    C2Message importMessage;
    require(service.prepareMessage("pwSh import PowerView.ps1", importMessage, true, "amd64") == 0, "pwSh import prepare failed");
    require(importMessage.cmd() == "00004", "pwSh import command mismatch");
    require(importMessage.inputfile() == "PowerView.ps1", "pwSh import script mismatch");
    require(importMessage.args().find("New-Module -ScriptBlock") != std::string::npos, "pwSh import wrapper mismatch");

    C2Message scriptMessage;
    require(service.prepareMessage("pwSh script PowerView.ps1", scriptMessage, true, "amd64") == 0, "pwSh script prepare failed");
    require(scriptMessage.cmd() == "00005", "pwSh script command mismatch");
    require(scriptMessage.args().find("Invoke-Command -ScriptBlock") != std::string::npos, "pwSh script wrapper mismatch");
}
} // namespace

int main()
{
    testPrepareCommonCommand();
    testPrepareModuleCommandCaseInsensitive();
    testPrepareMissingCommand();
    testPrepareLoadModuleUsesWindowsSessionArchitecture();
    testPrepareLoadModuleUsesLinuxSessionArchitecture();
    testPrepareAssemblyExecUsesShellcodeServiceAndGeneratedArtifactStore();
    testPrepareAssemblyExecDonutReportsMissingSource();
    testPrepareInjectUsesShellcodeServiceAndGeneratedArtifactStore();
    testPrepareInjectDonutReportsMissingSource();
    testPrepareUploadUsesUploadedArtifact();
    testPrepareDownloadCreatesGeneratedArtifactSlot();
    testPrepareChiselUsesFixedToolAndShellcodeService();
    testPrepareScriptAndPowershellUseScriptArtifacts();
    testPrepareMiniDumpCreatesGeneratedArtifactSlotAndRegistersChunks();
    testPrepareScreenShotCreatesGeneratedArtifactSlot();
    testPrepareKerberosUseTicketUsesUploadedArtifact();
    testPreparePsExecUsesToolThenUploadedArtifact();
    testPrepareCoffLoaderUsesToolArtifact();
    testPrepareDotnetExecLoadUsesToolArtifact();
    testPreparePwShUsesFixedRunnerAndScriptArtifacts();
    return 0;
}
