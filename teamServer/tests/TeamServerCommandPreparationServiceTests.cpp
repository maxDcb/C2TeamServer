#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

#include "TeamServerCommandPreparationService.hpp"

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

void testPrepareCommonCommand()
{
    ScopedPath tempRoot(makeTempDirectory("common"));
    CommonCommands commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>> modules;
    TeamServerCommandPreparationService service(
        makeLogger(),
        tempRoot.path().string(),
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
        tempRoot.path().string(),
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
        tempRoot.path().string(),
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
        (tempRoot.path() / "TeamServerModules").string(),
        commonCommands,
        modules);

    C2Message message;
    assert(service.prepareMessage("loadModule Inject.dll", message, true, "x86") == 0);
    assert(message.instruction() == LoadC2ModuleCmd);
    assert(message.inputfile() == "Inject.dll");
    assert(message.data() == "X86DLL");

    C2Message aliasMessage;
    assert(service.prepareMessage("loadModule Inject.dll", aliasMessage, true, "amd64") == 0);
    assert(aliasMessage.data() == "X64DLL");

    C2Message armMessage;
    assert(service.prepareMessage("loadModule Inject.dll", armMessage, true, "arm64") == 0);
    assert(armMessage.data() == "ARM64DLL");
}
} // namespace

int main()
{
    testPrepareCommonCommand();
    testPrepareModuleCommandCaseInsensitive();
    testPrepareMissingCommand();
    testPrepareLoadModuleUsesWindowsSessionArchitecture();
    return 0;
}
