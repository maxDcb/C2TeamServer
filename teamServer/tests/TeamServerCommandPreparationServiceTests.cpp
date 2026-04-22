#include <cassert>
#include <filesystem>
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
        return 42;
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
    assert(service.prepareMessage("fakemodule anything", message, true) == 42);
    assert(message.instruction() == "FAKE");
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
} // namespace

int main()
{
    testPrepareCommonCommand();
    testPrepareModuleCommandCaseInsensitive();
    testPrepareMissingCommand();
    return 0;
}
