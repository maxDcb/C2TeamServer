#include "TeamServerInjectCommandPreparer.hpp"

#include <array>
#include <filesystem>
#include <utility>

#include "modules/Inject/InjectCommandOptions.hpp"

namespace fs = std::filesystem;

namespace
{
std::string resolveSourcePath(
    const TeamServerRuntimeConfig& runtimeConfig,
    const std::string& path,
    const std::string& windowsArch)
{
    if (path.empty())
        return "";
    if (fs::exists(path))
        return path;

    const std::array<fs::path, 3> toolCandidates = {
        fs::path(runtimeConfig.toolsDirectoryPath) / "Windows" / windowsArch / path,
        fs::path(runtimeConfig.toolsDirectoryPath) / "Any" / "any" / path,
        fs::path(runtimeConfig.toolsDirectoryPath) / path,
    };
    for (const fs::path& toolPath : toolCandidates)
    {
        if (fs::exists(toolPath))
            return toolPath.string();
    }

    fs::path beaconPath = fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / path;
    if (fs::exists(beaconPath))
        return beaconPath.string();

    fs::path archBeaconPath = fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / windowsArch / path;
    if (fs::exists(archBeaconPath))
        return archBeaconPath.string();

    return path;
}

ModuleCmd* findModule(std::vector<std::unique_ptr<ModuleCmd>>& modules, const std::string& name)
{
    const std::string loweredName = inject_command::lowerCopy(name);
    for (const auto& module : modules)
    {
        if (module && inject_command::lowerCopy(module->getName()) == loweredName)
            return module.get();
    }
    return nullptr;
}
} // namespace

TeamServerInjectCommandPreparer::TeamServerInjectCommandPreparer(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerRuntimeConfig runtimeConfig,
    std::shared_ptr<TeamServerShellcodeService> shellcodeService,
    std::shared_ptr<TeamServerGeneratedArtifactStore> artifactStore,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd)
    : m_logger(std::move(logger)),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_shellcodeService(std::move(shellcodeService)),
      m_artifactStore(std::move(artifactStore)),
      m_moduleCmd(moduleCmd)
{
}

bool TeamServerInjectCommandPreparer::canPrepare(const std::string& instruction) const
{
    return inject_command::lowerCopy(instruction) == "inject";
}

TeamServerCommandPreparerResult TeamServerInjectCommandPreparer::prepare(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    inject_command::CommandOptions options = inject_command::parseCommandOptions(context.tokens);
    if (!options.error.empty())
    {
        c2Message.set_returnvalue(options.error + "\n");
        return result;
    }

    if (!m_shellcodeService || !m_artifactStore)
    {
        c2Message.set_returnvalue("Shellcode preparation service is not available.\n");
        return result;
    }

    TeamServerShellcodeRequest shellcodeRequest;
    shellcodeRequest.generator = options.generator;
    shellcodeRequest.sourcePath = resolveSourcePath(m_runtimeConfig, options.sourcePath, context.windowsArch);
    shellcodeRequest.sourceType = options.sourceType;
    shellcodeRequest.arch = context.windowsArch;
    shellcodeRequest.method = options.method;
    shellcodeRequest.arguments = options.arguments;
    shellcodeRequest.exitPolicy = "process";

    TeamServerShellcodeResult shellcode = m_shellcodeService->generate(shellcodeRequest);
    if (!shellcode.ok)
    {
        c2Message.set_returnvalue(shellcode.message + "\n");
        return result;
    }

    TeamServerGeneratedArtifactRequest artifactRequest;
    artifactRequest.nameHint = "inject-" + fs::path(shellcodeRequest.sourcePath).filename().string() + ".bin";
    artifactRequest.bytes = shellcode.bytes;
    artifactRequest.platform = context.isWindows ? "windows" : "linux";
    artifactRequest.arch = context.isWindows ? context.windowsArch : "any";
    artifactRequest.source = shellcode.generator;
    artifactRequest.description = "Generated shellcode for inject.";
    artifactRequest.tags = {"inject", shellcode.sourceType};
    TeamServerGeneratedArtifactRecord artifact = m_artifactStore->store(artifactRequest);
    if (artifact.path.empty())
    {
        c2Message.set_returnvalue("Could not store generated shellcode artifact.\n");
        return result;
    }

    ModuleCmd* module = findModule(m_moduleCmd, "inject");
    if (!module)
    {
        c2Message.set_returnvalue("Module inject not found.\n");
        return result;
    }

    ModulePreparedShellcodeTask task;
    task.inputFile = artifact.path;
    task.payload = shellcode.bytes;
    task.pid = options.pid;
    task.displayCommand = options.displayCommand;
    result.status = module->initPreparedShellcode(task, c2Message);
    if (result.status == 0 && m_logger)
        m_logger->info("inject prepared shellcode artifact {}", artifact.path);
    return result;
}
