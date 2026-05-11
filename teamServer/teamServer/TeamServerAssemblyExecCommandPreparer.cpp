#include "TeamServerAssemblyExecCommandPreparer.hpp"

#include <array>
#include <filesystem>
#include <utility>

#include "modules/AssemblyExec/AssemblyExecCommandOptions.hpp"

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
    return path;
}

ModuleCmd* findModule(std::vector<std::unique_ptr<ModuleCmd>>& modules, const std::string& name)
{
    const std::string loweredName = assembly_exec_command::lowerCopy(name);
    for (const auto& module : modules)
    {
        if (module && assembly_exec_command::lowerCopy(module->getName()) == loweredName)
            return module.get();
    }
    return nullptr;
}
} // namespace

TeamServerAssemblyExecCommandPreparer::TeamServerAssemblyExecCommandPreparer(
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

bool TeamServerAssemblyExecCommandPreparer::canPrepare(const std::string& instruction) const
{
    return assembly_exec_command::lowerCopy(instruction) == "assemblyexec";
}

TeamServerCommandPreparerResult TeamServerAssemblyExecCommandPreparer::prepare(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    assembly_exec_command::CommandOptions options = assembly_exec_command::parseCommandOptions(context.tokens);
    if (options.modeOnly)
        return result;

    result.handled = true;
    result.status = -1;
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
    shellcodeRequest.exitPolicy = options.mode == "thread" ? "thread" : "process";

    TeamServerShellcodeResult shellcode = m_shellcodeService->generate(shellcodeRequest);
    if (!shellcode.ok)
    {
        c2Message.set_returnvalue(shellcode.message + "\n");
        return result;
    }

    TeamServerGeneratedArtifactRequest artifactRequest;
    artifactRequest.nameHint = "assemblyExec-" + fs::path(shellcodeRequest.sourcePath).filename().string() + ".bin";
    artifactRequest.bytes = shellcode.bytes;
    artifactRequest.platform = context.isWindows ? "windows" : "linux";
    artifactRequest.arch = context.isWindows ? context.windowsArch : "any";
    artifactRequest.source = shellcode.generator;
    artifactRequest.description = "Generated shellcode for assemblyExec.";
    artifactRequest.tags = {"assemblyExec", shellcode.sourceType};
    TeamServerGeneratedArtifactRecord artifact = m_artifactStore->store(artifactRequest);
    if (artifact.path.empty())
    {
        c2Message.set_returnvalue("Could not store generated shellcode artifact.\n");
        return result;
    }

    ModuleCmd* module = findModule(m_moduleCmd, "assemblyExec");
    if (!module)
    {
        c2Message.set_returnvalue("Module assemblyExec not found.\n");
        return result;
    }

    ModulePreparedShellcodeTask task;
    task.inputFile = artifact.path;
    task.payload = shellcode.bytes;
    task.executionMode = options.mode.empty() ? "process" : options.mode;
    task.displayCommand = options.displayCommand;
    result.status = module->initPreparedShellcode(task, c2Message);
    if (result.status == 0 && m_logger)
        m_logger->info("assemblyExec prepared shellcode artifact {}", artifact.path);
    return result;
}
