#include "TeamServerScriptCommandPreparer.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>

#include "modules/ModuleCmd/Common.hpp"

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

std::string joinTailWithSpace(const std::vector<std::string>& tokens, std::size_t start)
{
    std::ostringstream output;
    for (std::size_t index = start; index < tokens.size(); ++index)
        output << tokens[index] << ' ';
    return output.str();
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

TeamServerScriptCommandPreparer::TeamServerScriptCommandPreparer(
    std::shared_ptr<spdlog::logger> logger,
    std::shared_ptr<TeamServerFileArtifactService> fileArtifactService,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd)
    : m_logger(std::move(logger)),
      m_fileArtifactService(std::move(fileArtifactService)),
      m_moduleCmd(moduleCmd)
{
}

bool TeamServerScriptCommandPreparer::canPrepare(const std::string& instruction) const
{
    const std::string lowered = toLower(instruction);
    return lowered == "script" || lowered == "powershell";
}

TeamServerCommandPreparerResult TeamServerScriptCommandPreparer::prepare(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    const std::string instruction = toLower(context.tokens.empty() ? "" : context.tokens[0]);
    if (instruction == "script")
        return prepareScript(context, c2Message);
    return preparePowershellScript(context, c2Message);
}

bool TeamServerScriptCommandPreparer::hasModule(const std::string& name) const
{
    const std::string lowered = toLower(name);
    for (const auto& module : m_moduleCmd)
    {
        if (module && toLower(module->getName()) == lowered)
            return true;
    }
    return false;
}

TeamServerCommandPreparerResult TeamServerScriptCommandPreparer::prepareScript(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    if (!hasModule("script"))
        return handledError(c2Message, "Module script not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() != 2)
        return handledError(c2Message, "Usage: script <script_artifact>\n");

    TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveScriptArtifact(
        tokens[1],
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("script");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_data(artifact.bytes);
    result.status = 0;
    if (m_logger)
        m_logger->info("Prepared script artifact {}", artifact.artifact.name);
    return result;
}

TeamServerCommandPreparerResult TeamServerScriptCommandPreparer::preparePowershellScript(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() < 2 || (tokens[1] != "-i" && tokens[1] != "-s"))
        return result;

    result.handled = true;
    result.status = -1;
    if (!hasModule("powershell"))
        return handledError(c2Message, "Module powershell not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");
    if (tokens.size() != 3)
        return handledError(c2Message, "Usage: powershell -i|-s <script_artifact>\n");

    TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveScriptArtifact(
        tokens[2],
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    std::string payload;
    if (tokens[1] == "-i")
    {
        payload = "New-Module -ScriptBlock {\n";
        payload += artifact.bytes;
        payload += "\nExport-ModuleMember -Function * -Alias *;};";
    }
    else
    {
        payload = "Invoke-Command -ScriptBlock  {\n";
        payload += artifact.bytes;
        payload += "};";
    }

    c2Message.set_instruction("powershell");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_cmd(joinTailWithSpace(tokens, 1));
    c2Message.set_data(payload.data(), payload.size());
    result.status = 0;
    if (m_logger)
        m_logger->info("Prepared powershell script artifact {}", artifact.artifact.name);
    return result;
}
