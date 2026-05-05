#include "TeamServerHelpService.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "modules/ModuleCmd/Common.hpp"

namespace
{
const std::string HelpCmd = "help";

std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool equalsCaseInsensitive(const std::string& left, const std::string& right)
{
    return toLower(left) == toLower(right);
}

std::string joinList(const std::vector<std::string>& values, const std::string& fallback = "")
{
    if (values.empty())
        return fallback;

    std::ostringstream output;
    for (size_t i = 0; i < values.size(); ++i)
    {
        if (i > 0)
            output << ", ";
        output << values[i];
    }
    return output.str();
}

std::string displayKind(const std::string& kind)
{
    const std::string lowered = toLower(kind);
    if (lowered == "common")
        return "Common Commands";
    if (lowered == "module")
        return "Module Commands";
    if (lowered == "operator")
        return "Operator Commands";
    if (kind.empty())
        return "Commands";
    return kind + " Commands";
}

void appendArtifactFilter(std::ostringstream& output, const TeamServerCommandArtifactFilter& filter)
{
    std::vector<std::string> parts;
    if (!filter.category.empty())
        parts.push_back("category=" + filter.category);
    if (!filter.scope.empty())
        parts.push_back("scope=" + filter.scope);
    if (!filter.target.empty())
        parts.push_back("target=" + filter.target);
    if (!filter.platform.empty())
        parts.push_back("platform=" + filter.platform);
    if (!filter.arch.empty())
        parts.push_back("arch=" + filter.arch);
    if (!filter.runtime.empty())
        parts.push_back("runtime=" + filter.runtime);
    if (!filter.nameContains.empty())
        parts.push_back("name_contains=" + filter.nameContains);

    if (!parts.empty())
        output << "\n    Artifact filter: " << joinList(parts);
}

std::string argUsageToken(const TeamServerCommandArgSpec& arg)
{
    std::string token = arg.name.empty() ? "arg" : arg.name;
    if (arg.variadic)
        token += "...";
    if (arg.required)
        return "<" + token + ">";
    return "[" + token + "]";
}
}

TeamServerHelpService::TeamServerHelpService(
    std::shared_ptr<spdlog::logger> logger,
    std::vector<std::shared_ptr<Listener>>& listeners,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    CommonCommands& commonCommands,
    TeamServerCommandCatalog catalog)
    : m_logger(std::move(logger)),
      m_listeners(listeners),
      m_moduleCmd(moduleCmd),
      m_commonCommands(commonCommands),
      m_catalog(std::move(catalog))
{
}

grpc::Status TeamServerHelpService::getHelp(const teamserverapi::CommandHelpRequest& command, teamserverapi::CommandHelpResponse* commandResponse) const
{
    m_logger->trace("GetCommandHelp");

    const std::string input = command.command();
    const std::string beaconHash = command.session().beacon_hash();
    const std::string listenerHash = command.session().listener_hash();

    std::vector<std::string> splitedCmd;
    splitList(input, " ", splitedCmd);

    std::string output;
    if (!splitedCmd.empty() && splitedCmd[0] == HelpCmd)
    {
        if (splitedCmd.size() < 2)
            output = buildGeneralHelp(sessionPlatform(beaconHash, listenerHash));
        else
            output = buildSpecificHelp(splitedCmd[1]);
    }

    teamserverapi::CommandHelpResponse commandResponseTmp;
    commandResponseTmp.set_status(output.empty() ? teamserverapi::KO : teamserverapi::OK);
    commandResponseTmp.set_command(input);
    commandResponseTmp.set_help(output);
    if (output.empty())
        commandResponseTmp.set_message("No help available.");
    *commandResponse = commandResponseTmp;

    m_logger->trace("GetCommandHelp end");
    return grpc::Status::OK;
}

std::string TeamServerHelpService::sessionPlatform(const std::string& beaconHash, const std::string& listenerHash) const
{
    for (const std::shared_ptr<Listener>& listener : m_listeners)
    {
        if (!listener->isSessionExist(beaconHash, listenerHash))
            continue;

        std::shared_ptr<Session> session = listener->getSessionPtr(beaconHash, listenerHash);
        if (!session)
            return "";

        const std::string os = toLower(session->getOs());
        if (os.find("windows") != std::string::npos || os.rfind("win", 0) == 0)
            return "windows";
        if (os.find("linux") != std::string::npos)
            return "linux";
        if (os.find("mac") != std::string::npos || os.find("darwin") != std::string::npos)
            return "macos";
        return "";
    }

    return "";
}

std::string TeamServerHelpService::buildGeneralHelp(const std::string& platform) const
{
    TeamServerCommandQuery query;
    query.platform = platform;
    const std::vector<TeamServerCommandSpecRecord> commands = m_catalog.listCommands(query);
    if (commands.empty())
        return buildLegacyGeneralHelp(platform == "windows");

    std::map<std::string, std::vector<TeamServerCommandSpecRecord>> commandsByKind;
    for (const TeamServerCommandSpecRecord& command : commands)
        commandsByKind[command.kind].push_back(command);

    std::ostringstream output;
    output << "Available commands";
    if (!platform.empty())
        output << " for " << platform;
    output << ":\n";
    output << "Use help <command> for command-specific details.\n";

    const std::vector<std::string> preferredOrder = {"common", "module", "operator"};
    for (const std::string& kind : preferredOrder)
    {
        auto it = commandsByKind.find(kind);
        if (it == commandsByKind.end())
            continue;

        output << "\n- " << displayKind(kind) << ":\n";
        for (const TeamServerCommandSpecRecord& command : it->second)
        {
            output << "  " << command.name;
            if (!command.description.empty())
                output << " - " << command.description;
            output << "\n";
        }
        commandsByKind.erase(it);
    }

    for (const auto& [kind, remainingCommands] : commandsByKind)
    {
        output << "\n- " << displayKind(kind) << ":\n";
        for (const TeamServerCommandSpecRecord& command : remainingCommands)
        {
            output << "  " << command.name;
            if (!command.description.empty())
                output << " - " << command.description;
            output << "\n";
        }
    }

    return output.str();
}

std::string TeamServerHelpService::buildSpecificHelp(const std::string& instruction) const
{
    TeamServerCommandSpecRecord command;
    if (findCommandSpec(instruction, command))
        return formatCommandHelp(command);

    return buildLegacySpecificHelp(instruction);
}

bool TeamServerHelpService::findCommandSpec(const std::string& instruction, TeamServerCommandSpecRecord& command) const
{
    TeamServerCommandQuery query;
    query.nameContains = instruction;
    const std::vector<TeamServerCommandSpecRecord> candidates = m_catalog.listCommands(query);
    for (const TeamServerCommandSpecRecord& candidate : candidates)
    {
        if (equalsCaseInsensitive(candidate.name, instruction))
        {
            command = candidate;
            return true;
        }
    }
    return false;
}

std::string TeamServerHelpService::formatCommandHelp(const TeamServerCommandSpecRecord& command) const
{
    std::ostringstream output;
    output << command.name << "\n";
    if (!command.description.empty())
        output << command.description << "\n";

    output << "\nUsage: " << command.name;
    for (const TeamServerCommandArgSpec& arg : command.args)
        output << " " << argUsageToken(arg);
    output << "\n";

    output << "\nKind: " << (command.kind.empty() ? "unknown" : command.kind) << "\n";
    output << "Target: " << (command.target.empty() ? "unknown" : command.target) << "\n";
    output << "Requires session: " << (command.requiresSession ? "yes" : "no") << "\n";
    output << "Platforms: " << joinList(command.platforms, "any") << "\n";
    output << "Archs: " << joinList(command.archs, "any") << "\n";

    if (!command.args.empty())
    {
        output << "\nArguments:\n";
        for (const TeamServerCommandArgSpec& arg : command.args)
        {
            output << "  " << argUsageToken(arg) << " (" << (arg.type.empty() ? "text" : arg.type);
            output << (arg.required ? ", required" : ", optional");
            if (arg.variadic)
                output << ", variadic";
            output << ")";
            if (!arg.description.empty())
                output << " - " << arg.description;
            if (!arg.values.empty())
                output << "\n    Values: " << joinList(arg.values);
            if (arg.hasArtifactFilter)
                appendArtifactFilter(output, arg.artifactFilter);
            output << "\n";
        }
    }

    if (!command.examples.empty())
    {
        output << "\nExamples:\n";
        for (const std::string& example : command.examples)
            output << "  " << example << "\n";
    }

    return output.str();
}

std::string TeamServerHelpService::buildLegacyGeneralHelp(bool isWindows) const
{
    std::string output;
    output += "- Beacon Commands:\n";
    for (int i = 0; i < m_commonCommands.getNumberOfCommand(); i++)
    {
        output += "  ";
        output += m_commonCommands.getCommand(i);
        output += "\n";
    }

    if (isWindows)
        output += "\n- Modules Commands Windows:\n";
    else
        output += "\n- Modules Commands Linux:\n";

    for (const std::unique_ptr<ModuleCmd>& module : m_moduleCmd)
    {
        if (isWindows && (module->osCompatibility() & OS_WINDOWS))
        {
            output += "  ";
            output += module->getName();
            output += "\n";
        }
        else if (!isWindows && (module->osCompatibility() & OS_LINUX))
        {
            output += "  ";
            output += module->getName();
            output += "\n";
        }
    }

    return output;
}

std::string TeamServerHelpService::buildLegacySpecificHelp(const std::string& instruction) const
{
    std::string output;

    for (int i = 0; i < m_commonCommands.getNumberOfCommand(); i++)
    {
        if (instruction == m_commonCommands.getCommand(i))
        {
            output += m_commonCommands.getHelp(instruction);
            output += "\n";
        }
    }

    for (const std::unique_ptr<ModuleCmd>& module : m_moduleCmd)
    {
        if (instruction == module->getName())
        {
            output += module->getInfo();
            output += "\n";
        }
    }

    return output;
}
