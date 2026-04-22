#include "TeamServerHelpService.hpp"

#include <string>
#include <vector>

#include "modules/ModuleCmd/Common.hpp"

namespace
{
const std::string HelpCmd = "help";
}

TeamServerHelpService::TeamServerHelpService(
    std::shared_ptr<spdlog::logger> logger,
    std::vector<std::shared_ptr<Listener>>& listeners,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    CommonCommands& commonCommands)
    : m_logger(std::move(logger)),
      m_listeners(listeners),
      m_moduleCmd(moduleCmd),
      m_commonCommands(commonCommands)
{
}

grpc::Status TeamServerHelpService::getHelp(const teamserverapi::Command& command, teamserverapi::CommandResponse* commandResponse) const
{
    m_logger->trace("GetHelp");

    const std::string input = command.cmd();
    const std::string beaconHash = command.beaconhash();
    const std::string listenerHash = command.listenerhash();

    std::vector<std::string> splitedCmd;
    splitList(input, " ", splitedCmd);

    std::string output;
    if (!splitedCmd.empty() && splitedCmd[0] == HelpCmd)
    {
        if (splitedCmd.size() < 2)
            output = buildGeneralHelp(isWindowsSession(beaconHash, listenerHash));
        else
            output = buildSpecificHelp(splitedCmd[1]);
    }

    teamserverapi::CommandResponse commandResponseTmp;
    commandResponseTmp.set_cmd(input);
    commandResponseTmp.set_response(output);
    *commandResponse = commandResponseTmp;

    m_logger->trace("GetHelp end");
    return grpc::Status::OK;
}

bool TeamServerHelpService::isWindowsSession(const std::string& beaconHash, const std::string& listenerHash) const
{
    for (const std::shared_ptr<Listener>& listener : m_listeners)
    {
        if (!listener->isSessionExist(beaconHash, listenerHash))
            continue;

        std::shared_ptr<Session> session = listener->getSessionPtr(beaconHash, listenerHash);
        return session && session->getOs() == "Windows";
    }

    return false;
}

std::string TeamServerHelpService::buildGeneralHelp(bool isWindows) const
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

std::string TeamServerHelpService::buildSpecificHelp(const std::string& instruction) const
{
    std::string output;
    bool isModuleFound = false;

    for (int i = 0; i < m_commonCommands.getNumberOfCommand(); i++)
    {
        if (instruction == m_commonCommands.getCommand(i))
        {
            output += m_commonCommands.getHelp(instruction);
            output += "\n";
            isModuleFound = true;
        }
    }

    for (const std::unique_ptr<ModuleCmd>& module : m_moduleCmd)
    {
        if (instruction == module->getName())
        {
            output += module->getInfo();
            output += "\n";
            isModuleFound = true;
        }
    }

    if (!isModuleFound)
    {
        output += "Module ";
        output += instruction;
        output += " not found.\n";
    }

    return output;
}
