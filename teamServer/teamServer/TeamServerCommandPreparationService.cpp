#include "TeamServerCommandPreparationService.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <utility>

#include "TeamServerRuntimeConfig.hpp"

namespace fs = std::filesystem;

TeamServerCommandPreparationService::TeamServerCommandPreparationService(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerRuntimeConfig runtimeConfig,
    CommonCommands& commonCommands,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers)
    : m_logger(std::move(logger)),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_commonCommands(commonCommands),
      m_moduleCmd(moduleCmd),
      m_preparers(std::move(preparers))
{
}

void TeamServerCommandPreparationService::splitInputCmd(const std::string& input, std::vector<std::string>& splitedList) const
{
    std::string tmp;
    for (size_t i = 0; i < input.size(); i++)
    {
        const char c = input[i];
        if (c == ' ')
        {
            if (!tmp.empty())
                splitedList.push_back(tmp);
            tmp.clear();
        }
        else if (c == '\'')
        {
            i++;
            while (input[i] != '\'')
            {
                tmp += input[i];
                i++;
            }
        }
        else
        {
            tmp += c;
        }
    }

    if (!tmp.empty())
        splitedList.push_back(tmp);
}

std::string TeamServerCommandPreparationService::toLower(const std::string& str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c)
        { return static_cast<char>(std::tolower(c)); });
    return result;
}

int TeamServerCommandPreparationService::prepareMessage(
    const std::string& input,
    C2Message& c2Message,
    bool isWindows,
    const std::string& windowsArch) const
{
    m_logger->trace("prepMsg");

    std::vector<std::string> splitedCmd;
    splitInputCmd(input, splitedCmd);
    if (splitedCmd.empty())
        return 0;

    int res = 0;
    const std::string instruction = splitedCmd[0];
    std::string normalizedTargetArch = isWindows
        ? TeamServerRuntimeConfig::normalizeWindowsArch(windowsArch)
        : TeamServerRuntimeConfig::normalizeLinuxArch(windowsArch);
    if (normalizedTargetArch.empty())
        normalizedTargetArch = isWindows ? m_runtimeConfig.defaultWindowsArch : m_runtimeConfig.defaultLinuxArch;
    bool isModuleFound = false;

    TeamServerCommandPreparerContext preparerContext;
    preparerContext.input = input;
    preparerContext.tokens = splitedCmd;
    preparerContext.isWindows = isWindows;
    preparerContext.windowsArch = normalizedTargetArch;
    for (const auto& preparer : m_preparers)
    {
        if (!preparer || !preparer->canPrepare(instruction))
            continue;
        TeamServerCommandPreparerResult prepared = preparer->prepare(preparerContext, c2Message);
        if (prepared.handled)
        {
            m_logger->trace("prepMsg end");
            return prepared.status;
        }
    }

    for (int i = 0; i < m_commonCommands.getNumberOfCommand(); i++)
    {
        if (instruction != m_commonCommands.getCommand(i))
            continue;

        if (instruction == LoadModuleInstruction && splitedCmd.size() == 2)
        {
            std::string param = splitedCmd[1];
            if (param == "ls")
                param = "listDirectory";
            else if (param == "cd")
                param = "changeDirectory";
            else if (param == "ps")
                param = "listProcesses";
            else if (param == "pwd")
                param = "printWorkingDirectory";

            if (!((param.size() >= 3 && param.substr(param.size() - 3) == ".so")
                    || (param.size() >= 4 && param.substr(param.size() - 3) == ".dll")))
            {
                m_logger->debug("Translate instruction to module name to load in {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
                try
                {
                    for (const auto& entry : fs::recursive_directory_iterator(m_runtimeConfig.teamServerModulesDirectoryPath))
                    {
                        if (!fs::is_regular_file(entry.path()) || entry.path().extension() != ".so")
                            continue;

                        std::string moduleName = entry.path().filename();
                        moduleName = moduleName.substr(3);
                        moduleName = moduleName.substr(0, moduleName.length() - 3);

                        if (toLower(param) == toLower(moduleName))
                        {
                            splitedCmd[1] = isWindows ? moduleName + ".dll" : entry.path().filename().string();
                            m_logger->debug("Found module to load {0}", splitedCmd[1]);
                        }
                    }
                }
                catch (const fs::filesystem_error&)
                {
                    m_logger->warn("Error accessing module directory");
                }
            }
        }

        m_logger->debug("Preparing common command={0} isWindows={1} targetArch={2}", instruction, isWindows, normalizedTargetArch);
        res = m_commonCommands.init(splitedCmd, c2Message, isWindows, normalizedTargetArch);
        if (instruction == LoadModuleInstruction && res == 0)
        {
            m_logger->info(
                "loadModule resolved module input={0} isWindows={1} targetArch={2} path={3}",
                splitedCmd.size() > 1 ? splitedCmd[1] : "",
                isWindows,
                normalizedTargetArch,
                m_commonCommands.getLastResolvedModulePath());
        }
        isModuleFound = true;
    }

    for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
    {
        if (toLower(instruction) != toLower((*it)->getName()))
            continue;

        splitedCmd[0] = (*it)->getName();
        (*it)->setWindowsArch(normalizedTargetArch);
        m_logger->debug("Preparing module command={0} isWindows={1} targetArch={2}", splitedCmd[0], isWindows, normalizedTargetArch);
        res = (*it)->init(splitedCmd, c2Message);
        isModuleFound = true;
    }

    if (!isModuleFound)
    {
        m_logger->warn("Module {0} not found.", instruction);
        c2Message.set_returnvalue("Module " + instruction + " not found.");
        res = -1;
    }

    m_logger->trace("prepMsg end");
    return res;
}
