#pragma once

#include <memory>
#include <string>
#include <vector>

#include "modules/ModuleCmd/CommonCommand.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerCommandPreparationService
{
public:
    TeamServerCommandPreparationService(
        std::shared_ptr<spdlog::logger> logger,
        std::string teamServerModulesDirectoryPath,
        CommonCommands& commonCommands,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd);

    int prepareMessage(const std::string& input, C2Message& c2Message, bool isWindows = true) const;

private:
    static std::string toLower(const std::string& str);
    void splitInputCmd(const std::string& input, std::vector<std::string>& splitedList) const;

    std::shared_ptr<spdlog::logger> m_logger;
    std::string m_teamServerModulesDirectoryPath;
    CommonCommands& m_commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
};
