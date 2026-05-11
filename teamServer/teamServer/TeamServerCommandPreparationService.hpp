#pragma once

#include <memory>
#include <string>
#include <vector>

#include "TeamServerCommandPreparer.hpp"
#include "TeamServerRuntimeConfig.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerCommandPreparationService
{
public:
    TeamServerCommandPreparationService(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerRuntimeConfig runtimeConfig,
        CommonCommands& commonCommands,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
        std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers = {});

    int prepareMessage(
        const std::string& input,
        C2Message& c2Message,
        bool isWindows = true,
        const std::string& windowsArch = "x64") const;

private:
    static std::string toLower(const std::string& str);
    void splitInputCmd(const std::string& input, std::vector<std::string>& splitedList) const;

    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerRuntimeConfig m_runtimeConfig;
    CommonCommands& m_commonCommands;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> m_preparers;
};
