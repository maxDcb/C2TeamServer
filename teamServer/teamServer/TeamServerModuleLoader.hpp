#pragma once

#include <memory>
#include <vector>

#include "TeamServerRuntimeConfig.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerModuleLoader
{
public:
    TeamServerModuleLoader(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerRuntimeConfig runtimeConfig);

    std::vector<std::unique_ptr<ModuleCmd>> loadModules() const;

private:
    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerRuntimeConfig m_runtimeConfig;
};
