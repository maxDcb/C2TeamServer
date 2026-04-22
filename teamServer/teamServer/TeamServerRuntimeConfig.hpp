#pragma once

#include <memory>
#include <string>

#include "nlohmann/json.hpp"

class CommonCommands;
class ModuleCmd;
namespace spdlog
{
class logger;
}

struct TeamServerRuntimeConfig
{
    std::string teamServerModulesDirectoryPath;
    std::string linuxModulesDirectoryPath;
    std::string windowsModulesDirectoryPath;
    std::string linuxBeaconsDirectoryPath;
    std::string windowsBeaconsDirectoryPath;
    std::string toolsDirectoryPath;
    std::string scriptsDirectoryPath;

    static TeamServerRuntimeConfig fromJson(const nlohmann::json& config);

    void validateDirectories(const std::shared_ptr<spdlog::logger>& logger) const;
    void configureCommonCommands(CommonCommands& commonCommands) const;
    void configureModule(ModuleCmd& module) const;
};
