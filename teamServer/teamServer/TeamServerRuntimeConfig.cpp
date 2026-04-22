#include "TeamServerRuntimeConfig.hpp"

#include <filesystem>

#include "modules/ModuleCmd/CommonCommand.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

namespace fs = std::filesystem;

TeamServerRuntimeConfig TeamServerRuntimeConfig::fromJson(const nlohmann::json& config)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.teamServerModulesDirectoryPath = config["TeamServerModulesDirectoryPath"].get<std::string>();
    runtimeConfig.linuxModulesDirectoryPath = config["LinuxModulesDirectoryPath"].get<std::string>();
    runtimeConfig.windowsModulesDirectoryPath = config["WindowsModulesDirectoryPath"].get<std::string>();
    runtimeConfig.linuxBeaconsDirectoryPath = config["LinuxBeaconsDirectoryPath"].get<std::string>();
    runtimeConfig.windowsBeaconsDirectoryPath = config["WindowsBeaconsDirectoryPath"].get<std::string>();
    runtimeConfig.toolsDirectoryPath = config["ToolsDirectoryPath"].get<std::string>();
    runtimeConfig.scriptsDirectoryPath = config["ScriptsDirectoryPath"].get<std::string>();
    return runtimeConfig;
}

void TeamServerRuntimeConfig::validateDirectories(const std::shared_ptr<spdlog::logger>& logger) const
{
    if (!fs::exists(teamServerModulesDirectoryPath))
        logger->error("TeamServer modules directory path don't exist: {0}", teamServerModulesDirectoryPath.c_str());

    if (!fs::exists(linuxModulesDirectoryPath))
        logger->error("Linux modules directory path don't exist: {0}", linuxModulesDirectoryPath.c_str());

    if (!fs::exists(windowsModulesDirectoryPath))
        logger->error("Windows modules directory path don't exist: {0}", windowsModulesDirectoryPath.c_str());

    if (!fs::exists(linuxBeaconsDirectoryPath))
        logger->error("Linux beacon directory path don't exist: {0}", linuxBeaconsDirectoryPath.c_str());

    if (!fs::exists(windowsBeaconsDirectoryPath))
        logger->error("Windows beacon directory path don't exist: {0}", windowsBeaconsDirectoryPath.c_str());

    if (!fs::exists(toolsDirectoryPath))
        logger->error("Tools directory path don't exist: {0}", toolsDirectoryPath.c_str());

    if (!fs::exists(scriptsDirectoryPath))
        logger->error("Script directory path don't exist: {0}", scriptsDirectoryPath.c_str());
}

void TeamServerRuntimeConfig::configureCommonCommands(CommonCommands& commonCommands) const
{
    commonCommands.setDirectories(
        teamServerModulesDirectoryPath,
        linuxModulesDirectoryPath,
        windowsModulesDirectoryPath,
        linuxBeaconsDirectoryPath,
        windowsBeaconsDirectoryPath,
        toolsDirectoryPath,
        scriptsDirectoryPath);
}

void TeamServerRuntimeConfig::configureModule(ModuleCmd& module) const
{
    module.setDirectories(
        teamServerModulesDirectoryPath,
        linuxModulesDirectoryPath,
        windowsModulesDirectoryPath,
        linuxBeaconsDirectoryPath,
        windowsBeaconsDirectoryPath,
        toolsDirectoryPath,
        scriptsDirectoryPath);
}
