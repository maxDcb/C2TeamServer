#include "TeamServerRuntimeConfig.hpp"

#include <algorithm>
#include <cctype>
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
    if (auto it = config.find("DefaultWindowsArch"); it != config.end() && it->is_string())
        runtimeConfig.defaultWindowsArch = normalizeWindowsArch(it->get<std::string>());
    if (auto it = config.find("SupportedWindowsArchs"); it != config.end() && it->is_array())
    {
        runtimeConfig.supportedWindowsArchs.clear();
        for (const auto& arch : *it)
        {
            if (!arch.is_string())
                continue;
            std::string normalized = normalizeWindowsArch(arch.get<std::string>());
            if (!normalized.empty()
                && std::find(runtimeConfig.supportedWindowsArchs.begin(), runtimeConfig.supportedWindowsArchs.end(), normalized)
                    == runtimeConfig.supportedWindowsArchs.end())
            {
                runtimeConfig.supportedWindowsArchs.push_back(normalized);
            }
        }
        if (runtimeConfig.supportedWindowsArchs.empty())
            runtimeConfig.supportedWindowsArchs = {"x86", "x64", "arm64"};
    }
    return runtimeConfig;
}

std::string TeamServerRuntimeConfig::normalizeWindowsArch(const std::string& arch)
{
    std::string lowered = arch;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });

    if (lowered == "x64" || lowered == "amd64" || lowered == "x86_64")
        return "x64";
    if (lowered == "x86" || lowered == "i386" || lowered == "i686")
        return "x86";
    if (lowered == "arm64" || lowered == "aarch64")
        return "arm64";
    return "";
}

void TeamServerRuntimeConfig::validateDirectories(const std::shared_ptr<spdlog::logger>& logger) const
{
    if (!fs::exists(teamServerModulesDirectoryPath))
        logger->error("TeamServer modules directory path don't exist: {0}", teamServerModulesDirectoryPath.c_str());

    if (!fs::exists(linuxModulesDirectoryPath))
        logger->error("Linux modules directory path don't exist: {0}", linuxModulesDirectoryPath.c_str());

    if (!fs::exists(windowsModulesDirectoryPath))
        logger->error("Windows modules directory path don't exist: {0}", windowsModulesDirectoryPath.c_str());
    else
    {
        for (const auto& arch : supportedWindowsArchs)
        {
            fs::path archPath = fs::path(windowsModulesDirectoryPath) / arch;
            if (!fs::exists(archPath))
                logger->error("Windows modules architecture directory path don't exist: {0}", archPath.string().c_str());
        }
    }

    if (!fs::exists(linuxBeaconsDirectoryPath))
        logger->error("Linux beacon directory path don't exist: {0}", linuxBeaconsDirectoryPath.c_str());

    if (!fs::exists(windowsBeaconsDirectoryPath))
        logger->error("Windows beacon directory path don't exist: {0}", windowsBeaconsDirectoryPath.c_str());
    else
    {
        for (const auto& arch : supportedWindowsArchs)
        {
            fs::path archPath = fs::path(windowsBeaconsDirectoryPath) / arch;
            if (!fs::exists(archPath))
                logger->error("Windows beacon architecture directory path don't exist: {0}", archPath.string().c_str());
        }
    }

    if (TeamServerRuntimeConfig::normalizeWindowsArch(defaultWindowsArch).empty())
        logger->error("DefaultWindowsArch is not supported: {0}", defaultWindowsArch.c_str());
    else if (std::find(supportedWindowsArchs.begin(), supportedWindowsArchs.end(), defaultWindowsArch) == supportedWindowsArchs.end())
        logger->error("DefaultWindowsArch is not listed in SupportedWindowsArchs: {0}", defaultWindowsArch.c_str());

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
