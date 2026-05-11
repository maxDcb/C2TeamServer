#include "TeamServerRuntimeConfig.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>

#include "modules/ModuleCmd/CommonCommand.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

namespace fs = std::filesystem;

namespace
{
std::string ensureTrailingSeparator(std::string path)
{
    if (!path.empty() && path.back() != '/' && path.back() != '\\')
        path += '/';
    return path;
}

std::string jsonString(const nlohmann::json& config, const char* key, const std::string& fallback)
{
    auto it = config.find(key);
    if (it == config.end() || !it->is_string())
        return fallback;
    return it->get<std::string>();
}

std::string childPath(const std::string& root, const std::string& child)
{
    return ensureTrailingSeparator((fs::path(root) / child).string());
}

void parseArchList(
    const nlohmann::json& config,
    const char* key,
    std::vector<std::string>& archs,
    const std::vector<std::string>& fallback,
    std::string (*normalizer)(const std::string&))
{
    auto it = config.find(key);
    if (it == config.end() || !it->is_array())
        return;

    archs.clear();
    for (const auto& arch : *it)
    {
        if (!arch.is_string())
            continue;
        std::string normalized = normalizer(arch.get<std::string>());
        if (!normalized.empty() && std::find(archs.begin(), archs.end(), normalized) == archs.end())
            archs.push_back(normalized);
    }
    if (archs.empty())
        archs = fallback;
}

void ensureDirectory(const fs::path& path, const char* label, const std::shared_ptr<spdlog::logger>& logger)
{
    std::error_code ec;
    if (fs::exists(path, ec) && fs::is_directory(path, ec))
        return;

    fs::create_directories(path, ec);
    if (ec)
        logger->error("{0} directory path don't exist and could not be created: {1}", label, path.string().c_str());
}

void ensurePlatformArchDirectories(
    const fs::path& root,
    const std::string& platformDirectory,
    const std::vector<std::string>& archs,
    const std::shared_ptr<spdlog::logger>& logger)
{
    for (const std::string& arch : archs)
        ensureDirectory(root / platformDirectory / arch, platformDirectory.c_str(), logger);
}
} // namespace

TeamServerRuntimeConfig TeamServerRuntimeConfig::fromJson(const nlohmann::json& config)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.releaseRoot = ensureTrailingSeparator(jsonString(config, "ReleaseRoot", runtimeConfig.releaseRoot));
    runtimeConfig.dataRoot = ensureTrailingSeparator(jsonString(config, "DataRoot", runtimeConfig.dataRoot));

    runtimeConfig.teamServerModulesDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "TeamServerModulesDirectoryPath", childPath(runtimeConfig.releaseRoot, "TeamServerModules")));
    runtimeConfig.linuxModulesDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "LinuxModulesDirectoryPath", childPath(runtimeConfig.releaseRoot, "LinuxModules")));
    runtimeConfig.windowsModulesDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "WindowsModulesDirectoryPath", childPath(runtimeConfig.releaseRoot, "WindowsModules")));
    runtimeConfig.linuxBeaconsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "LinuxBeaconsDirectoryPath", childPath(runtimeConfig.releaseRoot, "LinuxBeacons")));
    runtimeConfig.windowsBeaconsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "WindowsBeaconsDirectoryPath", childPath(runtimeConfig.releaseRoot, "WindowsBeacons")));
    runtimeConfig.commandSpecsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "CommandSpecsDirectoryPath", childPath(runtimeConfig.releaseRoot, "CommandSpecs")));

    runtimeConfig.toolsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "ToolsDirectoryPath", childPath(runtimeConfig.dataRoot, "Tools")));
    runtimeConfig.scriptsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "ScriptsDirectoryPath", childPath(runtimeConfig.dataRoot, "Scripts")));
    runtimeConfig.uploadedArtifactsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "UploadedArtifactsDirectoryPath", childPath(runtimeConfig.dataRoot, "UploadedArtifacts")));
    runtimeConfig.generatedArtifactsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "GeneratedArtifactsDirectoryPath", childPath(runtimeConfig.dataRoot, "GeneratedArtifacts")));
    runtimeConfig.hostedArtifactsDirectoryPath = ensureTrailingSeparator(
        jsonString(config, "HostedArtifactsDirectoryPath", childPath(runtimeConfig.generatedArtifactsDirectoryPath, "hosted")));

    if (auto it = config.find("DefaultWindowsArch"); it != config.end() && it->is_string())
        runtimeConfig.defaultWindowsArch = normalizeWindowsArch(it->get<std::string>());
    if (auto it = config.find("DefaultLinuxArch"); it != config.end() && it->is_string())
        runtimeConfig.defaultLinuxArch = normalizeLinuxArch(it->get<std::string>());
    parseArchList(config, "SupportedWindowsArchs", runtimeConfig.supportedWindowsArchs, {"x86", "x64", "arm64"}, normalizeWindowsArch);
    parseArchList(config, "SupportedLinuxArchs", runtimeConfig.supportedLinuxArchs, {"x64"}, normalizeLinuxArch);
    return runtimeConfig;
}

namespace
{
std::string normalizeCpuArch(const std::string& arch)
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
} // namespace

std::string TeamServerRuntimeConfig::normalizeWindowsArch(const std::string& arch)
{
    return normalizeCpuArch(arch);
}

std::string TeamServerRuntimeConfig::normalizeLinuxArch(const std::string& arch)
{
    return normalizeCpuArch(arch);
}

void TeamServerRuntimeConfig::validateDirectories(const std::shared_ptr<spdlog::logger>& logger) const
{
    if (!fs::exists(teamServerModulesDirectoryPath))
        logger->error("TeamServer modules directory path don't exist: {0}", teamServerModulesDirectoryPath.c_str());

    if (!fs::exists(linuxModulesDirectoryPath))
        logger->error("Linux modules directory path don't exist: {0}", linuxModulesDirectoryPath.c_str());
    else
    {
        for (const auto& arch : supportedLinuxArchs)
        {
            fs::path archPath = fs::path(linuxModulesDirectoryPath) / arch;
            if (!fs::exists(archPath))
                logger->error("Linux modules architecture directory path don't exist: {0}", archPath.string().c_str());
        }
    }

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
    else
    {
        for (const auto& arch : supportedLinuxArchs)
        {
            fs::path archPath = fs::path(linuxBeaconsDirectoryPath) / arch;
            if (!fs::exists(archPath))
                logger->error("Linux beacon architecture directory path don't exist: {0}", archPath.string().c_str());
        }
    }

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

    if (TeamServerRuntimeConfig::normalizeLinuxArch(defaultLinuxArch).empty())
        logger->error("DefaultLinuxArch is not supported: {0}", defaultLinuxArch.c_str());
    else if (std::find(supportedLinuxArchs.begin(), supportedLinuxArchs.end(), defaultLinuxArch) == supportedLinuxArchs.end())
        logger->error("DefaultLinuxArch is not listed in SupportedLinuxArchs: {0}", defaultLinuxArch.c_str());

    ensureDirectory(toolsDirectoryPath, "Tools", logger);
    ensurePlatformArchDirectories(toolsDirectoryPath, "Windows", supportedWindowsArchs, logger);
    ensurePlatformArchDirectories(toolsDirectoryPath, "Linux", supportedLinuxArchs, logger);

    ensureDirectory(scriptsDirectoryPath, "Scripts", logger);
    ensureDirectory(fs::path(scriptsDirectoryPath) / "Windows", "Windows scripts", logger);
    ensureDirectory(fs::path(scriptsDirectoryPath) / "Linux", "Linux scripts", logger);

    ensureDirectory(uploadedArtifactsDirectoryPath, "Uploaded artifacts", logger);
    ensureDirectory(fs::path(uploadedArtifactsDirectoryPath) / "Any" / "any", "Any uploaded artifacts", logger);
    ensurePlatformArchDirectories(uploadedArtifactsDirectoryPath, "Windows", supportedWindowsArchs, logger);
    ensurePlatformArchDirectories(uploadedArtifactsDirectoryPath, "Linux", supportedLinuxArchs, logger);

    ensureDirectory(generatedArtifactsDirectoryPath, "Generated artifacts", logger);
    ensureDirectory(hostedArtifactsDirectoryPath, "Hosted artifacts", logger);

    if (!fs::exists(commandSpecsDirectoryPath))
        logger->error("Command specs directory path don't exist: {0}", commandSpecsDirectoryPath.c_str());
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
