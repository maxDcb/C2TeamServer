#pragma once

#include <memory>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

class CommonCommands;
class ModuleCmd;
namespace spdlog
{
class logger;
}

struct TeamServerRuntimeConfig
{
    std::string releaseRoot = "../";
    std::string dataRoot = "../data/";
    std::string teamServerModulesDirectoryPath;
    std::string linuxModulesDirectoryPath;
    std::string windowsModulesDirectoryPath;
    std::string linuxBeaconsDirectoryPath;
    std::string windowsBeaconsDirectoryPath;
    std::string toolsDirectoryPath;
    std::string scriptsDirectoryPath;
    std::string commandSpecsDirectoryPath = "../CommandSpecs/";
    std::string uploadedArtifactsDirectoryPath = "../data/UploadedArtifacts/";
    std::string generatedArtifactsDirectoryPath = "../data/GeneratedArtifacts/";
    std::string hostedArtifactsDirectoryPath = "../data/GeneratedArtifacts/hosted/";
    std::string defaultWindowsArch = "x64";
    std::string defaultLinuxArch = "x64";
    std::vector<std::string> supportedWindowsArchs = {"x86", "x64", "arm64"};
    std::vector<std::string> supportedLinuxArchs = {"x64"};

    static TeamServerRuntimeConfig fromJson(const nlohmann::json& config);
    static std::string normalizeWindowsArch(const std::string& arch);
    static std::string normalizeLinuxArch(const std::string& arch);

    void validateDirectories(const std::shared_ptr<spdlog::logger>& logger) const;
    void configureCommonCommands(CommonCommands& commonCommands) const;
    void configureModule(ModuleCmd& module) const;
};
