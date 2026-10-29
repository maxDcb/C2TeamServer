#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "TeamServerRuntimeConfig.hpp"
#include "TeamServerOperationResult.hpp"
#include "listener/Listener.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "nlohmann/json.hpp"
#include "spdlog/logger.h"

class TeamServerListenerArtifactService;

class TeamServerLocalOperationService
{
public:
    using ModuleLoader = std::function<std::vector<std::unique_ptr<ModuleCmd>>()>;

    TeamServerLocalOperationService(
        std::shared_ptr<spdlog::logger> logger,
        const nlohmann::json& config,
        TeamServerRuntimeConfig runtimeConfig,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
        ModuleLoader moduleLoader = {},
        TeamServerListenerArtifactService* listenerArtifactService = nullptr,
        std::shared_mutex* moduleCmdMutex = nullptr);

    TeamServerOperationResult hostArtifact(const std::string& listenerHash,
        const std::string& artifactReference, const std::string& hostedFilename = {});
    TeamServerOperationResult reloadModules();
    TeamServerOperationResult uploadListenerFile(const std::string& listenerHash,
        const std::string& filename, const std::string& data);
    TeamServerOperationResult installTool(const std::string& filename, const std::string& data);
    TeamServerOperationResult installToolBundle(const std::vector<std::pair<std::string, std::string>>& files);

private:
    std::vector<std::unique_ptr<ModuleCmd>> loadModulesFromDisk() const;
    void recoverBatcaveBundles();
    bool isValidFilename(const std::string& filename) const;
    std::string resolveDownloadFolderForListener(
        const std::string& listenerHash, std::shared_ptr<Listener>& listener, std::string& error) const;
    std::shared_ptr<spdlog::logger> m_logger;
    const nlohmann::json& m_config;
    TeamServerRuntimeConfig m_runtimeConfig;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    ModuleLoader m_moduleLoader;
    TeamServerListenerArtifactService* m_listenerArtifactService;
    mutable std::shared_mutex m_localModuleCmdMutex;
    std::shared_mutex* m_moduleCmdMutex;
    std::mutex m_uploadMutex;
};
