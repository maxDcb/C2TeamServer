#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
#include "TeamServerRuntimeConfig.hpp"
#include "listener/Listener.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "nlohmann/json.hpp"
#include "spdlog/logger.h"

class TeamServerTermLocalService
{
public:
    using ModuleLoader = std::function<std::vector<std::unique_ptr<ModuleCmd>>()>;

    TeamServerTermLocalService(
        std::shared_ptr<spdlog::logger> logger,
        const nlohmann::json& config,
        TeamServerRuntimeConfig runtimeConfig,
        std::vector<std::shared_ptr<Listener>>& listeners,
        nlohmann::json& credentials,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
        ModuleLoader moduleLoader = {});

    bool canHandle(const std::string& instruction) const;
    grpc::Status handleCommand(
        const std::string& instruction,
        const std::vector<std::string>& splitedCmd,
        const teamserverapi::TerminalCommandRequest& command,
        teamserverapi::TerminalCommandResponse* response);

private:
    std::vector<std::unique_ptr<ModuleCmd>> loadModulesFromDisk() const;
    bool isValidFilename(const std::string& filename) const;
    std::string resolveDownloadFolderForListener(const std::string& listenerHash) const;
    grpc::Status handlePutIntoUploadDir(
        const std::vector<std::string>& splitedCmd,
        const teamserverapi::TerminalCommandRequest& command,
        teamserverapi::TerminalCommandResponse* response);
    grpc::Status handleBatcaveUpload(
        const std::vector<std::string>& splitedCmd,
        const teamserverapi::TerminalCommandRequest& command,
        teamserverapi::TerminalCommandResponse* response);
    grpc::Status handleAddCredential(
        const teamserverapi::TerminalCommandRequest& command,
        teamserverapi::TerminalCommandResponse* response);
    grpc::Status handleGetCredential(teamserverapi::TerminalCommandResponse* response);
    grpc::Status handleReloadModules(teamserverapi::TerminalCommandResponse* response);

    std::shared_ptr<spdlog::logger> m_logger;
    const nlohmann::json& m_config;
    TeamServerRuntimeConfig m_runtimeConfig;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    nlohmann::json& m_credentials;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    ModuleLoader m_moduleLoader;
};
