#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
#include "TeamServerRuntimeConfig.hpp"
#include "listener/Listener.hpp"
#include "nlohmann/json.hpp"
#include "spdlog/logger.h"

class TeamServerListenerArtifactService
{
public:
    using IpResolver = std::function<std::string(const std::string&)>;

    TeamServerListenerArtifactService(
        std::shared_ptr<spdlog::logger> logger,
        const nlohmann::json& config,
        TeamServerRuntimeConfig runtimeConfig,
        std::vector<std::shared_ptr<Listener>>& listeners,
        IpResolver ipResolver = {});

    bool canHandle(const std::string& instruction) const;
    grpc::Status handleCommand(
        const std::string& instruction,
        const std::vector<std::string>& splitedCmd,
        const teamserverapi::TerminalCommandRequest& command,
        teamserverapi::TerminalCommandResponse* response) const;

private:
    std::string resolvePublicAddress() const;
    std::string resolvePrimaryListenerInfo(const std::shared_ptr<Listener>& listener) const;
    std::string resolveBeaconBinaryPath(
        const std::string& type,
        const std::string& targetOs,
        const std::string& targetArch,
        bool primaryListener) const;
    grpc::Status handleInfoListener(
        const std::vector<std::string>& splitedCmd,
        const std::string& cmd,
        teamserverapi::TerminalCommandResponse* response) const;
    grpc::Status handleGetBeaconBinary(
        const std::vector<std::string>& splitedCmd,
        const std::string& cmd,
        teamserverapi::TerminalCommandResponse* response) const;

    std::shared_ptr<spdlog::logger> m_logger;
    const nlohmann::json& m_config;
    TeamServerRuntimeConfig m_runtimeConfig;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    IpResolver m_ipResolver;
};
