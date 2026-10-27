#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <shared_mutex>
#include <vector>


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
        IpResolver ipResolver = {},
        std::shared_mutex* listenersMutex = nullptr);

    void getListenerInfo(const std::string& listenerReference,
        teamserverapi::ListenerInfoResponse* response) const;
    void getBeaconBinary(const std::string& listenerReference,
        const std::string& targetOs, const std::string& targetArch,
        teamserverapi::BeaconBinaryResponse* response) const;

    std::shared_ptr<Listener> resolvePrimaryListener(
        const std::string& listenerReference, std::string& error) const;
    std::string hostedArtifactUrl(
        const std::shared_ptr<Listener>& listener, const std::string& filename) const;

private:
    struct SecondaryListenerInfo
    {
        std::string hash;
        std::string type;
        std::string address;
        std::string port;
    };

    std::optional<SecondaryListenerInfo> resolveSecondaryListener(
        const std::string& listenerReference, std::string& error) const;
    std::string resolvePublicAddress(const std::shared_ptr<Listener>& listener) const;
    bool fillPrimaryListenerInfo(const std::shared_ptr<Listener>& listener,
        teamserverapi::ListenerInfoResponse* response) const;
    std::string resolveBeaconBinaryPath(
        const std::string& type,
        const std::string& targetOs,
        const std::string& targetArch,
        bool primaryListener) const;
    std::shared_ptr<spdlog::logger> m_logger;
    const nlohmann::json& m_config;
    TeamServerRuntimeConfig m_runtimeConfig;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    mutable std::shared_mutex m_localListenersMutex;
    std::shared_mutex* m_listenersMutex;
    IpResolver m_ipResolver;
};
