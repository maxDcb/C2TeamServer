#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "TeamServerOperationResult.hpp"
#include "SocksServer.hpp"
#include "listener/Listener.hpp"
#include "spdlog/logger.h"

class ISocksServer
{
public:
    virtual ~ISocksServer() = default;
    virtual void launch() = 0;
    virtual void stop() = 0;
    virtual void cleanTunnel() = 0;
    virtual bool isServerStoped() const = 0;
    virtual bool isServerLaunched() const = 0;
    virtual std::size_t tunnelCount() = 0;
    virtual SocksTunnelServer* getTunnel(std::size_t idx) = 0;
    virtual void resetTunnel(std::size_t idx) = 0;
};

class TeamServerSocksService
{
public:
    using PortInUseCallback = std::function<bool(unsigned short)>;
    using ServerFactory = std::function<std::unique_ptr<ISocksServer>(int)>;

    TeamServerSocksService(
        std::shared_ptr<spdlog::logger> logger,
        std::vector<std::shared_ptr<Listener>>& listeners,
        PortInUseCallback portInUse = {},
        ServerFactory serverFactory = {},
        std::chrono::milliseconds tunnelResponseTimeout = std::chrono::minutes(2),
        std::shared_mutex* listenersMutex = nullptr);

    ~TeamServerSocksService();

    TeamServerOperationResult control(const std::string& action, const std::string& beaconHash = {});
    void shutdown();
    void run();

    bool isRunning() const;
    bool isBound() const;

private:
    std::shared_ptr<Session> findSessionByPrefix(const std::string& beaconHashPrefix, std::shared_ptr<Listener>& listener) const;
    std::unique_ptr<ISocksServer> createServer(int port);
    bool portInUse(unsigned short port) const;
    bool queueToBoundSession(const C2Message& message);
    bool responseMatchesTunnel(const C2Message& message, int id) const;
    void markTunnelPending(int id);
    bool tunnelResponseTimedOut(int id) const;
    void clearTunnelPending(int id);
    void resetTunnel(std::size_t index, int id);
    void requestRemoteStop();
    void resetAllTunnels();
    void unbindThread();
    void stopServer();

    std::shared_ptr<spdlog::logger> m_logger;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    mutable std::shared_mutex m_localListenersMutex;
    std::shared_mutex* m_listenersMutex;
    PortInUseCallback m_portInUse;
    ServerFactory m_serverFactory;
    std::chrono::milliseconds m_tunnelResponseTimeout;

    mutable std::mutex m_controlMutex;
    bool m_isSocksServerRunning;
    std::atomic_bool m_isSocksServerBinded;
    std::unique_ptr<ISocksServer> m_socksServer;
    std::unique_ptr<std::thread> m_socksThread;
    std::shared_ptr<Listener> m_socksListener;
    std::shared_ptr<Session> m_socksSession;
    std::string m_routeGeneration;
    std::unordered_map<int, std::chrono::steady_clock::time_point> m_pendingTunnels;
};
