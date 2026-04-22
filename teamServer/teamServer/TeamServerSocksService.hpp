#pragma once

#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
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
        ServerFactory serverFactory = {});

    ~TeamServerSocksService();

    grpc::Status handleCommand(const std::vector<std::string>& splitedCmd, teamserverapi::TermCommand* response);
    void shutdown();
    void run();

    bool isRunning() const;
    bool isBound() const;

private:
    std::shared_ptr<Session> findSessionByPrefix(const std::string& beaconHashPrefix, std::shared_ptr<Listener>& listener) const;
    std::unique_ptr<ISocksServer> createServer(int port);
    bool portInUse(unsigned short port) const;
    void unbindThread();
    void stopServer();

    std::shared_ptr<spdlog::logger> m_logger;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    PortInUseCallback m_portInUse;
    ServerFactory m_serverFactory;

    bool m_isSocksServerRunning;
    bool m_isSocksServerBinded;
    std::unique_ptr<ISocksServer> m_socksServer;
    std::unique_ptr<std::thread> m_socksThread;
    std::shared_ptr<Listener> m_socksListener;
    std::shared_ptr<Session> m_socksSession;
};
