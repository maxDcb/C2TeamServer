#include "TeamServerSocksService.hpp"

#include <chrono>

#include "modules/ModuleCmd/CommonCommand.hpp"

namespace
{
class SocksServerAdapter final : public ISocksServer
{
public:
    explicit SocksServerAdapter(int port)
        : m_server(std::make_unique<SocksServer>(port))
    {
    }

    void launch() override
    {
        m_server->launch();
    }

    void stop() override
    {
        m_server->stop();
    }

    void cleanTunnel() override
    {
        m_server->cleanTunnel();
    }

    bool isServerStoped() const override
    {
        return m_server->isServerStoped();
    }

    bool isServerLaunched() const override
    {
        return m_server->isServerLaunched();
    }

    std::size_t tunnelCount() override
    {
        return m_server->tunnelCount();
    }

    SocksTunnelServer* getTunnel(std::size_t idx) override
    {
        return m_server->getTunnel(idx);
    }

    void resetTunnel(std::size_t idx) override
    {
        m_server->resetTunnel(idx);
    }

private:
    std::unique_ptr<SocksServer> m_server;
};

bool defaultPortInUse(unsigned short)
{
    return false;
}

std::string joinCommand(const std::vector<std::string>& parts)
{
    std::string command;
    for (const auto& part : parts)
    {
        if (!command.empty())
            command += " ";
        command += part;
    }
    return command;
}

void setTerminalOk(teamserverapi::TerminalCommandResponse* response, const std::string& result)
{
    response->set_status(teamserverapi::OK);
    response->set_result(result);
    response->clear_message();
}

void setTerminalError(teamserverapi::TerminalCommandResponse* response, const std::string& result)
{
    response->set_status(teamserverapi::KO);
    response->set_result(result);
    response->set_message(result);
}
} // namespace

TeamServerSocksService::TeamServerSocksService(
    std::shared_ptr<spdlog::logger> logger,
    std::vector<std::shared_ptr<Listener>>& listeners,
    PortInUseCallback portInUse,
    ServerFactory serverFactory)
    : m_logger(std::move(logger)),
      m_listeners(listeners),
      m_portInUse(portInUse ? std::move(portInUse) : PortInUseCallback(defaultPortInUse)),
      m_serverFactory(serverFactory ? std::move(serverFactory) : ServerFactory()),
      m_isSocksServerRunning(false),
      m_isSocksServerBinded(false)
{
}

TeamServerSocksService::~TeamServerSocksService()
{
    shutdown();
}

grpc::Status TeamServerSocksService::handleCommand(const std::vector<std::string>& splitedCmd, teamserverapi::TerminalCommandResponse* response)
{
    response->set_status(teamserverapi::OK);
    response->set_command(joinCommand(splitedCmd));
    response->set_result("");
    response->set_data("");
    response->clear_message();

    if (splitedCmd.size() < 2)
    {
        setTerminalError(response, "Error: Socks server command missing.");
        return grpc::Status::OK;
    }

    const std::string cmd = splitedCmd[1];
    if (cmd == "start")
    {
        if (m_isSocksServerRunning)
        {
            m_logger->warn("Error: Socks server is already running");
            setTerminalError(response, "Error: Socks server is already running");
            return grpc::Status::OK;
        }

        const int port = 1080;
        if (portInUse(static_cast<unsigned short>(port)))
        {
            m_logger->warn("Error: Socks server port already used");
            setTerminalError(response, "Error: Socks server port already used");
            return grpc::Status::OK;
        }

        m_socksServer = createServer(port);
        int maxAttempt = 3;
        int attempts = 0;
        while (!m_socksServer->isServerLaunched())
        {
            m_socksServer->stop();
            m_socksServer->launch();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            m_logger->debug("Wait for SocksServer to start on port {}", port);
            attempts++;
            if (attempts > maxAttempt)
            {
                m_logger->error("Error: Unable to start the socks server on port {} after {} attempts", port, maxAttempt);
                break;
            }
        }

        if (m_socksServer->isServerStoped())
        {
            m_logger->warn("Error: Socks server failed to start on port {}", port);
            setTerminalError(response, "Error: Socks server failed to start on port " + std::to_string(port));
            return grpc::Status::OK;
        }

        m_isSocksServerRunning = true;
        m_logger->info("Socks server successfully started on port {}", port);
        setTerminalOk(response, "Socks server successfully started on port " + std::to_string(port));
        return grpc::Status::OK;
    }

    if (cmd == "stop")
    {
        stopServer();
        m_logger->info("Socks server stoped");
        setTerminalOk(response, "Socks server stoped");
        return grpc::Status::OK;
    }

    if (cmd == "bind")
    {
        if (!m_isSocksServerRunning)
        {
            m_logger->warn("Error: Socks server not running");
            setTerminalError(response, "Error: Socks server not running");
            return grpc::Status::OK;
        }
        if (m_isSocksServerBinded)
        {
            m_logger->warn("Error: Socks server already bind");
            setTerminalError(response, "Error: Socks server already bind");
            return grpc::Status::OK;
        }
        if (splitedCmd.size() == 3)
        {
            std::shared_ptr<Listener> listener;
            std::shared_ptr<Session> session = findSessionByPrefix(splitedCmd[2], listener);
            if (session)
            {
                m_socksListener = std::move(listener);
                m_socksSession = std::move(session);
                m_socksThread = std::make_unique<std::thread>(&TeamServerSocksService::run, this);
                m_isSocksServerBinded = true;
                m_logger->info("Socks server sucessfully binded");
                setTerminalOk(response, "Socks server sucessfully binded\nThink about setting the sleep time of the beacon to 0.001 to force a good throughput");
                return grpc::Status::OK;
            }
        }

        m_logger->warn("Error: Socks server bind failed, session not found");
        setTerminalError(response, "Error: Socks server bind failed, session not found");
        return grpc::Status::OK;
    }

    if (cmd == "unbind")
    {
        unbindThread();
        m_logger->info("Socks server successfully unbinding");
        setTerminalOk(response, "Socks server successfully unbinding");
        return grpc::Status::OK;
    }

    m_logger->warn("Error: Socks server command not found.");
    setTerminalError(response, "Error: Socks server command not found.");
    return grpc::Status::OK;
}

void TeamServerSocksService::shutdown()
{
    stopServer();
}

void TeamServerSocksService::run()
{
    std::string dataIn;
    std::string dataOut;
    m_isSocksServerBinded = true;
    while (m_isSocksServerBinded)
    {
        if (m_socksSession->isSessionKilled())
        {
            m_isSocksServerBinded = false;
            for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
                m_socksServer->resetTunnel(i);
        }

        C2Message c2Message = m_socksListener->getSocksTaskResult(m_socksSession->getBeaconHash());
        if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopSocksCmd)
        {
            m_socksServer->stop();
            m_isSocksServerBinded = false;
            for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
                m_socksServer->resetTunnel(i);
        }

        for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
        {
            SocksTunnelServer* tunnel = m_socksServer->getTunnel(i);
            if (tunnel == nullptr)
                continue;

            int id = tunnel->getId();
            SocksState state = tunnel->getState();
            if (state == SocksState::INIT)
            {
                int ip = tunnel->getIpDst();
                int port = tunnel->getPort();

                m_logger->debug("Socks5 to {}:{}", std::to_string(ip), std::to_string(port));

                C2Message c2MessageToSend;
                c2MessageToSend.set_instruction(Socks5Cmd);
                c2MessageToSend.set_cmd(InitCmd);
                c2MessageToSend.set_data(std::to_string(ip));
                c2MessageToSend.set_args(std::to_string(port));
                c2MessageToSend.set_pid(id);

                if (!c2MessageToSend.instruction().empty())
                    m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);

                tunnel->setState(SocksState::HANDSHAKE);
            }
            else if (state == SocksState::HANDSHAKE)
            {
                m_logger->trace("Socks5 wait handshake {}", id);

                if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == InitCmd && c2Message.pid() == id)
                {
                    m_logger->debug("Socks5 handshake received {}", id);

                    if (c2Message.data() == "fail")
                    {
                        m_logger->debug("Socks5 handshake failed {}", id);
                        m_socksServer->resetTunnel(i);
                    }
                    else
                    {
                        m_logger->debug("Socks5 handshake succed {}", id);
                        tunnel->finishHandshake();
                        tunnel->setState(SocksState::RUN);

                        dataIn = "";
                        int res = tunnel->process(dataIn, dataOut);
                        if (res <= 0)
                        {
                            m_logger->debug("Socks5 stop");
                            m_socksServer->resetTunnel(i);

                            C2Message c2MessageToSend;
                            c2MessageToSend.set_instruction(Socks5Cmd);
                            c2MessageToSend.set_cmd(StopCmd);
                            c2MessageToSend.set_pid(id);
                            if (!c2MessageToSend.instruction().empty())
                                m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                        }
                        else
                        {
                            m_logger->debug("Socks5 send data to beacon");

                            C2Message c2MessageToSend;
                            c2MessageToSend.set_instruction(Socks5Cmd);
                            c2MessageToSend.set_cmd(RunCmd);
                            c2MessageToSend.set_pid(id);
                            c2MessageToSend.set_data(dataOut);
                            if (!c2MessageToSend.instruction().empty())
                                m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                        }
                    }
                }
                else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopCmd && c2Message.pid() == id)
                {
                    m_socksServer->resetTunnel(i);
                }
            }
            else if (state == SocksState::RUN)
            {
                m_logger->trace("Socks5 run {}", id);

                dataIn = "";
                if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == RunCmd && c2Message.pid() == id)
                {
                    m_logger->debug("Socks5 {}: data received from beacon", id);

                    dataIn = c2Message.data();
                    int res = tunnel->process(dataIn, dataOut);

                    m_logger->debug("Socks5 process, res {}, dataIn {}, dataOut {}", res, dataIn.size(), dataOut.size());
                    if (res <= 0)
                    {
                        m_logger->debug("Socks5 stop");
                        m_socksServer->resetTunnel(i);

                        C2Message c2MessageToSend;
                        c2MessageToSend.set_instruction(Socks5Cmd);
                        c2MessageToSend.set_cmd(StopCmd);
                        c2MessageToSend.set_pid(id);
                        if (!c2MessageToSend.instruction().empty())
                            m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                    }
                    else
                    {
                        m_logger->debug("Socks5 send data to beacon");

                        C2Message c2MessageToSend;
                        c2MessageToSend.set_instruction(Socks5Cmd);
                        c2MessageToSend.set_cmd(RunCmd);
                        c2MessageToSend.set_pid(id);
                        c2MessageToSend.set_data(dataOut);
                        if (!c2MessageToSend.instruction().empty())
                            m_socksListener->queueTask(m_socksSession->getBeaconHash(), c2MessageToSend);
                    }
                }
                else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopCmd && c2Message.pid() == id)
                {
                    m_socksServer->resetTunnel(i);
                }
            }
        }

        m_socksServer->cleanTunnel();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    m_logger->info("End SocksServer binding");
}

bool TeamServerSocksService::isRunning() const
{
    return m_isSocksServerRunning;
}

bool TeamServerSocksService::isBound() const
{
    return m_isSocksServerBinded;
}

std::shared_ptr<Session> TeamServerSocksService::findSessionByPrefix(const std::string& beaconHashPrefix, std::shared_ptr<Listener>& listener) const
{
    for (const std::shared_ptr<Listener>& currentListener : m_listeners)
    {
        int nbSession = static_cast<int>(currentListener->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = currentListener->getSessionPtr(kk);
            if (!session)
                continue;

            std::string hash = session->getBeaconHash();
            if (hash.find(beaconHashPrefix) != std::string::npos && !session->isSessionKilled())
            {
                listener = currentListener;
                return session;
            }
        }
    }

    listener.reset();
    return nullptr;
}

std::unique_ptr<ISocksServer> TeamServerSocksService::createServer(int port)
{
    if (m_serverFactory)
        return m_serverFactory(port);
    return std::make_unique<SocksServerAdapter>(port);
}

bool TeamServerSocksService::portInUse(unsigned short port) const
{
    return m_portInUse(port);
}

void TeamServerSocksService::unbindThread()
{
    m_isSocksServerBinded = false;
    if (m_socksThread)
        m_socksThread->join();
    m_socksThread.reset();
    m_socksListener.reset();
    m_socksSession.reset();
}

void TeamServerSocksService::stopServer()
{
    unbindThread();
    m_isSocksServerRunning = false;
    if (m_socksServer)
        m_socksServer->stop();
    m_socksServer.reset();
}
