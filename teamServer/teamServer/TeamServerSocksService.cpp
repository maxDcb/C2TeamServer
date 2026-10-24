#include "TeamServerSocksService.hpp"

#include <chrono>
#include <random>

#include "modules/ModuleCmd/CommonCommand.hpp"

namespace
{
std::string makeRouteGeneration()
{
    static constexpr char alphabet[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    thread_local std::mt19937_64 generator(std::random_device{}());
    std::uniform_int_distribution<std::size_t> distribution(0, sizeof(alphabet) - 2);
    std::string generation(20, '0');
    for (char& value : generation)
        value = alphabet[distribution(generator)];
    return generation;
}

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

bool isSocksInitFailure(const std::string& data)
{
    return data == "fail" || data.rfind("fail:", 0) == 0;
}

std::string tunnelDestinationPayload(SocksTunnelServer* tunnel)
{
    if (tunnel->getAddressType() == AddressType::DName)
        return "host:" + tunnel->getDestinationHost();
    return std::to_string(tunnel->getIpDst());
}

std::string tunnelDestinationLabel(SocksTunnelServer* tunnel)
{
    if (tunnel->getAddressType() == AddressType::DName)
        return tunnel->getDestinationHost();
    return std::to_string(tunnel->getIpDst());
}
} // namespace

TeamServerSocksService::TeamServerSocksService(
    std::shared_ptr<spdlog::logger> logger,
    std::vector<std::shared_ptr<Listener>>& listeners,
    PortInUseCallback portInUse,
    ServerFactory serverFactory,
    std::chrono::milliseconds tunnelResponseTimeout,
    std::shared_mutex* listenersMutex)
    : m_logger(std::move(logger)),
      m_listeners(listeners),
      m_listenersMutex(listenersMutex ? listenersMutex : &m_localListenersMutex),
      m_portInUse(portInUse ? std::move(portInUse) : PortInUseCallback(defaultPortInUse)),
      m_serverFactory(serverFactory ? std::move(serverFactory) : ServerFactory()),
      m_tunnelResponseTimeout(tunnelResponseTimeout),
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
    std::lock_guard<std::mutex> lock(m_controlMutex);
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
        if (m_isSocksServerBinded.load())
        {
            m_logger->warn("Error: Socks server already bind");
            setTerminalError(response, "Error: Socks server already bind");
            return grpc::Status::OK;
        }
        // A finished worker remains joinable until its owner joins it.
        // Reap it before replacing the thread or changing its session pointers.
        if (m_socksThread)
            unbindThread();

        if (splitedCmd.size() == 3)
        {
            std::shared_ptr<Listener> listener;
            std::shared_ptr<Session> session = findSessionByPrefix(splitedCmd[2], listener);
            if (session)
            {
                m_socksListener = std::move(listener);
                m_socksSession = std::move(session);
                m_routeGeneration = makeRouteGeneration();
                m_pendingTunnels.clear();
                m_isSocksServerBinded.store(true);
                m_socksThread = std::make_unique<std::thread>(&TeamServerSocksService::run, this);
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
    std::lock_guard<std::mutex> lock(m_controlMutex);
    stopServer();
}

void TeamServerSocksService::run()
{
    std::string dataIn;
    std::string dataOut;
    try
    {
        while (m_isSocksServerBinded.load())
        {
            if (!m_socksSession || !m_socksListener || !m_socksServer ||
                m_socksSession->isSessionKilled())
            {
                m_isSocksServerBinded.store(false);
                resetAllTunnels();
                break;
            }

            C2Message c2Message = m_socksListener->getSocksTaskResult(
                m_socksSession->getBeaconHash(), m_socksSession->getListenerHash());

            for (std::size_t i = 0; i < m_socksServer->tunnelCount(); i++)
            {
                SocksTunnelServer* tunnel = m_socksServer->getTunnel(i);
                if (tunnel == nullptr)
                    continue;

                int id = tunnel->getId();
                SocksState state = tunnel->getState();
                if (state == SocksState::INIT)
                {
                    int port = tunnel->getPort();

                    m_logger->debug("Socks5 to {}:{}", tunnelDestinationLabel(tunnel), std::to_string(port));

                    C2Message c2MessageToSend;
                    c2MessageToSend.set_instruction(Socks5Cmd);
                    c2MessageToSend.set_cmd(InitCmd);
                    c2MessageToSend.set_data(tunnelDestinationPayload(tunnel));
                    c2MessageToSend.set_args(std::to_string(port));
                    c2MessageToSend.set_pid(id);

                    if (queueToBoundSession(c2MessageToSend))
                    {
                        tunnel->setState(SocksState::HANDSHAKE);
                        markTunnelPending(id);
                    }
                    else
                    {
                        tunnel->failHandshake(Response::HostUnreachable);
                        resetTunnel(i, id);
                    }
                }
                else if (state == SocksState::HANDSHAKE)
                {
                    m_logger->trace("Socks5 wait handshake {}", id);

                    if (tunnelResponseTimedOut(id))
                    {
                        tunnel->failHandshake(Response::HostUnreachable);
                        resetTunnel(i, id);
                        C2Message stop;
                        stop.set_instruction(Socks5Cmd);
                        stop.set_cmd(StopCmd);
                        stop.set_pid(id);
                        queueToBoundSession(stop);
                    }
                    else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == InitCmd &&
                             responseMatchesTunnel(c2Message, id))
                    {
                        clearTunnelPending(id);
                        m_logger->debug("Socks5 handshake received {}", id);

                        if (isSocksInitFailure(c2Message.data()))
                        {
                            m_logger->debug("Socks5 handshake failed {}", id);
                            tunnel->failHandshake(Response::HostUnreachable);
                            resetTunnel(i, id);
                        }
                        else if (!tunnel->finishHandshake())
                        {
                            resetTunnel(i, id);
                            C2Message stop;
                            stop.set_instruction(Socks5Cmd);
                            stop.set_cmd(StopCmd);
                            stop.set_pid(id);
                            queueToBoundSession(stop);
                        }
                        else
                        {
                            m_logger->debug("Socks5 handshake succed {}", id);
                            tunnel->setState(SocksState::RUN);

                            dataIn.clear();
                            int res = tunnel->process(dataIn, dataOut);
                            if (res <= 0)
                            {
                                m_logger->debug("Socks5 stop");
                                resetTunnel(i, id);

                                C2Message c2MessageToSend;
                                c2MessageToSend.set_instruction(Socks5Cmd);
                                c2MessageToSend.set_cmd(StopCmd);
                                c2MessageToSend.set_pid(id);
                                queueToBoundSession(c2MessageToSend);
                            }
                            else
                            {
                                m_logger->debug("Socks5 send data to beacon");

                                C2Message c2MessageToSend;
                                c2MessageToSend.set_instruction(Socks5Cmd);
                                c2MessageToSend.set_cmd(RunCmd);
                                c2MessageToSend.set_pid(id);
                                c2MessageToSend.set_data(dataOut);
                                if (!queueToBoundSession(c2MessageToSend))
                                    resetTunnel(i, id);
                                else
                                    markTunnelPending(id);
                            }
                        }
                    }
                    else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopCmd &&
                             responseMatchesTunnel(c2Message, id))
                    {
                        resetTunnel(i, id);
                    }
                }
                else if (state == SocksState::RUN)
                {
                    m_logger->trace("Socks5 run {}", id);

                    dataIn.clear();
                    if (tunnelResponseTimedOut(id))
                    {
                        resetTunnel(i, id);
                        C2Message stop;
                        stop.set_instruction(Socks5Cmd);
                        stop.set_cmd(StopCmd);
                        stop.set_pid(id);
                        queueToBoundSession(stop);
                    }
                    else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == RunCmd &&
                             responseMatchesTunnel(c2Message, id))
                    {
                        clearTunnelPending(id);
                        m_logger->debug("Socks5 {}: data received from beacon", id);

                        dataIn = c2Message.data();
                        int res = tunnel->process(dataIn, dataOut);

                        m_logger->debug("Socks5 process, res {}, dataIn {}, dataOut {}", res, dataIn.size(), dataOut.size());
                        if (res <= 0)
                        {
                            m_logger->debug("Socks5 stop");
                            resetTunnel(i, id);

                            C2Message c2MessageToSend;
                            c2MessageToSend.set_instruction(Socks5Cmd);
                            c2MessageToSend.set_cmd(StopCmd);
                            c2MessageToSend.set_pid(id);
                            queueToBoundSession(c2MessageToSend);
                        }
                        else
                        {
                            m_logger->debug("Socks5 send data to beacon");

                            C2Message c2MessageToSend;
                            c2MessageToSend.set_instruction(Socks5Cmd);
                            c2MessageToSend.set_cmd(RunCmd);
                            c2MessageToSend.set_pid(id);
                            c2MessageToSend.set_data(dataOut);
                            if (!queueToBoundSession(c2MessageToSend))
                                resetTunnel(i, id);
                            else
                                markTunnelPending(id);
                        }
                    }
                    else if (c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StopCmd &&
                             responseMatchesTunnel(c2Message, id))
                    {
                        resetTunnel(i, id);
                    }
                }
            }

            m_socksServer->cleanTunnel();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    catch (...)
    {
        m_isSocksServerBinded.store(false);
        requestRemoteStop();
        resetAllTunnels();
    }

    m_logger->info("End SocksServer binding");
}

bool TeamServerSocksService::isRunning() const
{
    std::lock_guard<std::mutex> lock(m_controlMutex);
    return m_isSocksServerRunning;
}

bool TeamServerSocksService::isBound() const
{
    return m_isSocksServerBinded.load();
}

std::shared_ptr<Session> TeamServerSocksService::findSessionByPrefix(const std::string& beaconHashPrefix, std::shared_ptr<Listener>& listener) const
{
    std::shared_ptr<Session> match;
    std::shared_ptr<Listener> matchListener;
    std::vector<std::shared_ptr<Listener>> listeners;
    {
        std::shared_lock<std::shared_mutex> lock(*m_listenersMutex);
        listeners = m_listeners;
    }
    for (const std::shared_ptr<Listener>& currentListener : listeners)
    {
        int nbSession = static_cast<int>(currentListener->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = currentListener->getSessionPtr(kk);
            if (!session)
                continue;

            std::string hash = session->getBeaconHash();
            if (hash.rfind(beaconHashPrefix, 0) == 0 && !session->isSessionKilled())
            {
                if (hash == beaconHashPrefix)
                {
                    listener = currentListener;
                    return session;
                }
                if (match)
                {
                    listener.reset();
                    return nullptr;
                }
                match = session;
                matchListener = currentListener;
            }
        }
    }

    listener = std::move(matchListener);
    return match;
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

bool TeamServerSocksService::queueToBoundSession(const C2Message& message)
{
    if (!m_socksListener || !m_socksSession)
        return false;
    C2Message routedMessage = message;
    routedMessage.set_uuid(m_routeGeneration);
    return m_socksListener->queueTaskIfSessionAlive(
        m_socksSession->getBeaconHash(),
        m_socksSession->getListenerHash(),
        routedMessage);
}

bool TeamServerSocksService::responseMatchesTunnel(const C2Message& message, int id) const
{
    return message.pid() == id && !m_routeGeneration.empty() &&
           message.uuid() == m_routeGeneration;
}

void TeamServerSocksService::markTunnelPending(int id)
{
    m_pendingTunnels[id] = std::chrono::steady_clock::now();
}

bool TeamServerSocksService::tunnelResponseTimedOut(int id) const
{
    const auto pending = m_pendingTunnels.find(id);
    return pending != m_pendingTunnels.end() &&
           std::chrono::steady_clock::now() - pending->second >= m_tunnelResponseTimeout;
}

void TeamServerSocksService::clearTunnelPending(int id)
{
    m_pendingTunnels.erase(id);
}

void TeamServerSocksService::resetTunnel(std::size_t index, int id)
{
    clearTunnelPending(id);
    m_socksServer->resetTunnel(index);
}

void TeamServerSocksService::requestRemoteStop()
{
    if (!m_socksListener || !m_socksSession || m_socksSession->isSessionKilled())
        return;
    C2Message stop;
    stop.set_instruction(Socks5Cmd);
    stop.set_cmd(StopSocksCmd);
    queueToBoundSession(stop);
}

void TeamServerSocksService::resetAllTunnels()
{
    if (!m_socksServer)
        return;
    const std::size_t count = m_socksServer->tunnelCount();
    for (std::size_t i = 0; i < count; ++i)
        m_socksServer->resetTunnel(i);
    m_socksServer->cleanTunnel();
    m_pendingTunnels.clear();
}

void TeamServerSocksService::unbindThread()
{
    m_isSocksServerBinded.store(false);
    if (m_socksThread)
        m_socksThread->join();
    m_socksThread.reset();
    requestRemoteStop();
    resetAllTunnels();
    if (m_socksListener && m_socksSession)
        m_socksListener->clearSocksSession(
            m_socksSession->getBeaconHash(), m_socksSession->getListenerHash());
    m_socksListener.reset();
    m_socksSession.reset();
    m_routeGeneration.clear();
}

void TeamServerSocksService::stopServer()
{
    unbindThread();
    m_isSocksServerRunning = false;
    if (m_socksServer)
        m_socksServer->stop();
    m_socksServer.reset();
}
