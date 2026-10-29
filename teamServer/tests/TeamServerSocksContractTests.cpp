#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "Beacon.hpp"
#include "TeamServerSocksService.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"
#include "nlohmann/json.hpp"

namespace
{
using namespace std::chrono_literals;

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

class SocketRuntime
{
public:
    SocketRuntime()
    {
#ifdef _WIN32
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed");
#endif
    }
    ~SocketRuntime()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

int lastSocketError()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool isTimeoutError(int error)
{
#ifdef _WIN32
    return error == WSAETIMEDOUT || error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK || error == ETIMEDOUT;
#endif
}

class EchoServer
{
public:
    EchoServer()
    {
        const socket_t listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        require(listener != INVALID_SOCKET_VALUE, "echo listener socket failed");
        m_listener.reset(listener);

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
                "echo listener bind failed");
        require(listen(listener, 4) == 0, "echo listener listen failed");
#ifdef _WIN32
        int length = sizeof(address);
#else
        socklen_t length = sizeof(address);
#endif
        require(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0,
                "echo listener getsockname failed");
        m_port = ntohs(address.sin_port);
        m_thread = std::thread(&EchoServer::run, this);
    }

    ~EchoServer()
    {
        m_stop.store(true);
        m_client.reset();
        m_listener.reset();
        if (m_thread.joinable())
            m_thread.join();
    }

    int port() const { return m_port; }
    bool disconnected() const { return m_disconnected.load(); }

private:
    void run()
    {
        sockaddr_in peer{};
#ifdef _WIN32
        int length = sizeof(peer);
#else
        socklen_t length = sizeof(peer);
#endif
        const socket_t accepted = accept(m_listener.get(), reinterpret_cast<sockaddr*>(&peer), &length);
        if (accepted == INVALID_SOCKET_VALUE)
            return;
        m_client.reset(accepted);
        configure_socket_io_timeouts(accepted, 100);

        char buffer[8192];
        while (!m_stop.load())
        {
            const int received = recv(accepted, buffer, sizeof(buffer), 0);
            if (received > 0)
            {
                if (send_sock(accepted, buffer, static_cast<uint32_t>(received)) != received)
                    break;
                continue;
            }
            if (received == 0)
                break;
            if (!isTimeoutError(lastSocketError()))
                break;
        }
        m_disconnected.store(true);
    }

    int m_port = 0;
    std::atomic_bool m_stop{false};
    std::atomic_bool m_disconnected{false};
    SocketHandle m_listener;
    SocketHandle m_client;
    std::thread m_thread;
};

int reservePort()
{
    SocketHandle reservation(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    require(reservation.get() != INVALID_SOCKET_VALUE, "port reservation socket failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    require(bind(reservation.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
            "port reservation bind failed");
#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    require(getsockname(reservation.get(), reinterpret_cast<sockaddr*>(&address), &length) == 0,
            "port reservation getsockname failed");
    return ntohs(address.sin_port);
}

class RealSocksServer final : public ISocksServer
{
public:
    explicit RealSocksServer(int port) : m_server(port) {}
    void launch() override { m_server.launch(); }
    void stop() override { m_server.stop(); }
    void cleanTunnel() override { m_server.cleanTunnel(); }
    bool isServerStoped() const override { return const_cast<SocksServer&>(m_server).isServerStoped(); }
    bool isServerLaunched() const override { return const_cast<SocksServer&>(m_server).isServerLaunched(); }
    std::size_t tunnelCount() override { return m_server.tunnelCount(); }
    SocksTunnelServer* getTunnel(std::size_t index) override { return m_server.getTunnel(index); }
    void resetTunnel(std::size_t index) override { m_server.resetTunnel(index); }

private:
    SocksServer m_server;
};

class ContractListener final : public Listener
{
public:
    ContractListener() : Listener("127.0.0.1", "0", ListenerHttpsType)
    {
        setIsPrimary();
    }

    const std::string& key() const { return m_key; }
    bool exchange(const std::string& input, std::string& output)
    {
        return handleMessages(input, output);
    }
};

class ContractBeacon final : public Beacon
{
public:
    void checkIn() override {}
    bool initialize(const std::string& key)
    {
        nlohmann::json config;
        config["xorKey"] = key;
        config["ModulesConfig"] = nlohmann::json::object();
        return initConfig(config.dump());
    }
    const std::string& hash() const { return m_beaconHash; }
    void executePending() { runTasks(); }
    void makeCheckIn(std::string& output) { taskResultsToCmd(output); }
    void acceptTasks(const std::string& input) { cmdToTasks(input); }
};

void pump(ContractBeacon& beacon, ContractListener& listener)
{
    beacon.executePending();
    std::string checkIn;
    beacon.makeCheckIn(checkIn);
    std::string tasks;
    listener.exchange(checkIn, tasks);
    beacon.acceptTasks(tasks);
}

socket_t connectLocal(int port)
{
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        const socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        require(sock != INVALID_SOCKET_VALUE, "SOCKS client socket failed");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(static_cast<uint16_t>(port));
        if (connect(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
        {
            configure_socket_io_timeouts(sock, 100);
            return sock;
        }
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        std::this_thread::sleep_for(10ms);
    }
    throw std::runtime_error("SOCKS client connect timed out");
}

void sendBytes(socket_t sock, const std::string& data)
{
    require(send_sock(sock, data.data(), static_cast<uint32_t>(data.size())) ==
                static_cast<int>(data.size()),
            "SOCKS client send failed");
}

std::string takeAvailable(socket_t sock)
{
    std::string output;
    const DrainStatus status = readAllAvailableNow_(sock, output, 0);
    require(status != DrainStatus::Error, "SOCKS client receive failed");
    require(status != DrainStatus::Disconnected || !output.empty(), "SOCKS client disconnected early");
    return output;
}

template <typename Predicate>
void pumpUntil(ContractBeacon& beacon, ContractListener& listener,
               Predicate predicate, const char* failure)
{
    const auto deadline = std::chrono::steady_clock::now() + 8s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        pump(beacon, listener);
        if (predicate())
            return;
        std::this_thread::sleep_for(5ms);
    }
    throw std::runtime_error(failure);
}

void negotiateNoAuth(socket_t client, ContractBeacon& beacon, ContractListener& listener)
{
    sendBytes(client, std::string("\x05\x01\x00", 3));
    std::string negotiation;
    pumpUntil(beacon, listener, [&] {
        negotiation += takeAvailable(client);
        return negotiation.size() >= 2;
    }, "SOCKS method negotiation timed out");
    require(negotiation.substr(0, 2) == std::string("\x05\x00", 2),
            "SOCKS method negotiation mismatch");
}

std::string connectByHostname(socket_t client, int targetPort,
                              ContractBeacon& beacon, ContractListener& listener)
{
    const std::string host = "127.0.0.1";
    std::string request("\x05\x01\x00\x03", 4);
    request.push_back(static_cast<char>(host.size()));
    request += host;
    const uint16_t networkPort = htons(static_cast<uint16_t>(targetPort));
    request.append(reinterpret_cast<const char*>(&networkPort), sizeof(networkPort));
    sendBytes(client, request);

    std::string reply;
    pumpUntil(beacon, listener, [&] {
        reply += takeAvailable(client);
        return reply.size() >= 10;
    }, "SOCKS CONNECT handshake timed out");
    require(static_cast<uint8_t>(reply[0]) == 5, "SOCKS CONNECT reply version mismatch");
    return reply;
}

std::string waitForReplyWithoutBeacon(socket_t client)
{
    std::string reply;
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        reply += takeAvailable(client);
        if (reply.size() >= 10)
            return reply;
        std::this_thread::sleep_for(5ms);
    }
    throw std::runtime_error("SOCKS timeout reply was not produced");
}
} // namespace

int main()
{
    SocketRuntime sockets;
    EchoServer echo;
    const int socksPort = reservePort();

    auto listener = std::make_shared<ContractListener>();
    ContractBeacon beacon;
    require(beacon.initialize(listener->key()), "beacon initialization failed");
    pump(beacon, *listener);
    require(listener->getNumberOfSession() == 1, "listener did not register beacon session");

    std::vector<std::shared_ptr<Listener>> listeners{listener};
    TeamServerSocksService service(
        std::make_shared<spdlog::logger>("socks-contract"), listeners,
        [](unsigned short) { return false; },
        [socksPort](int) { return std::make_unique<RealSocksServer>(socksPort); },
        250ms);
    TeamServerOperationResult response;
    require((response = service.control("start")).ok &&
                response.ok,
            "SOCKS service start failed");
    require((response = service.control("bind", beacon.hash().substr(0, 8))).ok &&
                response.ok,
            "SOCKS service bind failed");

    EchoServer timeoutEcho;
    SocketHandle timeoutClient(connectLocal(socksPort));
    negotiateNoAuth(timeoutClient.get(), beacon, *listener);
    const std::string host = "127.0.0.1";
    std::string timeoutRequest("\x05\x01\x00\x03", 4);
    timeoutRequest.push_back(static_cast<char>(host.size()));
    timeoutRequest += host;
    const uint16_t timeoutPort = htons(static_cast<uint16_t>(timeoutEcho.port()));
    timeoutRequest.append(reinterpret_cast<const char*>(&timeoutPort), sizeof(timeoutPort));
    sendBytes(timeoutClient.get(), timeoutRequest);
    const std::string timeoutReply = waitForReplyWithoutBeacon(timeoutClient.get());
    require(static_cast<uint8_t>(timeoutReply[1]) ==
                static_cast<uint8_t>(Response::HostUnreachable),
            "missing beacon response did not expire the SOCKS handshake");
    timeoutClient.reset();
    pumpUntil(beacon, *listener, [&] { return timeoutEcho.disconnected(); },
              "expired SOCKS handshake left a delayed target socket open");
    require(service.isBound(), "expired tunnel stopped the SOCKS service");

    const int unavailablePort = reservePort();
    SocketHandle rejectedClient(connectLocal(socksPort));
    negotiateNoAuth(rejectedClient.get(), beacon, *listener);
    const std::string rejectedReply =
        connectByHostname(rejectedClient.get(), unavailablePort, beacon, *listener);
    require(static_cast<uint8_t>(rejectedReply[1]) ==
                static_cast<uint8_t>(Response::HostUnreachable),
            "failed target connection did not produce a SOCKS failure reply");
    rejectedClient.reset();
    require(service.isBound(), "target connection failure stopped the SOCKS service");

    SocketHandle client(connectLocal(socksPort));
    negotiateNoAuth(client.get(), beacon, *listener);
    const std::string connectReply = connectByHostname(client.get(), echo.port(), beacon, *listener);
    require(static_cast<uint8_t>(connectReply[1]) == 0,
            "SOCKS CONNECT handshake failed");

    std::string payload;
    payload.reserve(32768);
    for (int i = 0; i < 32768; ++i)
        payload.push_back(static_cast<char>(i % 251));
    sendBytes(client.get(), payload);

    std::string echoed;
    pumpUntil(beacon, *listener, [&] {
        echoed += takeAvailable(client.get());
        return echoed.size() >= payload.size();
    }, "bidirectional SOCKS payload timed out");
    require(echoed == payload, "bidirectional SOCKS payload was corrupted");

    client.reset();
    pumpUntil(beacon, *listener, [&] { return echo.disconnected(); },
              "beacon target socket remained open after local client disconnect");
    require(service.isBound(), "local client disconnect stopped the SOCKS service");

    EchoServer unbindEcho;
    EchoServer parallelEcho;
    SocketHandle unbindClient(connectLocal(socksPort));
    negotiateNoAuth(unbindClient.get(), beacon, *listener);
    const std::string unbindReply =
        connectByHostname(unbindClient.get(), unbindEcho.port(), beacon, *listener);
    require(static_cast<uint8_t>(unbindReply[1]) == 0,
            "second SOCKS CONNECT handshake failed");

    SocketHandle parallelClient(connectLocal(socksPort));
    negotiateNoAuth(parallelClient.get(), beacon, *listener);
    const std::string parallelReply =
        connectByHostname(parallelClient.get(), parallelEcho.port(), beacon, *listener);
    require(static_cast<uint8_t>(parallelReply[1]) == 0,
            "parallel SOCKS CONNECT handshake failed");

    const std::string firstParallelPayload(65536, 'A');
    const std::string secondParallelPayload(65536, 'B');
    sendBytes(unbindClient.get(), firstParallelPayload);
    sendBytes(parallelClient.get(), secondParallelPayload);
    std::string firstParallelEcho;
    std::string secondParallelEcho;
    pumpUntil(beacon, *listener, [&] {
        firstParallelEcho += takeAvailable(unbindClient.get());
        secondParallelEcho += takeAvailable(parallelClient.get());
        return firstParallelEcho.size() >= firstParallelPayload.size() &&
               secondParallelEcho.size() >= secondParallelPayload.size();
    }, "parallel SOCKS payloads timed out");
    require(firstParallelEcho == firstParallelPayload &&
                secondParallelEcho == secondParallelPayload,
            "parallel SOCKS payloads were corrupted");

    parallelClient.reset();
    pumpUntil(beacon, *listener, [&] { return parallelEcho.disconnected(); },
              "closing one parallel tunnel did not reach its target");
    require(service.isBound(), "closing one parallel tunnel stopped the SOCKS route");

    require((response = service.control("unbind")).ok &&
                response.ok,
            "SOCKS service unbind failed");
    pumpUntil(beacon, *listener, [&] { return unbindEcho.disconnected(); },
              "beacon target socket remained open after unbind");
    require((response = service.control("stop")).ok,
            "SOCKS service stop failed");
    return 0;
}
