#include <cassert>
#include <chrono>
#include <string>
#include <thread>

#include <httplib.h>

#include "ListenerHttp.hpp"

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace
{
class TestListenerHttp : public ListenerHttp
{
public:
    using ListenerHttp::ListenerHttp;
    const std::string& key() const { return m_key; }
};

std::string makeExchangePayload(const std::string& key,
                                const std::string& beaconHash,
                                const std::string& exchangeId,
                                const std::string& resultInstruction)
{
    MultiBundleC2Message bundles;
    auto* bundle = bundles.add_bundlec2messages();
    bundle->set_beaconhash(beaconHash);
    bundle->set_hostname("host");
    bundle->set_username("user");
    bundle->set_arch("x64");
    bundle->set_privilege("user");
    bundle->set_os("Linux");
    bundle->set_lastProofOfLife("0");

    auto* exchange = bundle->add_c2messages();
    exchange->set_instruction(HttpExchangeCmd);
    exchange->set_cmd(exchangeId);
    if (!resultInstruction.empty())
        bundle->add_c2messages()->set_instruction(resultInstruction);

    std::string data;
    bundles.SerializeToString(&data);
    XOR(data, key);
    return base64_encode(data);
}

#ifndef _WIN32
int findFreePort()
{
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    const int bindResult = ::bind(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    assert(bindResult == 0);

    socklen_t len = sizeof(addr);
    const int nameResult = ::getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &len);
    assert(nameResult == 0);

    const int port = ntohs(addr.sin_port);
    ::close(sock);
    return port;
}

int bindLocalPort(int& port)
{
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    const int bindResult = ::bind(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    assert(bindResult == 0);

    socklen_t len = sizeof(addr);
    const int nameResult = ::getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &len);
    assert(nameResult == 0);

    port = ntohs(addr.sin_port);
    return sock;
}
#else
int findFreePort()
{
    return 18080;
}
#endif

void waitForListenerReady(int port)
{
    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(0, 100000);
    cli.set_read_timeout(0, 100000);
    cli.set_write_timeout(0, 100000);

    for (int attempt = 0; attempt < 50; ++attempt)
    {
        if (cli.Post("/checkin", "", "text/plain"))
            return;

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    assert(false && "listener did not become ready");
}

void testHttpAndWebSocketTransport()
{
    const int port = findFreePort();
    nlohmann::json config = {
        {"LogLevel", "off"},
        {"ListenerHttpConfig",
         {
             {"uri", {"/checkin"}},
             {"wsUri", {"/ws"}},
             {"uriFileDownload", "/downloads/"},
             {"downloadFolder", "."},
             {"wsMaxMessageSize", 4096},
             {"server",
              {
                  {"headers",
                   {
                       {"Content-Type", "application/json"},
                       {"Server", "Server"},
                   }},
              }},
         }},
    };

    TestListenerHttp listener("127.0.0.1", port, config, false);
    assert(listener.init() == 1);
    assert(listener.isRunning());
    waitForListenerReady(port);

    httplib::Client cli("127.0.0.1", port);
    auto ok = cli.Post("/checkin", "", "text/plain");
    assert(ok);
    assert(ok->status == 401);

    auto denied = cli.Post("/forbidden", "", "text/plain");
    assert(denied);
    assert(denied->status == 401);

    httplib::ws::WebSocketClient ws("ws://127.0.0.1:" + std::to_string(port) + "/ws");
    assert(ws.is_valid());
    assert(ws.connect());
    assert(ws.send(""));

    std::string reply;
    const auto result = ws.read(reply);
    assert(result == httplib::ws::Fail);
    assert(reply.empty());
    ws.close();

    const std::string beaconHash(SizeBeaconHash, 'B');
    const std::string firstExchange(SizeBeaconHash, '1');
    const auto firstPayload = makeExchangePayload(
        listener.key(), beaconHash, firstExchange, "http-contract-result");
    auto first = cli.Post("/checkin", firstPayload, "text/plain");
    assert(first && first->status == 200);
    auto duplicate = cli.Post("/checkin", firstPayload, "text/plain");
    assert(duplicate && duplicate->status == 200);
    assert(duplicate->body == first->body);
    assert(listener.getTaskResult(beaconHash).instruction() == "http-contract-result");
    assert(listener.getTaskResult(beaconHash).instruction().empty());

    C2Message task;
    task.set_instruction("http-contract-task");
    listener.queueTask(beaconHash, task);
    const auto secondPayload = makeExchangePayload(
        listener.key(), beaconHash, std::string(SizeBeaconHash, '2'), "");
    auto second = cli.Post("/checkin", secondPayload, "text/plain");
    assert(second && second->status == 200);
    assert(!second->body.empty());
    auto secondDuplicate = cli.Post("/checkin", secondPayload, "text/plain");
    assert(secondDuplicate && secondDuplicate->status == 200);
    assert(secondDuplicate->body == second->body);
}

void testHttpInitRejectsOccupiedPort()
{
#ifndef _WIN32
    int port = 0;
    const int occupiedSocket = bindLocalPort(port);

    nlohmann::json config = {
        {"LogLevel", "off"},
        {"ListenerHttpConfig",
         {
             {"uri", {"/checkin"}},
             {"server", {{"headers", nlohmann::json::object()}}},
         }},
    };

    ListenerHttp listener("127.0.0.1", port, config, false);
    assert(listener.init() < 0);
    assert(!listener.isRunning());

    ::close(occupiedSocket);
#endif
}
} // namespace

int main()
{
    testHttpAndWebSocketTransport();
    testHttpInitRejectsOccupiedPort();
    return 0;
}
