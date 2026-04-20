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
        if (auto res = cli.Post("/checkin", "", "text/plain"))
        {
            if (res->status == 200)
                return;
        }

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

    ListenerHttp listener("127.0.0.1", port, config, false);
    assert(listener.init() == 1);
    waitForListenerReady(port);

    httplib::Client cli("127.0.0.1", port);
    auto ok = cli.Post("/checkin", "", "text/plain");
    assert(ok);
    assert(ok->status == 200);

    auto denied = cli.Post("/forbidden", "", "text/plain");
    assert(denied);
    assert(denied->status == 401);

    httplib::ws::WebSocketClient ws("ws://127.0.0.1:" + std::to_string(port) + "/ws");
    assert(ws.is_valid());
    assert(ws.connect());
    assert(ws.send(""));

    std::string reply;
    const auto result = ws.read(reply);
    assert(result == httplib::ws::Text);
    assert(reply.empty());
    ws.close();
}
} // namespace

int main()
{
    testHttpAndWebSocketTransport();
    return 0;
}
