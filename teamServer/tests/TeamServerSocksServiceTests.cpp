#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include "TeamServerSocksService.hpp"

namespace
{
class TestListener final : public Listener
{
public:
    explicit TestListener(const std::string& hash)
        : Listener("127.0.0.1", "8443", ListenerHttpsType)
    {
        m_listenerHash = hash;
    }

    std::shared_ptr<Session> addSession(const std::string& listenerHash, const std::string& beaconHash, const std::string& os)
    {
        auto session = std::make_shared<Session>(listenerHash, beaconHash, "host", "user", "x64", "admin", os);
        m_sessions.push_back(session);
        return session;
    }
};

class FakeSocksServer final : public ISocksServer
{
public:
    explicit FakeSocksServer(bool launched = true, bool stoped = false)
        : m_launched(launched),
          m_stoped(stoped)
    {
    }

    void launch() override
    {
        m_launched = true;
    }

    void stop() override
    {
        m_stoped = true;
    }

    void cleanTunnel() override
    {
    }

    bool isServerStoped() const override
    {
        return m_stoped;
    }

    bool isServerLaunched() const override
    {
        return m_launched;
    }

    std::size_t tunnelCount() override
    {
        return 0;
    }

    SocksTunnelServer* getTunnel(std::size_t) override
    {
        return nullptr;
    }

    void resetTunnel(std::size_t) override
    {
    }

private:
    bool m_launched;
    bool m_stoped;
};

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("socks-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

void testStartAndStopLifecycle()
{
    std::vector<std::shared_ptr<Listener>> listeners;
    TeamServerSocksService service(
        makeLogger(),
        listeners,
        [](unsigned short)
        { return false; },
        [](int)
        { return std::make_unique<FakeSocksServer>(); });

    teamserverapi::TermCommand response;
    assert(service.handleCommand({"socks", "start"}, &response).ok());
    assert(response.result() == "Socks server successfully started on port 1080");
    assert(service.isRunning());

    assert(service.handleCommand({"socks", "stop"}, &response).ok());
    assert(response.result() == "Socks server stoped");
    assert(!service.isRunning());
}

void testBindAndUnbindLifecycle()
{
    auto listener = std::make_shared<TestListener>("listener-primary");
    listener->addSession("listener-primary", "ABCDEFGH12345678", "Windows");
    std::vector<std::shared_ptr<Listener>> listeners = {listener};

    TeamServerSocksService service(
        makeLogger(),
        listeners,
        [](unsigned short)
        { return false; },
        [](int)
        { return std::make_unique<FakeSocksServer>(); });

    teamserverapi::TermCommand response;
    assert(service.handleCommand({"socks", "bind", "ABCDEFGH"}, &response).ok());
    assert(response.result() == "Error: Socks server not running");

    assert(service.handleCommand({"socks", "start"}, &response).ok());
    assert(service.handleCommand({"socks", "bind", "ABCDEFGH"}, &response).ok());
    assert(response.result().find("Socks server sucessfully binded") != std::string::npos);
    assert(service.isBound());

    assert(service.handleCommand({"socks", "unbind"}, &response).ok());
    assert(response.result() == "Socks server successfully unbinding");
    assert(!service.isBound());
}

void testPortInUseAndUnknownCommand()
{
    std::vector<std::shared_ptr<Listener>> listeners;
    TeamServerSocksService service(
        makeLogger(),
        listeners,
        [](unsigned short)
        { return true; },
        [](int)
        { return std::make_unique<FakeSocksServer>(); });

    teamserverapi::TermCommand response;
    assert(service.handleCommand({"socks", "start"}, &response).ok());
    assert(response.result() == "Error: Socks server port already used");

    assert(service.handleCommand({"socks", "nope"}, &response).ok());
    assert(response.result() == "Error: Socks server command not found.");
}
} // namespace

int main()
{
    testStartAndStopLifecycle();
    testBindAndUnbindLifecycle();
    testPortInUseAndUnknownCommand();
    return 0;
}
