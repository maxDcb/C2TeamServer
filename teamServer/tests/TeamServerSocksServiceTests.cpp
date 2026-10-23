#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "TeamServerSocksService.hpp"

namespace
{
void require(bool condition)
{
    if (!condition)
        throw std::runtime_error("SOCKS service test assertion failed");
}

bool waitFor(const std::function<bool()>& predicate)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

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

    teamserverapi::TerminalCommandResponse response;
    require(service.handleCommand({"socks", "start"}, &response).ok());
    require(response.status() == teamserverapi::OK);
    require(response.result() == "Socks server successfully started on port 1080");
    require(service.isRunning());

    require(service.handleCommand({"socks", "stop"}, &response).ok());
    require(response.status() == teamserverapi::OK);
    require(response.result() == "Socks server stoped");
    require(!service.isRunning());
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

    teamserverapi::TerminalCommandResponse response;
    require(service.handleCommand({"socks", "bind", "ABCDEFGH"}, &response).ok());
    require(response.status() == teamserverapi::KO);
    require(response.result() == "Error: Socks server not running");
    require(response.message() == "Error: Socks server not running");

    require(service.handleCommand({"socks", "start"}, &response).ok());
    require(service.handleCommand({"socks", "bind", "ABCDEFGH"}, &response).ok());
    require(response.status() == teamserverapi::OK);
    require(response.result().find("Socks server sucessfully binded") != std::string::npos);
    require(response.message().empty());
    require(service.isBound());

    require(service.handleCommand({"socks", "unbind"}, &response).ok());
    require(response.status() == teamserverapi::OK);
    require(response.result() == "Socks server successfully unbinding");
    require(!service.isBound());
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

    teamserverapi::TerminalCommandResponse response;
    require(service.handleCommand({"socks", "start"}, &response).ok());
    require(response.status() == teamserverapi::KO);
    require(response.result() == "Error: Socks server port already used");
    require(response.message() == "Error: Socks server port already used");

    require(service.handleCommand({"socks", "nope"}, &response).ok());
    require(response.status() == teamserverapi::KO);
    require(response.result() == "Error: Socks server command not found.");
}

void testRebindAfterSessionKilled()
{
    auto listener = std::make_shared<TestListener>("listener-primary");
    auto first = listener->addSession("listener-primary", "ABCDEFGH12345678", "Linux");
    listener->addSession("listener-primary", "IJKLMNOP12345678", "Linux");
    std::vector<std::shared_ptr<Listener>> listeners = {listener};

    TeamServerSocksService service(
        makeLogger(),
        listeners,
        [](unsigned short) { return false; },
        [](int) { return std::make_unique<FakeSocksServer>(); });
    teamserverapi::TerminalCommandResponse response;
    require(service.handleCommand({"socks", "start"}, &response).ok());
    require(service.handleCommand({"socks", "bind", "ABCDEFGH"}, &response).ok());
    require(service.isBound());

    first->setSessionKilled();
    require(waitFor([&service] { return !service.isBound(); }));

    require(service.handleCommand({"socks", "bind", "IJKLMNOP"}, &response).ok());
    require(response.status() == teamserverapi::OK);
    require(service.isBound());
    require(service.handleCommand({"socks", "unbind"}, &response).ok());
    require(!service.isBound());
}

void testImmediateUnbindAfterBind()
{
    auto listener = std::make_shared<TestListener>("listener-primary");
    listener->addSession("listener-primary", "ABCDEFGH12345678", "Linux");
    std::vector<std::shared_ptr<Listener>> listeners = {listener};
    TeamServerSocksService service(
        makeLogger(),
        listeners,
        [](unsigned short) { return false; },
        [](int) { return std::make_unique<FakeSocksServer>(); });
    teamserverapi::TerminalCommandResponse response;
    require(service.handleCommand({"socks", "start"}, &response).ok());

    for (int i = 0; i < 20; ++i)
    {
        require(service.handleCommand({"socks", "bind", "ABCDEFGH"}, &response).ok());
        require(response.status() == teamserverapi::OK);
        require(service.handleCommand({"socks", "unbind"}, &response).ok());
        require(!service.isBound());
    }
}
} // namespace

int main()
{
    testStartAndStopLifecycle();
    testBindAndUnbindLifecycle();
    testPortInUseAndUnknownCommand();
    testRebindAfterSessionKilled();
    testImmediateUnbindAfterBind();
    return 0;
}
