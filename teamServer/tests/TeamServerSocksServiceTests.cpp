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

    const auto typedStart = service.control("start");
    require(typedStart.ok && service.isRunning());
    const auto typedStop = service.control("stop");
    require(typedStop.ok && !service.isRunning());

    TeamServerOperationResult response;
    response = service.control("start");
    require(response.ok);
    require(response.output == "Socks server successfully started on port 1080");
    require(service.isRunning());

    response = service.control("stop");
    require(response.ok);
    require(response.output == "Socks server stoped");
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

    TeamServerOperationResult response;
    response = service.control("bind", "ABCDEFGH");
    require(!response.ok);
    require(response.output == "Error: Socks server not running");

    response = service.control("start");
    response = service.control("bind", "ABCDEFGH");
    require(response.ok);
    require(response.output.find("Socks server sucessfully binded") != std::string::npos);
    require(service.isBound());

    response = service.control("unbind");
    require(response.ok);
    require(response.output == "Socks server successfully unbinding");
    require(!service.isBound());

    const C2Message stop = listener->getTask("ABCDEFGH12345678");
    require(stop.instruction() == Socks5Cmd);
    require(stop.cmd() == StopSocksCmd);
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

    TeamServerOperationResult response;
    response = service.control("start");
    require(!response.ok);
    require(response.output == "Error: Socks server port already used");

    response = service.control("nope");
    require(!response.ok);
    require(response.output == "Error: Socks server command not found.");
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
    TeamServerOperationResult response;
    response = service.control("start");
    response = service.control("bind", "ABCDEFGH");
    require(service.isBound());

    first->setSessionKilled();
    require(waitFor([&service] { return !service.isBound(); }));

    response = service.control("bind", "IJKLMNOP");
    require(response.ok);
    require(service.isBound());
    response = service.control("unbind");
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
    TeamServerOperationResult response;
    response = service.control("start");

    for (int i = 0; i < 20; ++i)
    {
        response = service.control("bind", "ABCDEFGH");
        require(response.ok);
        response = service.control("unbind");
        require(!service.isBound());
    }
}

void testAmbiguousSessionPrefixIsRejected()
{
    auto listener = std::make_shared<TestListener>("listener-primary");
    listener->addSession("listener-primary", "PREFIXAA12345678", "Linux");
    listener->addSession("listener-primary", "PREFIXBB12345678", "Linux");
    std::vector<std::shared_ptr<Listener>> listeners = {listener};
    TeamServerSocksService service(
        makeLogger(), listeners,
        [](unsigned short) { return false; },
        [](int) { return std::make_unique<FakeSocksServer>(); });
    TeamServerOperationResult response;
    response = service.control("start");
    response = service.control("bind", "PREFIX");
    require(!response.ok);
    require(!service.isBound());
}
} // namespace

int main()
{
    testStartAndStopLifecycle();
    testBindAndUnbindLifecycle();
    testPortInUseAndUnknownCommand();
    testRebindAfterSessionKilled();
    testImmediateUnbindAfterBind();
    testAmbiguousSessionPrefixIsRejected();
    return 0;
}
