#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include <nlohmann/json.hpp>

#include "TeamServerApi.grpc.pb.h"

namespace fs = std::filesystem;

namespace
{
class ScopedPath
{
public:
    explicit ScopedPath(fs::path path)
        : m_path(std::move(path))
    {
    }

    ~ScopedPath()
    {
        std::error_code ec;
        fs::remove_all(m_path, ec);
    }

    const fs::path& path() const
    {
        return m_path;
    }

private:
    fs::path m_path;
};

class ScopedServerProcess
{
public:
    explicit ScopedServerProcess(fs::path runtimeRoot)
        : m_runtimeRoot(std::move(runtimeRoot))
    {
    }

    ~ScopedServerProcess()
    {
        stop();
    }

    void start()
    {
        assert(m_pid == -1);

        fs::path teamServerDir = m_runtimeRoot / "TeamServer";
        fs::path teamServerBinary = teamServerDir / "TeamServer";
        assert(fs::exists(teamServerBinary));

        m_pid = ::fork();
        assert(m_pid >= 0);

        if (m_pid == 0)
        {
            const int chdirResult = ::chdir(teamServerDir.c_str());
            if (chdirResult != 0)
                _exit(126);
            ::execl(teamServerBinary.c_str(), teamServerBinary.c_str(), "TeamServerConfig.json", static_cast<char*>(nullptr));
            _exit(127);
        }
    }

    bool isRunning() const
    {
        if (m_pid <= 0)
            return false;

        int status = 0;
        pid_t result = ::waitpid(m_pid, &status, WNOHANG);
        return result == 0;
    }

    void stop()
    {
        if (m_pid <= 0)
            return;

        if (isRunning())
        {
            ::kill(m_pid, SIGTERM);

            for (int attempt = 0; attempt < 20; ++attempt)
            {
                int status = 0;
                pid_t result = ::waitpid(m_pid, &status, WNOHANG);
                if (result == m_pid)
                {
                    m_pid = -1;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            ::kill(m_pid, SIGKILL);
        }

        int status = 0;
        ::waitpid(m_pid, &status, 0);
        m_pid = -1;
    }

private:
    fs::path m_runtimeRoot;
    pid_t m_pid = -1;
};

std::string readFile(const fs::path& filePath)
{
    std::ifstream input(filePath, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), {});
}

int reserveTcpPort()
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);

    int bindResult = ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    assert(bindResult == 0);

    socklen_t addressLength = sizeof(address);
    int nameResult = ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &addressLength);
    assert(nameResult == 0);

    int port = ntohs(address.sin_port);
    ::close(fd);
    return port;
}

fs::path makeRuntimeCopy(const fs::path& stagedRuntimeRoot)
{
    fs::path tempRoot = fs::temp_directory_path() / ("c2teamserver-integration-" + std::to_string(::getpid()));
    fs::remove_all(tempRoot);
    fs::create_directories(tempRoot);

    fs::path runtimeCopy = tempRoot / "runtime";
    fs::copy(stagedRuntimeRoot, runtimeCopy, fs::copy_options::recursive);
    return runtimeCopy;
}

void rewriteRuntimeConfig(const fs::path& runtimeRoot, int grpcPort)
{
    fs::path configFile = runtimeRoot / "TeamServer" / "TeamServerConfig.json";
    std::ifstream input(configFile);
    nlohmann::json config = nlohmann::json::parse(input);

    config["ServerGRPCAdd"] = "127.0.0.1";
    config["ServerGRPCPort"] = std::to_string(grpcPort);

    std::ofstream output(configFile);
    output << config.dump(4);
}

std::unique_ptr<teamserverapi::TeamServerApi::Stub> makeStub(const fs::path& runtimeRoot, int grpcPort)
{
    grpc::SslCredentialsOptions credentialsOptions;
    credentialsOptions.pem_root_certs = readFile(runtimeRoot / "TeamServer" / "rootCA.crt");

    grpc::ChannelArguments channelArguments;
    channelArguments.SetSslTargetNameOverride("localhost");
    channelArguments.SetMaxReceiveMessageSize(512 * 1024 * 1024);
    channelArguments.SetMaxSendMessageSize(512 * 1024 * 1024);

    auto channel = grpc::CreateCustomChannel(
        "127.0.0.1:" + std::to_string(grpcPort),
        grpc::SslCredentials(credentialsOptions),
        channelArguments);
    return teamserverapi::TeamServerApi::NewStub(channel);
}

std::string authenticate(teamserverapi::TeamServerApi::Stub& stub)
{
    grpc::ClientContext context;
    teamserverapi::AuthRequest request;
    request.set_username("admin");
    request.set_password("admin");

    teamserverapi::AuthResponse response;
    grpc::Status status = stub.Authenticate(&context, request, &response);

    assert(status.ok());
    assert(response.status() == teamserverapi::OK);
    assert(!response.token().empty());
    return response.token();
}

void waitForServerReady(teamserverapi::TeamServerApi::Stub& stub, ScopedServerProcess& process)
{
    for (int attempt = 0; attempt < 50; ++attempt)
    {
        assert(process.isRunning());

        grpc::ClientContext context;
        teamserverapi::AuthRequest request;
        request.set_username("admin");
        request.set_password("admin");

        teamserverapi::AuthResponse response;
        grpc::Status status = stub.Authenticate(&context, request, &response);
        if (status.ok() && response.status() == teamserverapi::OK && !response.token().empty())
            return;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    assert(false && "TeamServer did not become ready in time");
}

void testStagedRuntimeSupportsGrpcAuthenticationAndStableRpc()
{
    fs::path stagedRuntimeRoot = fs::path(C2_INTEGRATION_STAGING_DIR) / "Release";
    assert(fs::exists(stagedRuntimeRoot / "TeamServer" / "TeamServer"));
    assert(fs::exists(stagedRuntimeRoot / "Client" / "c2client_protocol" / "TeamServerApi_pb2.py"));

    ScopedPath runtimeCopy(makeRuntimeCopy(stagedRuntimeRoot));
    const int grpcPort = reserveTcpPort();
    rewriteRuntimeConfig(runtimeCopy.path(), grpcPort);

    ScopedServerProcess process(runtimeCopy.path());
    process.start();

    auto stub = makeStub(runtimeCopy.path(), grpcPort);
    waitForServerReady(*stub, process);

    const std::string token = authenticate(*stub);

    grpc::ClientContext listenersContext;
    listenersContext.AddMetadata("authorization", "Bearer " + token);
    listenersContext.AddMetadata("clientid", "integration-test");

    teamserverapi::Empty empty;
    std::unique_ptr<grpc::ClientReader<teamserverapi::Listener>> listeners = stub->GetListeners(&listenersContext, empty);
    teamserverapi::Listener listener;
    std::vector<teamserverapi::Listener> streamedListeners;
    while (listeners->Read(&listener))
    {
        streamedListeners.push_back(listener);
    }
    grpc::Status listenersStatus = listeners->Finish();

    assert(listenersStatus.ok());
    assert(streamedListeners.empty());

    grpc::ClientContext sessionsContext;
    sessionsContext.AddMetadata("authorization", "Bearer " + token);
    sessionsContext.AddMetadata("clientid", "integration-test");

    std::unique_ptr<grpc::ClientReader<teamserverapi::Session>> sessions = stub->GetSessions(&sessionsContext, empty);
    teamserverapi::Session session;
    std::vector<teamserverapi::Session> streamedSessions;
    while (sessions->Read(&session))
    {
        streamedSessions.push_back(session);
    }
    grpc::Status sessionsStatus = sessions->Finish();

    assert(sessionsStatus.ok());
    assert(streamedSessions.empty());
}
} // namespace

int main()
{
    testStagedRuntimeSupportsGrpcAuthenticationAndStableRpc();
    return 0;
}
