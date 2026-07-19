#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <nlohmann/json.hpp>

#include "TeamServerApi.grpc.pb.h"
#undef assert
#define assert(condition) do { if (!(condition)) throw std::runtime_error( \
    std::string("test assertion failed: ") + #condition); } while (false)


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
        std::error_code error;
        fs::remove_all(m_path, error);
    }
    const fs::path& path() const { return m_path; }

private:
    fs::path m_path;
};

class ScopedServer
{
public:
    ScopedServer(fs::path binary, fs::path instance)
        : m_binary(std::move(binary)), m_instance(std::move(instance))
    {
    }
    ~ScopedServer() { stop(); }

    void start()
    {
        m_pid = ::fork();
        assert(m_pid >= 0);
        if (m_pid == 0)
        {
            ::execl(
                m_binary.c_str(),
                m_binary.c_str(),
                "run",
                "--instance-dir",
                m_instance.c_str(),
                static_cast<char*>(nullptr));
            _exit(127);
        }
    }

    bool running() const
    {
        int status = 0;
        return m_pid > 0 && ::waitpid(m_pid, &status, WNOHANG) == 0;
    }

    void stop()
    {
        if (m_pid <= 0)
            return;
        if (running())
        {
            ::kill(m_pid, SIGTERM);
            for (int attempt = 0; attempt < 20; ++attempt)
            {
                int status = 0;
                if (::waitpid(m_pid, &status, WNOHANG) == m_pid)
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
    fs::path m_binary;
    fs::path m_instance;
    pid_t m_pid = -1;
};

std::string readFile(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), {});
}

std::string bootstrapValue(const fs::path& path, const std::string& key)
{
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line))
    {
        const std::string prefix = key + "=";
        if (line.rfind(prefix, 0) == 0)
            return line.substr(prefix.size());
    }
    return {};
}

int reservePort()
{
    const int socketFd = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(socketFd >= 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(::bind(socketFd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socklen_t size = sizeof(address);
    assert(::getsockname(socketFd, reinterpret_cast<sockaddr*>(&address), &size) == 0);
    const int port = ntohs(address.sin_port);
    ::close(socketFd);
    return port;
}

fs::path copyRuntime()
{
    const fs::path source = fs::path(C2_INTEGRATION_STAGING_DIR) / "Release";
    const fs::path root = fs::temp_directory_path()
        / ("c2teamserver-rc1-integration-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);
    fs::copy(source, root / "Release", fs::copy_options::recursive);
    return root;
}

void initializeInstance(const fs::path& binary, const fs::path& instance, int port)
{
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0)
    {
        const std::string portValue = std::to_string(port);
        ::execl(
            binary.c_str(), binary.c_str(),
            "init", "--profile", "standalone",
            "--instance-dir", instance.c_str(),
            "--hostname", "localhost",
            "--listen-address", "127.0.0.1",
            "--port", portValue.c_str(),
            static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void waitUntilReady(teamserverapi::TeamServerApi::Stub& stub, ScopedServer& process, const std::string& password)
{
    for (int attempt = 0; attempt < 80; ++attempt)
    {
        assert(process.running());
        grpc::ClientContext context;
        teamserverapi::AuthRequest request;
        request.set_username("admin");
        request.set_password(password);
        teamserverapi::AuthResponse response;
        const grpc::Status status = stub.Authenticate(&context, request, &response);
        if (status.ok() && response.status() == teamserverapi::OK)
            return;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    assert(false && "TeamServer did not become ready");
}

void testFreshReleaseBootstrapsUniqueSecureRuntime()
{
    ScopedPath runtime(copyRuntime());
    const fs::path release = runtime.path() / "Release";
    const fs::path binary = release / "TeamServer" / "TeamServer";
    const fs::path instance = runtime.path() / "instance";
    const int port = reservePort();
    assert(fs::exists(binary));
    assert(!fs::exists(release / "TeamServer" / "server.key"));
    assert(!fs::exists(release / "TeamServer" / "auth_credentials.json"));

    initializeInstance(binary, instance, port);
    const auto profile = nlohmann::json::parse(readFile(instance / "client" / "client-profile.json"));
    const std::string rootCertificate = profile["tls"]["root_certificates_pem"].get<std::string>();
    const std::string password = bootstrapValue(instance / "secrets" / "bootstrap.txt", "password");
    assert(!password.empty());

    grpc::SslCredentialsOptions credentials;
    credentials.pem_root_certs = rootCertificate;
    grpc::ChannelArguments arguments;
    arguments.SetMaxReceiveMessageSize(64 * 1024 * 1024);
    arguments.SetMaxSendMessageSize(64 * 1024 * 1024);
    auto channel = grpc::CreateCustomChannel(
        "localhost:" + std::to_string(port), grpc::SslCredentials(credentials), arguments);
    auto stub = teamserverapi::TeamServerApi::NewStub(channel);

    ScopedServer server(binary, instance);
    server.start();
    waitUntilReady(*stub, server, password);

    grpc::ClientContext authenticationContext;
    teamserverapi::AuthRequest authenticationRequest;
    authenticationRequest.set_username("admin");
    authenticationRequest.set_password(password);
    teamserverapi::AuthResponse authenticationResponse;
    assert(stub->Authenticate(&authenticationContext, authenticationRequest, &authenticationResponse).ok());
    assert(authenticationResponse.status() == teamserverapi::OK);

    grpc::ClientContext listenersContext;
    listenersContext.AddMetadata("authorization", "Bearer " + authenticationResponse.token());
    teamserverapi::Empty empty;
    auto listeners = stub->ListListeners(&listenersContext, empty);
    teamserverapi::Listener listener;
    assert(!listeners->Read(&listener));
    assert(listeners->Finish().ok());
}
} // namespace

int main()
{
    testFreshReleaseBootstrapsUniqueSecureRuntime();
    return 0;
}

