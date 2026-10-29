#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

#include "TeamServerListenerArtifactService.hpp"

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

class TestListener final : public Listener
{
public:
    TestListener(const std::string& hash, const std::string& type = ListenerHttpsType, const std::string& param1 = "127.0.0.1", const std::string& param2 = "8443")
        : Listener(param1, param2, type)
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

fs::path makeTempDirectory(const std::string& name)
{
    fs::path root = fs::temp_directory_path() / ("c2teamserver-artifacts-" + name + "-" + std::to_string(::getpid()));
    fs::create_directories(root);
    return root;
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("artifact-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.teamServerModulesDirectoryPath = (root / "modules").string();
    runtimeConfig.linuxModulesDirectoryPath = (root / "linux-modules").string();
    runtimeConfig.windowsModulesDirectoryPath = (root / "windows-modules").string();
    runtimeConfig.linuxBeaconsDirectoryPath = (root / "linux-beacons/").string();
    runtimeConfig.windowsBeaconsDirectoryPath = (root / "windows-beacons/").string();
    runtimeConfig.toolsDirectoryPath = (root / "tools").string();
    runtimeConfig.scriptsDirectoryPath = (root / "scripts").string();

    fs::create_directories(runtimeConfig.teamServerModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxModulesDirectoryPath);
    fs::create_directories(runtimeConfig.windowsModulesDirectoryPath);
    fs::create_directories(runtimeConfig.linuxBeaconsDirectoryPath);
    fs::create_directories(runtimeConfig.windowsBeaconsDirectoryPath);
    for (const auto& arch : runtimeConfig.supportedLinuxArchs)
        fs::create_directories(fs::path(runtimeConfig.linuxBeaconsDirectoryPath) / arch);
    for (const auto& arch : runtimeConfig.supportedWindowsArchs)
        fs::create_directories(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / arch);
    fs::create_directories(runtimeConfig.toolsDirectoryPath);
    fs::create_directories(runtimeConfig.scriptsDirectoryPath);
    return runtimeConfig;
}

void writeFile(const fs::path& path, const std::string& content)
{
    std::ofstream output(path, std::ios::binary);
    output << content;
}

std::string infoText(const teamserverapi::ListenerInfoResponse& response)
{
    if (response.status() != teamserverapi::OK) return response.message();
    return response.type() + "\n" + response.address() + "\n" + response.port() + "\n" + response.download_uri();
}

std::string binaryText(const teamserverapi::BeaconBinaryResponse& response)
{
    return response.status() == teamserverapi::OK ? "ok" : response.message();
}

void testInfoListenerForPrimaryAndSecondary()
{
    ScopedPath tempRoot(makeTempDirectory("info"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    nlohmann::json config = {
        {"DomainName", "team.example"},
        {"ListenerHttpsConfig", {{"uriFileDownload", "/drop.bin"}}}};

    auto primary = std::make_shared<TestListener>("listener-primary");
    auto secondarySession = primary->addSession("listener-primary", "ABCDEFGH12345678", "Windows");
    secondarySession->addListener("secondary-hash", ListenerTcpType, "10.0.0.1", "4455");
    std::vector<std::shared_ptr<Listener>> listeners = {primary};

    TeamServerListenerArtifactService service(makeLogger(), config, runtimeConfig, listeners);

    teamserverapi::ListenerInfoResponse response;
    service.getListenerInfo("listener-pri", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "https\nteam.example\n8443\n/drop.bin");
    assert(response.message().empty());

    service.getListenerInfo("secondary", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "tcp\n10.0.0.1\n4455\nnone");

    service.getListenerInfo("missing", &response);
    assert(response.status() == teamserverapi::KO);
    assert(infoText(response) == "Error: Listener not found.");
    assert(response.message() == "Error: Listener not found.");

    listeners.push_back(std::make_shared<TestListener>("listener-primary-other"));
    service.getListenerInfo("listener-pri", &response);
    assert(response.status() == teamserverapi::KO);
    assert(infoText(response) == "Error: Listener reference is ambiguous.");

    service.getListenerInfo("listener-primary", &response);
    assert(response.status() == teamserverapi::OK);

    secondarySession->addListener("secondary-other", ListenerTcpType, "10.0.0.2", "4466");
    service.getListenerInfo("secondary", &response);
    assert(response.status() == teamserverapi::KO);
    assert(infoText(response) == "Error: Listener reference is ambiguous.");

    service.getListenerInfo("secondary-hash", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "tcp\n10.0.0.1\n4455\nnone");

    listeners.push_back(std::make_shared<TestListener>("listener-primary"));
    service.getListenerInfo("listener-primary", &response);
    assert(response.status() == teamserverapi::KO);
    assert(infoText(response) == "Error: Listener reference is ambiguous.");
}

void testInfoListenerAddressFallbacks()
{
    ScopedPath tempRoot(makeTempDirectory("info-fallback"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    nlohmann::json config = {
        {"DomainName", ""},
        {"ExposedIp", ""},
        {"IpInterface", "missing0"},
        {"ListenerHttpsConfig", {{"uriFileDownload", "/drop.bin"}}}};

    auto primary = std::make_shared<TestListener>("listener-primary", ListenerHttpsType, "192.168.56.10", "8443");
    std::vector<std::shared_ptr<Listener>> listeners = {primary};

    TeamServerListenerArtifactService service(
        makeLogger(),
        config,
        runtimeConfig,
        listeners,
        [](const std::string&)
        {
            return "";
        });

    teamserverapi::ListenerInfoResponse response;
    service.getListenerInfo("listener-pri", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "https\n192.168.56.10\n8443\n/drop.bin");

    config["ExposedIp"] = "203.0.113.10";
    TeamServerListenerArtifactService exposedService(makeLogger(), config, runtimeConfig, listeners);
    exposedService.getListenerInfo("listener-pri", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "https\n203.0.113.10\n8443\n/drop.bin");

    config["ExposedIp"] = "";
    config["IpInterface"] = "eth-test";
    TeamServerListenerArtifactService interfaceService(
        makeLogger(),
        config,
        runtimeConfig,
        listeners,
        [](const std::string& interface)
        {
            return interface == "eth-test" ? "10.10.10.10" : "";
        });
    interfaceService.getListenerInfo("listener-pri", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "https\n10.10.10.10\n8443\n/drop.bin");

    auto wildcard = std::make_shared<TestListener>("wildcard-listener", ListenerHttpsType, "0.0.0.0", "8443");
    std::vector<std::shared_ptr<Listener>> wildcardListeners = {wildcard};
    config["IpInterface"] = "";
    TeamServerListenerArtifactService wildcardService(makeLogger(), config, runtimeConfig, wildcardListeners);
    wildcardService.getListenerInfo("wildcard", &response);
    assert(response.status() == teamserverapi::OK);
    assert(infoText(response) == "https\n127.0.0.1\n8443\n/drop.bin");

    auto ipv6 = std::make_shared<TestListener>("ipv6-listener", ListenerHttpsType, "::1", "8443");
    std::vector<std::shared_ptr<Listener>> ipv6Listeners = {ipv6};
    config["ListenerHttpsConfig"]["uriFileDownload"] = "/downloads/";
    TeamServerListenerArtifactService ipv6Service(makeLogger(), config, runtimeConfig, ipv6Listeners);
    assert(ipv6Service.hostedArtifactUrl(ipv6, "payload.bin") == "https://[::1]:8443/downloads/payload.bin");
}

void testGetBeaconBinaryForPrimaryAndSecondary()
{
    ScopedPath tempRoot(makeTempDirectory("beacon"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    writeFile(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / "x64" / "BeaconHttp.exe", "HTTPBIN-X64");
    writeFile(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / "x86" / "BeaconHttp.exe", "HTTPBIN-X86");
    writeFile(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / "arm64" / "BeaconHttp.exe", "HTTPBIN-ARM64");
    writeFile(fs::path(runtimeConfig.windowsBeaconsDirectoryPath) / "x64" / "BeaconSmb.exe", "SMBBIN-X64");
    writeFile(fs::path(runtimeConfig.linuxBeaconsDirectoryPath) / "x64" / "BeaconHttp", "LINUX-HTTPBIN-X64");
    writeFile(fs::path(runtimeConfig.linuxBeaconsDirectoryPath) / "x64" / "BeaconSmb", "STALE-SMB");

    nlohmann::json config = nlohmann::json::object();
    auto primary = std::make_shared<TestListener>("listener-primary");
    auto secondarySession = primary->addSession("listener-primary", "ABCDEFGH12345678", "Windows");
    secondarySession->addListener("secondary-hash", ListenerSmbType, "namedpipe", "none");
    std::vector<std::shared_ptr<Listener>> listeners = {primary};

    TeamServerListenerArtifactService service(makeLogger(), config, runtimeConfig, listeners);

    teamserverapi::BeaconBinaryResponse response;
    service.getBeaconBinary("listener-pri", "", "", &response);
    assert(response.status() == teamserverapi::OK);
    assert(binaryText(response) == "ok");
    assert(response.data() == "HTTPBIN-X64");

    service.getBeaconBinary("listener-pri", "Windows", "x86", &response);
    assert(response.status() == teamserverapi::OK);
    assert(binaryText(response) == "ok");
    assert(response.data() == "HTTPBIN-X86");

    service.getBeaconBinary("listener-pri", "Windows", "amd64", &response);
    assert(response.status() == teamserverapi::OK);
    assert(binaryText(response) == "ok");
    assert(response.data() == "HTTPBIN-X64");

    service.getBeaconBinary("listener-pri", "Windows", "arm64", &response);
    assert(response.status() == teamserverapi::OK);
    assert(binaryText(response) == "ok");
    assert(response.data() == "HTTPBIN-ARM64");

    service.getBeaconBinary("listener-pri", "Windows", "sparc", &response);
    assert(response.status() == teamserverapi::KO);
    assert(binaryText(response) == "Error: Unsupported architecture.");
    assert(response.message() == "Error: Unsupported architecture.");

    service.getBeaconBinary("listener-pri", "Linux", "x64", &response);
    assert(response.status() == teamserverapi::OK);
    assert(binaryText(response) == "ok");
    assert(response.data() == "LINUX-HTTPBIN-X64");

    service.getBeaconBinary("secondary", "", "", &response);
    assert(response.status() == teamserverapi::OK);
    assert(binaryText(response) == "ok");
    assert(response.message().empty());
    assert(response.data() == "SMBBIN-X64");

    service.getBeaconBinary("secondary", "Linux", "x64", &response);
    assert(response.status() == teamserverapi::KO);
    assert(binaryText(response) == "Error: SMB is supported only on Windows.");

    listeners.push_back(std::make_shared<TestListener>("listener-primary-other"));
    service.getBeaconBinary("listener-pri", "", "", &response);
    assert(response.status() == teamserverapi::KO);
    assert(binaryText(response) == "Error: Listener reference is ambiguous.");

    service.getBeaconBinary("listener-primary", "", "", &response);
    assert(response.status() == teamserverapi::OK);
    assert(response.data() == "HTTPBIN-X64");
}
} // namespace

int main()
{
    testInfoListenerForPrimaryAndSecondary();
    testInfoListenerAddressFallbacks();
    testGetBeaconBinaryForPrimaryAndSecondary();
    return 0;
}
