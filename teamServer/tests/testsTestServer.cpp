#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <unistd.h>

#include <grpcpp/support/string_ref.h>

#include "TeamServerAuth.hpp"
#include "TeamServerBootstrap.hpp"

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

fs::path makeTempDirectory(const std::string& name)
{
    fs::path root = fs::temp_directory_path() / ("c2teamserver-" + name + "-" + std::to_string(::getpid()));
    fs::create_directories(root);
    return root;
}

void writeFile(const fs::path& path, const std::string& content)
{
    std::ofstream output(path, std::ios::binary);
    output << content;
}

void testLoadConfigFile()
{
    ScopedPath tempDir(makeTempDirectory("config"));
    fs::path validConfig = tempDir.path() / "config.json";
    writeFile(validConfig, R"({"ServerGRPCAdd":"127.0.0.1","ServerGRPCPort":"50051"})");

    auto loadedConfig = loadTeamServerConfigFile(validConfig.string());
    assert(loadedConfig["ServerGRPCAdd"] == "127.0.0.1");
    assert(loadedConfig["ServerGRPCPort"] == "50051");

    bool missingFileRaised = false;
    try
    {
        (void)loadTeamServerConfigFile((tempDir.path() / "missing.json").string());
    }
    catch (const std::runtime_error&)
    {
        missingFileRaised = true;
    }
    assert(missingFileRaised);

    fs::path invalidConfig = tempDir.path() / "invalid.json";
    writeFile(invalidConfig, "{not-json");

    bool invalidJsonRaised = false;
    try
    {
        (void)loadTeamServerConfigFile(invalidConfig.string());
    }
    catch (const std::runtime_error&)
    {
        invalidJsonRaised = true;
    }
    assert(invalidJsonRaised);
}

void testLoadTlsMaterial()
{
    ScopedPath tempDir(makeTempDirectory("tls"));
    fs::path cert = tempDir.path() / "server.crt";
    fs::path key = tempDir.path() / "server.key";
    fs::path root = tempDir.path() / "root.crt";
    writeFile(cert, "CERT");
    writeFile(key, "KEY");
    writeFile(root, "ROOT");

    nlohmann::json config = {
        {"ServCrtFile", cert.string()},
        {"ServKeyFile", key.string()},
        {"RootCA", root.string()},
        {"LogLevel", "off"}};

    auto logger = createTeamServerLogger(config);
    auto tlsMaterial = loadTeamServerTlsMaterial(config, logger);

    assert(tlsMaterial.certificate == "CERT");
    assert(tlsMaterial.key == "KEY");
    assert(tlsMaterial.rootCertificate == "ROOT");
    assert(buildTeamServerGrpcAddress({
               {"ServerGRPCAdd", "127.0.0.1"},
               {"ServerGRPCPort", "50051"}}) == "127.0.0.1:50051");
}

void testAuthManagerRoundTrip()
{
    ScopedPath tempDir(makeTempDirectory("auth"));
    fs::path credentials = tempDir.path() / "auth.json";
    writeFile(credentials, R"({
        "token_ttl_minutes": 10,
        "users": [
            {
                "username": "operator",
                "password": "secret"
            }
        ]
    })");

    nlohmann::json config = {
        {"AuthCredentialsFile", credentials.string()},
        {"LogLevel", "off"}};

    auto logger = createTeamServerLogger(config);
    TeamServerAuthManager authManager(logger);
    authManager.configure(config);

    teamserverapi::AuthRequest validRequest;
    validRequest.set_username("operator");
    validRequest.set_password("secret");

    teamserverapi::AuthResponse validResponse;
    assert(authManager.authenticate(validRequest, validResponse).ok());
    assert(validResponse.status() == teamserverapi::OK);
    assert(!validResponse.token().empty());

    std::string metadataKey = "authorization";
    std::string metadataValue = "Bearer " + validResponse.token();
    std::multimap<grpc::string_ref, grpc::string_ref> metadata;
    metadata.emplace(
        grpc::string_ref(metadataKey.data(), metadataKey.size()),
        grpc::string_ref(metadataValue.data(), metadataValue.size()));

    assert(authManager.ensureAuthenticated(metadata).ok());

    teamserverapi::AuthRequest invalidRequest;
    invalidRequest.set_username("operator");
    invalidRequest.set_password("wrong");

    teamserverapi::AuthResponse invalidResponse;
    assert(authManager.authenticate(invalidRequest, invalidResponse).ok());
    assert(invalidResponse.status() == teamserverapi::KO);

    std::multimap<grpc::string_ref, grpc::string_ref> missingMetadata;
    assert(!authManager.ensureAuthenticated(missingMetadata).ok());
}
} // namespace

int main()
{
    testLoadConfigFile();
    testLoadTlsMaterial();
    testAuthManagerRoundTrip();
    return 0;
}
