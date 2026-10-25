#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include <grpcpp/support/string_ref.h>

#include "TeamServerAuth.hpp"
#include "TeamServerBootstrap.hpp"

extern "C" int argon2id_hash_encoded(unsigned int, unsigned int, unsigned int,
    const void*, size_t, const void*, size_t, size_t, char*, size_t);

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
    const std::string password = "secret";
    const std::string salt = "fixed-tests-salt";
    char encoded[256] {};
    assert(argon2id_hash_encoded(2, 19456, 1, password.data(), password.size(),
        salt.data(), salt.size(), 32, encoded, sizeof(encoded)) == 0);
    writeFile(credentials, nlohmann::json({
        {"token_ttl_minutes", 10},
        {"users", {{{"username", "operator"}, {"password_hash", encoded}}}}
    }).dump());

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

    std::string authenticatedUsername;
    assert(authManager.ensureAuthenticated(metadata, &authenticatedUsername).ok());
    assert(authenticatedUsername == "operator");

    teamserverapi::AuthRequest invalidRequest;
    invalidRequest.set_username("operator");
    invalidRequest.set_password("wrong");

    teamserverapi::AuthResponse invalidResponse;
    assert(authManager.authenticate(invalidRequest, invalidResponse).ok());
    assert(invalidResponse.status() == teamserverapi::KO);

    std::multimap<grpc::string_ref, grpc::string_ref> missingMetadata;
    assert(!authManager.ensureAuthenticated(missingMetadata).ok());

    TeamServerAuthManager missingManager(logger);
    bool missingRejected = false;
    try { missingManager.configure({{"LogLevel", "off"}}); }
    catch (const std::runtime_error&) { missingRejected = true; }
    assert(missingRejected);
    assert(!missingManager.ensureAuthenticated(missingMetadata).ok());

    writeFile(credentials, R"({"users":[{"username":"operator","password":"secret"}]})");
    TeamServerAuthManager plaintextManager(logger);
    bool plaintextRejected = false;
    try { plaintextManager.configure(config); }
    catch (const std::runtime_error&) { plaintextRejected = true; }
    assert(plaintextRejected);

    writeFile(credentials, R"({"users":[{"username":"admin","password_hash":"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"}]})");
    TeamServerAuthManager legacyManager(logger);
    legacyManager.configure(config);
    teamserverapi::AuthRequest legacyRequest;
    legacyRequest.set_username("admin");
    legacyRequest.set_password("admin");
    teamserverapi::AuthResponse legacyResponse;
    assert(legacyManager.authenticate(legacyRequest, legacyResponse).ok());
    assert(legacyResponse.status() == teamserverapi::OK);
    std::ifstream migratedInput(credentials);
    auto migratedCredentials = nlohmann::json::parse(migratedInput);
    assert(migratedCredentials["users"][0]["password_hash"].get<std::string>().rfind("$argon2id$", 0) == 0);
}

void testAuditLogIsPrivateAndIndependentOfDiagnosticLevel()
{
    ScopedPath tempDir(makeTempDirectory("audit"));
    const fs::path path = tempDir.path() / "TeamServer.audit.jsonl";
    auto logger = createTeamServerAuditLogger(path.string());
    assert(logger->level() == spdlog::level::info);
    logger->info(R"({"action":"StopSession","outcome":"accepted"})");
    logger->flush();

    std::ifstream input(path);
    const auto record = nlohmann::json::parse(input);
    assert(record["action"] == "StopSession");
    assert(record["outcome"] == "accepted");
    struct stat fileInfo {};
    assert(::stat(path.c_str(), &fileInfo) == 0);
    assert((fileInfo.st_mode & 0777) == 0600);
}
} // namespace

int main()
{
    testLoadConfigFile();
    testLoadTlsMaterial();
    testAuthManagerRoundTrip();
    testAuditLogIsPrivateAndIndependentOfDiagnosticLevel();
    return 0;
}
