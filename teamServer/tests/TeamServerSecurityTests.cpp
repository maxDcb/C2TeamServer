#include <cassert>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include <grpcpp/support/string_ref.h>
#undef assert
#define assert(condition) do { if (!(condition)) throw std::runtime_error( \
    std::string("test assertion failed: ") + #condition); } while (false)


#include "TeamServerAuthorization.hpp"
#include "TeamServerBootstrap.hpp"
#include "TeamServerInstance.hpp"

namespace fs = std::filesystem;

namespace
{
class ScopedPath
{
public:
    explicit ScopedPath(fs::path path)
        : m_path(std::move(path))
    {
        fs::remove_all(m_path);
        fs::create_directories(m_path);
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

fs::path temporaryRoot(const std::string& name)
{
    return fs::temp_directory_path()
        / ("c2teamserver-security-" + name + "-" + std::to_string(::getpid()));
}

std::string readFile(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), {});
}

std::string bootstrapValue(const fs::path& bootstrap, const std::string& key)
{
    std::ifstream input(bootstrap);
    std::string line;
    while (std::getline(input, line))
    {
        const std::string prefix = key + "=";
        if (line.rfind(prefix, 0) == 0)
            return line.substr(prefix.size());
    }
    return {};
}

TeamServerInstanceResult initialize(const fs::path& root, const fs::path& releaseRoot)
{
    TeamServerInstanceOptions options;
    options.instanceRoot = root;
    options.releaseRoot = releaseRoot;
    options.profile = TeamServerProfile::Standalone;
    options.hostname = "localhost";
    options.listenAddress = "127.0.0.1";
    return initializeTeamServerInstance(options);
}

void testInstancesHaveUniqueDeploymentSecrets()
{
    ScopedPath root(temporaryRoot("unique"));
    const fs::path releaseRoot = root.path() / "Release";
    fs::create_directories(releaseRoot);
    const TeamServerInstanceResult first = initialize(root.path() / "first", releaseRoot);
    const TeamServerInstanceResult second = initialize(root.path() / "second", releaseRoot);

    assert(first.certificateFingerprint.size() == 64);
    assert(second.certificateFingerprint.size() == 64);
    assert(first.certificateFingerprint != second.certificateFingerprint);
    assert(readFile(root.path() / "first" / "secrets" / "server.key")
        != readFile(root.path() / "second" / "secrets" / "server.key"));
    assert(bootstrapValue(first.bootstrapFile, "password").size() >= 32);
    assert(!fs::exists(releaseRoot / "server.key"));
    assert(!fs::exists(releaseRoot / "credentials.json"));

#ifndef _WIN32
    const auto keyPermissions = fs::status(root.path() / "first" / "secrets" / "server.key").permissions();
    assert((keyPermissions & fs::perms::group_all) == fs::perms::none);
    assert((keyPermissions & fs::perms::others_all) == fs::perms::none);
#endif
}

void testAuthenticationIsFailClosedAndRoleAware()
{
    ScopedPath root(temporaryRoot("auth"));
    const fs::path releaseRoot = root.path() / "Release";
    fs::create_directories(releaseRoot);
    const TeamServerInstanceResult instance = initialize(root.path() / "instance", releaseRoot);
    const nlohmann::json config = loadTeamServerConfigFile(instance.configFile.string());
    const auto logger = createTeamServerLogger(config);

    TeamServerAuthorization authorization(logger);
    authorization.configure(config);

    teamserverapi::AuthRequest request;
    request.set_username("admin");
    request.set_password(bootstrapValue(instance.bootstrapFile, "password"));
    teamserverapi::AuthResponse response;
    assert(authorization.authenticate(request, response, "test-peer").ok());
    assert(response.status() == teamserverapi::OK);

    const std::string key = "authorization";
    const std::string value = "Bearer " + response.token();
    std::multimap<grpc::string_ref, grpc::string_ref> metadata;
    metadata.emplace(grpc::string_ref(key.data(), key.size()), grpc::string_ref(value.data(), value.size()));
    TeamServerAuthorization::Principal principal;
    assert(authorization.authorize(metadata, TeamServerAuthorization::Role::Admin, &principal).ok());
    assert(principal.username == "admin");
    assert(principal.role == TeamServerAuthorization::Role::Admin);

    nlohmann::json invalid = config;
    invalid.erase("Security");
    bool rejected = false;
    try
    {
        TeamServerAuthorization invalidAuthorization(logger);
        invalidAuthorization.configure(invalid);
    }
    catch (const std::runtime_error&)
    {
        rejected = true;
    }
    assert(rejected);
}

void testTlsMaterialIsDeploymentOwnedAndValidated()
{
    ScopedPath root(temporaryRoot("tls"));
    const fs::path releaseRoot = root.path() / "Release";
    fs::create_directories(releaseRoot);
    const TeamServerInstanceResult instance = initialize(root.path() / "instance", releaseRoot);
    const nlohmann::json config = loadTeamServerConfigFile(instance.configFile.string());
    const auto logger = createTeamServerLogger(config);
    const TeamServerTlsMaterial material = loadTeamServerTlsMaterial(config, logger);
    assert(material.certificate.find("BEGIN CERTIFICATE") != std::string::npos);
    assert(material.key.find("BEGIN PRIVATE KEY") != std::string::npos);

    TeamServerInstanceOptions production;
    production.instanceRoot = root.path() / "production";
    production.releaseRoot = releaseRoot;
    production.profile = TeamServerProfile::Production;
    bool rejected = false;
    try
    {
        (void)initializeTeamServerInstance(production);
    }
    catch (const std::runtime_error&)
    {
        rejected = true;
    }
    assert(rejected);
}
} // namespace

int main()
{
    testInstancesHaveUniqueDeploymentSecrets();
    testAuthenticationIsFailClosedAndRoleAware();
    testTlsMaterialIsDeploymentOwnedAndValidated();
    return 0;
}

