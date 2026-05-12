#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include "TeamServerCredentialVaultService.hpp"
#include "spdlog/logger.h"

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
    fs::path root = fs::temp_directory_path() / ("c2teamserver-credential-vault-" + name + "-" + std::to_string(::getpid()));
    fs::create_directories(root);
    return root;
}

std::shared_ptr<spdlog::logger> makeLogger()
{
    auto logger = std::make_shared<spdlog::logger>("credential-vault-tests");
    logger->set_level(spdlog::level::off);
    return logger;
}

void require(bool condition, const std::string& message)
{
    if (!condition)
        throw std::runtime_error(message);
}

TeamServerRuntimeConfig makeRuntimeConfig(const fs::path& root)
{
    TeamServerRuntimeConfig runtimeConfig;
    runtimeConfig.dataRoot = root.string();
    runtimeConfig.credentialVaultDirectoryPath = (root / "CredentialVault").string();
    runtimeConfig.credentialVaultPath = (root / "CredentialVault" / "vault.json").string();
    runtimeConfig.credentialVaultKeyFile = (root / "CredentialVault" / "vault.key").string();
    fs::create_directories(runtimeConfig.credentialVaultDirectoryPath);
    return runtimeConfig;
}

void testAddListRevealAndPersistence()
{
    ScopedPath tempRoot(makeTempDirectory("basic"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());

    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);
    teamserverapi::CredentialUpsertRequest addRequest;
    addRequest.set_display_name("corp alice");
    addRequest.set_type("password");
    addRequest.set_username("alice");
    addRequest.set_domain("CORP");
    addRequest.set_protocol("smb");
    teamserverapi::CredentialSecret* password = addRequest.add_secrets();
    password->set_name("password");
    password->set_value("secret-value");

    teamserverapi::OperationAck ack;
    require(service.addCredential(addRequest, &ack).ok(), "addCredential RPC status failed");
    require(ack.status() == teamserverapi::OK, "addCredential ack failed: " + ack.message());
    require(ack.message().find("cred:") != std::string::npos, "addCredential did not return credential reference");

    std::vector<teamserverapi::CredentialSummary> summaries;
    teamserverapi::CredentialQuery query;
    require(service.listCredentials(query, [&](const teamserverapi::CredentialSummary& summary)
    {
        summaries.push_back(summary);
        return true;
    }).ok(), "listCredentials RPC status failed");
    require(summaries.size() == 1, "listCredentials did not return stored credential");
    require(summaries[0].username() == "alice", "stored username mismatch");
    require(summaries[0].secret_fields_size() == 1, "secret fields metadata missing");

    teamserverapi::CredentialSelector selector;
    selector.set_credential_id(summaries[0].credential_id().substr(0, 8));
    selector.set_reveal_secret(false);
    teamserverapi::CredentialDetail detail;
    require(service.getCredential(selector, &detail).ok(), "getCredential hidden RPC status failed");
    require(detail.status() == teamserverapi::OK, "getCredential hidden failed: " + detail.message());
    require(detail.secrets_size() == 0, "hidden credential unexpectedly revealed secrets");

    selector.set_reveal_secret(true);
    require(service.getCredential(selector, &detail).ok(), "getCredential reveal RPC status failed");
    require(detail.status() == teamserverapi::OK, "getCredential reveal failed: " + detail.message());
    require(detail.secrets_size() == 1, "credential reveal did not return secret");
    bool revealedPassword = false;
    for (const auto& secret : detail.secrets())
        revealedPassword = revealedPassword || (secret.name() == "password" && secret.value() == "secret-value");
    require(revealedPassword, "revealed password mismatch");

    std::ifstream vaultFile(runtimeConfig.credentialVaultPath);
    std::string vaultContent((std::istreambuf_iterator<char>(vaultFile)), std::istreambuf_iterator<char>());
    require(vaultContent.find("secret-value") == std::string::npos, "vault file contains plaintext secret");

    TeamServerCredentialVaultService reloadedService(makeLogger(), runtimeConfig);
    std::vector<teamserverapi::CredentialSummary> reloaded;
    require(reloadedService.listCredentials(teamserverapi::CredentialQuery(), [&](const teamserverapi::CredentialSummary& summary)
    {
        reloaded.push_back(summary);
        return true;
    }).ok(), "reloaded listCredentials RPC status failed");
    require(reloaded.size() == 1, "credential was not persisted");
}

void testTerminalIntegration()
{
    ScopedPath tempRoot(makeTempDirectory("terminal"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);

    teamserverapi::TerminalCommandRequest addCommand;
    addCommand.set_command("cred add");
    addCommand.set_data(R"({"username":"bob","domain":"CORP","password":"super-secret"})");
    teamserverapi::TerminalCommandResponse response;
    require(service.handleTerminalCommand({"cred", "add"}, addCommand, &response).ok(), "terminal cred add RPC status failed");
    require(response.status() == teamserverapi::OK, "terminal cred add failed: " + response.message());

    teamserverapi::TerminalCommandRequest listCommand;
    listCommand.set_command("cred list bob");
    require(service.handleTerminalCommand({"cred", "list", "bob"}, listCommand, &response).ok(), "terminal cred list RPC status failed");
    require(response.status() == teamserverapi::OK, "terminal cred list failed: " + response.message());
    require(response.result().find("bob") != std::string::npos, "terminal cred list missing username");
    require(response.result().find("super-secret") == std::string::npos, "terminal cred list leaked secret");
}
} // namespace

int main()
{
    testAddListRevealAndPersistence();
    testTerminalIntegration();
    return 0;
}
