#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
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

void testUpdateDeleteAndExpiredFiltering()
{
    ScopedPath tempRoot(makeTempDirectory("lifecycle"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);

    teamserverapi::CredentialUpsertRequest expiredRequest;
    expiredRequest.set_display_name("expired alice");
    expiredRequest.set_type("password");
    expiredRequest.set_username("alice");
    expiredRequest.set_domain("CORP");
    expiredRequest.set_expires_at("2000-01-01T00:00:00Z");
    teamserverapi::CredentialSecret* expiredPassword = expiredRequest.add_secrets();
    expiredPassword->set_name("password");
    expiredPassword->set_value("old-secret");
    teamserverapi::OperationAck ack;
    require(service.addCredential(expiredRequest, &ack).ok(), "expired addCredential RPC status failed");
    require(ack.status() == teamserverapi::OK, "expired addCredential failed: " + ack.message());

    std::vector<teamserverapi::CredentialSummary> activeCredentials;
    require(service.listCredentials(teamserverapi::CredentialQuery(), [&](const teamserverapi::CredentialSummary& summary)
    {
        activeCredentials.push_back(summary);
        return true;
    }).ok(), "active listCredentials RPC status failed");
    require(activeCredentials.empty(), "expired credential should be hidden by default");

    teamserverapi::CredentialQuery includeExpiredQuery;
    includeExpiredQuery.set_include_expired(true);
    std::vector<teamserverapi::CredentialSummary> allCredentials;
    require(service.listCredentials(includeExpiredQuery, [&](const teamserverapi::CredentialSummary& summary)
    {
        allCredentials.push_back(summary);
        return true;
    }).ok(), "include expired listCredentials RPC status failed");
    require(allCredentials.size() == 1, "include expired did not return expired credential");

    teamserverapi::CredentialUpsertRequest updateRequest;
    updateRequest.set_credential_id(allCredentials[0].credential_id().substr(0, 8));
    updateRequest.set_expires_at("2999-01-01T00:00:00Z");
    updateRequest.set_replace_secrets(true);
    teamserverapi::CredentialSecret* newPassword = updateRequest.add_secrets();
    newPassword->set_name("password");
    newPassword->set_value("new-secret");
    require(service.updateCredential(updateRequest, &ack).ok(), "updateCredential RPC status failed");
    require(ack.status() == teamserverapi::OK, "updateCredential failed: " + ack.message());

    activeCredentials.clear();
    require(service.listCredentials(teamserverapi::CredentialQuery(), [&](const teamserverapi::CredentialSummary& summary)
    {
        activeCredentials.push_back(summary);
        return true;
    }).ok(), "post-update listCredentials RPC status failed");
    require(activeCredentials.size() == 1, "updated credential should be active");

    teamserverapi::CredentialSelector selector;
    selector.set_credential_id(activeCredentials[0].credential_id().substr(0, 8));
    selector.set_reveal_secret(true);
    teamserverapi::CredentialDetail detail;
    require(service.getCredential(selector, &detail).ok(), "updated getCredential RPC status failed");
    require(detail.status() == teamserverapi::OK, "updated getCredential failed: " + detail.message());
    require(detail.secrets_size() == 1, "updated credential secret count mismatch");
    require(detail.secrets(0).value() == "new-secret", "updated credential secret mismatch");

    require(service.deleteCredential(selector, &ack).ok(), "deleteCredential RPC status failed");
    require(ack.status() == teamserverapi::OK, "deleteCredential failed: " + ack.message());
    activeCredentials.clear();
    require(service.listCredentials(includeExpiredQuery, [&](const teamserverapi::CredentialSummary& summary)
    {
        activeCredentials.push_back(summary);
        return true;
    }).ok(), "post-delete listCredentials RPC status failed");
    require(activeCredentials.empty(), "deleted credential still listed");
}

void testRejectsEmptyAndAmbiguousSelectors()
{
    ScopedPath tempRoot(makeTempDirectory("selectors"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);

    auto addCredential = [&](const std::string& credentialId, const std::string& username)
    {
        teamserverapi::CredentialUpsertRequest request;
        request.set_credential_id(credentialId);
        request.set_username(username);
        teamserverapi::CredentialSecret* password = request.add_secrets();
        password->set_name("password");
        password->set_value("secret");
        teamserverapi::OperationAck ack;
        require(service.addCredential(request, &ack).ok(), "selector fixture add RPC failed");
        require(ack.status() == teamserverapi::OK, "selector fixture add failed: " + ack.message());
    };

    addCredential("abcdef0011111111", "alice");
    addCredential("abcdef0022222222", "bob");

    teamserverapi::CredentialSelector selector;
    selector.set_reveal_secret(true);
    teamserverapi::CredentialDetail detail;
    require(service.getCredential(selector, &detail).ok(), "empty selector get RPC failed");
    require(detail.status() == teamserverapi::KO, "empty selector unexpectedly returned a credential");
    require(detail.message().find("required") != std::string::npos, "empty selector error was not explicit");

    teamserverapi::OperationAck ack;
    require(service.deleteCredential(selector, &ack).ok(), "empty selector delete RPC failed");
    require(ack.status() == teamserverapi::KO, "empty selector unexpectedly deleted a credential");

    selector.set_credential_id("abcdef00");
    require(service.getCredential(selector, &detail).ok(), "ambiguous selector get RPC failed");
    require(detail.status() == teamserverapi::KO, "ambiguous selector unexpectedly returned a credential");
    require(detail.message().find("ambiguous") != std::string::npos, "ambiguous selector error was not explicit");
    require(service.deleteCredential(selector, &ack).ok(), "ambiguous selector delete RPC failed");
    require(ack.status() == teamserverapi::KO, "ambiguous selector unexpectedly deleted a credential");

    std::vector<teamserverapi::CredentialSummary> remaining;
    require(service.listCredentials(teamserverapi::CredentialQuery(), [&](const teamserverapi::CredentialSummary& summary)
    {
        remaining.push_back(summary);
        return true;
    }).ok(), "selector fixture list failed");
    require(remaining.size() == 2, "invalid selectors changed the vault contents");
}

void testCorruptVaultFailsClosed()
{
    ScopedPath tempRoot(makeTempDirectory("corrupt"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    const std::string originalContent = "{not-valid-json\n";
    {
        std::ofstream output(runtimeConfig.credentialVaultPath);
        output << originalContent;
    }

    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);
    teamserverapi::CredentialUpsertRequest request;
    request.set_username("must-not-be-written");
    teamserverapi::CredentialSecret* password = request.add_secrets();
    password->set_name("password");
    password->set_value("secret");
    teamserverapi::OperationAck ack;
    require(service.addCredential(request, &ack).ok(), "corrupt vault add RPC failed");
    require(ack.status() == teamserverapi::KO, "corrupt vault accepted a mutation");

    std::ifstream input(runtimeConfig.credentialVaultPath);
    const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    require(content == originalContent, "corrupt vault was overwritten after a failed load");
}

void testWrongKeyFailsClosed()
{
    ScopedPath tempRoot(makeTempDirectory("wrong-key"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService initialService(makeLogger(), runtimeConfig);

    teamserverapi::CredentialUpsertRequest initialRequest;
    initialRequest.set_username("alice");
    teamserverapi::CredentialSecret* initialPassword = initialRequest.add_secrets();
    initialPassword->set_name("password");
    initialPassword->set_value("original-secret");
    teamserverapi::OperationAck ack;
    require(initialService.addCredential(initialRequest, &ack).ok(), "wrong-key fixture add RPC failed");
    require(ack.status() == teamserverapi::OK, "wrong-key fixture add failed");

    std::ifstream vaultBefore(runtimeConfig.credentialVaultPath);
    const std::string originalVault((std::istreambuf_iterator<char>(vaultBefore)), std::istreambuf_iterator<char>());
    {
        std::ofstream keyFile(runtimeConfig.credentialVaultKeyFile, std::ios::out | std::ios::trunc);
        keyFile << std::string(64, '0') << "\n";
    }

    TeamServerCredentialVaultService reloadedService(makeLogger(), runtimeConfig);
    teamserverapi::CredentialUpsertRequest rejectedRequest;
    rejectedRequest.set_username("bob");
    teamserverapi::CredentialSecret* rejectedPassword = rejectedRequest.add_secrets();
    rejectedPassword->set_name("password");
    rejectedPassword->set_value("must-not-be-written");
    require(reloadedService.addCredential(rejectedRequest, &ack).ok(), "wrong-key add RPC failed");
    require(ack.status() == teamserverapi::KO, "wrong key accepted a mutation");

    std::ifstream vaultAfter(runtimeConfig.credentialVaultPath);
    const std::string currentVault((std::istreambuf_iterator<char>(vaultAfter)), std::istreambuf_iterator<char>());
    require(currentVault == originalVault, "vault was overwritten after decryption failed");
}

void testMissingKeyFailsClosedWithoutGeneratingReplacement()
{
    ScopedPath tempRoot(makeTempDirectory("missing-key"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService initialService(makeLogger(), runtimeConfig);

    teamserverapi::CredentialUpsertRequest initialRequest;
    initialRequest.set_username("alice");
    teamserverapi::CredentialSecret* initialPassword = initialRequest.add_secrets();
    initialPassword->set_name("password");
    initialPassword->set_value("original-secret");
    teamserverapi::OperationAck ack;
    require(initialService.addCredential(initialRequest, &ack).ok(), "missing-key fixture add RPC failed");
    require(ack.status() == teamserverapi::OK, "missing-key fixture add failed");

    std::ifstream vaultBefore(runtimeConfig.credentialVaultPath);
    const std::string originalVault((std::istreambuf_iterator<char>(vaultBefore)), std::istreambuf_iterator<char>());
    require(fs::remove(runtimeConfig.credentialVaultKeyFile), "could not remove vault key fixture");

    TeamServerCredentialVaultService reloadedService(makeLogger(), runtimeConfig);
    teamserverapi::CredentialUpsertRequest rejectedRequest;
    rejectedRequest.set_username("bob");
    require(reloadedService.addCredential(rejectedRequest, &ack).ok(), "missing-key add RPC failed");
    require(ack.status() == teamserverapi::KO, "missing key accepted a mutation");
    require(!fs::exists(runtimeConfig.credentialVaultKeyFile), "missing key was silently replaced");

    std::ifstream vaultAfter(runtimeConfig.credentialVaultPath);
    const std::string currentVault((std::istreambuf_iterator<char>(vaultAfter)), std::istreambuf_iterator<char>());
    require(currentVault == originalVault, "vault was overwritten after its key was missing");
}

void testFailedSaveRollsBackMutations()
{
    ScopedPath tempRoot(makeTempDirectory("rollback"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);

    teamserverapi::CredentialUpsertRequest initialRequest;
    initialRequest.set_credential_id("1111111111111111");
    initialRequest.set_username("alice");
    teamserverapi::CredentialSecret* initialPassword = initialRequest.add_secrets();
    initialPassword->set_name("password");
    initialPassword->set_value("secret");
    teamserverapi::OperationAck ack;
    require(service.addCredential(initialRequest, &ack).ok(), "rollback fixture add RPC failed");
    require(ack.status() == teamserverapi::OK, "rollback fixture add failed");

    require(::chmod(runtimeConfig.credentialVaultDirectoryPath.c_str(), S_IRUSR | S_IXUSR) == 0, "could not make vault directory read-only");

    teamserverapi::CredentialSelector revealSelector;
    revealSelector.set_credential_id("1111111111111111");
    revealSelector.set_reveal_secret(true);
    teamserverapi::CredentialDetail revealDetail;
    require(service.getCredential(revealSelector, &revealDetail).ok(), "failed-audit reveal RPC failed");
    require(revealDetail.status() == teamserverapi::KO, "credential was revealed without persisting its audit event");
    require(revealDetail.secrets_size() == 0, "failed-audit reveal returned a secret");

    teamserverapi::CredentialUpsertRequest rejectedRequest;
    rejectedRequest.set_credential_id("2222222222222222");
    rejectedRequest.set_username("bob");
    teamserverapi::CredentialSecret* rejectedPassword = rejectedRequest.add_secrets();
    rejectedPassword->set_name("password");
    rejectedPassword->set_value("secret");
    require(service.addCredential(rejectedRequest, &ack).ok(), "failed-save add RPC failed");
    require(ack.status() == teamserverapi::KO, "failed save reported a successful add");

    teamserverapi::CredentialSelector selector;
    selector.set_credential_id("1111111111111111");
    require(service.deleteCredential(selector, &ack).ok(), "failed-save delete RPC failed");
    require(ack.status() == teamserverapi::KO, "failed save reported a successful delete");

    require(::chmod(runtimeConfig.credentialVaultDirectoryPath.c_str(), S_IRWXU) == 0, "could not restore vault directory permissions");

    std::vector<teamserverapi::CredentialSummary> credentials;
    require(service.listCredentials(teamserverapi::CredentialQuery(), [&](const teamserverapi::CredentialSummary& summary)
    {
        credentials.push_back(summary);
        return true;
    }).ok(), "rollback list failed");
    require(credentials.size() == 1, "failed mutations changed the in-memory vault");
    require(credentials[0].credential_id() == "1111111111111111", "failed delete was not rolled back");
}

void testUpdateMaskCanClearMetadata()
{
    ScopedPath tempRoot(makeTempDirectory("clear-fields"));
    TeamServerRuntimeConfig runtimeConfig = makeRuntimeConfig(tempRoot.path());
    TeamServerCredentialVaultService service(makeLogger(), runtimeConfig);

    teamserverapi::CredentialUpsertRequest addRequest;
    addRequest.set_credential_id("3333333333333333");
    addRequest.set_username("alice");
    addRequest.set_domain("CORP");
    addRequest.set_description("temporary description");
    addRequest.set_expires_at("2999-01-01T00:00:00Z");
    addRequest.add_tags("temporary");
    teamserverapi::CredentialSecret* password = addRequest.add_secrets();
    password->set_name("password");
    password->set_value("secret");
    teamserverapi::OperationAck ack;
    require(service.addCredential(addRequest, &ack).ok(), "clear-fields fixture add RPC failed");
    require(ack.status() == teamserverapi::OK, "clear-fields fixture add failed");

    teamserverapi::CredentialUpsertRequest updateRequest;
    updateRequest.set_credential_id("33333333");
    updateRequest.add_update_fields("domain");
    updateRequest.add_update_fields("description");
    updateRequest.add_update_fields("expires_at");
    updateRequest.add_update_fields("tags");
    require(service.updateCredential(updateRequest, &ack).ok(), "clear-fields update RPC failed");
    require(ack.status() == teamserverapi::OK, "clear-fields update failed: " + ack.message());

    teamserverapi::CredentialSelector selector;
    selector.set_credential_id("33333333");
    teamserverapi::CredentialDetail detail;
    require(service.getCredential(selector, &detail).ok(), "clear-fields get RPC failed");
    require(detail.status() == teamserverapi::OK, "clear-fields get failed");
    require(detail.summary().domain().empty(), "update mask did not clear domain");
    require(detail.summary().description().empty(), "update mask did not clear description");
    require(detail.summary().expires_at().empty(), "update mask did not clear expiration");
    require(detail.summary().tags().empty(), "update mask did not clear tags");
    require(detail.summary().secret_fields_size() == 1, "metadata update unexpectedly cleared secrets");
}
} // namespace

int main()
{
    testAddListRevealAndPersistence();
    testTerminalIntegration();
    testUpdateDeleteAndExpiredFiltering();
    testRejectsEmptyAndAmbiguousSelectors();
    testCorruptVaultFailsClosed();
    testWrongKeyFailsClosed();
    testMissingKeyFailsClosedWithoutGeneratingReplacement();
    testFailedSaveRollsBackMutations();
    testUpdateMaskCanClearMetadata();
    return 0;
}
