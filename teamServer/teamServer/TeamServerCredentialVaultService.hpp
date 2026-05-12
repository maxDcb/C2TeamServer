#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
#include "TeamServerRuntimeConfig.hpp"
#include "nlohmann/json.hpp"

namespace spdlog
{
class logger;
}

struct TeamServerCredentialRecord
{
    std::string credentialId;
    std::string displayName;
    std::string type;
    std::string username;
    std::string domain;
    std::string realm;
    std::string target;
    std::string protocol;
    std::vector<std::string> tags;
    std::string description;
    std::string createdAt;
    std::string updatedAt;
    std::string lastUsedAt;
    std::string expiresAt;
    std::map<std::string, std::string> secrets;
};

class TeamServerCredentialVaultService
{
public:
    using CredentialEmitter = std::function<bool(const teamserverapi::CredentialSummary&)>;

    TeamServerCredentialVaultService(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerRuntimeConfig runtimeConfig);

    grpc::Status listCredentials(
        const teamserverapi::CredentialQuery& query,
        const CredentialEmitter& emit);
    grpc::Status getCredential(
        const teamserverapi::CredentialSelector& selector,
        teamserverapi::CredentialDetail* response);
    grpc::Status addCredential(
        const teamserverapi::CredentialUpsertRequest& request,
        teamserverapi::OperationAck* response);
    grpc::Status updateCredential(
        const teamserverapi::CredentialUpsertRequest& request,
        teamserverapi::OperationAck* response);
    grpc::Status deleteCredential(
        const teamserverapi::CredentialSelector& selector,
        teamserverapi::OperationAck* response);

    grpc::Status handleTerminalCommand(
        const std::vector<std::string>& splitedCmd,
        const teamserverapi::TerminalCommandRequest& command,
        teamserverapi::TerminalCommandResponse* response);

private:
    void loadLocked();
    bool saveLocked(std::string& message) const;
    bool ensureVaultKeyLocked(std::vector<unsigned char>& key, std::string& message) const;
    bool readVaultKeyLocked(std::vector<unsigned char>& key, std::string& message) const;
    bool writeNewVaultKeyLocked(std::vector<unsigned char>& key, std::string& message) const;
    bool encryptVaultLocked(const nlohmann::json& plainVault, nlohmann::json& encryptedVault, std::string& message) const;
    bool decryptVaultLocked(const nlohmann::json& encryptedVault, nlohmann::json& plainVault, std::string& message) const;

    TeamServerCredentialRecord recordFromRequest(const teamserverapi::CredentialUpsertRequest& request) const;
    TeamServerCredentialRecord recordFromJson(const nlohmann::json& input) const;
    nlohmann::json recordToJson(const TeamServerCredentialRecord& record, bool revealSecrets) const;
    teamserverapi::CredentialSummary toSummary(const TeamServerCredentialRecord& record) const;
    void fillDetail(const TeamServerCredentialRecord& record, bool revealSecret, teamserverapi::CredentialDetail* response) const;
    bool matchesQuery(const TeamServerCredentialRecord& record, const teamserverapi::CredentialQuery& query) const;
    TeamServerCredentialRecord* findRecordLocked(const std::string& credentialId);
    const TeamServerCredentialRecord* findRecordLocked(const std::string& credentialId) const;
    std::string generateCredentialId() const;
    std::string currentTimestamp() const;
    std::string terminalPayloadJson(const std::vector<std::string>& splitedCmd, const teamserverapi::TerminalCommandRequest& command, std::size_t tailIndex) const;
    std::string listCredentialsJsonLocked(const teamserverapi::CredentialQuery& query) const;
    void appendAuditLocked(const std::string& action, const std::string& credentialId);

    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerRuntimeConfig m_runtimeConfig;
    mutable std::mutex m_mutex;
    bool m_loaded = false;
    std::vector<TeamServerCredentialRecord> m_credentials;
    nlohmann::json m_audit = nlohmann::json::array();
};
