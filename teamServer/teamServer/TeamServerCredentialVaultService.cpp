#include "TeamServerCredentialVaultService.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <system_error>
#include <sys/stat.h>

#include "spdlog/logger.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
constexpr std::size_t VaultKeySize = 32;
constexpr std::size_t VaultNonceSize = 12;
constexpr std::size_t VaultTagSize = 16;

void setTerminalOk(teamserverapi::TerminalCommandResponse* response, const std::string& result)
{
    response->set_status(teamserverapi::OK);
    response->set_result(result);
    response->clear_message();
}

void setTerminalError(teamserverapi::TerminalCommandResponse* response, const std::string& result)
{
    response->set_status(teamserverapi::KO);
    response->set_result(result);
    response->set_message(result);
}

void setAck(teamserverapi::OperationAck* response, teamserverapi::Status status, const std::string& message)
{
    response->set_status(status);
    response->set_message(message);
}

std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle)
{
    if (needle.empty())
        return true;
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

bool matchesField(const std::string& requested, const std::string& actual)
{
    return requested.empty() || toLower(requested) == toLower(actual);
}

bool updateFieldRequested(const teamserverapi::CredentialUpsertRequest& request, const std::string& field)
{
    const auto& fields = request.update_fields();
    return std::find(fields.begin(), fields.end(), field) != fields.end();
}

std::string bytesToHex(const std::vector<unsigned char>& bytes)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : bytes)
        output << std::setw(2) << static_cast<int>(byte);
    return output.str();
}

bool hexToBytes(const std::string& hex, std::vector<unsigned char>& bytes)
{
    if (hex.size() % 2 != 0)
        return false;
    bytes.clear();
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        const std::string part = hex.substr(i, 2);
        char* end = nullptr;
        const unsigned long value = std::strtoul(part.c_str(), &end, 16);
        if (end == nullptr || *end != '\0' || value > 255)
            return false;
        bytes.push_back(static_cast<unsigned char>(value));
    }
    return true;
}

std::string jsonString(const json& input, const char* key, const std::string& fallback = "")
{
    auto it = input.find(key);
    if (it == input.end() || !it->is_string())
        return fallback;
    return it->get<std::string>();
}

std::vector<std::string> jsonStringList(const json& input, const char* key)
{
    std::vector<std::string> values;
    auto it = input.find(key);
    if (it == input.end() || !it->is_array())
        return values;
    for (const auto& value : *it)
    {
        if (value.is_string())
            values.push_back(value.get<std::string>());
    }
    return values;
}

bool isKnownSecretField(const std::string& field)
{
    const std::string normalized = toLower(field);
    return normalized == "password"
        || normalized == "ntlm"
        || normalized == "ntlm_hash"
        || normalized == "hash"
        || normalized == "token"
        || normalized == "manual"
        || normalized == "private_key"
        || normalized == "secret"
        || normalized == "aes_key";
}

std::string defaultTypeFromSecrets(const std::map<std::string, std::string>& secrets)
{
    if (secrets.find("password") != secrets.end() || secrets.find("manual") != secrets.end())
        return "password";
    if (secrets.find("ntlm") != secrets.end() || secrets.find("ntlm_hash") != secrets.end() || secrets.find("hash") != secrets.end())
        return "ntlm_hash";
    if (secrets.find("token") != secrets.end())
        return "token";
    if (secrets.find("private_key") != secrets.end())
        return "ssh_key";
    return "custom";
}

bool aesGcmEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::string& plaintext,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool ok = false;
    int len = 0;
    ciphertext.assign(plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    tag.assign(VaultTagSize, 0);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1
        && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1
        && EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) == 1)
    {
        int total = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) == 1)
        {
            total += len;
            ciphertext.resize(static_cast<std::size_t>(total));
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aesGcmDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& tag,
    std::string& plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool ok = false;
    int len = 0;
    std::vector<unsigned char> output(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, 0);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1
        && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1
        && EVP_DecryptUpdate(ctx, output.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) == 1)
    {
        int total = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<unsigned char*>(tag.data())) == 1
            && EVP_DecryptFinal_ex(ctx, output.data() + total, &len) == 1)
        {
            total += len;
            plaintext.assign(reinterpret_cast<const char*>(output.data()), static_cast<std::size_t>(total));
            ok = true;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
} // namespace

TeamServerCredentialVaultService::TeamServerCredentialVaultService(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerRuntimeConfig runtimeConfig)
    : m_logger(std::move(logger)),
      m_runtimeConfig(std::move(runtimeConfig))
{
}

std::string TeamServerCredentialVaultService::currentTimestamp() const
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm utcTime {};
#ifdef _WIN32
    gmtime_s(&utcTime, &nowTime);
#else
    gmtime_r(&nowTime, &utcTime);
#endif
    std::ostringstream output;
    output << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string TeamServerCredentialVaultService::generateCredentialId() const
{
    std::vector<unsigned char> bytes(8, 0);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
        return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    return bytesToHex(bytes);
}

bool TeamServerCredentialVaultService::ensureVaultKeyLocked(std::vector<unsigned char>& key, std::string& message) const
{
    if (readVaultKeyLocked(key, message))
        return true;
    if (fs::exists(m_runtimeConfig.credentialVaultKeyFile))
        return false;
    return writeNewVaultKeyLocked(key, message);
}

bool TeamServerCredentialVaultService::readVaultKeyLocked(std::vector<unsigned char>& key, std::string& message) const
{
    std::ifstream input(m_runtimeConfig.credentialVaultKeyFile);
    if (!input.good())
    {
        message = "credential vault key file not found";
        return false;
    }

    std::string hex;
    input >> hex;
    if (!hexToBytes(hex, key) || key.size() != VaultKeySize)
    {
        message = "credential vault key file is invalid";
        return false;
    }
    return true;
}

bool TeamServerCredentialVaultService::writeNewVaultKeyLocked(std::vector<unsigned char>& key, std::string& message) const
{
    key.assign(VaultKeySize, 0);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
    {
        message = "could not generate credential vault key";
        return false;
    }

    std::error_code ec;
    fs::create_directories(fs::path(m_runtimeConfig.credentialVaultKeyFile).parent_path(), ec);
    if (ec)
    {
        message = "could not create credential vault key directory";
        return false;
    }

    std::ofstream output(m_runtimeConfig.credentialVaultKeyFile, std::ios::out | std::ios::trunc);
    if (!output.good())
    {
        message = "could not write credential vault key file";
        return false;
    }
    if (chmod(m_runtimeConfig.credentialVaultKeyFile.c_str(), S_IRUSR | S_IWUSR) != 0)
    {
        output.close();
        fs::remove(m_runtimeConfig.credentialVaultKeyFile, ec);
        message = "could not secure credential vault key file permissions";
        return false;
    }
    output << bytesToHex(key) << "\n";
    output.close();
    if (!output.good())
    {
        fs::remove(m_runtimeConfig.credentialVaultKeyFile, ec);
        message = "could not flush credential vault key file";
        return false;
    }
    return true;
}

bool TeamServerCredentialVaultService::encryptVaultLocked(const json& plainVault, json& encryptedVault, std::string& message) const
{
    std::vector<unsigned char> key;
    if (!ensureVaultKeyLocked(key, message))
        return false;

    std::vector<unsigned char> nonce(VaultNonceSize, 0);
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
    {
        message = "could not generate credential vault nonce";
        return false;
    }

    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    if (!aesGcmEncrypt(key, nonce, plainVault.dump(), ciphertext, tag))
    {
        message = "could not encrypt credential vault";
        return false;
    }

    encryptedVault = json::object();
    encryptedVault["version"] = 1;
    encryptedVault["cipher"] = "AES-256-GCM";
    encryptedVault["nonce"] = bytesToHex(nonce);
    encryptedVault["tag"] = bytesToHex(tag);
    encryptedVault["ciphertext"] = bytesToHex(ciphertext);
    return true;
}

bool TeamServerCredentialVaultService::decryptVaultLocked(const json& encryptedVault, json& plainVault, std::string& message) const
{
    if (!encryptedVault.is_object()
        || encryptedVault.value("version", 0) != 1
        || encryptedVault.value("cipher", std::string()) != "AES-256-GCM")
    {
        message = "credential vault format is invalid";
        return false;
    }

    std::vector<unsigned char> key;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> ciphertext;
    if (!readVaultKeyLocked(key, message))
        return false;
    if (!hexToBytes(encryptedVault.value("nonce", std::string()), nonce)
        || !hexToBytes(encryptedVault.value("tag", std::string()), tag)
        || !hexToBytes(encryptedVault.value("ciphertext", std::string()), ciphertext)
        || nonce.size() != VaultNonceSize
        || tag.size() != VaultTagSize)
    {
        message = "credential vault envelope is invalid";
        return false;
    }

    std::string plaintext;
    if (!aesGcmDecrypt(key, nonce, ciphertext, tag, plaintext))
    {
        message = "could not decrypt credential vault";
        return false;
    }

    plainVault = json::parse(plaintext, nullptr, false);
    if (plainVault.is_discarded() || !plainVault.is_object())
    {
        message = "decrypted credential vault content is invalid";
        return false;
    }
    return true;
}

bool TeamServerCredentialVaultService::loadLocked(std::string& message)
{
    if (m_loaded)
        return true;

    std::ifstream input(m_runtimeConfig.credentialVaultPath);
    if (!input.good())
    {
        if (fs::exists(m_runtimeConfig.credentialVaultPath))
        {
            message = "could not read credential vault";
            m_logger->error("Unable to load credential vault: {0}", message);
            return false;
        }
        m_credentials.clear();
        m_audit = json::array();
        m_loaded = true;
        return true;
    }

    json encryptedVault = json::parse(input, nullptr, false);
    if (encryptedVault.is_discarded())
    {
        message = "credential vault file is not valid JSON";
        m_logger->error("{0}: {1}", message, m_runtimeConfig.credentialVaultPath);
        return false;
    }

    json plainVault;
    if (!decryptVaultLocked(encryptedVault, plainVault, message))
    {
        m_logger->error("Unable to load credential vault: {0}", message);
        return false;
    }

    m_credentials.clear();
    const json credentials = plainVault.value("credentials", json::array());
    if (credentials.is_array())
    {
        for (const auto& item : credentials)
        {
            if (item.is_object())
                m_credentials.push_back(recordFromJson(item));
        }
    }
    m_audit = plainVault.value("audit", json::array());
    if (!m_audit.is_array())
        m_audit = json::array();
    m_loaded = true;
    return true;
}

bool TeamServerCredentialVaultService::saveLocked(std::string& message) const
{
    json plainVault = json::object();
    plainVault["version"] = 1;
    plainVault["credentials"] = json::array();
    for (const TeamServerCredentialRecord& record : m_credentials)
        plainVault["credentials"].push_back(recordToJson(record, true));
    plainVault["audit"] = m_audit;

    json encryptedVault;
    if (!encryptVaultLocked(plainVault, encryptedVault, message))
        return false;

    std::error_code ec;
    fs::create_directories(fs::path(m_runtimeConfig.credentialVaultPath).parent_path(), ec);
    if (ec)
    {
        message = "could not create credential vault directory";
        return false;
    }

    const fs::path destination(m_runtimeConfig.credentialVaultPath);
    const fs::path temporary = destination.string() + ".tmp";
    std::ofstream output(temporary, std::ios::out | std::ios::trunc);
    if (!output.good())
    {
        message = "could not write credential vault";
        return false;
    }
    if (chmod(temporary.c_str(), S_IRUSR | S_IWUSR) != 0)
    {
        output.close();
        fs::remove(temporary, ec);
        message = "could not secure credential vault file permissions";
        return false;
    }
    output << encryptedVault.dump(2) << "\n";
    output.close();
    if (!output.good())
    {
        fs::remove(temporary, ec);
        message = "could not flush credential vault";
        return false;
    }
    fs::rename(temporary, destination, ec);
    if (ec)
    {
        const fs::path backup = destination.string() + ".bak";
        std::error_code cleanupError;
        fs::remove(backup, cleanupError);

        const bool hadDestination = fs::exists(destination);
        ec.clear();
        if (hadDestination)
            fs::rename(destination, backup, ec);
        if (ec)
        {
            fs::remove(temporary, cleanupError);
            message = "could not preserve existing credential vault before replacement";
            return false;
        }

        fs::rename(temporary, destination, ec);
        if (ec)
        {
            std::error_code restoreError;
            if (hadDestination)
                fs::rename(backup, destination, restoreError);
            message = restoreError
                ? "could not replace credential vault and failed to restore the previous file"
                : "could not replace credential vault";
            return false;
        }
        if (hadDestination)
            fs::remove(backup, cleanupError);
    }
    return true;
}

TeamServerCredentialRecord TeamServerCredentialVaultService::recordFromRequest(const teamserverapi::CredentialUpsertRequest& request) const
{
    TeamServerCredentialRecord record;
    record.credentialId = request.credential_id();
    record.displayName = request.display_name();
    record.type = request.type();
    record.username = request.username();
    record.domain = request.domain();
    record.realm = request.realm();
    record.target = request.target();
    record.protocol = request.protocol();
    record.description = request.description();
    record.expiresAt = request.expires_at();
    for (const std::string& tag : request.tags())
    {
        if (!tag.empty())
            record.tags.push_back(tag);
    }
    for (const auto& secret : request.secrets())
    {
        if (!secret.name().empty())
            record.secrets[secret.name()] = secret.value();
    }
    if (record.type.empty())
        record.type = defaultTypeFromSecrets(record.secrets);
    if (record.displayName.empty())
    {
        record.displayName = record.domain.empty()
            ? record.username
            : record.domain + "\\" + record.username;
        if (record.displayName.empty())
            record.displayName = record.type;
    }
    return record;
}

TeamServerCredentialRecord TeamServerCredentialVaultService::recordFromJson(const json& input) const
{
    TeamServerCredentialRecord record;
    record.credentialId = jsonString(input, "credential_id", jsonString(input, "id"));
    record.displayName = jsonString(input, "display_name");
    record.type = jsonString(input, "type");
    record.username = jsonString(input, "username");
    record.domain = jsonString(input, "domain");
    record.realm = jsonString(input, "realm");
    record.target = jsonString(input, "target");
    record.protocol = jsonString(input, "protocol");
    record.tags = jsonStringList(input, "tags");
    record.description = jsonString(input, "description");
    record.createdAt = jsonString(input, "created_at");
    record.updatedAt = jsonString(input, "updated_at");
    record.lastUsedAt = jsonString(input, "last_used_at");
    record.expiresAt = jsonString(input, "expires_at");

    auto secretsIt = input.find("secrets");
    if (secretsIt != input.end())
    {
        if (secretsIt->is_object())
        {
            for (auto it = secretsIt->begin(); it != secretsIt->end(); ++it)
            {
                if (it.value().is_string())
                    record.secrets[it.key()] = it.value().get<std::string>();
            }
        }
        else if (secretsIt->is_array())
        {
            for (const auto& secret : *secretsIt)
            {
                const std::string name = jsonString(secret, "name");
                if (!name.empty())
                    record.secrets[name] = jsonString(secret, "value");
            }
        }
    }

    for (auto it = input.begin(); it != input.end(); ++it)
    {
        if (it.value().is_string() && isKnownSecretField(it.key()))
            record.secrets[it.key()] = it.value().get<std::string>();
    }

    if (record.type.empty())
        record.type = defaultTypeFromSecrets(record.secrets);
    if (record.displayName.empty())
        record.displayName = record.domain.empty() ? record.username : record.domain + "\\" + record.username;
    if (record.displayName.empty())
        record.displayName = record.type;
    return record;
}

json TeamServerCredentialVaultService::recordToJson(const TeamServerCredentialRecord& record, bool revealSecrets) const
{
    json output = json::object();
    output["credential_id"] = record.credentialId;
    output["display_name"] = record.displayName;
    output["type"] = record.type;
    output["username"] = record.username;
    output["domain"] = record.domain;
    output["realm"] = record.realm;
    output["target"] = record.target;
    output["protocol"] = record.protocol;
    output["tags"] = record.tags;
    output["description"] = record.description;
    output["created_at"] = record.createdAt;
    output["updated_at"] = record.updatedAt;
    output["last_used_at"] = record.lastUsedAt;
    output["expires_at"] = record.expiresAt;
    output["secret_fields"] = json::array();
    for (const auto& [name, _] : record.secrets)
        output["secret_fields"].push_back(name);
    if (revealSecrets)
    {
        output["secrets"] = json::object();
        for (const auto& [name, value] : record.secrets)
            output["secrets"][name] = value;
    }
    return output;
}

teamserverapi::CredentialSummary TeamServerCredentialVaultService::toSummary(const TeamServerCredentialRecord& record) const
{
    teamserverapi::CredentialSummary summary;
    summary.set_credential_id(record.credentialId);
    summary.set_display_name(record.displayName);
    summary.set_type(record.type);
    summary.set_username(record.username);
    summary.set_domain(record.domain);
    summary.set_realm(record.realm);
    summary.set_target(record.target);
    summary.set_protocol(record.protocol);
    summary.set_description(record.description);
    summary.set_created_at(record.createdAt);
    summary.set_updated_at(record.updatedAt);
    summary.set_last_used_at(record.lastUsedAt);
    summary.set_expires_at(record.expiresAt);
    for (const std::string& tag : record.tags)
        summary.add_tags(tag);
    for (const auto& [name, _] : record.secrets)
        summary.add_secret_fields(name);
    return summary;
}

void TeamServerCredentialVaultService::fillDetail(const TeamServerCredentialRecord& record, bool revealSecret, teamserverapi::CredentialDetail* response) const
{
    response->set_status(teamserverapi::OK);
    response->clear_message();
    *response->mutable_summary() = toSummary(record);
    response->clear_secrets();
    if (!revealSecret)
        return;
    for (const auto& [name, value] : record.secrets)
    {
        teamserverapi::CredentialSecret* secret = response->add_secrets();
        secret->set_name(name);
        secret->set_value(value);
    }
}

bool TeamServerCredentialVaultService::matchesQuery(const TeamServerCredentialRecord& record, const teamserverapi::CredentialQuery& query) const
{
    if (!query.include_expired()
        && !record.expiresAt.empty()
        && record.expiresAt <= currentTimestamp())
    {
        return false;
    }

    bool tagMatches = query.tag().empty();
    for (const std::string& tag : record.tags)
    {
        if (toLower(tag) == toLower(query.tag()))
            tagMatches = true;
    }

    return matchesField(query.type(), record.type)
        && containsCaseInsensitive(record.username, query.username())
        && containsCaseInsensitive(record.domain, query.domain())
        && containsCaseInsensitive(record.target, query.target())
        && matchesField(query.protocol(), record.protocol)
        && tagMatches
        && (containsCaseInsensitive(record.displayName, query.name_contains())
            || containsCaseInsensitive(record.username, query.name_contains())
            || containsCaseInsensitive(record.domain, query.name_contains())
            || containsCaseInsensitive(record.target, query.name_contains())
            || containsCaseInsensitive(record.credentialId, query.name_contains()));
}

TeamServerCredentialRecord* TeamServerCredentialVaultService::findRecordLocked(const std::string& credentialId, bool* ambiguous)
{
    if (ambiguous)
        *ambiguous = false;
    if (credentialId.empty())
        return nullptr;

    TeamServerCredentialRecord* candidate = nullptr;
    for (TeamServerCredentialRecord& record : m_credentials)
    {
        if (record.credentialId == credentialId)
            return &record;
        if (record.credentialId.rfind(credentialId, 0) != 0)
            continue;
        if (candidate)
        {
            if (ambiguous)
                *ambiguous = true;
            return nullptr;
        }
        candidate = &record;
    }
    return candidate;
}

const TeamServerCredentialRecord* TeamServerCredentialVaultService::findRecordLocked(const std::string& credentialId, bool* ambiguous) const
{
    if (ambiguous)
        *ambiguous = false;
    if (credentialId.empty())
        return nullptr;

    const TeamServerCredentialRecord* candidate = nullptr;
    for (const TeamServerCredentialRecord& record : m_credentials)
    {
        if (record.credentialId == credentialId)
            return &record;
        if (record.credentialId.rfind(credentialId, 0) != 0)
            continue;
        if (candidate)
        {
            if (ambiguous)
                *ambiguous = true;
            return nullptr;
        }
        candidate = &record;
    }
    return candidate;
}

void TeamServerCredentialVaultService::appendAuditLocked(const std::string& action, const std::string& credentialId)
{
    json event = json::object();
    event["timestamp"] = currentTimestamp();
    event["action"] = action;
    event["credential_id"] = credentialId;
    m_audit.push_back(event);
}

grpc::Status TeamServerCredentialVaultService::listCredentials(
    const teamserverapi::CredentialQuery& query,
    const CredentialEmitter& emit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string message;
    if (!loadLocked(message))
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, message);
    for (const TeamServerCredentialRecord& record : m_credentials)
    {
        if (matchesQuery(record, query) && !emit(toSummary(record)))
            return grpc::Status::OK;
    }
    return grpc::Status::OK;
}

grpc::Status TeamServerCredentialVaultService::getCredential(
    const teamserverapi::CredentialSelector& selector,
    teamserverapi::CredentialDetail* response)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string message;
    if (!loadLocked(message))
    {
        response->set_status(teamserverapi::KO);
        response->set_message(message);
        return grpc::Status::OK;
    }
    if (selector.credential_id().empty())
    {
        response->set_status(teamserverapi::KO);
        response->set_message("Credential id is required.");
        return grpc::Status::OK;
    }
    bool ambiguous = false;
    const TeamServerCredentialRecord* record = findRecordLocked(selector.credential_id(), &ambiguous);
    if (!record)
    {
        response->set_status(teamserverapi::KO);
        response->set_message(ambiguous ? "Credential id is ambiguous." : "Credential not found.");
        return grpc::Status::OK;
    }

    const json previousAudit = m_audit;
    appendAuditLocked(selector.reveal_secret() ? "credential_revealed" : "credential_read", record->credentialId);
    if (!saveLocked(message))
    {
        m_audit = previousAudit;
        response->set_status(teamserverapi::KO);
        response->set_message("Could not persist credential audit: " + message);
        return grpc::Status::OK;
    }
    fillDetail(*record, selector.reveal_secret(), response);
    return grpc::Status::OK;
}

grpc::Status TeamServerCredentialVaultService::addCredential(
    const teamserverapi::CredentialUpsertRequest& request,
    teamserverapi::OperationAck* response)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string message;
    if (!loadLocked(message))
    {
        setAck(response, teamserverapi::KO, message);
        return grpc::Status::OK;
    }

    TeamServerCredentialRecord record = recordFromRequest(request);
    record.credentialId = record.credentialId.empty() ? generateCredentialId() : record.credentialId;
    if (findRecordLocked(record.credentialId))
    {
        setAck(response, teamserverapi::KO, "Credential already exists.");
        return grpc::Status::OK;
    }
    const std::string now = currentTimestamp();
    record.createdAt = now;
    record.updatedAt = now;
    const auto previousCredentials = m_credentials;
    const json previousAudit = m_audit;
    m_credentials.push_back(std::move(record));
    appendAuditLocked("credential_created", m_credentials.back().credentialId);

    if (!saveLocked(message))
    {
        m_credentials = previousCredentials;
        m_audit = previousAudit;
        setAck(response, teamserverapi::KO, message);
        return grpc::Status::OK;
    }
    setAck(response, teamserverapi::OK, "Credential stored: cred:" + m_credentials.back().credentialId);
    return grpc::Status::OK;
}

grpc::Status TeamServerCredentialVaultService::updateCredential(
    const teamserverapi::CredentialUpsertRequest& request,
    teamserverapi::OperationAck* response)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string message;
    if (!loadLocked(message))
    {
        setAck(response, teamserverapi::KO, message);
        return grpc::Status::OK;
    }

    if (request.credential_id().empty())
    {
        setAck(response, teamserverapi::KO, "Credential id is required.");
        return grpc::Status::OK;
    }

    bool ambiguous = false;
    TeamServerCredentialRecord* existing = findRecordLocked(request.credential_id(), &ambiguous);
    if (!existing)
    {
        setAck(response, teamserverapi::KO, ambiguous ? "Credential id is ambiguous." : "Credential not found.");
        return grpc::Status::OK;
    }

    const auto previousCredentials = m_credentials;
    const json previousAudit = m_audit;
    TeamServerCredentialRecord update = recordFromRequest(request);
    const bool hasUpdateMask = request.update_fields_size() > 0;
    auto shouldUpdate = [&](const std::string& field, const std::string& value)
    {
        return hasUpdateMask ? updateFieldRequested(request, field) : !value.empty();
    };
    if (shouldUpdate("display_name", request.display_name())) existing->displayName = request.display_name();
    if (shouldUpdate("type", request.type())) existing->type = request.type();
    if (shouldUpdate("username", request.username())) existing->username = request.username();
    if (shouldUpdate("domain", request.domain())) existing->domain = request.domain();
    if (shouldUpdate("realm", request.realm())) existing->realm = request.realm();
    if (shouldUpdate("target", request.target())) existing->target = request.target();
    if (shouldUpdate("protocol", request.protocol())) existing->protocol = request.protocol();
    if ((hasUpdateMask && updateFieldRequested(request, "tags")) || (!hasUpdateMask && !update.tags.empty())) existing->tags = update.tags;
    if (shouldUpdate("description", request.description())) existing->description = request.description();
    if (shouldUpdate("expires_at", request.expires_at())) existing->expiresAt = request.expires_at();
    if (request.replace_secrets())
        existing->secrets.clear();
    for (const auto& [name, value] : update.secrets)
        existing->secrets[name] = value;
    existing->updatedAt = currentTimestamp();
    appendAuditLocked("credential_updated", existing->credentialId);

    if (!saveLocked(message))
    {
        m_credentials = previousCredentials;
        m_audit = previousAudit;
        setAck(response, teamserverapi::KO, message);
        return grpc::Status::OK;
    }
    setAck(response, teamserverapi::OK, "Credential updated.");
    return grpc::Status::OK;
}

grpc::Status TeamServerCredentialVaultService::deleteCredential(
    const teamserverapi::CredentialSelector& selector,
    teamserverapi::OperationAck* response)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string message;
    if (!loadLocked(message))
    {
        setAck(response, teamserverapi::KO, message);
        return grpc::Status::OK;
    }

    const std::string credentialId = selector.credential_id();
    if (credentialId.empty())
    {
        setAck(response, teamserverapi::KO, "Credential id is required.");
        return grpc::Status::OK;
    }
    bool ambiguous = false;
    TeamServerCredentialRecord* record = findRecordLocked(credentialId, &ambiguous);
    if (!record)
    {
        setAck(response, teamserverapi::KO, ambiguous ? "Credential id is ambiguous." : "Credential not found.");
        return grpc::Status::OK;
    }

    const auto previousCredentials = m_credentials;
    const json previousAudit = m_audit;
    const std::string removedId = record->credentialId;
    auto it = std::find_if(m_credentials.begin(), m_credentials.end(), [&](const TeamServerCredentialRecord& candidate)
    {
        return candidate.credentialId == removedId;
    });
    m_credentials.erase(it);
    appendAuditLocked("credential_deleted", removedId);

    if (!saveLocked(message))
    {
        m_credentials = previousCredentials;
        m_audit = previousAudit;
        setAck(response, teamserverapi::KO, message);
        return grpc::Status::OK;
    }
    setAck(response, teamserverapi::OK, "Credential deleted.");
    return grpc::Status::OK;
}

std::string TeamServerCredentialVaultService::terminalPayloadJson(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    std::size_t tailIndex) const
{
    if (!command.data().empty())
        return command.data();

    std::string raw = command.command();
    std::size_t offset = 0;
    for (std::size_t i = 0; i < tailIndex && i < splitedCmd.size(); ++i)
    {
        offset = raw.find(splitedCmd[i], offset);
        if (offset == std::string::npos)
            return "";
        offset += splitedCmd[i].size();
    }
    while (offset < raw.size() && std::isspace(static_cast<unsigned char>(raw[offset])))
        ++offset;
    return raw.substr(offset);
}

std::string TeamServerCredentialVaultService::listCredentialsJsonLocked(const teamserverapi::CredentialQuery& query) const
{
    json output = json::array();
    for (const TeamServerCredentialRecord& record : m_credentials)
    {
        if (matchesQuery(record, query))
            output.push_back(recordToJson(record, false));
    }
    return output.dump(2);
}

grpc::Status TeamServerCredentialVaultService::handleTerminalCommand(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    if (splitedCmd.empty())
    {
        setTerminalError(response, "Error: missing credential command.");
        return grpc::Status::OK;
    }

    const std::string root = toLower(splitedCmd[0]);
    if (root == "addcred")
    {
        const std::string payload = command.data();
        json input = json::parse(payload, nullptr, false);
        if (input.is_discarded() || !input.is_object())
        {
            setTerminalError(response, "Error: invalid credential payload.");
            return grpc::Status::OK;
        }

        teamserverapi::CredentialUpsertRequest request;
        TeamServerCredentialRecord record = recordFromJson(input);
        request.set_display_name(record.displayName);
        request.set_type(record.type);
        request.set_username(record.username);
        request.set_domain(record.domain);
        request.set_realm(record.realm);
        request.set_target(record.target);
        request.set_protocol(record.protocol);
        request.set_description(record.description);
        request.set_expires_at(record.expiresAt);
        for (const std::string& tag : record.tags)
            request.add_tags(tag);
        for (const auto& [name, value] : record.secrets)
        {
            teamserverapi::CredentialSecret* secret = request.add_secrets();
            secret->set_name(name);
            secret->set_value(value);
        }
        teamserverapi::OperationAck ack;
        addCredential(request, &ack);
        if (ack.status() == teamserverapi::OK)
            setTerminalOk(response, ack.message());
        else
            setTerminalError(response, "Error: " + ack.message());
        return grpc::Status::OK;
    }

    if (root == "getcred")
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string message;
        if (!loadLocked(message))
        {
            setTerminalError(response, "Error: " + message);
            return grpc::Status::OK;
        }
        teamserverapi::CredentialQuery query;
        setTerminalOk(response, listCredentialsJsonLocked(query));
        return grpc::Status::OK;
    }

    if (root != "cred")
    {
        setTerminalError(response, "Error: unknown credential command.");
        return grpc::Status::OK;
    }

    if (splitedCmd.size() < 2)
    {
        setTerminalOk(response,
            "cred <list|add|get|update|delete>\n"
            "Examples:\n"
            "  cred list\n"
            "  cred list alice\n"
            "  cred add {\"username\":\"alice\",\"domain\":\"CORP\",\"password\":\"secret\"}\n"
            "  cred get <id> --reveal\n"
            "  cred delete <id>");
        return grpc::Status::OK;
    }

    const std::string action = toLower(splitedCmd[1]);
    if (action == "list" || action == "search")
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string message;
        if (!loadLocked(message))
        {
            setTerminalError(response, "Error: " + message);
            return grpc::Status::OK;
        }
        teamserverapi::CredentialQuery query;
        if (splitedCmd.size() >= 3)
            query.set_name_contains(splitedCmd[2]);
        setTerminalOk(response, listCredentialsJsonLocked(query));
        return grpc::Status::OK;
    }

    if (action == "get" || action == "reveal")
    {
        if (splitedCmd.size() < 3)
        {
            setTerminalError(response, "Error: credential id is required.");
            return grpc::Status::OK;
        }
        teamserverapi::CredentialSelector selector;
        selector.set_credential_id(splitedCmd[2]);
        selector.set_reveal_secret(action == "reveal" || std::find(splitedCmd.begin(), splitedCmd.end(), "--reveal") != splitedCmd.end());
        teamserverapi::CredentialDetail detail;
        getCredential(selector, &detail);
        if (detail.status() != teamserverapi::OK)
        {
            setTerminalError(response, "Error: " + detail.message());
            return grpc::Status::OK;
        }

        json output = json::object();
        output["credential_id"] = detail.summary().credential_id();
        output["display_name"] = detail.summary().display_name();
        output["type"] = detail.summary().type();
        output["username"] = detail.summary().username();
        output["domain"] = detail.summary().domain();
        output["realm"] = detail.summary().realm();
        output["target"] = detail.summary().target();
        output["protocol"] = detail.summary().protocol();
        output["secret_fields"] = json::array();
        for (const std::string& field : detail.summary().secret_fields())
            output["secret_fields"].push_back(field);
        if (selector.reveal_secret())
        {
            output["secrets"] = json::object();
            for (const auto& secret : detail.secrets())
                output["secrets"][secret.name()] = secret.value();
        }
        setTerminalOk(response, output.dump(2));
        return grpc::Status::OK;
    }

    if (action == "add")
    {
        const std::string payload = terminalPayloadJson(splitedCmd, command, 2);
        json input = json::parse(payload, nullptr, false);
        if (input.is_discarded() || !input.is_object())
        {
            setTerminalError(response, "Error: invalid credential payload.");
            return grpc::Status::OK;
        }
        TeamServerCredentialRecord record = recordFromJson(input);
        teamserverapi::CredentialUpsertRequest request;
        request.set_display_name(record.displayName);
        request.set_type(record.type);
        request.set_username(record.username);
        request.set_domain(record.domain);
        request.set_realm(record.realm);
        request.set_target(record.target);
        request.set_protocol(record.protocol);
        request.set_description(record.description);
        request.set_expires_at(record.expiresAt);
        auto markUpdatedField = [&](const char* jsonField, const char* requestField)
        {
            if (input.contains(jsonField))
                request.add_update_fields(requestField);
        };
        markUpdatedField("display_name", "display_name");
        markUpdatedField("type", "type");
        markUpdatedField("username", "username");
        markUpdatedField("domain", "domain");
        markUpdatedField("realm", "realm");
        markUpdatedField("target", "target");
        markUpdatedField("protocol", "protocol");
        markUpdatedField("tags", "tags");
        markUpdatedField("description", "description");
        markUpdatedField("expires_at", "expires_at");
        for (const std::string& tag : record.tags)
            request.add_tags(tag);
        for (const auto& [name, value] : record.secrets)
        {
            teamserverapi::CredentialSecret* secret = request.add_secrets();
            secret->set_name(name);
            secret->set_value(value);
        }
        teamserverapi::OperationAck ack;
        addCredential(request, &ack);
        if (ack.status() == teamserverapi::OK)
            setTerminalOk(response, ack.message());
        else
            setTerminalError(response, "Error: " + ack.message());
        return grpc::Status::OK;
    }

    if (action == "update")
    {
        if (splitedCmd.size() < 3)
        {
            setTerminalError(response, "Error: credential id is required.");
            return grpc::Status::OK;
        }
        const std::string payload = terminalPayloadJson(splitedCmd, command, 3);
        json input = json::parse(payload, nullptr, false);
        if (input.is_discarded() || !input.is_object())
        {
            setTerminalError(response, "Error: invalid credential payload.");
            return grpc::Status::OK;
        }
        TeamServerCredentialRecord record = recordFromJson(input);
        teamserverapi::CredentialUpsertRequest request;
        request.set_credential_id(splitedCmd[2]);
        request.set_display_name(record.displayName);
        request.set_type(record.type);
        request.set_username(record.username);
        request.set_domain(record.domain);
        request.set_realm(record.realm);
        request.set_target(record.target);
        request.set_protocol(record.protocol);
        request.set_description(record.description);
        request.set_expires_at(record.expiresAt);
        for (const std::string& tag : record.tags)
            request.add_tags(tag);
        for (const auto& [name, value] : record.secrets)
        {
            teamserverapi::CredentialSecret* secret = request.add_secrets();
            secret->set_name(name);
            secret->set_value(value);
        }
        teamserverapi::OperationAck ack;
        updateCredential(request, &ack);
        if (ack.status() == teamserverapi::OK)
            setTerminalOk(response, ack.message());
        else
            setTerminalError(response, "Error: " + ack.message());
        return grpc::Status::OK;
    }

    if (action == "delete")
    {
        if (splitedCmd.size() < 3)
        {
            setTerminalError(response, "Error: credential id is required.");
            return grpc::Status::OK;
        }
        teamserverapi::CredentialSelector selector;
        selector.set_credential_id(splitedCmd[2]);
        teamserverapi::OperationAck ack;
        deleteCredential(selector, &ack);
        if (ack.status() == teamserverapi::OK)
            setTerminalOk(response, ack.message());
        else
            setTerminalError(response, "Error: " + ack.message());
        return grpc::Status::OK;
    }

    setTerminalError(response, "Error: unknown credential action.");
    return grpc::Status::OK;
}
