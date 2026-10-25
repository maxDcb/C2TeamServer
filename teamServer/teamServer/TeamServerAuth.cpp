#include "TeamServerAuth.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
int argon2id_hash_encoded(unsigned int t_cost, unsigned int m_cost, unsigned int parallelism,
    const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, size_t hashlen,
    char* encoded, size_t encodedlen);
int argon2id_verify(const char* encoded, const void* pwd, size_t pwdlen);
}

using json = nlohmann::json;

namespace
{
std::string normalizeHash(std::string hash)
{
    if (hash.rfind("$argon2id$", 0) == 0)
        return hash;
    std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c)
        { return static_cast<char>(std::tolower(c)); });
    return hash;
}

bool isLegacySha256(const std::string& hash)
{
    return hash.size() == SHA256_DIGEST_LENGTH * 2
        && std::all_of(hash.begin(), hash.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

void writePrivateFile(const std::filesystem::path& path, const std::string& content)
{
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0)
        throw std::runtime_error("Cannot create temporary credentials file");
    size_t written = 0;
    while (written < content.size())
    {
        const ssize_t count = ::write(fd, content.data() + written, content.size() - written);
        if (count <= 0)
        {
            ::close(fd);
            std::filesystem::remove(path);
            throw std::runtime_error("Cannot write temporary credentials file");
        }
        written += static_cast<size_t>(count);
    }
    const int syncResult = ::fsync(fd);
    const int closeResult = ::close(fd);
    if (syncResult != 0 || closeResult != 0)
    {
        std::filesystem::remove(path);
        throw std::runtime_error("Cannot sync temporary credentials file");
    }
}
} // namespace

TeamServerAuthManager::TeamServerAuthManager(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger)),
      m_authCredentialsFile(""),
      m_tokenValidityDuration(std::chrono::minutes(60))
{
}

void TeamServerAuthManager::configure(const nlohmann::json& config)
{
    m_authCredentialsFile.clear();
    m_userPasswordHashes.clear();
    m_activeTokens.clear();
    m_tokenValidityDuration = std::chrono::minutes(60);

    auto authFileIt = config.find("AuthCredentialsFile");
    if (authFileIt == config.end() || !authFileIt->is_string())
    {
        throw std::runtime_error("AuthCredentialsFile is required.");
    }

    m_authCredentialsFile = authFileIt->get<std::string>();
    std::ifstream authFile(m_authCredentialsFile);
    if (!authFile.good())
    {
        throw std::runtime_error("Authentication credential file not found: " + m_authCredentialsFile);
    }

    try
    {
        json authConfig = json::parse(authFile);
        int ttlMinutes = authConfig.value("token_ttl_minutes", static_cast<int>(m_tokenValidityDuration.count()));
        if (ttlMinutes > 0)
        {
            m_tokenValidityDuration = std::chrono::minutes(ttlMinutes);
        }

        auto usersIt = authConfig.find("users");
        if (usersIt != authConfig.end())
        {
            if (!usersIt->is_array())
                throw std::runtime_error("Authentication credentials 'users' must be an array.");
            else
            {
                for (const auto& userEntry : *usersIt)
                {
                    if (!userEntry.is_object())
                        throw std::runtime_error("Authentication user entry must be an object.");

                    std::string username = userEntry.value("username", std::string());
                    if (username.empty())
                        throw std::runtime_error("Authentication username is missing.");

                    std::string passwordHash = normalizeHash(userEntry.value("password_hash", std::string()));
                    if (passwordHash.rfind("$argon2id$", 0) != 0 && !isLegacySha256(passwordHash))
                        throw std::runtime_error("Invalid password hash for user '" + username + "'.");

                    m_userPasswordHashes[username] = passwordHash;
                }
            }
        }
        else
        {
            std::string username = authConfig.value("username", std::string());
            std::string passwordHash = normalizeHash(authConfig.value("password_hash", std::string()));
            if (username.empty() || (passwordHash.rfind("$argon2id$", 0) != 0 && !isLegacySha256(passwordHash)))
                throw std::runtime_error("Invalid legacy authentication credentials.");
            m_userPasswordHashes[username] = passwordHash;
        }

        if (m_userPasswordHashes.empty())
            throw std::runtime_error("Authentication credential file contains no users.");
        m_logger->info("Authentication enabled for {0} user(s) using credentials file: {1}", m_userPasswordHashes.size(), m_authCredentialsFile);
    }
    catch (const std::exception& ex)
    {
        throw std::runtime_error("Invalid authentication credentials in " + m_authCredentialsFile + ": " + ex.what());
    }
}

grpc::Status TeamServerAuthManager::authenticate(const teamserverapi::AuthRequest& request, teamserverapi::AuthResponse& response)
{
    cleanupExpiredTokens();

    const std::string& username = request.username();
    const std::string& password = request.password();

    std::string storedHash;
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        auto userIt = m_userPasswordHashes.find(username);
        if (userIt != m_userPasswordHashes.end())
            storedHash = userIt->second;
    }
    if (storedHash.empty())
    {
        response.set_status(teamserverapi::KO);
        response.set_message("Invalid credentials");
        m_logger->warn("Authentication failed for unknown user '{}'", username);
        return grpc::Status::OK;
    }

    if (!verifyPassword(password, storedHash))
    {
        response.set_status(teamserverapi::KO);
        response.set_message("Invalid credentials");
        m_logger->warn("Authentication failed due to incorrect password for user '{}'", username);
        return grpc::Status::OK;
    }

    if (isLegacySha256(storedHash))
        upgradeLegacyPassword(username, password);

    std::string token = generateToken();
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        m_activeTokens[token] = {std::chrono::steady_clock::now() + m_tokenValidityDuration, username};
    }

    response.set_status(teamserverapi::OK);
    response.set_token(token);
    response.set_message("Authentication successful");
    m_logger->info("User '{}' authenticated successfully", username);

    return grpc::Status::OK;
}

grpc::Status TeamServerAuthManager::ensureAuthenticated(const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
    std::string* authenticatedUsername)
{
    if (m_userPasswordHashes.empty())
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Authentication is not configured");

    auto metadataIt = std::find_if(metadata.begin(), metadata.end(), [](const auto& entry)
        { return entry.first == "authorization"; });
    if (metadataIt == metadata.end())
    {
        m_logger->warn("gRPC request rejected: missing authorization metadata");
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Missing authorization metadata");
    }

    std::string authHeader(metadataIt->second.data(), metadataIt->second.length());
    static const std::string prefix = "Bearer ";
    if (authHeader.rfind(prefix, 0) != 0)
    {
        m_logger->warn("gRPC request rejected: malformed authorization header");
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Malformed authorization header");
    }

    std::string token = authHeader.substr(prefix.size());

    std::lock_guard<std::mutex> lock(m_authMutex);
    auto now = std::chrono::steady_clock::now();
    auto tokenIt = m_activeTokens.find(token);
    if (tokenIt == m_activeTokens.end())
    {
        m_logger->warn("gRPC request rejected: invalid token presented");
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid token");
    }

    if (now >= tokenIt->second.expiresAt)
    {
        m_logger->warn("gRPC request rejected: expired token presented");
        m_activeTokens.erase(tokenIt);
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Token expired");
    }

    tokenIt->second.expiresAt = now + m_tokenValidityDuration;
    if (authenticatedUsername)
        *authenticatedUsername = tokenIt->second.username;
    return grpc::Status::OK;
}

std::string TeamServerAuthManager::generateToken() const
{
    std::array<unsigned char, 32> bytes {};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
        throw std::runtime_error("Unable to generate authentication token.");
    std::ostringstream encoded;
    for (unsigned char byte : bytes)
        encoded << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return encoded.str();
}

std::string TeamServerAuthManager::hashPassword(const std::string& password) const
{
    std::array<unsigned char, 16> salt {};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("Unable to generate password salt.");
    std::array<char, 256> encoded {};
    if (argon2id_hash_encoded(2, 19456, 1, password.data(), password.size(),
            salt.data(), salt.size(), 32, encoded.data(), encoded.size()) != 0)
        throw std::runtime_error("Unable to hash password with Argon2id.");
    return encoded.data();
}

bool TeamServerAuthManager::verifyPassword(const std::string& password, const std::string& encodedHash) const
{
    if (encodedHash.rfind("$argon2id$", 0) == 0)
        return argon2id_verify(encodedHash.c_str(), password.data(), password.size()) == 0;
    if (!isLegacySha256(encodedHash))
        return false;
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), digest.data());
    std::ostringstream encoded;
    for (unsigned char byte : digest)
        encoded << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    const std::string candidate = encoded.str();
    return CRYPTO_memcmp(candidate.data(), encodedHash.data(), candidate.size()) == 0;
}

void TeamServerAuthManager::upgradeLegacyPassword(const std::string& username, const std::string& password)
{
    std::lock_guard<std::mutex> lock(m_authMutex);
    auto entry = m_userPasswordHashes.find(username);
    if (entry == m_userPasswordHashes.end() || !isLegacySha256(entry->second))
        return;

    try
    {
        std::ifstream input(m_authCredentialsFile);
        json credentials = json::parse(input);
        const std::string encoded = hashPassword(password);
        if (credentials.contains("users"))
        {
            for (auto& user : credentials["users"])
            {
                if (user.value("username", std::string()) == username)
                {
                    user["password_hash"] = encoded;
                    user.erase("password");
                    break;
                }
            }
        }
        else
        {
            credentials["password_hash"] = encoded;
            credentials.erase("password");
        }

        const std::filesystem::path destination(m_authCredentialsFile);
        const std::filesystem::path temporary = destination.string() + ".tmp." + std::to_string(::getpid());
        writePrivateFile(temporary, credentials.dump(4) + "\n");
        std::filesystem::rename(temporary, destination);
        entry->second = encoded;
        m_logger->info("Migrated password hash for user '{}' to Argon2id", username);
    }
    catch (const std::exception& ex)
    {
        m_logger->error("Could not migrate legacy password hash for user '{}': {}", username, ex.what());
    }
}

void TeamServerAuthManager::cleanupExpiredTokens()
{
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_authMutex);
    for (auto it = m_activeTokens.begin(); it != m_activeTokens.end();)
    {
        if (now >= it->second.expiresAt)
        {
            it = m_activeTokens.erase(it);
        }
        else
        {
            ++it;
        }
    }
}
