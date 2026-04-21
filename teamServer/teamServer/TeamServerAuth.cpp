#include "TeamServerAuth.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <openssl/sha.h>
#include <random>
#include <sstream>

using json = nlohmann::json;

namespace
{
std::string normalizeHash(std::string hash)
{
    std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c)
        { return static_cast<char>(std::tolower(c)); });
    return hash;
}
} // namespace

TeamServerAuthManager::TeamServerAuthManager(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger)),
      m_authCredentialsFile(""),
      m_authEnabled(false),
      m_tokenValidityDuration(std::chrono::minutes(60))
{
}

void TeamServerAuthManager::configure(const nlohmann::json& config)
{
    m_authCredentialsFile.clear();
    m_userPasswordHashes.clear();
    m_activeTokens.clear();
    m_authEnabled = false;
    m_tokenValidityDuration = std::chrono::minutes(60);

    auto authFileIt = config.find("AuthCredentialsFile");
    if (authFileIt == config.end() || !authFileIt->is_string())
    {
        m_logger->warn("AuthCredentialsFile entry missing from configuration. gRPC authentication is disabled.");
        return;
    }

    m_authCredentialsFile = authFileIt->get<std::string>();
    std::ifstream authFile(m_authCredentialsFile);
    if (!authFile.good())
    {
        m_logger->critical("Authentication credential file not found: {0}", m_authCredentialsFile);
        return;
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
            {
                m_logger->error("Authentication credential file {0} has a 'users' entry that is not an array.", m_authCredentialsFile);
            }
            else
            {
                for (const auto& userEntry : *usersIt)
                {
                    if (!userEntry.is_object())
                    {
                        m_logger->warn("Skipping malformed user entry in {0}; expected an object.", m_authCredentialsFile);
                        continue;
                    }

                    std::string username = userEntry.value("username", std::string());
                    if (username.empty())
                    {
                        m_logger->warn("Skipping user entry with missing username in {0}.", m_authCredentialsFile);
                        continue;
                    }

                    std::string passwordHash = normalizeHash(userEntry.value("password_hash", std::string()));
                    if (passwordHash.empty())
                    {
                        std::string plaintextPassword = userEntry.value("password", std::string());
                        if (!plaintextPassword.empty())
                        {
                            m_logger->warn("User '{0}' in credentials file provides a plaintext password; hashing at startup but please update the file to store 'password_hash'.", username);
                            passwordHash = hashPassword(plaintextPassword);
                        }
                    }

                    if (passwordHash.empty())
                    {
                        m_logger->warn("Skipping user '{0}' in {1} due to missing password hash.", username, m_authCredentialsFile);
                        continue;
                    }

                    m_userPasswordHashes[username] = passwordHash;
                }
            }
        }
        else
        {
            std::string username = authConfig.value("username", std::string());
            std::string passwordHash = normalizeHash(authConfig.value("password_hash", std::string()));
            if (passwordHash.empty())
            {
                std::string plaintextPassword = authConfig.value("password", std::string());
                if (!plaintextPassword.empty())
                {
                    m_logger->warn("Legacy credentials format detected in {0}; hashing plaintext password but please migrate to 'users' array with hashed passwords.", m_authCredentialsFile);
                    passwordHash = hashPassword(plaintextPassword);
                }
            }

            if (!username.empty() && !passwordHash.empty())
            {
                m_userPasswordHashes[username] = passwordHash;
            }
        }

        if (!m_userPasswordHashes.empty())
        {
            m_authEnabled = true;
            m_logger->info("Authentication enabled for {0} user(s) using credentials file: {1}", m_userPasswordHashes.size(), m_authCredentialsFile);
        }
        else
        {
            m_logger->error("Authentication credential file {0} does not contain any valid user credentials.", m_authCredentialsFile);
        }
    }
    catch (const std::exception& ex)
    {
        m_logger->error("Failed to parse authentication credential file {0}: {1}", m_authCredentialsFile, ex.what());
    }
}

grpc::Status TeamServerAuthManager::authenticate(const teamserverapi::AuthRequest& request, teamserverapi::AuthResponse& response)
{
    if (!m_authEnabled)
    {
        response.set_status(teamserverapi::KO);
        response.set_message("Authentication is not configured on the server");
        return grpc::Status::OK;
    }

    cleanupExpiredTokens();

    const std::string& username = request.username();
    const std::string& password = request.password();

    auto userIt = m_userPasswordHashes.find(username);
    if (userIt == m_userPasswordHashes.end())
    {
        response.set_status(teamserverapi::KO);
        response.set_message("Invalid credentials");
        m_logger->warn("Authentication failed for unknown user '{}'", username);
        return grpc::Status::OK;
    }

    std::string providedHash = hashPassword(password);
    if (providedHash != userIt->second)
    {
        response.set_status(teamserverapi::KO);
        response.set_message("Invalid credentials");
        m_logger->warn("Authentication failed due to incorrect password for user '{}'", username);
        return grpc::Status::OK;
    }

    std::string token = generateToken();
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        m_activeTokens[token] = std::chrono::steady_clock::now() + m_tokenValidityDuration;
    }

    response.set_status(teamserverapi::OK);
    response.set_token(token);
    response.set_message("Authentication successful");
    m_logger->info("User '{}' authenticated successfully", username);

    return grpc::Status::OK;
}

grpc::Status TeamServerAuthManager::ensureAuthenticated(const std::multimap<grpc::string_ref, grpc::string_ref>& metadata)
{
    if (!m_authEnabled)
        return grpc::Status::OK;

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

    if (now >= tokenIt->second)
    {
        m_logger->warn("gRPC request rejected: expired token presented");
        m_activeTokens.erase(tokenIt);
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Token expired");
    }

    tokenIt->second = now + m_tokenValidityDuration;
    return grpc::Status::OK;
}

std::string TeamServerAuthManager::generateToken() const
{
    static constexpr char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<std::size_t> distribution(0, sizeof(charset) - 2);

    std::string token(64, '\0');
    for (auto& ch : token)
    {
        ch = charset[distribution(generator)];
    }

    return token;
}

std::string TeamServerAuthManager::hashPassword(const std::string& password) const
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, reinterpret_cast<const unsigned char*>(password.data()), password.size());
    SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str();
}

void TeamServerAuthManager::cleanupExpiredTokens()
{
    if (!m_authEnabled)
        return;

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_authMutex);
    for (auto it = m_activeTokens.begin(); it != m_activeTokens.end();)
    {
        if (now >= it->second)
        {
            it = m_activeTokens.erase(it);
        }
        else
        {
            ++it;
        }
    }
}
