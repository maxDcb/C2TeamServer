#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <grpcpp/support/status.h>
#include <grpcpp/support/string_ref.h>

#include "TeamServerApi.pb.h"
#include "nlohmann/json.hpp"
#include "spdlog/logger.h"

class TeamServerAuthManager
{
public:
    explicit TeamServerAuthManager(std::shared_ptr<spdlog::logger> logger);

    void configure(const nlohmann::json& config);

    grpc::Status authenticate(const teamserverapi::AuthRequest& request, teamserverapi::AuthResponse& response);
    grpc::Status ensureAuthenticated(const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
        std::string* authenticatedUsername = nullptr);

private:
    std::string generateToken() const;
    std::string hashPassword(const std::string& password) const;
    bool verifyPassword(const std::string& password, const std::string& encodedHash) const;
    void upgradeLegacyPassword(const std::string& username, const std::string& password);
    void cleanupExpiredTokens();

    std::shared_ptr<spdlog::logger> m_logger;
    std::string m_authCredentialsFile;
    std::unordered_map<std::string, std::string> m_userPasswordHashes;
    struct ActiveToken
    {
        std::chrono::steady_clock::time_point expiresAt;
        std::string username;
    };
    std::unordered_map<std::string, ActiveToken> m_activeTokens;
    std::chrono::minutes m_tokenValidityDuration;
    mutable std::mutex m_authMutex;
};
