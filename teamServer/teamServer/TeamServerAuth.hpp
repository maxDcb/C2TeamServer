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
    grpc::Status ensureAuthenticated(const std::multimap<grpc::string_ref, grpc::string_ref>& metadata);

private:
    std::string generateToken() const;
    std::string hashPassword(const std::string& password) const;
    void cleanupExpiredTokens();

    std::shared_ptr<spdlog::logger> m_logger;
    std::string m_authCredentialsFile;
    std::unordered_map<std::string, std::string> m_userPasswordHashes;
    bool m_authEnabled;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_activeTokens;
    std::chrono::minutes m_tokenValidityDuration;
    mutable std::mutex m_authMutex;
};
