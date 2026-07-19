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
#include "TeamServerSecurity.hpp"
#include "nlohmann/json.hpp"

namespace spdlog
{
class logger;
}

class TeamServerAuthorization
{
public:
    enum class Role
    {
        Viewer = 0,
        Operator = 1,
        Admin = 2
    };

    struct Principal
    {
        std::string username;
        Role role = Role::Viewer;
    };

    explicit TeamServerAuthorization(std::shared_ptr<spdlog::logger> logger);

    void configure(const nlohmann::json& config);
    grpc::Status authenticate(
        const teamserverapi::AuthRequest& request,
        teamserverapi::AuthResponse& response,
        const std::string& peer);
    grpc::Status authorize(
        const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
        Role requiredRole,
        Principal* principal = nullptr);

private:
    struct UserRecord
    {
        TeamServerPasswordHash password;
        Role role = Role::Viewer;
    };

    struct TokenRecord
    {
        Principal principal;
        std::chrono::steady_clock::time_point expiresAt;
    };

    struct FailureRecord
    {
        int failures = 0;
        std::chrono::steady_clock::time_point blockedUntil {};
    };

    static Role parseRole(const std::string& role);
    static const char* roleName(Role role);
    void cleanupExpiredTokens();

    std::shared_ptr<spdlog::logger> m_logger;
    std::unordered_map<std::string, UserRecord> m_users;
    std::unordered_map<std::string, TokenRecord> m_activeTokens;
    std::unordered_map<std::string, FailureRecord> m_failures;
    std::chrono::minutes m_tokenValidityDuration {60};
    int m_maxFailures = 5;
    std::chrono::seconds m_lockoutDuration {60};
    std::mutex m_mutex;
};

