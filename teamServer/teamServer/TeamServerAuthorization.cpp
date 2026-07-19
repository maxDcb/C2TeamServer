#include "TeamServerAuthorization.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "spdlog/logger.h"

using json = nlohmann::json;

TeamServerAuthorization::TeamServerAuthorization(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
{
}

TeamServerAuthorization::Role TeamServerAuthorization::parseRole(const std::string& role)
{
    if (role == "viewer")
        return Role::Viewer;
    if (role == "operator")
        return Role::Operator;
    if (role == "admin")
        return Role::Admin;
    throw std::runtime_error("Unknown authorization role: " + role);
}

const char* TeamServerAuthorization::roleName(Role role)
{
    switch (role)
    {
    case Role::Viewer:
        return "viewer";
    case Role::Operator:
        return "operator";
    case Role::Admin:
        return "admin";
    }
    return "unknown";
}

void TeamServerAuthorization::configure(const nlohmann::json& config)
{
    const auto security = config.find("Security");
    if (security == config.end() || !security->is_object())
        throw std::runtime_error("Security configuration is required");
    const auto authentication = security->find("authentication");
    if (authentication == security->end() || !authentication->is_object())
        throw std::runtime_error("Security.authentication configuration is required");

    const std::string credentialsFile = authentication->value("credentials_file", std::string());
    if (credentialsFile.empty())
        throw std::runtime_error("Security.authentication.credentials_file is required");
    requirePrivateTeamServerFile(
        credentialsFile,
        "Authentication credential file",
        config.value("Profile", "production") == "production");

    const int ttlMinutes = authentication->value("token_ttl_minutes", 60);
    const int maxFailures = authentication->value("max_failures", 5);
    const int lockoutSeconds = authentication->value("lockout_seconds", 60);
    if (ttlMinutes < 1 || ttlMinutes > 1440)
        throw std::runtime_error("Authentication token TTL must be between 1 and 1440 minutes");
    if (maxFailures < 1 || maxFailures > 100)
        throw std::runtime_error("Authentication max_failures must be between 1 and 100");
    if (lockoutSeconds < 1 || lockoutSeconds > 86400)
        throw std::runtime_error("Authentication lockout_seconds must be between 1 and 86400");

    std::ifstream input(credentialsFile);
    if (!input.good())
        throw std::runtime_error("Authentication credential file could not be opened: " + credentialsFile);

    json document;
    try
    {
        document = json::parse(input);
    }
    catch (const std::exception& error)
    {
        throw std::runtime_error("Authentication credential file is invalid: " + std::string(error.what()));
    }
    if (document.value("schema_version", 0) != 1 || !document.contains("users") || !document["users"].is_array())
        throw std::runtime_error("Authentication credential file schema is invalid");

    std::unordered_map<std::string, UserRecord> users;
    bool hasAdministrator = false;
    for (const auto& entry : document["users"])
    {
        if (!entry.is_object())
            throw std::runtime_error("Authentication user entry must be an object");
        const std::string username = entry.value("username", std::string());
        if (username.empty() || username.size() > 128)
            throw std::runtime_error("Authentication username is invalid");
        if (users.find(username) != users.end())
            throw std::runtime_error("Duplicate authentication username: " + username);

        UserRecord record;
        record.role = parseRole(entry.value("role", std::string()));
        record.password = TeamServerPasswordHash::fromJson(entry.at("password"));
        hasAdministrator = hasAdministrator || record.role == Role::Admin;
        users.emplace(username, std::move(record));
    }
    if (users.empty() || !hasAdministrator)
        throw std::runtime_error("Authentication requires at least one administrator");

    std::lock_guard<std::mutex> lock(m_mutex);
    m_users = std::move(users);
    m_activeTokens.clear();
    m_failures.clear();
    m_tokenValidityDuration = std::chrono::minutes(ttlMinutes);
    m_maxFailures = maxFailures;
    m_lockoutDuration = std::chrono::seconds(lockoutSeconds);
    m_logger->info("Authentication enabled for {} user(s); configuration is fail-closed", m_users.size());
}

grpc::Status TeamServerAuthorization::authenticate(
    const teamserverapi::AuthRequest& request,
    teamserverapi::AuthResponse& response,
    const std::string& peer)
{
    cleanupExpiredTokens();
    const std::string username = request.username();
    const std::string failureKey = peer + "\n" + username;
    const auto now = std::chrono::steady_clock::now();

    UserRecord user;
    bool knownUser = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto failure = m_failures.find(failureKey);
        if (failure != m_failures.end() && now < failure->second.blockedUntil)
        {
            response.set_status(teamserverapi::KO);
            response.set_message("Authentication temporarily locked");
            return grpc::Status::OK;
        }
        const auto found = m_users.find(username);
        if (found != m_users.end())
        {
            user = found->second;
            knownUser = true;
        }
    }

    bool passwordValid = false;
    if (knownUser)
    {
        try
        {
            passwordValid = verifyTeamServerPassword(request.password(), user.password);
        }
        catch (const std::exception& error)
        {
            m_logger->error("Password verification failed: {}", error.what());
        }
    }

    if (!knownUser || !passwordValid)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        FailureRecord& failure = m_failures[failureKey];
        ++failure.failures;
        if (failure.failures >= m_maxFailures)
        {
            failure.failures = 0;
            failure.blockedUntil = now + m_lockoutDuration;
        }
        response.set_status(teamserverapi::KO);
        response.set_message("Invalid credentials");
        m_logger->warn("Authentication rejected for peer {}", peer);
        return grpc::Status::OK;
    }

    const std::string token = generateTeamServerSecret(32);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_failures.erase(failureKey);
        m_activeTokens[token] = {{username, user.role}, now + m_tokenValidityDuration};
    }
    response.set_status(teamserverapi::OK);
    response.set_token(token);
    response.set_message("Authentication successful");
    m_logger->info("User '{}' authenticated with role {}", username, roleName(user.role));
    return grpc::Status::OK;
}

grpc::Status TeamServerAuthorization::authorize(
    const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
    Role requiredRole,
    Principal* principal)
{
    const auto authorization = std::find_if(metadata.begin(), metadata.end(), [](const auto& entry)
        { return entry.first == "authorization"; });
    if (authorization == metadata.end())
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Missing authorization metadata");

    const std::string header(authorization->second.data(), authorization->second.length());
    static const std::string prefix = "Bearer ";
    if (header.rfind(prefix, 0) != 0 || header.size() <= prefix.size())
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Malformed authorization header");

    std::lock_guard<std::mutex> lock(m_mutex);
    const auto found = m_activeTokens.find(header.substr(prefix.size()));
    if (found == m_activeTokens.end())
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid token");
    if (std::chrono::steady_clock::now() >= found->second.expiresAt)
    {
        m_activeTokens.erase(found);
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Token expired");
    }
    if (static_cast<int>(found->second.principal.role) < static_cast<int>(requiredRole))
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Insufficient role");
    if (principal)
        *principal = found->second.principal;
    return grpc::Status::OK;
}

void TeamServerAuthorization::cleanupExpiredTokens()
{
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto iterator = m_activeTokens.begin(); iterator != m_activeTokens.end();)
    {
        if (now >= iterator->second.expiresAt)
            iterator = m_activeTokens.erase(iterator);
        else
            ++iterator;
    }
}

