#pragma once

#include <memory>
#include <string>

#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>

#include "nlohmann/json.hpp"

namespace spdlog
{
class logger;
}

class TeamServer;

struct TeamServerTlsMaterial
{
    std::string certificate;
    std::string key;
    std::string rootCertificate;
};

nlohmann::json loadTeamServerConfigFile(const std::string& configFile);
std::shared_ptr<spdlog::logger> createTeamServerLogger(const nlohmann::json& config);
TeamServerTlsMaterial loadTeamServerTlsMaterial(const nlohmann::json& config, const std::shared_ptr<spdlog::logger>& logger);
std::string buildTeamServerGrpcAddress(const nlohmann::json& config);
std::unique_ptr<grpc::Server> buildAndStartTeamServerServer(
    const nlohmann::json& config,
    TeamServer& service,
    const TeamServerTlsMaterial& tlsMaterial);
