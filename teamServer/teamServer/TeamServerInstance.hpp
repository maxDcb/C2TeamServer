#pragma once

#include <filesystem>
#include <string>

enum class TeamServerProfile
{
    Development,
    Standalone,
    Production
};

struct TeamServerInstanceOptions
{
    TeamServerProfile profile = TeamServerProfile::Standalone;
    std::filesystem::path instanceRoot;
    std::filesystem::path releaseRoot;
    std::string hostname = "localhost";
    std::string listenAddress = "127.0.0.1";
    int port = 50051;
    std::string adminUsername = "admin";
    std::string adminPassword;
    std::filesystem::path tlsCertificate;
    std::filesystem::path tlsPrivateKey;
    std::filesystem::path trustCertificate;
    std::filesystem::path clientCaCertificate;
    bool requireClientCertificate = false;
    bool force = false;
};

struct TeamServerInstanceResult
{
    std::filesystem::path configFile;
    std::filesystem::path clientProfileFile;
    std::filesystem::path bootstrapFile;
    std::string certificateFingerprint;
};

std::string teamServerProfileName(TeamServerProfile profile);
TeamServerProfile parseTeamServerProfile(const std::string& value);
std::filesystem::path defaultTeamServerInstanceRoot();
TeamServerInstanceResult initializeTeamServerInstance(const TeamServerInstanceOptions& options);

