#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

#include "nlohmann/json.hpp"

struct TeamServerPasswordHash
{
    std::string algorithm = "pbkdf2-sha256";
    int iterations = 600000;
    std::string salt;
    std::string digest;

    nlohmann::json toJson() const;
    static TeamServerPasswordHash fromJson(const nlohmann::json& value);
};

TeamServerPasswordHash deriveTeamServerPasswordHash(
    const std::string& password,
    int iterations = 600000);
bool verifyTeamServerPassword(
    const std::string& password,
    const TeamServerPasswordHash& expected);
std::string generateTeamServerSecret(std::size_t bytes = 32);
std::string sha256Fingerprint(const std::string& pemCertificate);

void writeTeamServerFile(
    const std::filesystem::path& path,
    const std::string& content,
    bool privateFile);
void requirePrivateTeamServerFile(
    const std::filesystem::path& path,
    const std::string& description,
    bool strictPermissions);

