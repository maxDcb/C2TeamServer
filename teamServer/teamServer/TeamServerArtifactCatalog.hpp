#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "TeamServerRuntimeConfig.hpp"

struct TeamServerArtifactQuery
{
    std::string category;
    std::string scope;
    std::string target;
    std::string platform;
    std::string arch;
    std::string runtime;
    std::string nameContains;
};

struct TeamServerArtifactRecord
{
    std::string artifactId;
    std::string name;
    std::string displayName;
    std::string category;
    std::string scope;
    std::string target;
    std::string platform;
    std::string arch;
    std::string format;
    std::string runtime;
    std::string source;
    std::int64_t size = 0;
    std::string sha256;
    std::string description;
    std::vector<std::string> tags;
    std::string internalPath;
};

class TeamServerArtifactCatalog
{
public:
    explicit TeamServerArtifactCatalog(TeamServerRuntimeConfig runtimeConfig);

    std::vector<TeamServerArtifactRecord> listArtifacts(const TeamServerArtifactQuery& query = {}) const;

private:
    TeamServerRuntimeConfig m_runtimeConfig;
};
