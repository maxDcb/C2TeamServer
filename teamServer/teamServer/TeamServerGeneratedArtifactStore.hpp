#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "TeamServerRuntimeConfig.hpp"

struct TeamServerGeneratedArtifactRequest
{
    std::string nameHint;
    std::string bytes;
    std::string category = "payload";
    std::string scope = "generated";
    std::string target = "beacon";
    std::string platform = "any";
    std::string arch = "any";
    std::string format = "bin";
    std::string runtime = "shellcode";
    std::string source = "generated";
    std::string description;
    std::vector<std::string> tags;
};

struct TeamServerGeneratedArtifactRecord
{
    std::string artifactId;
    std::string path;
    std::string name;
    std::string displayName;
    std::string sha256;
    std::int64_t size = 0;
};

class TeamServerGeneratedArtifactStore
{
public:
    explicit TeamServerGeneratedArtifactStore(TeamServerRuntimeConfig runtimeConfig);

    TeamServerGeneratedArtifactRecord store(const TeamServerGeneratedArtifactRequest& request) const;

private:
    TeamServerRuntimeConfig m_runtimeConfig;
};
