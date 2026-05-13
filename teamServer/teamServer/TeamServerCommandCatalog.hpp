#pragma once

#include <string>
#include <vector>

#include "TeamServerRuntimeConfig.hpp"

struct TeamServerCommandArtifactFilter
{
    std::string category;
    std::string scope;
    std::string target;
    std::string platform;
    std::string arch;
    std::string runtime;
    std::string nameContains;
    std::string format;
};

struct TeamServerCommandCredentialFilter
{
    std::string type;
    std::string username;
    std::string domain;
    std::string target;
    std::string protocol;
    std::string tag;
    std::string nameContains;
    bool includeExpired = false;
};

struct TeamServerCommandArgSpec
{
    std::string name;
    std::string type;
    bool required = false;
    std::string description;
    std::vector<std::string> values;
    TeamServerCommandArtifactFilter artifactFilter;
    std::vector<TeamServerCommandArtifactFilter> artifactFilters;
    bool hasArtifactFilter = false;
    TeamServerCommandCredentialFilter credentialFilter;
    std::vector<TeamServerCommandCredentialFilter> credentialFilters;
    bool hasCredentialFilter = false;
    bool variadic = false;
    std::vector<std::string> completionParents;
};

struct TeamServerCommandSpecRecord
{
    std::string name;
    std::string displayName;
    std::string kind;
    std::string description;
    std::string target;
    bool requiresSession = false;
    std::vector<std::string> platforms;
    std::vector<std::string> archs;
    std::vector<TeamServerCommandArgSpec> args;
    std::vector<std::string> examples;
    std::string source;
    std::string commandTemplate;
    std::string internalPath;
};

struct TeamServerCommandQuery
{
    std::string kind;
    std::string target;
    std::string platform;
    std::string nameContains;
};

class TeamServerCommandCatalog
{
public:
    explicit TeamServerCommandCatalog(TeamServerRuntimeConfig runtimeConfig);

    std::vector<TeamServerCommandSpecRecord> listCommands(const TeamServerCommandQuery& query = {}) const;

private:
    TeamServerRuntimeConfig m_runtimeConfig;
};
