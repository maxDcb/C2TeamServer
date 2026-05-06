#pragma once

#include <memory>
#include <string>
#include <vector>

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "TeamServerRuntimeConfig.hpp"
#include "modules/ModuleCmd/C2Message.hpp"
#include "spdlog/logger.h"

struct TeamServerPreparedInputArtifact
{
    bool ok = false;
    std::string message;
    TeamServerArtifactRecord artifact;
    std::string bytes;
};

struct TeamServerPreparedDownloadArtifact
{
    bool ok = false;
    std::string message;
    std::string path;
    std::string displayName;
};

struct TeamServerGeneratedFileArtifactSpec
{
    std::string remotePath;
    std::string nameHint;
    std::string category = "download";
    std::string scope = "generated";
    std::string target = "teamserver";
    std::string format;
    std::string runtime = "file";
    std::string source = "beacon";
    std::string description;
    std::vector<std::string> tags;
    bool isWindows = true;
    std::string arch;
    bool writeResultData = false;
};

class TeamServerFileArtifactService
{
public:
    TeamServerFileArtifactService(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerRuntimeConfig runtimeConfig,
        std::shared_ptr<TeamServerGeneratedArtifactStore> generatedArtifactStore);

    TeamServerPreparedInputArtifact resolveUploadArtifact(
        const std::string& selector,
        bool isWindows,
        const std::string& arch) const;
    TeamServerPreparedInputArtifact resolveScriptArtifact(
        const std::string& selector,
        bool isWindows,
        const std::string& arch) const;

    TeamServerPreparedDownloadArtifact prepareDownloadArtifact(
        const std::string& remotePath,
        const std::string& nameHint,
        bool isWindows,
        const std::string& arch) const;
    TeamServerPreparedDownloadArtifact prepareGeneratedFileArtifact(
        const TeamServerGeneratedFileArtifactSpec& spec) const;

    bool shouldKeepCommandContext(const C2Message& c2Message) const;
    bool handleCommandResult(const C2Message& c2Message, std::string& outputMessage) const;

private:
    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerRuntimeConfig m_runtimeConfig;
    std::shared_ptr<TeamServerGeneratedArtifactStore> m_generatedArtifactStore;
};
