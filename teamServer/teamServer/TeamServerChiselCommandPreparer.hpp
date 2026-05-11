#pragma once

#include <memory>
#include <string>
#include <vector>

#include "TeamServerCommandPreparer.hpp"
#include "TeamServerGeneratedArtifactStore.hpp"
#include "TeamServerRuntimeConfig.hpp"
#include "TeamServerShellcodeService.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerChiselCommandPreparer final : public TeamServerCommandPreparer
{
public:
    TeamServerChiselCommandPreparer(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerRuntimeConfig runtimeConfig,
        std::shared_ptr<TeamServerShellcodeService> shellcodeService,
        std::shared_ptr<TeamServerGeneratedArtifactStore> artifactStore,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd);

    bool canPrepare(const std::string& instruction) const override;
    TeamServerCommandPreparerResult prepare(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const override;

private:
    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerRuntimeConfig m_runtimeConfig;
    std::shared_ptr<TeamServerShellcodeService> m_shellcodeService;
    std::shared_ptr<TeamServerGeneratedArtifactStore> m_artifactStore;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
};
