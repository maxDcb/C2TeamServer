#pragma once

#include <memory>
#include <string>
#include <vector>

#include "TeamServerCommandPreparer.hpp"
#include "TeamServerFileArtifactService.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerScriptCommandPreparer final : public TeamServerCommandPreparer
{
public:
    TeamServerScriptCommandPreparer(
        std::shared_ptr<spdlog::logger> logger,
        std::shared_ptr<TeamServerFileArtifactService> fileArtifactService,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd);

    bool canPrepare(const std::string& instruction) const override;
    TeamServerCommandPreparerResult prepare(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const override;

private:
    bool hasModule(const std::string& name) const;
    TeamServerCommandPreparerResult prepareScript(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;
    TeamServerCommandPreparerResult preparePowershellScript(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;

    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<TeamServerFileArtifactService> m_fileArtifactService;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
};
