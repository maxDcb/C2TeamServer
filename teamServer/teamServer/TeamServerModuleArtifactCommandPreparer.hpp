#pragma once

#include <memory>
#include <string>
#include <vector>

#include "TeamServerCommandPreparer.hpp"
#include "TeamServerFileArtifactService.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerModuleArtifactCommandPreparer final : public TeamServerCommandPreparer
{
public:
    TeamServerModuleArtifactCommandPreparer(
        std::shared_ptr<spdlog::logger> logger,
        std::shared_ptr<TeamServerFileArtifactService> fileArtifactService,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd);

    bool canPrepare(const std::string& instruction) const override;
    TeamServerCommandPreparerResult prepare(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const override;

private:
    bool hasModule(const std::string& name) const;
    TeamServerPreparedInputArtifact resolveToolOrUpload(
        const std::string& selector,
        const TeamServerCommandPreparerContext& context,
        std::string& errorMessage) const;

    TeamServerCommandPreparerResult prepareScreenShot(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;
    TeamServerCommandPreparerResult prepareKerberosUseTicket(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;
    TeamServerCommandPreparerResult preparePsExec(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;
    TeamServerCommandPreparerResult prepareCoffLoader(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;
    TeamServerCommandPreparerResult prepareDotnetExec(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;
    TeamServerCommandPreparerResult preparePwSh(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const;

    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<TeamServerFileArtifactService> m_fileArtifactService;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
};
