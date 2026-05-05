#pragma once

#include <memory>
#include <string>
#include <vector>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
#include "TeamServerCommandCatalog.hpp"
#include "listener/Listener.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "spdlog/logger.h"

class TeamServerHelpService
{
public:
    TeamServerHelpService(
        std::shared_ptr<spdlog::logger> logger,
        std::vector<std::shared_ptr<Listener>>& listeners,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
        CommonCommands& commonCommands,
        TeamServerCommandCatalog catalog);

    grpc::Status getHelp(const teamserverapi::CommandHelpRequest& command, teamserverapi::CommandHelpResponse* commandResponse) const;

private:
    std::string sessionPlatform(const std::string& beaconHash, const std::string& listenerHash) const;
    std::string buildGeneralHelp(const std::string& platform) const;
    std::string buildSpecificHelp(const std::string& instruction) const;
    std::string buildLegacyGeneralHelp(bool isWindows) const;
    std::string buildLegacySpecificHelp(const std::string& instruction) const;
    bool findCommandSpec(const std::string& instruction, TeamServerCommandSpecRecord& command) const;
    std::string formatCommandHelp(const TeamServerCommandSpecRecord& command) const;

    std::shared_ptr<spdlog::logger> m_logger;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    CommonCommands& m_commonCommands;
    TeamServerCommandCatalog m_catalog;
};
