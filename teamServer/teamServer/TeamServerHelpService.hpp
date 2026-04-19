#pragma once

#include <memory>
#include <string>
#include <vector>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
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
        CommonCommands& commonCommands);

    grpc::Status getHelp(const teamserverapi::Command& command, teamserverapi::CommandResponse* commandResponse) const;

private:
    bool isWindowsSession(const std::string& beaconHash, const std::string& listenerHash) const;
    std::string buildGeneralHelp(bool isWindows) const;
    std::string buildSpecificHelp(const std::string& instruction) const;

    std::shared_ptr<spdlog::logger> m_logger;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    CommonCommands& m_commonCommands;
};
