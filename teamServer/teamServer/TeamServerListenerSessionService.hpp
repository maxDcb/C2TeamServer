#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <grpcpp/support/status.h>
#include <grpcpp/support/string_ref.h>

#include "TeamServerApi.pb.h"
#include "TeamServerCommandTracking.hpp"
#include "listener/Listener.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"
#include "modules/ModuleCmd/ModuleCmd.hpp"
#include "nlohmann/json.hpp"
#include "spdlog/logger.h"

class TeamServerListenerSessionService
{
public:
    using PrepMsgCallback = std::function<int(const std::string&, C2Message&, bool, const std::string&)>;
    using ListenerEmitter = std::function<bool(const teamserverapi::Listener&)>;
    using SessionEmitter = std::function<bool(const teamserverapi::Session&)>;
    using CommandResponseEmitter = std::function<bool(const teamserverapi::CommandResponse&)>;

    TeamServerListenerSessionService(
        std::shared_ptr<spdlog::logger> logger,
        const nlohmann::json& config,
        std::vector<std::shared_ptr<Listener>>& listeners,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
        CommonCommands& commonCommands,
        std::vector<teamserverapi::CommandResponse>& cmdResponses,
        std::unordered_map<std::string, std::vector<int>>& sentResponses,
        std::vector<BeaconCommandContext>& sentCommands,
        PrepMsgCallback prepMsg);

    grpc::Status streamListeners(const ListenerEmitter& emit);
    grpc::Status addListener(const teamserverapi::Listener& listenerToCreate);
    grpc::Status stopListener(const teamserverapi::Listener& listenerToStop, teamserverapi::Response* response);

    grpc::Status streamSessions(const SessionEmitter& emit);
    grpc::Status stopSession(const teamserverapi::Session& sessionToStop, teamserverapi::Response* response);
    grpc::Status sendCmdToSession(const teamserverapi::Command& command, teamserverapi::CommandAck* response);
    grpc::Status streamResponsesForSession(
        const teamserverapi::Session& targetSession,
        const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
        const CommandResponseEmitter& emit);

    int handleCmdResponse();
    bool isListenerAlive(const std::string& listenerHash) const;

private:
    std::shared_ptr<spdlog::logger> m_logger;
    const nlohmann::json& m_config;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    CommonCommands& m_commonCommands;
    std::vector<teamserverapi::CommandResponse>& m_cmdResponses;
    std::unordered_map<std::string, std::vector<int>>& m_sentResponses;
    std::vector<BeaconCommandContext>& m_sentCommands;
    PrepMsgCallback m_prepMsg;
};
