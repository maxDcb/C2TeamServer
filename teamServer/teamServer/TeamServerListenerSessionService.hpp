#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
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
    using CommandResultEmitter = std::function<bool(const teamserverapi::CommandResult&)>;
    using ModuleEmitter = std::function<bool(const teamserverapi::LoadedModule&)>;

    TeamServerListenerSessionService(
        std::shared_ptr<spdlog::logger> logger,
        const nlohmann::json& config,
        std::vector<std::shared_ptr<Listener>>& listeners,
        std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
        CommonCommands& commonCommands,
        std::vector<teamserverapi::CommandResult>& cmdResponses,
        std::unordered_map<std::string, std::vector<int>>& sentResponses,
        std::vector<BeaconCommandContext>& sentCommands,
        PrepMsgCallback prepMsg);

    grpc::Status streamListeners(const ListenerEmitter& emit);
    grpc::Status addListener(const teamserverapi::Listener& listenerToCreate, teamserverapi::OperationAck* response);
    grpc::Status stopListener(const teamserverapi::ListenerSelector& listenerToStop, teamserverapi::OperationAck* response);

    grpc::Status streamSessions(const SessionEmitter& emit);
    grpc::Status stopSession(const teamserverapi::SessionSelector& sessionToStop, teamserverapi::OperationAck* response);
    grpc::Status streamModulesForSession(const teamserverapi::SessionSelector& targetSession, const ModuleEmitter& emit) const;
    grpc::Status sendSessionCommand(const teamserverapi::SessionCommandRequest& command, teamserverapi::CommandAck* response);
    grpc::Status streamResponsesForSession(
        const teamserverapi::SessionSelector& targetSession,
        const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
        const CommandResultEmitter& emit);

    int handleCmdResponse();
    bool isListenerAlive(const std::string& listenerHash) const;

private:
    std::shared_ptr<spdlog::logger> m_logger;
    const nlohmann::json& m_config;
    std::vector<std::shared_ptr<Listener>>& m_listeners;
    std::vector<std::unique_ptr<ModuleCmd>>& m_moduleCmd;
    CommonCommands& m_commonCommands;
    std::vector<teamserverapi::CommandResult>& m_cmdResponses;
    std::unordered_map<std::string, std::vector<int>>& m_sentResponses;
    std::vector<BeaconCommandContext>& m_sentCommands;
    PrepMsgCallback m_prepMsg;

    struct BeaconModuleRecord
    {
        std::string beaconHash;
        std::string listenerHash;
        std::string name;
        std::string state;
        std::string commandId;
        std::string artifact;
        std::string updatedAt;
        int loadCount = 0;
    };

    std::string sessionModuleKey(const std::string& beaconHash) const;
    std::string canonicalModuleName(const std::string& value) const;
    std::string moduleNameFromLoadTask(const std::string& input, const C2Message& c2Message) const;
    std::string moduleNameFromUnloadTask(const std::string& input, const C2Message& c2Message) const;
    bool hasActiveModule(const std::string& beaconHash, const std::string& moduleName, std::string& state) const;
    void markModuleLoading(
        const std::string& beaconHash,
        const std::string& listenerHash,
        const std::string& moduleName,
        const std::string& commandId,
        const std::string& artifact);
    void markModuleUnloading(const std::string& beaconHash, const std::string& moduleName, const std::string& commandId);
    void applyModuleResult(
        const std::string& beaconHash,
        const std::string& listenerHash,
        const std::string& commandId,
        const std::string& instruction,
        bool success);

    mutable std::mutex m_loadedModulesMutex;
    std::unordered_map<std::string, std::unordered_map<std::string, BeaconModuleRecord>> m_loadedModulesByBeacon;
};
