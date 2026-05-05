#pragma once

#include <functional>
#include <memory>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
#include "TeamServerCommandCatalog.hpp"
#include "spdlog/logger.h"

class TeamServerCommandCatalogService
{
public:
    using CommandWriter = std::function<bool(const teamserverapi::CommandSpec&)>;

    TeamServerCommandCatalogService(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerCommandCatalog catalog);

    grpc::Status listCommands(
        const teamserverapi::CommandQuery& query,
        const CommandWriter& writer) const;

private:
    static teamserverapi::CommandSpec toProto(const TeamServerCommandSpecRecord& command);

    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerCommandCatalog m_catalog;
};
