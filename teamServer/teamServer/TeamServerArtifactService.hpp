#pragma once

#include <functional>
#include <memory>

#include <grpcpp/support/status.h>

#include "TeamServerApi.pb.h"
#include "TeamServerArtifactCatalog.hpp"
#include "spdlog/logger.h"

class TeamServerArtifactService
{
public:
    using ArtifactWriter = std::function<bool(const teamserverapi::ArtifactSummary&)>;

    TeamServerArtifactService(
        std::shared_ptr<spdlog::logger> logger,
        TeamServerArtifactCatalog catalog);

    grpc::Status listArtifacts(
        const teamserverapi::ArtifactQuery& query,
        const ArtifactWriter& writer) const;
    grpc::Status downloadArtifact(
        const teamserverapi::ArtifactSelector& selector,
        teamserverapi::ArtifactContent* response) const;
    grpc::Status uploadArtifact(
        const teamserverapi::ArtifactUploadRequest& request,
        teamserverapi::OperationAck* response) const;
    grpc::Status deleteGeneratedArtifact(
        const teamserverapi::ArtifactSelector& selector,
        teamserverapi::OperationAck* response) const;

private:
    static teamserverapi::ArtifactSummary toProto(const TeamServerArtifactRecord& artifact);

    std::shared_ptr<spdlog::logger> m_logger;
    TeamServerArtifactCatalog m_catalog;
};
