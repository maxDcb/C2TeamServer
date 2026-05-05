#include "TeamServerArtifactService.hpp"

#include <string>
#include <utility>
#include <vector>

TeamServerArtifactService::TeamServerArtifactService(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerArtifactCatalog catalog)
    : m_logger(std::move(logger)),
      m_catalog(std::move(catalog))
{
}

grpc::Status TeamServerArtifactService::listArtifacts(
    const teamserverapi::ArtifactQuery& query,
    const ArtifactWriter& writer) const
{
    TeamServerArtifactQuery catalogQuery;
    catalogQuery.category = query.category();
    catalogQuery.scope = query.scope();
    catalogQuery.target = query.target();
    catalogQuery.platform = query.platform();
    catalogQuery.arch = query.arch();
    catalogQuery.runtime = query.runtime();
    catalogQuery.nameContains = query.name_contains();

    const std::vector<TeamServerArtifactRecord> artifacts = m_catalog.listArtifacts(catalogQuery);
    m_logger->debug("ListArtifacts returned {0} artifact(s)", artifacts.size());

    for (const TeamServerArtifactRecord& artifact : artifacts)
    {
        if (!writer(toProto(artifact)))
            break;
    }

    return grpc::Status::OK;
}

grpc::Status TeamServerArtifactService::deleteGeneratedArtifact(
    const teamserverapi::ArtifactSelector& selector,
    teamserverapi::OperationAck* response) const
{
    std::string message;
    const bool deleted = m_catalog.deleteGeneratedArtifact(selector.artifact_id(), message);

    response->set_status(deleted ? teamserverapi::OK : teamserverapi::KO);
    response->set_message(message);
    if (deleted)
        m_logger->info("Deleted generated artifact {0}", selector.artifact_id());
    else
        m_logger->warn("Delete generated artifact failed for {0}: {1}", selector.artifact_id(), message);

    return grpc::Status::OK;
}

teamserverapi::ArtifactSummary TeamServerArtifactService::toProto(const TeamServerArtifactRecord& artifact)
{
    teamserverapi::ArtifactSummary summary;
    summary.set_artifact_id(artifact.artifactId);
    summary.set_name(artifact.name);
    summary.set_display_name(artifact.displayName);
    summary.set_category(artifact.category);
    summary.set_scope(artifact.scope);
    summary.set_target(artifact.target);
    summary.set_platform(artifact.platform);
    summary.set_arch(artifact.arch);
    summary.set_format(artifact.format);
    summary.set_runtime(artifact.runtime);
    summary.set_source(artifact.source);
    summary.set_size(artifact.size);
    summary.set_sha256(artifact.sha256);
    summary.set_description(artifact.description);
    for (const std::string& tag : artifact.tags)
        summary.add_tags(tag);
    return summary;
}
