#include "TeamServerCommandCatalogService.hpp"

#include <string>
#include <utility>
#include <vector>

TeamServerCommandCatalogService::TeamServerCommandCatalogService(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerCommandCatalog catalog)
    : m_logger(std::move(logger)),
      m_catalog(std::move(catalog))
{
}

grpc::Status TeamServerCommandCatalogService::listCommands(
    const teamserverapi::CommandQuery& query,
    const CommandWriter& writer) const
{
    TeamServerCommandQuery catalogQuery;
    catalogQuery.kind = query.kind();
    catalogQuery.target = query.target();
    catalogQuery.platform = query.platform();
    catalogQuery.nameContains = query.name_contains();

    const std::vector<TeamServerCommandSpecRecord> commands = m_catalog.listCommands(catalogQuery);
    m_logger->debug("ListCommands returned {0} command(s)", commands.size());

    for (const TeamServerCommandSpecRecord& command : commands)
    {
        if (!writer(toProto(command)))
            break;
    }
    return grpc::Status::OK;
}

teamserverapi::CommandSpec TeamServerCommandCatalogService::toProto(const TeamServerCommandSpecRecord& command)
{
    teamserverapi::CommandSpec spec;
    spec.set_name(command.name);
    spec.set_display_name(command.displayName);
    spec.set_kind(command.kind);
    spec.set_description(command.description);
    spec.set_target(command.target);
    spec.set_requires_session(command.requiresSession);
    spec.set_source(command.source);

    for (const std::string& platform : command.platforms)
        spec.add_platforms(platform);
    for (const std::string& arch : command.archs)
        spec.add_archs(arch);
    for (const std::string& example : command.examples)
        spec.add_examples(example);

    for (const TeamServerCommandArgSpec& arg : command.args)
    {
        teamserverapi::CommandArgSpec* argSpec = spec.add_args();
        argSpec->set_name(arg.name);
        argSpec->set_type(arg.type);
        argSpec->set_required(arg.required);
        argSpec->set_description(arg.description);
        argSpec->set_variadic(arg.variadic);
        for (const std::string& value : arg.values)
            argSpec->add_values(value);

        if (arg.hasArtifactFilter)
        {
            teamserverapi::ArtifactQuery* filter = argSpec->mutable_artifact_filter();
            filter->set_category(arg.artifactFilter.category);
            filter->set_target(arg.artifactFilter.target);
            filter->set_scope(arg.artifactFilter.scope);
            filter->set_platform(arg.artifactFilter.platform);
            filter->set_arch(arg.artifactFilter.arch);
            filter->set_runtime(arg.artifactFilter.runtime);
            filter->set_name_contains(arg.artifactFilter.nameContains);
        }

        for (const TeamServerCommandArtifactFilter& artifactFilter : arg.artifactFilters)
        {
            teamserverapi::ArtifactQuery* filter = argSpec->add_artifact_filters();
            filter->set_category(artifactFilter.category);
            filter->set_target(artifactFilter.target);
            filter->set_scope(artifactFilter.scope);
            filter->set_platform(artifactFilter.platform);
            filter->set_arch(artifactFilter.arch);
            filter->set_runtime(artifactFilter.runtime);
            filter->set_name_contains(artifactFilter.nameContains);
        }
    }

    return spec;
}
