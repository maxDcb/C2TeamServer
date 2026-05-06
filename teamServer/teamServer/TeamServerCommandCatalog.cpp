#include "TeamServerCommandCatalog.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <system_error>
#include <tuple>
#include <utility>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string jsonString(const json& input, const char* key, const std::string& fallback = "")
{
    auto it = input.find(key);
    if (it == input.end() || !it->is_string())
        return fallback;
    return it->get<std::string>();
}

bool jsonBool(const json& input, const char* key, bool fallback = false)
{
    auto it = input.find(key);
    if (it == input.end() || !it->is_boolean())
        return fallback;
    return it->get<bool>();
}

std::vector<std::string> jsonStringList(const json& input, const char* key)
{
    std::vector<std::string> values;
    auto it = input.find(key);
    if (it == input.end() || !it->is_array())
        return values;

    for (const auto& value : *it)
    {
        if (value.is_string())
            values.push_back(value.get<std::string>());
    }
    return values;
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle)
{
    if (needle.empty())
        return true;
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

bool matchesExact(const std::string& requested, const std::string& actual)
{
    return requested.empty() || toLower(requested) == toLower(actual);
}

bool listContainsOrAny(const std::vector<std::string>& values, const std::string& requested)
{
    if (requested.empty())
        return true;

    const std::string requestedLower = toLower(requested);
    for (const std::string& value : values)
    {
        const std::string valueLower = toLower(value);
        if (valueLower == requestedLower || valueLower == "any")
            return true;
    }
    return false;
}

bool matchesQuery(const TeamServerCommandSpecRecord& command, const TeamServerCommandQuery& query)
{
    return matchesExact(query.kind, command.kind)
        && matchesExact(query.target, command.target)
        && listContainsOrAny(command.platforms, query.platform)
        && containsCaseInsensitive(command.name, query.nameContains);
}

TeamServerCommandArtifactFilter parseArtifactFilter(const json& input)
{
    TeamServerCommandArtifactFilter filter;
    filter.category = jsonString(input, "category");
    filter.scope = jsonString(input, "scope");
    filter.target = jsonString(input, "target");
    filter.platform = jsonString(input, "platform");
    filter.arch = jsonString(input, "arch");
    filter.runtime = jsonString(input, "runtime");
    filter.nameContains = jsonString(input, "name_contains");
    return filter;
}

void addArtifactFilter(TeamServerCommandArgSpec& arg, TeamServerCommandArtifactFilter filter)
{
    arg.artifactFilters.push_back(std::move(filter));
    arg.artifactFilter = arg.artifactFilters.front();
    arg.hasArtifactFilter = true;
}

TeamServerCommandArgSpec parseArgSpec(const json& input)
{
    TeamServerCommandArgSpec arg;
    arg.name = jsonString(input, "name");
    arg.type = jsonString(input, "type", "text");
    arg.required = jsonBool(input, "required", false);
    arg.description = jsonString(input, "description");
    arg.values = jsonStringList(input, "values");
    arg.variadic = jsonBool(input, "variadic", false);

    auto artifactFilterIt = input.find("artifact_filter");
    if (artifactFilterIt != input.end() && artifactFilterIt->is_object())
    {
        addArtifactFilter(arg, parseArtifactFilter(*artifactFilterIt));
    }

    auto artifactFiltersIt = input.find("artifact_filters");
    if (artifactFiltersIt != input.end() && artifactFiltersIt->is_array())
    {
        for (const auto& artifactFilter : *artifactFiltersIt)
        {
            if (artifactFilter.is_object())
                addArtifactFilter(arg, parseArtifactFilter(artifactFilter));
        }
    }
    return arg;
}

TeamServerCommandSpecRecord parseCommandSpec(const fs::path& path)
{
    std::ifstream input(path);
    if (!input.good())
        return {};

    json spec = json::parse(input, nullptr, false);
    if (spec.is_discarded() || !spec.is_object())
        return {};

    TeamServerCommandSpecRecord command;
    command.name = jsonString(spec, "name");
    command.displayName = jsonString(spec, "display_name", command.name);
    command.kind = jsonString(spec, "kind", "module");
    command.description = jsonString(spec, "description");
    command.target = jsonString(spec, "target", "beacon");
    command.requiresSession = jsonBool(spec, "requires_session", true);
    command.platforms = jsonStringList(spec, "platforms");
    command.archs = jsonStringList(spec, "archs");
    command.examples = jsonStringList(spec, "examples");
    command.source = jsonString(spec, "source", "manifest");
    command.internalPath = path.string();

    auto argsIt = spec.find("args");
    if (argsIt != spec.end() && argsIt->is_array())
    {
        for (const auto& arg : *argsIt)
        {
            if (arg.is_object())
                command.args.push_back(parseArgSpec(arg));
        }
    }

    if (command.platforms.empty())
        command.platforms.push_back("any");
    if (command.archs.empty())
        command.archs.push_back("any");

    return command;
}

std::vector<TeamServerCommandSpecRecord> loadManifestCommands(const fs::path& root)
{
    std::vector<TeamServerCommandSpecRecord> commands;
    std::error_code ec;
    if (root.empty() || !fs::exists(root, ec) || !fs::is_directory(root, ec))
        return commands;

    fs::recursive_directory_iterator iterator(root, fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;
    if (ec)
        return commands;

    for (; iterator != end; iterator.increment(ec))
    {
        if (ec)
        {
            ec.clear();
            continue;
        }
        const fs::path path = iterator->path();
        if (!fs::is_regular_file(path, ec) || path.extension() != ".json")
            continue;

        TeamServerCommandSpecRecord command = parseCommandSpec(path);
        if (!command.name.empty())
            commands.push_back(std::move(command));
    }
    return commands;
}

bool sortCommands(const TeamServerCommandSpecRecord& left, const TeamServerCommandSpecRecord& right)
{
    return std::tie(left.kind, left.target, left.name, left.source)
        < std::tie(right.kind, right.target, right.name, right.source);
}
} // namespace

TeamServerCommandCatalog::TeamServerCommandCatalog(TeamServerRuntimeConfig runtimeConfig)
    : m_runtimeConfig(std::move(runtimeConfig))
{
}

std::vector<TeamServerCommandSpecRecord> TeamServerCommandCatalog::listCommands(const TeamServerCommandQuery& query) const
{
    std::vector<TeamServerCommandSpecRecord> commands = loadManifestCommands(m_runtimeConfig.commandSpecsDirectoryPath);
    std::vector<TeamServerCommandSpecRecord> filteredCommands;
    for (const TeamServerCommandSpecRecord& command : commands)
    {
        if (matchesQuery(command, query))
            filteredCommands.push_back(command);
    }

    std::sort(filteredCommands.begin(), filteredCommands.end(), sortCommands);
    return filteredCommands;
}
