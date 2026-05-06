#include "TeamServerFileArtifactService.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <sstream>
#include <utility>

#include "nlohmann/json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
constexpr const char* PendingDownloadSuffix = ".artifact.pending.json";

std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string platformName(bool isWindows)
{
    return isWindows ? "windows" : "linux";
}

std::string normalizeArch(bool isWindows, const std::string& arch, const TeamServerRuntimeConfig& runtimeConfig)
{
    std::string normalized = isWindows
        ? TeamServerRuntimeConfig::normalizeWindowsArch(arch)
        : TeamServerRuntimeConfig::normalizeLinuxArch(arch);
    if (normalized.empty())
        normalized = isWindows ? runtimeConfig.defaultWindowsArch : runtimeConfig.defaultLinuxArch;
    return normalized.empty() ? "any" : normalized;
}

std::string basename(std::string value)
{
    const auto slash = value.find_last_of("/\\");
    if (slash != std::string::npos)
        value = value.substr(slash + 1);
    return value;
}

std::string sanitizeName(std::string value)
{
    for (char& ch : value)
    {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c) && ch != '.' && ch != '-' && ch != '_')
            ch = '_';
    }
    value.erase(std::remove(value.begin(), value.end(), '/'), value.end());
    value.erase(std::remove(value.begin(), value.end(), '\\'), value.end());
    if (value.empty())
        value = "artifact.bin";
    return value;
}

std::string detectFormat(const std::string& name)
{
    fs::path path(name);
    std::string extension = path.extension().string();
    if (extension.empty())
        return "binary";
    if (extension.front() == '.')
        extension.erase(extension.begin());
    extension = toLower(extension);
    return extension.empty() ? "binary" : extension;
}

std::string uniquePrefix()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device randomDevice;
    std::mt19937 generator(randomDevice());
    std::uniform_int_distribution<unsigned int> distribution(0, 0xffff);

    std::ostringstream output;
    output << now << "-" << std::hex << distribution(generator);
    return output.str();
}

bool readFile(const fs::path& path, std::string& bytes)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.good())
        return false;
    bytes.assign(std::istreambuf_iterator<char>(input), {});
    return input.good() || input.eof();
}

bool matchesSelector(const TeamServerArtifactRecord& artifact, const std::string& selector)
{
    const std::string loweredSelector = toLower(selector);
    return toLower(artifact.artifactId) == loweredSelector
        || toLower(artifact.name) == loweredSelector
        || toLower(artifact.displayName) == loweredSelector
        || toLower(basename(artifact.name)) == loweredSelector
        || toLower(basename(artifact.displayName)) == loweredSelector;
}

fs::path pendingPathFor(const std::string& artifactPath)
{
    return fs::path(artifactPath + PendingDownloadSuffix);
}

bool isSuccess(const C2Message& c2Message)
{
    return toLower(c2Message.returnvalue()) == "success";
}

std::string jsonString(const json& input, const char* key, const std::string& fallback = "")
{
    auto it = input.find(key);
    if (it == input.end() || !it->is_string())
        return fallback;
    return it->get<std::string>();
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

bool jsonBool(const json& input, const char* key, bool fallback = false)
{
    auto it = input.find(key);
    if (it == input.end() || !it->is_boolean())
        return fallback;
    return it->get<bool>();
}
} // namespace

TeamServerFileArtifactService::TeamServerFileArtifactService(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerRuntimeConfig runtimeConfig,
    std::shared_ptr<TeamServerGeneratedArtifactStore> generatedArtifactStore)
    : m_logger(std::move(logger)),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_generatedArtifactStore(std::move(generatedArtifactStore))
{
}

TeamServerPreparedInputArtifact TeamServerFileArtifactService::resolveUploadArtifact(
    const std::string& selector,
    bool isWindows,
    const std::string& arch) const
{
    TeamServerPreparedInputArtifact result;
    if (selector.empty())
    {
        result.message = "Missing upload artifact.";
        return result;
    }

    TeamServerArtifactQuery query;
    query.category = "upload";
    query.scope = "operator";
    query.target = "beacon";
    query.platform = platformName(isWindows);
    query.arch = normalizeArch(isWindows, arch, m_runtimeConfig);
    query.runtime = "file";

    TeamServerArtifactCatalog catalog(m_runtimeConfig);
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    const auto artifact = std::find_if(
        artifacts.begin(),
        artifacts.end(),
        [&](const TeamServerArtifactRecord& candidate)
        {
            return matchesSelector(candidate, selector);
        });

    if (artifact == artifacts.end())
    {
        result.message = "Upload artifact not found: " + selector
            + ". Put files under UploadedArtifacts/"
            + platformName(isWindows) + "/" + query.arch
            + " or UploadedArtifacts/Any/any.";
        return result;
    }

    std::string bytes;
    if (!readFile(artifact->internalPath, bytes))
    {
        result.message = "Upload artifact could not be read: " + artifact->name;
        return result;
    }

    result.ok = true;
    result.artifact = *artifact;
    result.bytes = std::move(bytes);
    return result;
}

TeamServerPreparedInputArtifact TeamServerFileArtifactService::resolveScriptArtifact(
    const std::string& selector,
    bool isWindows,
    const std::string& arch) const
{
    TeamServerPreparedInputArtifact result;
    if (selector.empty())
    {
        result.message = "Missing script artifact.";
        return result;
    }

    TeamServerArtifactQuery query;
    query.category = "script";
    query.scope = "server";
    query.target = "beacon";
    query.platform = platformName(isWindows);
    query.arch = normalizeArch(isWindows, arch, m_runtimeConfig);
    query.runtime = "script";

    TeamServerArtifactCatalog catalog(m_runtimeConfig);
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    const auto artifact = std::find_if(
        artifacts.begin(),
        artifacts.end(),
        [&](const TeamServerArtifactRecord& candidate)
        {
            return matchesSelector(candidate, selector);
        });

    if (artifact == artifacts.end())
    {
        result.message = "Script artifact not found: " + selector
            + ". Put scripts under Scripts/"
            + platformName(isWindows)
            + " or Scripts/Any.";
        return result;
    }

    std::string bytes;
    if (!readFile(artifact->internalPath, bytes))
    {
        result.message = "Script artifact could not be read: " + artifact->name;
        return result;
    }

    result.ok = true;
    result.artifact = *artifact;
    result.bytes = std::move(bytes);
    return result;
}

TeamServerPreparedInputArtifact TeamServerFileArtifactService::resolveToolArtifact(
    const std::string& selector,
    bool isWindows,
    const std::string& arch) const
{
    TeamServerPreparedInputArtifact result;
    if (selector.empty())
    {
        result.message = "Missing tool artifact.";
        return result;
    }

    TeamServerArtifactQuery query;
    query.category = "tool";
    query.scope = "server";
    query.target = "teamserver";
    query.platform = platformName(isWindows);
    query.arch = normalizeArch(isWindows, arch, m_runtimeConfig);
    query.runtime = "any";

    TeamServerArtifactCatalog catalog(m_runtimeConfig);
    const std::vector<TeamServerArtifactRecord> artifacts = catalog.listArtifacts(query);
    const auto artifact = std::find_if(
        artifacts.begin(),
        artifacts.end(),
        [&](const TeamServerArtifactRecord& candidate)
        {
            return matchesSelector(candidate, selector);
        });

    if (artifact == artifacts.end())
    {
        result.message = "Tool artifact not found: " + selector
            + ". Put tools under Tools/"
            + platformName(isWindows) + "/" + query.arch
            + " or Tools/Any/any.";
        return result;
    }

    std::string bytes;
    if (!readFile(artifact->internalPath, bytes))
    {
        result.message = "Tool artifact could not be read: " + artifact->name;
        return result;
    }

    result.ok = true;
    result.artifact = *artifact;
    result.bytes = std::move(bytes);
    return result;
}

TeamServerPreparedDownloadArtifact TeamServerFileArtifactService::prepareDownloadArtifact(
    const std::string& remotePath,
    const std::string& nameHint,
    bool isWindows,
    const std::string& arch) const
{
    TeamServerGeneratedFileArtifactSpec spec;
    spec.remotePath = remotePath;
    spec.nameHint = nameHint;
    spec.category = "download";
    spec.source = "beacon";
    spec.description = "Downloaded from beacon path: " + remotePath;
    spec.tags = {"download"};
    spec.isWindows = isWindows;
    spec.arch = arch;
    return prepareGeneratedFileArtifact(spec);
}

TeamServerPreparedDownloadArtifact TeamServerFileArtifactService::prepareGeneratedFileArtifact(
    const TeamServerGeneratedFileArtifactSpec& spec) const
{
    TeamServerPreparedDownloadArtifact result;
    if (spec.remotePath.empty())
    {
        result.message = "Missing artifact source path.";
        return result;
    }

    const std::string category = spec.category.empty() ? "download" : spec.category;
    const std::string source = spec.source.empty() ? "beacon" : spec.source;
    std::string displayName = spec.nameHint.empty() ? basename(spec.remotePath) : basename(spec.nameHint);
    displayName = sanitizeName(displayName.empty() ? category + ".bin" : displayName);
    const std::string fileName = uniquePrefix() + "-" + displayName;
    const fs::path root = fs::path(m_runtimeConfig.generatedArtifactsDirectoryPath) / category / source;
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec)
    {
        result.message = "Generated artifact directory could not be created: " + ec.message();
        return result;
    }

    const fs::path artifactPath = root / fileName;
    json pending;
    pending["name_hint"] = displayName;
    pending["category"] = category;
    pending["scope"] = spec.scope.empty() ? "generated" : spec.scope;
    pending["target"] = spec.target.empty() ? "teamserver" : spec.target;
    pending["platform"] = platformName(spec.isWindows);
    pending["arch"] = normalizeArch(spec.isWindows, spec.arch, m_runtimeConfig);
    pending["format"] = spec.format.empty() ? detectFormat(displayName) : spec.format;
    pending["runtime"] = spec.runtime.empty() ? "file" : spec.runtime;
    pending["source"] = source;
    pending["description"] = spec.description;
    pending["tags"] = spec.tags;
    pending["remote_path"] = spec.remotePath;
    pending["write_result_data"] = spec.writeResultData;

    std::ofstream pendingOutput(pendingPathFor(artifactPath.string()), std::ios::binary);
    if (!pendingOutput.good())
    {
        result.message = "Download artifact metadata could not be created.";
        return result;
    }
    pendingOutput << pending.dump(2);
    pendingOutput.close();
    if (!pendingOutput.good())
    {
        fs::remove(pendingPathFor(artifactPath.string()), ec);
        result.message = "Download artifact metadata could not be written.";
        return result;
    }

    result.ok = true;
    result.path = artifactPath.string();
    result.displayName = displayName;
    return result;
}

bool TeamServerFileArtifactService::shouldKeepCommandContext(const C2Message& c2Message) const
{
    const fs::path pendingPath = pendingPathFor(c2Message.outputfile());
    std::error_code ec;
    return !c2Message.outputfile().empty()
        && fs::exists(pendingPath, ec)
        && c2Message.errorCode() == -1
        && !isSuccess(c2Message);
}

bool TeamServerFileArtifactService::handleCommandResult(const C2Message& c2Message, std::string& outputMessage) const
{
    outputMessage.clear();
    if (c2Message.outputfile().empty())
        return false;

    const fs::path artifactPath = c2Message.outputfile();
    const fs::path pendingPath = pendingPathFor(c2Message.outputfile());
    std::error_code ec;
    if (!fs::exists(pendingPath, ec))
        return false;

    if (c2Message.errorCode() > 0)
    {
        fs::remove(artifactPath, ec);
        fs::remove(pendingPath, ec);
        if (m_logger)
            m_logger->warn("Discarded pending generated artifact after beacon error: {}", artifactPath.string());
        return true;
    }

    std::ifstream pendingInput(pendingPath);
    json metadata = json::parse(pendingInput, nullptr, false);
    if (metadata.is_discarded() || !metadata.is_object())
    {
        outputMessage = "Generated artifact metadata is invalid: " + artifactPath.string();
        return true;
    }

    const bool writeResultData = jsonBool(metadata, "write_result_data", false);
    if (writeResultData && !c2Message.data().empty())
    {
        fs::create_directories(artifactPath.parent_path(), ec);
        if (ec)
        {
            outputMessage = "Generated artifact directory could not be created: " + ec.message();
            return true;
        }

        const bool firstChunk = c2Message.args() == "0";
        std::ofstream output(
            artifactPath,
            std::ios::binary | (firstChunk ? std::ios::trunc : std::ios::app));
        if (!output.good())
        {
            outputMessage = "Generated artifact payload could not be opened: " + artifactPath.string();
            return true;
        }
        output.write(c2Message.data().data(), static_cast<std::streamsize>(c2Message.data().size()));
        output.close();
        if (!output.good())
        {
            outputMessage = "Generated artifact payload could not be written: " + artifactPath.string();
            return true;
        }
    }

    if (!isSuccess(c2Message))
        return true;

    if (!m_generatedArtifactStore)
    {
        outputMessage = "Generated artifact completed, but generated artifact store is not available: " + artifactPath.string();
        return true;
    }

    TeamServerGeneratedArtifactRequest request;
    request.nameHint = jsonString(metadata, "name_hint", artifactPath.filename().string());
    request.category = jsonString(metadata, "category", "download");
    request.scope = jsonString(metadata, "scope", "generated");
    request.target = jsonString(metadata, "target", "teamserver");
    request.platform = jsonString(metadata, "platform", "any");
    request.arch = jsonString(metadata, "arch", "any");
    request.format = jsonString(metadata, "format", detectFormat(artifactPath.filename().string()));
    request.runtime = jsonString(metadata, "runtime", "file");
    request.source = jsonString(metadata, "source", "beacon");
    request.description = jsonString(metadata, "description");
    request.tags = jsonStringList(metadata, "tags");

    TeamServerGeneratedArtifactRecord artifact = m_generatedArtifactStore->registerExistingFile(request, artifactPath.string());
    if (artifact.path.empty())
    {
        outputMessage = "Generated artifact completed, but registration failed: " + artifactPath.string();
        return true;
    }

    fs::remove(pendingPath, ec);
    const std::string category = jsonString(metadata, "category", "download");
    outputMessage = (category == "download" ? "Downloaded artifact stored: " : "Generated artifact stored: ") + artifact.name;
    if (m_logger)
        m_logger->info("Registered generated artifact {}", artifact.path);
    return true;
}
