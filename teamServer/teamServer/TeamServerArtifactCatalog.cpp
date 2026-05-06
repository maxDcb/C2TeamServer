#include "TeamServerArtifactCatalog.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <openssl/evp.h>
#include <sstream>
#include <system_error>
#include <tuple>
#include <utility>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
constexpr const char* ReleaseSource = "release";

std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle)
{
    if (needle.empty())
        return true;
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

bool matchesExactOrAny(const std::string& requested, const std::string& actual)
{
    if (requested.empty())
        return true;

    const std::string requestedLower = toLower(requested);
    const std::string actualLower = toLower(actual);
    return actualLower == requestedLower || actualLower == "any";
}

bool matchesExact(const std::string& requested, const std::string& actual)
{
    return requested.empty() || toLower(requested) == toLower(actual);
}

bool matchesQuery(const TeamServerArtifactRecord& artifact, const TeamServerArtifactQuery& query)
{
    return matchesExact(query.category, artifact.category)
        && matchesExact(query.scope, artifact.scope)
        && matchesExact(query.target, artifact.target)
        && matchesExactOrAny(query.platform, artifact.platform)
        && matchesExactOrAny(query.arch, artifact.arch)
        && matchesExactOrAny(query.runtime, artifact.runtime)
        && containsCaseInsensitive(artifact.name, query.nameContains);
}

std::string bytesToHex(const unsigned char* bytes, unsigned int length)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < length; ++index)
        output << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    return output.str();
}

std::string sha256String(const std::string& value)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest = {};
    unsigned int digestLength = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context)
        return "";

    const bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1
        && EVP_DigestUpdate(context, value.data(), value.size()) == 1
        && EVP_DigestFinal_ex(context, digest.data(), &digestLength) == 1;
    EVP_MD_CTX_free(context);

    if (!ok)
        return "";
    return bytesToHex(digest.data(), digestLength);
}

std::string sha256File(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.good())
        return "";

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context)
        return "";

    bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<char, 64 * 1024> buffer = {};
    while (ok && input.good())
    {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0)
            ok = EVP_DigestUpdate(context, buffer.data(), static_cast<std::size_t>(bytesRead)) == 1;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest = {};
    unsigned int digestLength = 0;
    if (ok)
        ok = EVP_DigestFinal_ex(context, digest.data(), &digestLength) == 1;
    EVP_MD_CTX_free(context);

    if (!ok)
        return "";
    return bytesToHex(digest.data(), digestLength);
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

bool hasHiddenComponent(const fs::path& relativePath)
{
    for (const auto& component : relativePath)
    {
        const std::string value = component.string();
        if (!value.empty() && value.front() == '.')
            return true;
    }
    return false;
}

bool isPathWithinRoot(const fs::path& path, const fs::path& root)
{
    std::error_code ec;
    const fs::path canonicalRoot = fs::weakly_canonical(root, ec);
    if (ec)
        return false;

    const fs::path canonicalPath = fs::weakly_canonical(path, ec);
    if (ec)
        return false;

    auto rootIt = canonicalRoot.begin();
    auto pathIt = canonicalPath.begin();
    for (; rootIt != canonicalRoot.end(); ++rootIt, ++pathIt)
    {
        if (pathIt == canonicalPath.end() || *pathIt != *rootIt)
            return false;
    }
    return true;
}

std::string detectFormat(const fs::path& path)
{
    std::string extension = path.extension().string();
    if (extension.empty())
        return "binary";
    if (extension.front() == '.')
        extension.erase(extension.begin());
    extension = toLower(extension);
    if (extension.empty())
        return "binary";
    return extension;
}

std::string sanitizeArtifactName(std::string value)
{
    value = fs::path(value).filename().string();
    for (char& ch : value)
    {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c) && ch != '.' && ch != '-' && ch != '_')
            ch = '_';
    }
    value.erase(std::remove(value.begin(), value.end(), '/'), value.end());
    value.erase(std::remove(value.begin(), value.end(), '\\'), value.end());
    return value.empty() ? "artifact.bin" : value;
}

std::string normalizeUploadPlatform(std::string platform)
{
    platform = toLower(platform);
    if (platform == "windows" || platform == "win")
        return "windows";
    if (platform == "linux")
        return "linux";
    return "any";
}

std::string normalizeUploadArch(
    const std::string& platform,
    const std::string& arch,
    const TeamServerRuntimeConfig& runtimeConfig)
{
    std::string normalized;
    if (platform == "windows")
        normalized = TeamServerRuntimeConfig::normalizeWindowsArch(arch);
    else if (platform == "linux")
        normalized = TeamServerRuntimeConfig::normalizeLinuxArch(arch);

    if (!normalized.empty())
        return normalized;
    if (platform == "windows")
        return runtimeConfig.defaultWindowsArch.empty() ? "x64" : runtimeConfig.defaultWindowsArch;
    if (platform == "linux")
        return runtimeConfig.defaultLinuxArch.empty() ? "x64" : runtimeConfig.defaultLinuxArch;
    return "any";
}

void collectDirectoryArtifacts(
    const fs::path& root,
    const std::string& category,
    const std::string& scope,
    const std::string& target,
    const std::string& platform,
    const std::string& arch,
    const std::string& runtime,
    std::vector<TeamServerArtifactRecord>& artifacts,
    const std::string& source = ReleaseSource)
{
    std::error_code ec;
    if (root.empty() || !fs::exists(root, ec) || !fs::is_directory(root, ec))
        return;

    fs::recursive_directory_iterator iterator(root, fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;
    if (ec)
        return;

    for (; iterator != end; iterator.increment(ec))
    {
        if (ec)
        {
            ec.clear();
            continue;
        }

        const fs::path path = iterator->path();
        if (!fs::is_regular_file(path, ec))
            continue;

        const fs::path relativePath = fs::relative(path, root, ec);
        if (ec)
        {
            ec.clear();
            continue;
        }
        if (hasHiddenComponent(relativePath))
            continue;
        if (path.filename().string().find(".artifact.") != std::string::npos)
            continue;
        if (fs::exists(fs::path(path.string() + ".artifact.json"), ec))
            continue;
        ec.clear();

        const std::string contentHash = sha256File(path);
        if (contentHash.empty())
            continue;

        TeamServerArtifactRecord artifact;
        artifact.name = relativePath.generic_string();
        artifact.displayName = path.filename().string();
        artifact.category = category;
        artifact.scope = scope;
        artifact.target = target;
        artifact.platform = platform;
        artifact.arch = arch;
        artifact.format = detectFormat(path);
        artifact.runtime = runtime;
        artifact.source = source;
        artifact.sha256 = contentHash;
        artifact.internalPath = path.string();

        artifact.size = static_cast<std::int64_t>(fs::file_size(path, ec));
        if (ec)
        {
            ec.clear();
            artifact.size = 0;
        }

        artifact.artifactId = sha256String(
            artifact.source + "\n"
            + artifact.category + "\n"
            + artifact.target + "\n"
            + artifact.platform + "\n"
            + artifact.arch + "\n"
            + artifact.runtime + "\n"
            + artifact.name + "\n"
            + artifact.sha256);
        if (artifact.artifactId.empty())
            continue;
        artifacts.push_back(std::move(artifact));
    }
}

void collectGeneratedArtifacts(
    const fs::path& root,
    std::vector<TeamServerArtifactRecord>& artifacts)
{
    std::error_code ec;
    if (root.empty() || !fs::exists(root, ec) || !fs::is_directory(root, ec))
        return;

    fs::recursive_directory_iterator iterator(root, fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;
    if (ec)
        return;

    for (; iterator != end; iterator.increment(ec))
    {
        if (ec)
        {
            ec.clear();
            continue;
        }

        const fs::path sidecarPath = iterator->path();
        if (!fs::is_regular_file(sidecarPath, ec) || sidecarPath.extension() != ".json")
            continue;
        if (sidecarPath.filename().string().find(".artifact.json") == std::string::npos)
            continue;

        std::ifstream input(sidecarPath);
        if (!input.good())
            continue;
        json metadata = json::parse(input, nullptr, false);
        if (metadata.is_discarded() || !metadata.is_object())
            continue;

        const fs::path payloadPath = sidecarPath.parent_path() / jsonString(metadata, "file");
        if (!isPathWithinRoot(payloadPath, root))
            continue;
        if (!fs::exists(payloadPath, ec) || !fs::is_regular_file(payloadPath, ec))
            continue;
        const std::string contentHash = sha256File(payloadPath);
        if (contentHash.empty())
            continue;

        TeamServerArtifactRecord artifact;
        artifact.name = jsonString(metadata, "name", payloadPath.filename().string());
        artifact.displayName = jsonString(metadata, "display_name", payloadPath.filename().string());
        artifact.category = jsonString(metadata, "category", "payload");
        artifact.scope = jsonString(metadata, "scope", "generated");
        artifact.target = jsonString(metadata, "target", "beacon");
        artifact.platform = jsonString(metadata, "platform", "any");
        artifact.arch = jsonString(metadata, "arch", "any");
        artifact.format = jsonString(metadata, "format", detectFormat(payloadPath));
        artifact.runtime = jsonString(metadata, "runtime", "shellcode");
        artifact.source = jsonString(metadata, "source", "generated");
        artifact.description = jsonString(metadata, "description");
        artifact.tags = jsonStringList(metadata, "tags");
        artifact.sha256 = jsonString(metadata, "sha256", contentHash);
        if (artifact.sha256 != contentHash)
            continue;
        artifact.internalPath = payloadPath.string();
        artifact.size = static_cast<std::int64_t>(fs::file_size(payloadPath, ec));
        if (ec)
        {
            ec.clear();
            artifact.size = 0;
        }

        artifact.artifactId = jsonString(metadata, "artifact_id");
        if (artifact.artifactId.empty())
        {
            artifact.artifactId = sha256String(
                artifact.source + "\n"
                + artifact.category + "\n"
                + artifact.target + "\n"
                + artifact.platform + "\n"
                + artifact.arch + "\n"
                + artifact.runtime + "\n"
                + artifact.name + "\n"
                + artifact.sha256);
        }
        if (!artifact.artifactId.empty() && !artifact.sha256.empty())
            artifacts.push_back(std::move(artifact));
    }
}

void collectPlatformArchArtifacts(
    const fs::path& root,
    const std::vector<std::string>& supportedArchs,
    const std::string& platform,
    const std::string& category,
    const std::string& scope,
    const std::string& target,
    const std::string& runtime,
    std::vector<TeamServerArtifactRecord>& artifacts)
{
    for (const std::string& arch : supportedArchs)
        collectDirectoryArtifacts(root / arch, category, scope, target, platform, arch, runtime, artifacts);
}

void collectToolsArtifacts(
    const fs::path& root,
    const std::vector<std::string>& supportedWindowsArchs,
    const std::vector<std::string>& supportedLinuxArchs,
    std::vector<TeamServerArtifactRecord>& artifacts)
{
    collectDirectoryArtifacts(root / "Any" / "any", "tool", "server", "teamserver", "any", "any", "any", artifacts);
    collectPlatformArchArtifacts(root / "Windows", supportedWindowsArchs, "windows", "tool", "server", "teamserver", "any", artifacts);
    collectPlatformArchArtifacts(root / "Linux", supportedLinuxArchs, "linux", "tool", "server", "teamserver", "any", artifacts);
}

void collectScriptArtifacts(
    const fs::path& root,
    std::vector<TeamServerArtifactRecord>& artifacts)
{
    collectDirectoryArtifacts(root / "Windows", "script", "server", "beacon", "windows", "any", "script", artifacts);
    collectDirectoryArtifacts(root / "Linux", "script", "server", "beacon", "linux", "any", "script", artifacts);
    collectDirectoryArtifacts(root / "Any", "script", "server", "beacon", "any", "any", "script", artifacts);
}

void collectUploadedArtifacts(
    const fs::path& root,
    const std::vector<std::string>& supportedWindowsArchs,
    const std::vector<std::string>& supportedLinuxArchs,
    std::vector<TeamServerArtifactRecord>& artifacts)
{
    collectDirectoryArtifacts(root / "Any" / "any", "upload", "operator", "beacon", "any", "any", "file", artifacts);
    collectPlatformArchArtifacts(root / "Windows", supportedWindowsArchs, "windows", "upload", "operator", "beacon", "file", artifacts);
    collectPlatformArchArtifacts(root / "Linux", supportedLinuxArchs, "linux", "upload", "operator", "beacon", "file", artifacts);
}

bool sortArtifacts(const TeamServerArtifactRecord& left, const TeamServerArtifactRecord& right)
{
    return std::tie(left.category, left.scope, left.platform, left.arch, left.name, left.artifactId)
        < std::tie(right.category, right.scope, right.platform, right.arch, right.name, right.artifactId);
}
} // namespace

TeamServerArtifactCatalog::TeamServerArtifactCatalog(TeamServerRuntimeConfig runtimeConfig)
    : m_runtimeConfig(std::move(runtimeConfig))
{
}

std::vector<TeamServerArtifactRecord> TeamServerArtifactCatalog::listArtifacts(const TeamServerArtifactQuery& query) const
{
    std::vector<TeamServerArtifactRecord> allArtifacts;
    collectDirectoryArtifacts(m_runtimeConfig.teamServerModulesDirectoryPath, "module", "teamserver", "teamserver", "server", "any", "native", allArtifacts);
    collectPlatformArchArtifacts(m_runtimeConfig.linuxModulesDirectoryPath, m_runtimeConfig.supportedLinuxArchs, "linux", "module", "beacon", "beacon", "native", allArtifacts);
    collectPlatformArchArtifacts(m_runtimeConfig.windowsModulesDirectoryPath, m_runtimeConfig.supportedWindowsArchs, "windows", "module", "beacon", "beacon", "native", allArtifacts);
    collectPlatformArchArtifacts(m_runtimeConfig.linuxBeaconsDirectoryPath, m_runtimeConfig.supportedLinuxArchs, "linux", "beacon", "implant", "listener", "native", allArtifacts);
    collectPlatformArchArtifacts(m_runtimeConfig.windowsBeaconsDirectoryPath, m_runtimeConfig.supportedWindowsArchs, "windows", "beacon", "implant", "listener", "native", allArtifacts);
    collectToolsArtifacts(m_runtimeConfig.toolsDirectoryPath, m_runtimeConfig.supportedWindowsArchs, m_runtimeConfig.supportedLinuxArchs, allArtifacts);
    collectScriptArtifacts(m_runtimeConfig.scriptsDirectoryPath, allArtifacts);
    collectUploadedArtifacts(m_runtimeConfig.uploadedArtifactsDirectoryPath, m_runtimeConfig.supportedWindowsArchs, m_runtimeConfig.supportedLinuxArchs, allArtifacts);
    collectDirectoryArtifacts(m_runtimeConfig.hostedArtifactsDirectoryPath, "hosted", "generated", "listener", "any", "any", "file", allArtifacts, "operator");
    collectGeneratedArtifacts(m_runtimeConfig.generatedArtifactsDirectoryPath, allArtifacts);

    std::vector<TeamServerArtifactRecord> filteredArtifacts;
    for (const TeamServerArtifactRecord& artifact : allArtifacts)
    {
        if (matchesQuery(artifact, query))
            filteredArtifacts.push_back(artifact);
    }

    std::sort(filteredArtifacts.begin(), filteredArtifacts.end(), sortArtifacts);
    return filteredArtifacts;
}

bool TeamServerArtifactCatalog::readArtifactPayload(
    const std::string& artifactId,
    TeamServerArtifactRecord& artifact,
    std::string& bytes,
    std::string& message) const
{
    if (artifactId.empty())
    {
        message = "Missing artifact id.";
        return false;
    }

    const std::vector<TeamServerArtifactRecord> artifacts = listArtifacts();
    const auto it = std::find_if(
        artifacts.begin(),
        artifacts.end(),
        [&](const TeamServerArtifactRecord& candidate)
        {
            return candidate.artifactId == artifactId;
        });
    if (it == artifacts.end())
    {
        message = "Artifact not found.";
        return false;
    }

    std::ifstream input(it->internalPath, std::ios::binary);
    if (!input.good())
    {
        message = "Artifact payload could not be read.";
        return false;
    }

    bytes.assign(std::istreambuf_iterator<char>(input), {});
    if (!input.good() && !input.eof())
    {
        message = "Artifact payload read failed.";
        return false;
    }

    artifact = *it;
    message = "Artifact downloaded.";
    return true;
}

bool TeamServerArtifactCatalog::storeUploadedArtifact(
    const std::string& name,
    const std::string& bytes,
    const std::string& platform,
    const std::string& arch,
    TeamServerArtifactRecord& artifact,
    std::string& message) const
{
    const std::string fileName = sanitizeArtifactName(name);
    const std::string normalizedPlatform = normalizeUploadPlatform(platform);
    const std::string normalizedArch = normalizeUploadArch(normalizedPlatform, arch, m_runtimeConfig);

    fs::path destinationRoot = m_runtimeConfig.uploadedArtifactsDirectoryPath;
    if (normalizedPlatform == "windows")
        destinationRoot /= fs::path("Windows") / normalizedArch;
    else if (normalizedPlatform == "linux")
        destinationRoot /= fs::path("Linux") / normalizedArch;
    else
        destinationRoot /= fs::path("Any") / "any";

    std::error_code ec;
    fs::create_directories(destinationRoot, ec);
    if (ec)
    {
        message = "Upload artifact directory could not be created: " + ec.message();
        return false;
    }

    const fs::path destinationPath = destinationRoot / fileName;
    std::ofstream output(destinationPath, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        message = "Upload artifact could not be opened: " + destinationPath.filename().string();
        return false;
    }
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output.good())
    {
        message = "Upload artifact could not be written: " + destinationPath.filename().string();
        return false;
    }

    const std::string destinationString = destinationPath.string();
    for (const TeamServerArtifactRecord& candidate : listArtifacts())
    {
        if (candidate.internalPath == destinationString)
        {
            artifact = candidate;
            message = "Uploaded artifact stored: " + candidate.name;
            return true;
        }
    }

    message = "Upload artifact stored, but catalog indexing failed.";
    return false;
}

bool TeamServerArtifactCatalog::deleteGeneratedArtifact(const std::string& artifactId, std::string& message) const
{
    if (artifactId.empty())
    {
        message = "Missing artifact id.";
        return false;
    }

    std::vector<TeamServerArtifactRecord> generatedArtifacts;
    collectGeneratedArtifacts(m_runtimeConfig.generatedArtifactsDirectoryPath, generatedArtifacts);

    const auto it = std::find_if(
        generatedArtifacts.begin(),
        generatedArtifacts.end(),
        [&](const TeamServerArtifactRecord& artifact)
        {
            return artifact.artifactId == artifactId;
        });
    if (it == generatedArtifacts.end())
    {
        message = "Generated artifact not found.";
        return false;
    }

    if (it->scope != "generated")
    {
        message = "Only generated artifacts can be deleted.";
        return false;
    }

    const fs::path root = m_runtimeConfig.generatedArtifactsDirectoryPath;
    const fs::path payloadPath = it->internalPath;
    const fs::path sidecarPath = it->internalPath + ".artifact.json";
    if (!isPathWithinRoot(payloadPath, root) || !isPathWithinRoot(sidecarPath, root))
    {
        message = "Generated artifact path is outside the generated artifact root.";
        return false;
    }

    std::error_code ec;
    const bool removedPayload = fs::remove(payloadPath, ec);
    if (ec)
    {
        message = "Generated artifact payload could not be deleted: " + ec.message();
        return false;
    }

    const bool removedSidecar = fs::remove(sidecarPath, ec);
    if (ec)
    {
        message = "Generated artifact metadata could not be deleted: " + ec.message();
        return false;
    }

    if (!removedPayload && !removedSidecar)
    {
        message = "Generated artifact files were already missing.";
        return false;
    }

    message = "Generated artifact deleted.";
    return true;
}
