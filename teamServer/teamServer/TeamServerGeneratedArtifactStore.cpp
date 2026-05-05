#include "TeamServerGeneratedArtifactStore.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>
#include <utility>

#include "nlohmann/json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
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

std::string artifactIdFor(const TeamServerGeneratedArtifactRequest& request, const std::string& name, const std::string& sha256)
{
    return sha256String(
        request.source + "\n"
        + request.category + "\n"
        + request.target + "\n"
        + request.platform + "\n"
        + request.arch + "\n"
        + request.runtime + "\n"
        + name + "\n"
        + sha256);
}
} // namespace

TeamServerGeneratedArtifactStore::TeamServerGeneratedArtifactStore(TeamServerRuntimeConfig runtimeConfig)
    : m_runtimeConfig(std::move(runtimeConfig))
{
}

TeamServerGeneratedArtifactRecord TeamServerGeneratedArtifactStore::store(const TeamServerGeneratedArtifactRequest& request) const
{
    TeamServerGeneratedArtifactRecord record;
    if (request.bytes.empty())
        return record;

    const std::string sha256 = sha256String(request.bytes);
    if (sha256.empty())
        return record;

    std::string displayName = sanitizeName(request.nameHint);
    if (displayName.find('.') == std::string::npos && !request.format.empty())
        displayName += "." + request.format;
    const std::string name = sha256.substr(0, 12) + "-" + displayName;

    const fs::path root = fs::path(m_runtimeConfig.generatedArtifactsDirectoryPath)
        / request.category
        / request.source;
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec)
        return record;

    const fs::path artifactPath = root / name;
    std::ofstream output(artifactPath, std::ios::binary);
    if (!output.good())
        return record;
    output.write(request.bytes.data(), static_cast<std::streamsize>(request.bytes.size()));
    output.close();

    record.artifactId = artifactIdFor(request, name, sha256);
    record.path = artifactPath.string();
    record.name = name;
    record.displayName = displayName;
    record.sha256 = sha256;
    record.size = static_cast<std::int64_t>(request.bytes.size());

    json sidecar;
    sidecar["artifact_id"] = record.artifactId;
    sidecar["file"] = artifactPath.filename().string();
    sidecar["name"] = record.name;
    sidecar["display_name"] = record.displayName;
    sidecar["category"] = request.category;
    sidecar["scope"] = request.scope;
    sidecar["target"] = request.target;
    sidecar["platform"] = request.platform;
    sidecar["arch"] = request.arch;
    sidecar["format"] = request.format;
    sidecar["runtime"] = request.runtime;
    sidecar["source"] = request.source;
    sidecar["sha256"] = record.sha256;
    sidecar["description"] = request.description;
    sidecar["tags"] = request.tags;

    std::ofstream sidecarOutput(artifactPath.string() + ".artifact.json", std::ios::binary);
    if (!sidecarOutput.good())
    {
        fs::remove(artifactPath, ec);
        return {};
    }
    sidecarOutput << sidecar.dump(2);
    sidecarOutput.close();
    if (!sidecarOutput.good())
    {
        fs::remove(artifactPath, ec);
        fs::remove(artifactPath.string() + ".artifact.json", ec);
        return {};
    }

    return record;
}
