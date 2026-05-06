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

bool writeSidecar(
    const fs::path& artifactPath,
    const TeamServerGeneratedArtifactRequest& request,
    const TeamServerGeneratedArtifactRecord& record,
    const std::string& format)
{
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
    sidecar["format"] = format;
    sidecar["runtime"] = request.runtime;
    sidecar["source"] = request.source;
    sidecar["sha256"] = record.sha256;
    sidecar["description"] = request.description;
    sidecar["tags"] = request.tags;

    std::ofstream sidecarOutput(artifactPath.string() + ".artifact.json", std::ios::binary);
    if (!sidecarOutput.good())
        return false;
    sidecarOutput << sidecar.dump(2);
    sidecarOutput.close();
    return sidecarOutput.good();
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

    if (!writeSidecar(artifactPath, request, record, request.format))
    {
        fs::remove(artifactPath, ec);
        fs::remove(artifactPath.string() + ".artifact.json", ec);
        return {};
    }

    return record;
}

TeamServerGeneratedArtifactRecord TeamServerGeneratedArtifactStore::registerExistingFile(
    const TeamServerGeneratedArtifactRequest& request,
    const std::string& filePath) const
{
    TeamServerGeneratedArtifactRecord record;
    const fs::path artifactPath = filePath;
    std::error_code ec;
    if (filePath.empty() || !fs::exists(artifactPath, ec) || !fs::is_regular_file(artifactPath, ec))
        return record;

    const fs::path root = m_runtimeConfig.generatedArtifactsDirectoryPath;
    if (!isPathWithinRoot(artifactPath, root))
        return record;

    const std::string sha256 = sha256File(artifactPath);
    if (sha256.empty())
        return record;

    std::string displayName = request.nameHint.empty()
        ? artifactPath.filename().string()
        : sanitizeName(request.nameHint);
    const std::string name = artifactPath.filename().string();

    record.artifactId = artifactIdFor(request, name, sha256);
    record.path = artifactPath.string();
    record.name = name;
    record.displayName = displayName;
    record.sha256 = sha256;
    record.size = static_cast<std::int64_t>(fs::file_size(artifactPath, ec));
    if (ec)
        record.size = 0;

    if (!writeSidecar(artifactPath, request, record, request.format))
    {
        fs::remove(artifactPath.string() + ".artifact.json", ec);
        return {};
    }

    return record;
}
