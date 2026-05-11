#include "TeamServerShellcodeService.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <openssl/evp.h>
#include <sstream>
#include <utility>
#include <unistd.h>

#include <donut.h>

namespace fs = std::filesystem;

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

bool copyBounded(char* destination, std::size_t destinationSize, const std::string& value)
{
    if (destinationSize == 0 || value.size() >= destinationSize)
        return false;
    std::memcpy(destination, value.c_str(), value.size());
    destination[value.size()] = '\0';
    return true;
}

int donutArch(const std::string& arch)
{
    const std::string lowered = toLower(arch);
    if (lowered == "x64" || lowered == "amd64" || lowered == "x86_64")
        return DONUT_ARCH_X64;
    if (lowered == "x86" || lowered == "i386" || lowered == "i686")
        return DONUT_ARCH_X86;
    if (lowered == "arm64" || lowered == "aarch64")
        return DONUT_ARCH_ARM64;
    return 0;
}

fs::path donutOutputPath()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return fs::temp_directory_path() / ("c2-donut-" + std::to_string(::getpid()) + "-" + std::to_string(now) + ".bin");
}
} // namespace

TeamServerShellcodeService::TeamServerShellcodeService(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
{
}

TeamServerShellcodeResult TeamServerShellcodeService::generate(const TeamServerShellcodeRequest& request) const
{
    const std::string generator = toLower(request.generator.empty() ? "raw" : request.generator);
    if (generator == "raw")
        return generateRaw(request);
    if (generator == "donut")
        return generateDonut(request);

    TeamServerShellcodeResult result;
    result.message = "Unsupported shellcode generator: " + request.generator;
    return result;
}

TeamServerShellcodeResult TeamServerShellcodeService::generateRaw(const TeamServerShellcodeRequest& request) const
{
    TeamServerShellcodeResult result;
    result.generator = "raw";
    result.sourceType = "raw";

    std::ifstream input(request.sourcePath, std::ios::binary);
    if (!input.good())
    {
        result.message = "Couldn't open shellcode file.";
        return result;
    }

    result.bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    if (result.bytes.empty())
    {
        result.message = "Shellcode payload is empty.";
        return result;
    }

    result.sha256 = sha256String(result.bytes);
    result.ok = !result.sha256.empty();
    if (!result.ok)
        result.message = "Could not hash shellcode payload.";
    return result;
}

TeamServerShellcodeResult TeamServerShellcodeService::generateDonut(const TeamServerShellcodeRequest& request) const
{
    TeamServerShellcodeResult result;
    result.generator = "donut";
    result.sourceType = request.sourceType.empty() ? "dotnet_exe" : request.sourceType;

    if (request.sourcePath.empty())
    {
        result.message = "Donut source path is required.";
        return result;
    }
    if (!fs::exists(request.sourcePath))
    {
        result.message = "Couldn't open Donut source file.";
        return result;
    }

    const int arch = donutArch(request.arch);
    if (arch == 0)
    {
        result.message = "Unsupported Donut architecture.";
        return result;
    }

    const fs::path outputPath = donutOutputPath();

    DONUT_CONFIG config;
    std::memset(&config, 0, sizeof(config));
    config.inst_type = DONUT_INSTANCE_EMBED;
    config.arch = arch;
    config.bypass = DONUT_BYPASS_CONTINUE;
    config.format = DONUT_FORMAT_BINARY;
    config.compress = DONUT_COMPRESS_NONE;
    config.entropy = DONUT_ENTROPY_DEFAULT;
    config.headers = DONUT_HEADERS_OVERWRITE;
    config.exit_opt = toLower(request.exitPolicy) == "thread" ? DONUT_OPT_EXIT_THREAD : DONUT_OPT_EXIT_PROCESS;
    config.thread = 0;
    config.unicode = 0;

    if (!copyBounded(config.input, sizeof(config.input), request.sourcePath)
        || !copyBounded(config.output, sizeof(config.output), outputPath.string())
        || !copyBounded(config.method, sizeof(config.method), request.method)
        || !copyBounded(config.args, sizeof(config.args), request.arguments))
    {
        result.message = "Donut input, output, method or arguments are too long.";
        return result;
    }

    const int err = DonutCreate(&config);
    if (err != DONUT_ERROR_OK)
    {
        result.message = "Donut error: ";
        result.message += DonutError(err);
        return result;
    }

    std::ifstream output(outputPath, std::ios::binary);
    result.bytes.assign(std::istreambuf_iterator<char>(output), std::istreambuf_iterator<char>());
    DonutDelete(&config);

    std::error_code ec;
    fs::remove(outputPath, ec);

    if (result.bytes.empty())
    {
        result.message = "Donut generated an empty shellcode payload.";
        return result;
    }

    result.sha256 = sha256String(result.bytes);
    result.ok = !result.sha256.empty();
    if (!result.ok)
        result.message = "Could not hash Donut shellcode payload.";
    return result;
}
