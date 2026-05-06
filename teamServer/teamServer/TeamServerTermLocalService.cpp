#include "TeamServerTermLocalService.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <system_error>

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerModuleLoader.hpp"
#include "listener/ListenerHttp.hpp"
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace
{
const std::string HostArtifactInstruction = "hostArtifact";
const std::string PutIntoUploadDirInstruction = "putIntoUploadDir";
const std::string ReloadModulesInstruction = "reloadModules";
const std::string BatcaveInstruction = "batcaveUpload";
const std::string AddCredentialInstruction = "addCred";
const std::string GetCredentialInstruction = "getCred";

void setTerminalOk(teamserverapi::TerminalCommandResponse* response, const std::string& result)
{
    response->set_status(teamserverapi::OK);
    response->set_result(result);
    response->clear_message();
}

void setTerminalError(teamserverapi::TerminalCommandResponse* response, const std::string& result)
{
    response->set_status(teamserverapi::KO);
    response->set_result(result);
    response->set_message(result);
}

std::string basename(std::string value)
{
    const auto slash = value.find_last_of("/\\");
    if (slash != std::string::npos)
        value = value.substr(slash + 1);
    return value;
}

std::string sanitizeHostedFilename(std::string value)
{
    value = basename(std::move(value));
    for (char& ch : value)
    {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c) && ch != '.' && ch != '-' && ch != '_')
            ch = '_';
    }
    return value.empty() ? "artifact.bin" : value;
}

bool samePath(const fs::path& left, const fs::path& right)
{
    std::error_code ec;
    const fs::path canonicalLeft = fs::weakly_canonical(left, ec);
    if (ec)
        return false;
    const fs::path canonicalRight = fs::weakly_canonical(right, ec);
    if (ec)
        return false;
    return canonicalLeft == canonicalRight;
}
} // namespace

TeamServerTermLocalService::TeamServerTermLocalService(
    std::shared_ptr<spdlog::logger> logger,
    const nlohmann::json& config,
    TeamServerRuntimeConfig runtimeConfig,
    std::vector<std::shared_ptr<Listener>>& listeners,
    nlohmann::json& credentials,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    ModuleLoader moduleLoader)
    : m_logger(std::move(logger)),
      m_config(config),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_listeners(listeners),
      m_credentials(credentials),
      m_moduleCmd(moduleCmd),
      m_moduleLoader(std::move(moduleLoader))
{
}

bool TeamServerTermLocalService::canHandle(const std::string& instruction) const
{
    return instruction == HostArtifactInstruction
        || instruction == PutIntoUploadDirInstruction
        || instruction == BatcaveInstruction
        || instruction == AddCredentialInstruction
        || instruction == GetCredentialInstruction
        || instruction == ReloadModulesInstruction;
}

grpc::Status TeamServerTermLocalService::handleCommand(
    const std::string& instruction,
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    response->set_status(teamserverapi::OK);
    response->set_command(command.command());
    response->set_result("");
    response->set_data("");
    response->clear_message();

    if (instruction == HostArtifactInstruction)
        return handleHostArtifact(splitedCmd, response);
    if (instruction == PutIntoUploadDirInstruction)
        return handlePutIntoUploadDir(splitedCmd, command, response);
    if (instruction == BatcaveInstruction)
        return handleBatcaveUpload(splitedCmd, command, response);
    if (instruction == AddCredentialInstruction)
        return handleAddCredential(command, response);
    if (instruction == GetCredentialInstruction)
        return handleGetCredential(response);
    if (instruction == ReloadModulesInstruction)
        return handleReloadModules(response);

    response->set_status(teamserverapi::KO);
    response->set_result("Error: not implemented.");
    response->set_message("Terminal command not implemented.");
    return grpc::Status::OK;
}

std::vector<std::unique_ptr<ModuleCmd>> TeamServerTermLocalService::loadModulesFromDisk() const
{
    TeamServerModuleLoader loader(m_logger, m_runtimeConfig);
    return loader.loadModules();
}

bool TeamServerTermLocalService::isValidFilename(const std::string& filename) const
{
    return filename.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.") == std::string::npos;
}

std::string TeamServerTermLocalService::resolveDownloadFolderForListener(const std::string& listenerHash) const
{
    std::string downloadFolder;
    for (const auto& listener : m_listeners)
    {
        const std::string& hash = listener->getListenerHash();
        if (hash.find(listenerHash) == std::string::npos)
            continue;

        const std::string& type = listener->getType();
        try
        {
            if (type == ListenerHttpType)
            {
                json configHttp = m_config["ListenerHttpConfig"];
                auto it = configHttp.find("downloadFolder");
                if (it != configHttp.end())
                    downloadFolder = configHttp["downloadFolder"].get<std::string>();
            }
            else if (type == ListenerHttpsType)
            {
                json configHttps = m_config["ListenerHttpsConfig"];
                auto it = configHttps.find("downloadFolder");
                if (it != configHttps.end())
                    downloadFolder = configHttps["downloadFolder"].get<std::string>();
            }
        }
        catch (...)
        {
            return "";
        }
    }

    return downloadFolder;
}

grpc::Status TeamServerTermLocalService::handleHostArtifact(
    const std::vector<std::string>& splitedCmd,
    teamserverapi::TerminalCommandResponse* response)
{
    m_logger->debug("hostArtifact");

    if (splitedCmd.size() != 3 && splitedCmd.size() != 4)
    {
        setTerminalError(response, "Error: hostArtifact takes a listener hash, an artifact reference, and an optional filename.");
        return grpc::Status::OK;
    }

    const std::string& listenerHash = splitedCmd[1];
    const std::string& artifactReference = splitedCmd[2];
    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash);
    if (downloadFolder.empty())
    {
        setTerminalError(response, "Error: Listener don't have a download folder.");
        m_logger->warn("Listener {0} has no download folder configured; unable to host artifact {1}", listenerHash, artifactReference);
        return grpc::Status::OK;
    }

    TeamServerArtifactCatalog catalog(m_runtimeConfig);
    std::vector<TeamServerArtifactRecord> matches;
    for (const TeamServerArtifactRecord& candidate : catalog.listArtifacts())
    {
        if (candidate.artifactId == artifactReference
            || candidate.name == artifactReference
            || candidate.displayName == artifactReference)
        {
            matches.push_back(candidate);
        }
    }

    if (matches.empty() && artifactReference.size() >= 8)
    {
        for (const TeamServerArtifactRecord& candidate : catalog.listArtifacts())
        {
            if (candidate.artifactId.rfind(artifactReference, 0) == 0)
                matches.push_back(candidate);
        }
    }

    if (matches.empty())
    {
        setTerminalError(response, "Error: artifact not found.");
        return grpc::Status::OK;
    }
    if (matches.size() > 1)
    {
        setTerminalError(response, "Error: artifact reference is ambiguous.");
        return grpc::Status::OK;
    }

    TeamServerArtifactRecord artifact;
    std::string bytes;
    std::string message;
    if (!catalog.readArtifactPayload(matches.front().artifactId, artifact, bytes, message))
    {
        setTerminalError(response, "Error: " + message);
        return grpc::Status::OK;
    }

    std::string filename;
    if (splitedCmd.size() == 4)
    {
        filename = splitedCmd[3];
        if (!isValidFilename(filename))
        {
            setTerminalError(response, "Error: filename not allowed.");
            return grpc::Status::OK;
        }
    }
    else
    {
        filename = sanitizeHostedFilename(!artifact.displayName.empty() ? artifact.displayName : artifact.name);
    }

    const fs::path destinationPath = fs::path(downloadFolder) / filename;
    std::error_code ec;
    fs::create_directories(destinationPath.parent_path(), ec);
    if (ec)
    {
        setTerminalError(response, "Error: Cannot create hosted artifact directory.");
        m_logger->warn("Failed to create hosted artifact directory for {0}: {1}", filename, ec.message());
        return grpc::Status::OK;
    }

    if (!samePath(artifact.internalPath, destinationPath))
    {
        std::ofstream outputFile(destinationPath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!outputFile.good())
        {
            setTerminalError(response, "Error: Cannot write file.");
            m_logger->warn("Failed to host artifact {0} at {1}", artifact.artifactId, destinationPath.string());
            return grpc::Status::OK;
        }
        outputFile.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        outputFile.close();
        if (!outputFile.good())
        {
            setTerminalError(response, "Error: Cannot write file.");
            m_logger->warn("Failed to finish hosting artifact {0} at {1}", artifact.artifactId, destinationPath.string());
            return grpc::Status::OK;
        }
    }

    setTerminalOk(response, filename);
    m_logger->info("Hosted artifact {0} as {1} for listener {2}", artifact.artifactId, destinationPath.string(), listenerHash);
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handlePutIntoUploadDir(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    m_logger->debug("putIntoUploadDir {0}", command.command());

    if (splitedCmd.size() != 3)
    {
        setTerminalError(response, "Error: putIntoUploadDir take tow arguements.");
        return grpc::Status::OK;
    }

    const std::string& listenerHash = splitedCmd[1];
    const std::string& filename = splitedCmd[2];
    if (!isValidFilename(filename))
    {
        setTerminalError(response, "Error: filename not allowed.");
        return grpc::Status::OK;
    }

    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash);
    if (downloadFolder.empty())
    {
        setTerminalError(response, "Error: Listener don't have a download folder.");
        m_logger->warn("Listener {0} has no download folder configured; unable to store {1}", listenerHash, filename);
        return grpc::Status::OK;
    }

    const std::string filePath = downloadFolder + "/" + filename;
    std::ofstream outputFile(filePath, std::ios::out | std::ios::binary);
    if (outputFile.good())
    {
        outputFile << command.data();
        outputFile.close();
        setTerminalOk(response, "ok");
        m_logger->info("Stored uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath);
        return grpc::Status::OK;
    }

    setTerminalError(response, "Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath);
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleBatcaveUpload(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    m_logger->debug("batcaveUpload {0}", command.command());

    if (splitedCmd.size() != 2)
    {
        setTerminalError(response, "Error: batcaveUpload take one arguement.");
        return grpc::Status::OK;
    }

    const std::string& filename = splitedCmd[1];
    m_logger->debug("batcaveUpload {0}", filename);
    if (!isValidFilename(filename))
    {
        setTerminalError(response, "Error: filename not allowed.");
        return grpc::Status::OK;
    }

    const fs::path filePath = fs::path(m_runtimeConfig.toolsDirectoryPath) / "Any" / "any" / filename;
    std::error_code ec;
    fs::create_directories(filePath.parent_path(), ec);
    if (ec)
    {
        setTerminalError(response, "Error: Cannot create tools directory.");
        m_logger->warn("Failed to create tools directory for uploaded tool '{0}' at {1}", filename, filePath.parent_path().string());
        return grpc::Status::OK;
    }
    std::ofstream outputFile(filePath, std::ios::out | std::ios::binary);
    if (outputFile.good())
    {
        outputFile << command.data();
        outputFile.close();
        setTerminalOk(response, "ok");
        m_logger->info("Saved uploaded tool '{0}' to {1}", filename, filePath.string());
        return grpc::Status::OK;
    }

    setTerminalError(response, "Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded tool '{0}' at {1}", filename, filePath.string());
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleAddCredential(
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    m_logger->debug("AddCredentials command received");

    json cred;
    try
    {
        cred = json::parse(command.data());
    }
    catch (const json::parse_error&)
    {
        setTerminalError(response, "Error: invalid credential payload.");
        return grpc::Status::OK;
    }

    m_credentials.push_back(cred);
    m_logger->info("Stored credential entry. Total credentials: {0}", m_credentials.size());
    setTerminalOk(response, "ok");
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleGetCredential(teamserverapi::TerminalCommandResponse* response)
{
    m_logger->debug("GetCredentials command received");
    setTerminalOk(response, m_credentials.dump());
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleReloadModules(teamserverapi::TerminalCommandResponse* response)
{
    m_logger->info("Reloading TeamServer modules from directory: {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    m_moduleCmd.clear();
    std::vector<std::unique_ptr<ModuleCmd>> reloaded = m_moduleLoader ? m_moduleLoader() : loadModulesFromDisk();
    const std::size_t reloadedModules = reloaded.size();
    m_moduleCmd = std::move(reloaded);

    if (reloadedModules == 0)
        m_logger->warn("No TeamServer modules loaded from {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
    else
        m_logger->info("Reloaded {0} TeamServer module(s) from {1}", reloadedModules, m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    setTerminalOk(response, "");
    return grpc::Status::OK;
}
