#include "TeamServerTermLocalService.hpp"

#include <fstream>

#include "TeamServerModuleLoader.hpp"
#include "listener/ListenerHttp.hpp"
using json = nlohmann::json;

namespace
{
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
    return instruction == PutIntoUploadDirInstruction
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

    const std::string filePath = m_runtimeConfig.toolsDirectoryPath + "/" + filename;
    std::ofstream outputFile(filePath, std::ios::out | std::ios::binary);
    if (outputFile.good())
    {
        outputFile << command.data();
        outputFile.close();
        setTerminalOk(response, "ok");
        m_logger->info("Saved uploaded tool '{0}' to {1}", filename, filePath);
        return grpc::Status::OK;
    }

    setTerminalError(response, "Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded tool '{0}' at {1}", filename, filePath);
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
