#include "TeamServerTermLocalService.hpp"

#include <dlfcn.h>

#include <filesystem>
#include <fstream>

#include "listener/ListenerHttp.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
using constructProc = ModuleCmd* (*)();

const std::string PutIntoUploadDirInstruction = "putIntoUploadDir";
const std::string ReloadModulesInstruction = "reloadModules";
const std::string BatcaveInstruction = "batcaveUpload";
const std::string AddCredentialInstruction = "addCred";
const std::string GetCredentialInstruction = "getCred";
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
    const teamserverapi::TermCommand& command,
    teamserverapi::TermCommand* response)
{
    response->set_cmd("");
    response->set_result("");
    response->set_data("");

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

    response->set_result("Error: not implemented.");
    return grpc::Status::OK;
}

std::vector<std::unique_ptr<ModuleCmd>> TeamServerTermLocalService::loadModulesFromDisk() const
{
    std::vector<std::unique_ptr<ModuleCmd>> modules;

    try
    {
        for (const auto& entry : fs::recursive_directory_iterator(m_runtimeConfig.teamServerModulesDirectoryPath))
        {
            if (!fs::is_regular_file(entry.path()) || entry.path().extension() != ".so")
                continue;

            m_logger->debug("Trying to load {0}", entry.path().c_str());

            void* handle = dlopen(entry.path().c_str(), RTLD_LAZY);
            if (!handle)
            {
                m_logger->warn("Failed to load {0}: {1}", entry.path().c_str(), dlerror());
                continue;
            }

            std::string funcName = entry.path().filename();
            funcName = funcName.substr(3);
            funcName = funcName.substr(0, funcName.length() - 3);
            funcName += "Constructor";

            m_logger->debug("Looking for constructor function: {0}", funcName);

            constructProc construct = reinterpret_cast<constructProc>(dlsym(handle, funcName.c_str()));
            if (!construct)
            {
                m_logger->warn("Failed to find constructor: {0}", dlerror());
                dlclose(handle);
                continue;
            }

            ModuleCmd* moduleCmd = construct();
            if (!moduleCmd)
            {
                m_logger->warn("Constructor returned null");
                dlclose(handle);
                continue;
            }

            std::unique_ptr<ModuleCmd> moduleCmdPtr(moduleCmd);
            m_runtimeConfig.configureModule(*moduleCmdPtr);
            m_logger->debug("Module {0} loaded", entry.path().filename().c_str());
            modules.push_back(std::move(moduleCmdPtr));
        }
    }
    catch (const fs::filesystem_error& e)
    {
        m_logger->warn("Error accessing module directory: {0}", e.what());
    }

    return modules;
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
    const teamserverapi::TermCommand& command,
    teamserverapi::TermCommand* response)
{
    m_logger->debug("putIntoUploadDir {0}", command.cmd());

    if (splitedCmd.size() != 3)
    {
        response->set_result("Error: putIntoUploadDir take tow arguements.");
        return grpc::Status::OK;
    }

    const std::string& listenerHash = splitedCmd[1];
    const std::string& filename = splitedCmd[2];
    if (!isValidFilename(filename))
    {
        response->set_result("Error: filename not allowed.");
        return grpc::Status::OK;
    }

    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash);
    if (downloadFolder.empty())
    {
        response->set_result("Error: Listener don't have a download folder.");
        m_logger->warn("Listener {0} has no download folder configured; unable to store {1}", listenerHash, filename);
        return grpc::Status::OK;
    }

    const std::string filePath = downloadFolder + "/" + filename;
    std::ofstream outputFile(filePath, std::ios::out | std::ios::binary);
    if (outputFile.good())
    {
        outputFile << command.data();
        outputFile.close();
        response->set_result("ok");
        m_logger->info("Stored uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath);
        return grpc::Status::OK;
    }

    response->set_result("Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath);
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleBatcaveUpload(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TermCommand& command,
    teamserverapi::TermCommand* response)
{
    m_logger->debug("batcaveUpload {0}", command.cmd());

    if (splitedCmd.size() != 2)
        return grpc::Status::OK;

    const std::string& filename = splitedCmd[1];
    m_logger->debug("batcaveUpload {0}", filename);
    if (!isValidFilename(filename))
    {
        response->set_result("Error: filename not allowed.");
        return grpc::Status::OK;
    }

    const std::string filePath = m_runtimeConfig.toolsDirectoryPath + "/" + filename;
    std::ofstream outputFile(filePath, std::ios::out | std::ios::binary);
    if (outputFile.good())
    {
        outputFile << command.data();
        outputFile.close();
        response->set_result("ok");
        m_logger->info("Saved uploaded tool '{0}' to {1}", filename, filePath);
        return grpc::Status::OK;
    }

    response->set_result("Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded tool '{0}' at {1}", filename, filePath);
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleAddCredential(
    const teamserverapi::TermCommand& command,
    teamserverapi::TermCommand* response)
{
    m_logger->debug("AddCredentials command received");

    json cred = json::parse(command.data());
    m_credentials.push_back(cred);
    m_logger->info("Stored credential entry. Total credentials: {0}", m_credentials.size());
    response->set_result("ok");
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleGetCredential(teamserverapi::TermCommand* response)
{
    m_logger->debug("GetCredentials command received");
    response->set_result(m_credentials.dump());
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleReloadModules(teamserverapi::TermCommand* response)
{
    (void)response;
    m_logger->info("Reloading TeamServer modules from directory: {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    m_moduleCmd.clear();
    std::vector<std::unique_ptr<ModuleCmd>> reloaded = m_moduleLoader ? m_moduleLoader() : loadModulesFromDisk();
    const std::size_t reloadedModules = reloaded.size();
    m_moduleCmd = std::move(reloaded);

    if (reloadedModules == 0)
        m_logger->warn("No TeamServer modules loaded from {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
    else
        m_logger->info("Reloaded {0} TeamServer module(s) from {1}", reloadedModules, m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    return grpc::Status::OK;
}
