#include "TeamServerTermLocalService.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <unistd.h>

#include "TeamServerArtifactCatalog.hpp"
#include "TeamServerCredentialVaultService.hpp"
#include "TeamServerListenerArtifactService.hpp"
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
const std::string BatcaveBundleInstruction = "batcaveUploadBundle";
const std::string AddCredentialInstruction = "addCred";
const std::string GetCredentialInstruction = "getCred";
const std::string CredentialVaultInstruction = "cred";

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
    return value.empty() || value == "." || value == ".." ? "artifact.bin" : value;
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

fs::path temporarySibling(const fs::path& destination)
{
    static std::atomic<unsigned long long> sequence{0};
    return destination.parent_path() /
        ("." + destination.filename().string() + ".c2tmp-" + std::to_string(::getpid())
            + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
            + "-" + std::to_string(++sequence));
}

bool writeFileAtomically(const fs::path& destination, std::string_view bytes)
{
    std::error_code ec;
    fs::create_directories(destination.parent_path(), ec);
    if (ec)
        return false;

    const fs::path temporary = temporarySibling(destination);
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output.good())
            return false;
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.close();
        if (!output.good())
        {
            fs::remove(temporary, ec);
            return false;
        }
    }
    fs::rename(temporary, destination, ec);
    if (ec)
    {
        fs::remove(temporary, ec);
        return false;
    }
    return true;
}

void removeCommittedStage(const fs::path& stage, std::error_code& ec)
{
    fs::remove_all(stage / "files", ec);
    if (ec) return;
    fs::remove_all(stage / "backups", ec);
    if (ec) return;
    fs::remove(stage / "recovery.json", ec);
    if (ec) return;
    fs::remove(stage / "committed", ec);
    if (ec) return;
    fs::remove_all(stage, ec);
}
} // namespace

TeamServerTermLocalService::TeamServerTermLocalService(
    std::shared_ptr<spdlog::logger> logger,
    const nlohmann::json& config,
    TeamServerRuntimeConfig runtimeConfig,
    std::vector<std::shared_ptr<Listener>>& listeners,
    nlohmann::json& credentials,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    ModuleLoader moduleLoader,
    std::shared_ptr<TeamServerCredentialVaultService> credentialVaultService,
    std::shared_mutex* listenersMutex,
    TeamServerListenerArtifactService* listenerArtifactService,
    std::shared_mutex* moduleCmdMutex)
    : m_logger(std::move(logger)),
      m_config(config),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_listeners(listeners),
      m_listenersMutex(listenersMutex ? listenersMutex : &m_localListenersMutex),
      m_credentials(credentials),
      m_moduleCmd(moduleCmd),
    m_credentialVaultService(std::move(credentialVaultService)),
      m_moduleLoader(std::move(moduleLoader)),
      m_listenerArtifactService(listenerArtifactService),
      m_moduleCmdMutex(moduleCmdMutex ? moduleCmdMutex : &m_localModuleCmdMutex)
{
    recoverBatcaveBundles();
}

void TeamServerTermLocalService::recoverBatcaveBundles()
{
    const fs::path toolsDirectory = fs::path(m_runtimeConfig.toolsDirectoryPath) / "Any" / "any";
    const fs::path stagingRoot = fs::path(m_runtimeConfig.toolsDirectoryPath) / ".batcave-staging";
    std::error_code ec;
    if (!fs::exists(stagingRoot, ec) || ec)
        return;

    for (fs::directory_iterator it(stagingRoot, ec), end; !ec && it != end; it.increment(ec))
    {
        const fs::path stage = it->path();
        if (it->is_symlink(ec) || ec || !it->is_directory(ec) || ec
            || stage.filename().string().rfind(".bundle.c2tmp-", 0) != 0)
            continue;
        const bool committed = fs::exists(stage / "committed", ec);
        if (ec)
        {
            m_logger->error("Cannot inspect Batcave stage {}: {}", stage.string(), ec.message());
            continue;
        }
        if (committed)
        {
            removeCommittedStage(stage, ec);
            if (ec)
                m_logger->error("Cannot clean committed Batcave stage {}: {}", stage.string(), ec.message());
            continue;
        }
        std::ifstream input(stage / "recovery.json", std::ios::binary);
        if (!input.good())
        {
            m_logger->warn("Batcave stage {} has no recovery journal; leaving it for inspection", stage.string());
            continue;
        }
        const json journal = json::parse(input, nullptr, false);
        if (!journal.is_array())
        {
            m_logger->error("Invalid Batcave recovery journal in {}", stage.string());
            continue;
        }
        bool valid = !journal.empty() && journal.size() <= 256;
        std::unordered_set<std::string> names;
        for (const auto& entry : journal)
        {
            if (!entry.is_array() || entry.size() != 2 || !entry[0].is_string() || !entry[1].is_boolean()
                || !isValidFilename(entry[0].get<std::string>())
                || !names.insert(entry[0].get<std::string>()).second)
            {
                valid = false;
                break;
            }
        }
        if (!valid)
        {
            m_logger->error("Invalid Batcave recovery entries in {}", stage.string());
            continue;
        }
        for (auto entry = journal.rbegin(); entry != journal.rend(); ++entry)
        {
            const std::string name = (*entry)[0].get<std::string>();
            const bool originallyExisted = (*entry)[1].get<bool>();
            const fs::path destination = toolsDirectory / name;
            const fs::path backup = stage / "backups" / name;
            const fs::path staged = stage / "files" / name;
            std::error_code itemError;
            const bool hasBackup = fs::exists(backup, itemError);
            if (itemError)
            {
                valid = false;
                m_logger->error("Cannot inspect Batcave backup {}: {}", backup.string(), itemError.message());
                continue;
            }
            if (hasBackup)
            {
                fs::remove(destination, itemError);
                if (!itemError)
                    fs::rename(backup, destination, itemError);
            }
            else if (!originallyExisted)
            {
                const bool stillStaged = fs::exists(staged, itemError);
                if (!itemError && !stillStaged)
                    fs::remove(destination, itemError);
            }
            if (itemError)
            {
                m_logger->error("Cannot recover Batcave file {} from {}: {}", name, stage.string(), itemError.message());
                valid = false;
            }
        }
        if (valid)
        {
            fs::remove_all(stage, ec);
            if (ec)
                m_logger->error("Cannot remove recovered Batcave stage {}: {}", stage.string(), ec.message());
            else
                m_logger->warn("Recovered interrupted Batcave bundle from {}", stage.string());
        }
    }
    if (ec)
        m_logger->error("Cannot inspect Batcave staging directory {}: {}", stagingRoot.string(), ec.message());
}

bool TeamServerTermLocalService::canHandle(const std::string& instruction) const
{
    return instruction == HostArtifactInstruction
        || instruction == PutIntoUploadDirInstruction
        || instruction == BatcaveInstruction
        || instruction == BatcaveBundleInstruction
        || instruction == AddCredentialInstruction
        || instruction == GetCredentialInstruction
        || instruction == CredentialVaultInstruction
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
    if (instruction == BatcaveBundleInstruction)
        return handleBatcaveUploadBundle(splitedCmd, command, response);
    if (instruction == CredentialVaultInstruction)
        return handleCredentialVault(splitedCmd, command, response);
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
    return !filename.empty() && filename != "." && filename != ".."
        && filename.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.") == std::string::npos;
}

std::string TeamServerTermLocalService::resolveDownloadFolderForListener(
    const std::string& listenerHash, std::shared_ptr<Listener>& listener, std::string& error) const
{
    if (!m_listenerArtifactService)
    {
        error = "Error: Listener lookup is unavailable.";
        return "";
    }
    listener = m_listenerArtifactService->resolvePrimaryListener(listenerHash, error);
    if (!listener)
        return "";

    const std::string& type = listener->getType();
    const char* section = type == ListenerHttpType ? "ListenerHttpConfig"
        : type == ListenerHttpsType ? "ListenerHttpsConfig" : nullptr;
    if (!section)
    {
        error = "Error: Listener must be HTTP or HTTPS.";
        return "";
    }
    const auto sectionIt = m_config.find(section);
    if (sectionIt == m_config.end() || !sectionIt->is_object())
    {
        error = "Error: Listener has no download folder configured.";
        return "";
    }
    const auto folderIt = sectionIt->find("downloadFolder");
    if (folderIt == sectionIt->end() || !folderIt->is_string() || folderIt->get<std::string>().empty())
    {
        error = "Error: Listener has no download folder configured.";
        return "";
    }
    return folderIt->get<std::string>();
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
    std::shared_ptr<Listener> listener;
    std::string listenerError;
    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash, listener, listenerError);
    if (downloadFolder.empty())
    {
        setTerminalError(response, listenerError);
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

    const std::string hostedUrl = m_listenerArtifactService->hostedArtifactUrl(listener, filename);
    if (hostedUrl.empty())
    {
        setTerminalError(response, "Error: Listener has no public download URL configured.");
        return grpc::Status::OK;
    }

    const fs::path destinationPath = fs::path(downloadFolder) / filename;

    if (!samePath(artifact.internalPath, destinationPath))
    {
        if (!writeFileAtomically(destinationPath, bytes))
        {
            setTerminalError(response, "Error: Cannot write file.");
            m_logger->warn("Failed to host artifact {0} at {1}", artifact.artifactId, destinationPath.string());
            return grpc::Status::OK;
        }
    }

    setTerminalOk(response, hostedUrl);
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

    std::shared_ptr<Listener> listener;
    std::string listenerError;
    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash, listener, listenerError);
    if (downloadFolder.empty())
    {
        setTerminalError(response, listenerError);
        m_logger->warn("Listener {0} has no download folder configured; unable to store {1}", listenerHash, filename);
        return grpc::Status::OK;
    }

    const fs::path filePath = fs::path(downloadFolder) / filename;
    if (writeFileAtomically(filePath, command.data()))
    {
        setTerminalOk(response, "ok");
        m_logger->info("Stored uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath.string());
        return grpc::Status::OK;
    }

    setTerminalError(response, "Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded file '{0}' for listener {1} in {2}", filename, listenerHash, filePath.string());
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
    std::lock_guard<std::mutex> lock(m_uploadMutex);
    if (writeFileAtomically(filePath, command.data()))
    {
        setTerminalOk(response, "ok");
        m_logger->info("Saved uploaded tool '{0}' to {1}", filename, filePath.string());
        return grpc::Status::OK;
    }

    setTerminalError(response, "Error: Cannot write file.");
    m_logger->warn("Failed to store uploaded tool '{0}' at {1}", filename, filePath.string());
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleBatcaveUploadBundle(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    if (splitedCmd.size() != 1)
    {
        setTerminalError(response, "Error: batcaveUploadBundle takes no arguments.");
        return grpc::Status::OK;
    }

    // The payload is a JSON array of [filename, byte_length] pairs, followed
    // by a newline and the concatenated raw file bytes.
    const std::string& payload = command.data();
    const std::size_t separator = payload.find('\n');
    if (separator == std::string::npos || separator > 65536)
    {
        setTerminalError(response, "Error: Invalid Batcave bundle manifest.");
        return grpc::Status::OK;
    }
    const json manifest = json::parse(payload.substr(0, separator), nullptr, false);
    if (!manifest.is_array() || manifest.empty() || manifest.size() > 256)
    {
        setTerminalError(response, "Error: Invalid Batcave bundle manifest.");
        return grpc::Status::OK;
    }

    std::vector<std::pair<std::string, std::string_view>> files;
    std::unordered_set<std::string> names;
    std::size_t offset = separator + 1;
    for (const auto& entry : manifest)
    {
        if (!entry.is_array() || entry.size() != 2 || !entry[0].is_string() || !entry[1].is_number_unsigned())
        {
            setTerminalError(response, "Error: Invalid Batcave bundle manifest.");
            return grpc::Status::OK;
        }
        const std::string name = entry[0].get<std::string>();
        const std::uint64_t length = entry[1].get<std::uint64_t>();
        if (!isValidFilename(name) || !names.insert(name).second || length > payload.size() - offset)
        {
            setTerminalError(response, "Error: Invalid Batcave bundle manifest.");
            return grpc::Status::OK;
        }
        files.emplace_back(name, std::string_view(payload.data() + offset, static_cast<std::size_t>(length)));
        offset += static_cast<std::size_t>(length);
    }
    if (offset != payload.size())
    {
        setTerminalError(response, "Error: Invalid Batcave bundle payload length.");
        return grpc::Status::OK;
    }

    std::lock_guard<std::mutex> lock(m_uploadMutex);
    const fs::path toolsDirectory = fs::path(m_runtimeConfig.toolsDirectoryPath) / "Any" / "any";
    const fs::path stagingDirectory = temporarySibling(
        fs::path(m_runtimeConfig.toolsDirectoryPath) / ".batcave-staging" / "bundle");
    std::error_code ec;
    fs::create_directories(stagingDirectory / "files", ec);
    if (!ec)
        fs::create_directories(stagingDirectory / "backups", ec);
    if (ec)
    {
        std::error_code ignored;
        fs::remove_all(stagingDirectory, ignored);
        setTerminalError(response, "Error: Cannot create Batcave staging directory.");
        return grpc::Status::OK;
    }

    auto cleanup = [&]() { std::error_code ignored; fs::remove_all(stagingDirectory, ignored); };
    json recoveryJournal = json::array();
    for (const auto& [name, bytes] : files)
    {
        const fs::path destination = toolsDirectory / name;
        const bool exists = fs::exists(destination, ec);
        if (ec || (exists && !fs::is_regular_file(destination, ec)) || ec)
        {
            cleanup();
            setTerminalError(response, "Error: Batcave destination is not a file.");
            return grpc::Status::OK;
        }
        if (!writeFileAtomically(stagingDirectory / "files" / name, bytes))
        {
            cleanup();
            setTerminalError(response, "Error: Cannot stage Batcave bundle.");
            return grpc::Status::OK;
        }
        recoveryJournal.push_back(json::array({name, exists}));
    }
    if (!writeFileAtomically(stagingDirectory / "recovery.json", recoveryJournal.dump()))
    {
        cleanup();
        setTerminalError(response, "Error: Cannot journal Batcave bundle.");
        return grpc::Status::OK;
    }

    struct CommittedFile { fs::path destination; fs::path backup; bool hadBackup; };
    std::vector<CommittedFile> committed;
    auto rollback = [&]() -> bool
    {
        bool restored = true;
        for (auto it = committed.rbegin(); it != committed.rend(); ++it)
        {
            std::error_code rollbackError;
            fs::remove(it->destination, rollbackError);
            if (rollbackError)
                restored = false;
            if (it->hadBackup)
            {
                fs::rename(it->backup, it->destination, rollbackError);
                if (rollbackError)
                    restored = false;
            }
        }
        return restored;
    };
    auto commitError = [&](bool restored) -> grpc::Status
    {
        if (restored)
            cleanup();
        else
            m_logger->error("Batcave rollback incomplete; recovery files remain in {}", stagingDirectory.string());
        setTerminalError(response, restored
            ? "Error: Cannot replace Batcave bundle files."
            : "Error: Batcave rollback incomplete; recovery files remain on TeamServer.");
        return grpc::Status::OK;
    };
    for (const auto& file : files)
    {
        const std::string& name = file.first;
        const fs::path destination = toolsDirectory / name;
        const fs::path backup = stagingDirectory / "backups" / name;
        const bool hadBackup = fs::exists(destination, ec);
        if (ec)
            return commitError(rollback());
        if (hadBackup)
        {
            fs::rename(destination, backup, ec);
            if (ec)
                return commitError(rollback());
        }
        fs::rename(stagingDirectory / "files" / name, destination, ec);
        if (ec)
        {
            bool restored = true;
            if (hadBackup)
            {
                std::error_code restoreError;
                fs::rename(backup, destination, restoreError);
                restored = !restoreError;
            }
            return commitError(rollback() && restored);
        }
        committed.push_back({destination, backup, hadBackup});
    }
    if (!writeFileAtomically(stagingDirectory / "committed", ""))
        return commitError(rollback());
    removeCommittedStage(stagingDirectory, ec);
    if (ec)
        m_logger->warn("Batcave bundle installed but staging cleanup failed at {}: {}", stagingDirectory.string(), ec.message());
    setTerminalOk(response, "Batcave bundle installed (" + std::to_string(files.size()) + " tools).");
    m_logger->info("Installed Batcave bundle with {} tools", files.size());
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleAddCredential(
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    if (m_credentialVaultService)
        return m_credentialVaultService->handleTerminalCommand({AddCredentialInstruction}, command, response);

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
    if (m_credentialVaultService)
    {
        teamserverapi::TerminalCommandRequest command;
        command.set_command(GetCredentialInstruction);
        return m_credentialVaultService->handleTerminalCommand({GetCredentialInstruction}, command, response);
    }

    m_logger->debug("GetCredentials command received");
    setTerminalOk(response, m_credentials.dump());
    return grpc::Status::OK;
}

grpc::Status TeamServerTermLocalService::handleCredentialVault(
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response)
{
    if (!m_credentialVaultService)
    {
        setTerminalError(response, "Error: credential vault service is not available.");
        return grpc::Status::OK;
    }
    return m_credentialVaultService->handleTerminalCommand(splitedCmd, command, response);
}

grpc::Status TeamServerTermLocalService::handleReloadModules(teamserverapi::TerminalCommandResponse* response)
{
    m_logger->info("Reloading TeamServer modules from directory: {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    std::vector<std::unique_ptr<ModuleCmd>> reloaded;
    try
    {
        reloaded = m_moduleLoader ? m_moduleLoader() : loadModulesFromDisk();
    }
    catch (const std::exception& error)
    {
        m_logger->error("Module reload failed: {}", error.what());
        setTerminalError(response, "Error: Module reload failed; previous modules remain active.");
        return grpc::Status::OK;
    }
    const std::size_t reloadedModules = reloaded.size();
    if (reloadedModules == 0)
    {
        m_logger->warn("No TeamServer modules loaded from {0}; keeping previous modules", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
        setTerminalError(response, "Error: No modules loaded; previous modules remain active.");
        return grpc::Status::OK;
    }

    {
        std::unique_lock<std::shared_mutex> lock(*m_moduleCmdMutex);
        m_moduleCmd.swap(reloaded);
    }
    m_logger->info("Reloaded {0} TeamServer module(s) from {1}", reloadedModules, m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    setTerminalOk(response, "");
    return grpc::Status::OK;
}
