#include "TeamServerLocalOperationService.hpp"

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
#include "TeamServerListenerArtifactService.hpp"
#include "TeamServerModuleLoader.hpp"
#include "listener/ListenerHttp.hpp"
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace
{
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

TeamServerLocalOperationService::TeamServerLocalOperationService(
    std::shared_ptr<spdlog::logger> logger,
    const nlohmann::json& config,
    TeamServerRuntimeConfig runtimeConfig,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    ModuleLoader moduleLoader,
    TeamServerListenerArtifactService* listenerArtifactService,
    std::shared_mutex* moduleCmdMutex)
    : m_logger(std::move(logger)),
      m_config(config),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_moduleCmd(moduleCmd),
      m_moduleLoader(std::move(moduleLoader)),
      m_listenerArtifactService(listenerArtifactService),
      m_moduleCmdMutex(moduleCmdMutex ? moduleCmdMutex : &m_localModuleCmdMutex)
{
    recoverBatcaveBundles();
}

void TeamServerLocalOperationService::recoverBatcaveBundles()
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

std::vector<std::unique_ptr<ModuleCmd>> TeamServerLocalOperationService::loadModulesFromDisk() const
{
    TeamServerModuleLoader loader(m_logger, m_runtimeConfig);
    return loader.loadModules();
}

bool TeamServerLocalOperationService::isValidFilename(const std::string& filename) const
{
    return !filename.empty() && filename != "." && filename != ".."
        && filename.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.") == std::string::npos;
}

std::string TeamServerLocalOperationService::resolveDownloadFolderForListener(
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

TeamServerOperationResult TeamServerLocalOperationService::hostArtifact(
    const std::string& listenerHash, const std::string& artifactReference,
    const std::string& hostedFilename)
{
    m_logger->debug("hostArtifact");
    if (listenerHash.empty() || artifactReference.empty())
        return {false, "Error: listener hash and artifact reference are required."};
    std::lock_guard<std::mutex> lock(m_uploadMutex);
    std::shared_ptr<Listener> listener;
    std::string listenerError;
    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash, listener, listenerError);
    if (downloadFolder.empty())
    {
        m_logger->warn("Listener {0} has no download folder configured; unable to host artifact {1}", listenerHash, artifactReference);
        return {false, listenerError};
    }

    TeamServerArtifactCatalog catalog(m_runtimeConfig);
    std::vector<TeamServerArtifactRecord> matches;
    for (const TeamServerArtifactRecord& candidate : catalog.listArtifacts())
    {
        if (candidate.artifactId == artifactReference
            || candidate.name == artifactReference
            || candidate.displayName == artifactReference)
            matches.push_back(candidate);
    }
    if (matches.empty() && artifactReference.size() >= 8)
    {
        for (const TeamServerArtifactRecord& candidate : catalog.listArtifacts())
            if (candidate.artifactId.rfind(artifactReference, 0) == 0)
                matches.push_back(candidate);
    }
    if (matches.empty())
        return {false, "Error: artifact not found."};
    if (matches.size() > 1)
        return {false, "Error: artifact reference is ambiguous."};

    TeamServerArtifactRecord artifact;
    std::string bytes;
    std::string message;
    if (!catalog.readArtifactPayload(matches.front().artifactId, artifact, bytes, message))
        return {false, "Error: " + message};

    const std::string filename = hostedFilename.empty()
        ? sanitizeHostedFilename(!artifact.displayName.empty() ? artifact.displayName : artifact.name)
        : hostedFilename;
    if (!isValidFilename(filename))
        return {false, "Error: filename not allowed."};

    const std::string hostedUrl = m_listenerArtifactService->hostedArtifactUrl(listener, filename);
    if (hostedUrl.empty())
        return {false, "Error: Listener has no public download URL configured."};

    const fs::path destinationPath = fs::path(downloadFolder) / filename;
    if (!samePath(artifact.internalPath, destinationPath) && !writeFileAtomically(destinationPath, bytes))
    {
        m_logger->warn("Failed to host artifact {0} at {1}", artifact.artifactId, destinationPath.string());
        return {false, "Error: Cannot write file."};
    }
    m_logger->info("Hosted artifact {0} as {1} for listener {2}", artifact.artifactId, destinationPath.string(), listenerHash);
    return {true, hostedUrl};
}

TeamServerOperationResult TeamServerLocalOperationService::uploadListenerFile(
    const std::string& listenerHash, const std::string& filename, const std::string& data)
{
    if (!isValidFilename(filename))
        return {false, "Error: filename not allowed."};
    std::lock_guard<std::mutex> lock(m_uploadMutex);
    std::shared_ptr<Listener> listener;
    std::string listenerError;
    const std::string downloadFolder = resolveDownloadFolderForListener(listenerHash, listener, listenerError);
    if (downloadFolder.empty())
        return {false, listenerError};
    const fs::path filePath = fs::path(downloadFolder) / filename;
    if (!writeFileAtomically(filePath, data))
        return {false, "Error: Cannot write file."};
    m_logger->info("Stored uploaded file '{}' for listener {} in {}", filename, listenerHash, filePath.string());
    return {true, "ok"};
}

TeamServerOperationResult TeamServerLocalOperationService::installTool(
    const std::string& filename, const std::string& data)
{
    if (!isValidFilename(filename))
        return {false, "Error: filename not allowed."};
    const fs::path filePath = fs::path(m_runtimeConfig.toolsDirectoryPath) / "Any" / "any" / filename;
    std::lock_guard<std::mutex> lock(m_uploadMutex);
    if (!writeFileAtomically(filePath, data))
        return {false, "Error: Cannot write file."};
    m_logger->info("Saved uploaded tool '{}' to {}", filename, filePath.string());
    return {true, "ok"};
}

TeamServerOperationResult TeamServerLocalOperationService::installToolBundle(
    const std::vector<std::pair<std::string, std::string>>& files)
{
    if (files.empty() || files.size() > 256)
        return {false, "Error: Invalid Batcave bundle manifest."};
    std::unordered_set<std::string> names;
    for (const auto& file : files)
    {
        if (!isValidFilename(file.first) || !names.insert(file.first).second)
            return {false, "Error: Invalid Batcave bundle manifest."};
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
        return {false, "Error: Cannot create Batcave staging directory."};
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
            return {false, "Error: Batcave destination is not a file."};
        }
        if (!writeFileAtomically(stagingDirectory / "files" / name, bytes))
        {
            cleanup();
            return {false, "Error: Cannot stage Batcave bundle."};
        }
        recoveryJournal.push_back(json::array({name, exists}));
    }
    if (!writeFileAtomically(stagingDirectory / "recovery.json", recoveryJournal.dump()))
    {
        cleanup();
        return {false, "Error: Cannot journal Batcave bundle."};
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
    auto commitError = [&](bool restored) -> TeamServerOperationResult
    {
        if (restored)
            cleanup();
        else
            m_logger->error("Batcave rollback incomplete; recovery files remain in {}", stagingDirectory.string());
        return {false, restored
            ? "Error: Cannot replace Batcave bundle files."
            : "Error: Batcave rollback incomplete; recovery files remain on TeamServer."};
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
    m_logger->info("Installed Batcave bundle with {} tools", files.size());
    return {true, "Batcave bundle installed (" + std::to_string(files.size()) + " tools)."};
}

TeamServerOperationResult TeamServerLocalOperationService::reloadModules()
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
        return {false, "Error: Module reload failed; previous modules remain active."};
    }
    const std::size_t reloadedModules = reloaded.size();
    if (reloadedModules == 0)
    {
        m_logger->warn("No TeamServer modules loaded from {0}; keeping previous modules", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
        return {false, "Error: No modules loaded; previous modules remain active."};
    }

    {
        std::unique_lock<std::shared_mutex> lock(*m_moduleCmdMutex);
        m_moduleCmd.swap(reloaded);
    }
    m_logger->info("Reloaded {0} TeamServer module(s) from {1}", reloadedModules, m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
    return {true, "Reloaded " + std::to_string(reloadedModules) + " TeamServer module(s)."};
}
