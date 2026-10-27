#include "TeamServerListenerArtifactService.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

#include "listener/ListenerHttp.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"

namespace
{
namespace fs = std::filesystem;

std::string lowerCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string readBinaryFile(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

std::string configString(const nlohmann::json& config, const char* key)
{
    const auto it = config.find(key);
    if (it == config.end() || !it->is_string())
        return "";
    return it->get<std::string>();
}

bool isWildcardAddress(const std::string& address)
{
    return address.empty()
        || address == "0.0.0.0"
        || address == "::"
        || address == "[::]";
}

void setError(teamserverapi::ListenerInfoResponse* response, const std::string& message)
{
    response->set_status(teamserverapi::KO);
    response->set_message(message);
}

void setError(teamserverapi::BeaconBinaryResponse* response, const std::string& message)
{
    response->set_status(teamserverapi::KO);
    response->set_message(message);
}
} // namespace

TeamServerListenerArtifactService::TeamServerListenerArtifactService(
    std::shared_ptr<spdlog::logger> logger,
    const nlohmann::json& config,
    TeamServerRuntimeConfig runtimeConfig,
    std::vector<std::shared_ptr<Listener>>& listeners,
    IpResolver ipResolver,
    std::shared_mutex* listenersMutex)
    : m_logger(std::move(logger)),
      m_config(config),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_listeners(listeners),
      m_listenersMutex(listenersMutex ? listenersMutex : &m_localListenersMutex),
      m_ipResolver(std::move(ipResolver))
{
}

std::string TeamServerListenerArtifactService::resolvePublicAddress(const std::shared_ptr<Listener>& listener) const
{
    const std::string domainName = configString(m_config, "DomainName");
    if (!domainName.empty())
        return domainName;

    const std::string exposedIp = configString(m_config, "ExposedIp");
    if (!exposedIp.empty())
        return exposedIp;

    const std::string ipInterface = configString(m_config, "IpInterface");
    if (!ipInterface.empty() && m_ipResolver)
    {
        const std::string interfaceAddress = m_ipResolver(ipInterface);
        if (!interfaceAddress.empty())
            return interfaceAddress;
    }

    const std::string listenerAddress = listener ? listener->getParam1() : "";
    if (!isWildcardAddress(listenerAddress))
        return listenerAddress;

    if (isWildcardAddress(listenerAddress))
        return "127.0.0.1";

    return "";
}

bool TeamServerListenerArtifactService::fillPrimaryListenerInfo(
    const std::shared_ptr<Listener>& listener, teamserverapi::ListenerInfoResponse* response) const
{
    const std::string address = resolvePublicAddress(listener);
    if (address.empty())
        return false;
    const std::string type = listener->getType();
    const char* section = type == ListenerHttpType ? "ListenerHttpConfig"
        : type == ListenerHttpsType ? "ListenerHttpsConfig" : nullptr;
    response->set_type(type);
    response->set_address(address);
    response->set_port(listener->getParam2());
    if (section)
    {
        const auto configIt = m_config.find(section);
        if (configIt != m_config.end() && configIt->is_object())
            response->set_download_uri(configString(*configIt, "uriFileDownload"));
    }
    return true;
}

std::shared_ptr<Listener> TeamServerListenerArtifactService::resolvePrimaryListener(
    const std::string& listenerReference, std::string& error) const
{
    if (listenerReference.empty())
    {
        error = "Error: Listener reference is empty.";
        return {};
    }

    std::vector<std::shared_ptr<Listener>> matches;
    {
        std::shared_lock<std::shared_mutex> lock(*m_listenersMutex);
        for (const auto& listener : m_listeners)
        {
            if (listener && listener->getListenerHash().rfind(listenerReference, 0) == 0)
                matches.push_back(listener);
        }
    }
    std::shared_ptr<Listener> exact;
    for (const auto& listener : matches)
    {
        if (listener->getListenerHash() == listenerReference)
        {
            if (exact)
            {
                error = "Error: Listener reference is ambiguous.";
                return {};
            }
            exact = listener;
        }
    }
    if (exact)
        return exact;
    if (matches.size() == 1)
        return matches.front();

    error = matches.empty() ? "Error: Listener not found." : "Error: Listener reference is ambiguous.";
    return {};
}

std::optional<TeamServerListenerArtifactService::SecondaryListenerInfo>
TeamServerListenerArtifactService::resolveSecondaryListener(
    const std::string& listenerReference, std::string& error) const
{
    std::vector<SecondaryListenerInfo> matches;
    std::vector<std::shared_ptr<Listener>> listeners;
    {
        std::shared_lock<std::shared_mutex> lock(*m_listenersMutex);
        listeners = m_listeners;
    }
    for (const auto& listener : listeners)
    {
        if (!listener)
            continue;
        const int sessionCount = listener->getNumberOfSession();
        for (int index = 0; index < sessionCount; ++index)
        {
            const auto session = listener->getSessionPtr(index);
            if (!session || session->isSessionKilled())
                continue;
            for (const auto& child : session->getListener())
            {
                if (child.getListenerHash().rfind(listenerReference, 0) == 0)
                    matches.push_back({child.getListenerHash(), child.getType(), child.getParam1(), child.getParam2()});
            }
        }
    }
    std::optional<SecondaryListenerInfo> exact;
    for (const auto& match : matches)
    {
        if (match.hash == listenerReference)
        {
            if (exact)
            {
                error = "Error: Listener reference is ambiguous.";
                return std::nullopt;
            }
            exact = match;
        }
    }
    if (exact)
        return exact;
    if (matches.size() == 1)
        return matches.front();
    error = matches.empty() ? "Error: Listener not found." : "Error: Listener reference is ambiguous.";
    return std::nullopt;
}

std::string TeamServerListenerArtifactService::hostedArtifactUrl(
    const std::shared_ptr<Listener>& listener, const std::string& filename) const
{
    if (!listener || (listener->getType() != ListenerHttpType && listener->getType() != ListenerHttpsType))
        return "";

    const std::string address = resolvePublicAddress(listener);
    if (address.empty())
        return "";

    const char* section = listener->getType() == ListenerHttpType ? "ListenerHttpConfig" : "ListenerHttpsConfig";
    const auto configIt = m_config.find(section);
    if (configIt == m_config.end() || !configIt->is_object())
        return "";
    std::string path = configString(*configIt, "uriFileDownload");
    if (path.empty())
        return "";
    if (path.front() != '/')
        path.insert(path.begin(), '/');
    if (path.back() != '/')
        path += '/';

    const std::string urlHost = address.find(':') != std::string::npos && address.front() != '['
        ? "[" + address + "]" : address;
    return listener->getType() + "://" + urlHost + ":" + listener->getParam2() + path + filename;
}

std::string TeamServerListenerArtifactService::resolveBeaconBinaryPath(
    const std::string& type,
    const std::string& targetOs,
    const std::string& targetArch,
    bool primaryListener) const
{
    const bool linuxTarget = targetOs == "Linux";
    const fs::path windowsBeaconRoot = fs::path(m_runtimeConfig.windowsBeaconsDirectoryPath) / targetArch;
    const fs::path linuxBeaconRoot = fs::path(m_runtimeConfig.linuxBeaconsDirectoryPath) / targetArch;
    if (type == ListenerHttpType || type == ListenerHttpsType)
        return linuxTarget ? (linuxBeaconRoot / "BeaconHttp").string() : (windowsBeaconRoot / "BeaconHttp.exe").string();
    if (type == ListenerTcpType)
        return linuxTarget ? (linuxBeaconRoot / "BeaconTcp").string() : (windowsBeaconRoot / "BeaconTcp.exe").string();
#ifdef C2_ENABLE_GITHUB_TRANSPORT
    if (primaryListener && type == ListenerGithubType)
        return linuxTarget ? (linuxBeaconRoot / "BeaconGithub").string() : (windowsBeaconRoot / "BeaconGithub.exe").string();
#endif
    if (primaryListener && type == ListenerDnsType)
        return linuxTarget ? (linuxBeaconRoot / "BeaconDns").string() : (windowsBeaconRoot / "BeaconDns.exe").string();
    if (!primaryListener && type == ListenerSmbType)
        return linuxTarget ? "" : (windowsBeaconRoot / "BeaconSmb.exe").string();
    return "";
}

void TeamServerListenerArtifactService::getListenerInfo(
    const std::string& listenerHash, teamserverapi::ListenerInfoResponse* response) const
{
    response->Clear();
    std::string lookupError;
    const auto primary = resolvePrimaryListener(listenerHash, lookupError);
    if (primary)
    {
        if (!fillPrimaryListenerInfo(primary, response))
        {
            setError(response, "Error: No IP or Hostname in config.");
            return;
        }
        response->set_status(teamserverapi::OK);
        return;
    }
    if (lookupError != "Error: Listener not found.")
    {
        setError(response, lookupError);
        return;
    }
    const auto secondary = resolveSecondaryListener(listenerHash, lookupError);
    if (!secondary)
    {
        setError(response, lookupError);
        return;
    }
    response->set_type(secondary->type);
    response->set_address(secondary->address);
    response->set_port(secondary->port);
    response->set_download_uri("none");
    response->set_status(teamserverapi::OK);
}

void TeamServerListenerArtifactService::getBeaconBinary(
    const std::string& listenerHash, const std::string& os,
    const std::string& arch, teamserverapi::BeaconBinaryResponse* response) const
{
    response->Clear();
    const std::string targetOs = lowerCopy(os) == "linux" ? "Linux" : "Windows";
    std::string targetArch = arch.empty()
        ? (targetOs == "Linux" ? m_runtimeConfig.defaultLinuxArch : m_runtimeConfig.defaultWindowsArch)
        : arch;
    if (targetOs == "Windows")
    {
        targetArch = TeamServerRuntimeConfig::normalizeWindowsArch(targetArch);
        if (targetArch.empty() || std::find(m_runtimeConfig.supportedWindowsArchs.begin(),
            m_runtimeConfig.supportedWindowsArchs.end(), targetArch) == m_runtimeConfig.supportedWindowsArchs.end())
        {
            setError(response, "Error: Unsupported architecture.");
            return;
        }
    }
    else
    {
        targetArch = TeamServerRuntimeConfig::normalizeLinuxArch(targetArch);
        if (targetArch.empty() || std::find(m_runtimeConfig.supportedLinuxArchs.begin(),
            m_runtimeConfig.supportedLinuxArchs.end(), targetArch) == m_runtimeConfig.supportedLinuxArchs.end())
        {
            setError(response, "Error: Unsupported architecture.");
            return;
        }
    }

    std::string lookupError;
    const auto primary = resolvePrimaryListener(listenerHash, lookupError);
    std::string beaconFilePath;
    if (primary)
        beaconFilePath = resolveBeaconBinaryPath(primary->getType(), targetOs, targetArch, true);
    else if (lookupError == "Error: Listener not found.")
    {
        const auto secondary = resolveSecondaryListener(listenerHash, lookupError);
        if (!secondary)
        {
            setError(response, lookupError);
            return;
        }
        if (targetOs == "Linux" && secondary->type == ListenerSmbType)
        {
            setError(response, "Error: SMB is supported only on Windows.");
            return;
        }
        beaconFilePath = resolveBeaconBinaryPath(secondary->type, targetOs, targetArch, false);
    }
    else
    {
        setError(response, lookupError);
        return;
    }
    std::ifstream beaconFile(beaconFilePath, std::ios::binary);
    if (!beaconFile.good())
    {
        setError(response, "Error: Beacons not found.");
        return;
    }
    response->set_data(readBinaryFile(beaconFilePath));
    response->set_status(teamserverapi::OK);
}
