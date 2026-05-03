#include "TeamServerListenerArtifactService.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

#include "listener/ListenerHttp.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"

namespace
{
const std::string InfoListenerInstruction = "infoListener";
const std::string GetBeaconBinaryInstruction = "getBeaconBinary";
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

TeamServerListenerArtifactService::TeamServerListenerArtifactService(
    std::shared_ptr<spdlog::logger> logger,
    const nlohmann::json& config,
    TeamServerRuntimeConfig runtimeConfig,
    std::vector<std::shared_ptr<Listener>>& listeners,
    IpResolver ipResolver)
    : m_logger(std::move(logger)),
      m_config(config),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_listeners(listeners),
      m_ipResolver(std::move(ipResolver))
{
}

bool TeamServerListenerArtifactService::canHandle(const std::string& instruction) const
{
    return instruction == InfoListenerInstruction || instruction == GetBeaconBinaryInstruction;
}

grpc::Status TeamServerListenerArtifactService::handleCommand(
    const std::string& instruction,
    const std::vector<std::string>& splitedCmd,
    const teamserverapi::TerminalCommandRequest& command,
    teamserverapi::TerminalCommandResponse* response) const
{
    response->set_status(teamserverapi::OK);
    response->set_command(command.command());
    response->set_result("");
    response->set_data("");
    response->clear_message();

    if (instruction == InfoListenerInstruction)
        return handleInfoListener(splitedCmd, command.command(), response);
    if (instruction == GetBeaconBinaryInstruction)
        return handleGetBeaconBinary(splitedCmd, command.command(), response);

    response->set_status(teamserverapi::KO);
    response->set_result("Error: not implemented.");
    response->set_message("Terminal command not implemented.");
    return grpc::Status::OK;
}

std::string TeamServerListenerArtifactService::resolvePublicAddress() const
{
    const auto domainIt = m_config.find("DomainName");
    if (domainIt != m_config.end())
        return domainIt->get<std::string>();

    const auto exposedIt = m_config.find("ExposedIp");
    if (exposedIt != m_config.end())
        return exposedIt->get<std::string>();

    const auto interfaceIt = m_config.find("IpInterface");
    if (interfaceIt != m_config.end() && !interfaceIt->get<std::string>().empty() && m_ipResolver)
        return m_ipResolver(interfaceIt->get<std::string>());

    return "";
}

std::string TeamServerListenerArtifactService::resolvePrimaryListenerInfo(const std::shared_ptr<Listener>& listener) const
{
    const std::string finalAddress = resolvePublicAddress();
    if (finalAddress.empty())
        return "";

    std::string uriFileDownload;
    const std::string type = listener->getType();
    if (type == ListenerHttpType)
    {
        const auto configHttp = m_config["ListenerHttpConfig"];
        const auto it = configHttp.find("uriFileDownload");
        if (it != configHttp.end())
            uriFileDownload = configHttp["uriFileDownload"].get<std::string>();
    }
    else if (type == ListenerHttpsType)
    {
        const auto configHttps = m_config["ListenerHttpsConfig"];
        const auto it = configHttps.find("uriFileDownload");
        if (it != configHttps.end())
            uriFileDownload = configHttps["uriFileDownload"].get<std::string>();
    }

    std::string result = type;
    result += "\n";
    result += finalAddress;
    result += "\n";
    result += listener->getParam2();
    result += "\n";
    result += uriFileDownload;
    return result;
}

std::string TeamServerListenerArtifactService::resolveBeaconBinaryPath(
    const std::string& type,
    const std::string& targetOs,
    const std::string& targetArch,
    bool primaryListener) const
{
    const bool linuxTarget = targetOs == "Linux";
    const fs::path windowsBeaconRoot = fs::path(m_runtimeConfig.windowsBeaconsDirectoryPath) / targetArch;
    if (type == ListenerHttpType || type == ListenerHttpsType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconHttp" : (windowsBeaconRoot / "BeaconHttp.exe").string();
    if (type == ListenerTcpType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconTcp" : (windowsBeaconRoot / "BeaconTcp.exe").string();
    if (primaryListener && type == ListenerGithubType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconGithub" : (windowsBeaconRoot / "BeaconGithub.exe").string();
    if (primaryListener && type == ListenerDnsType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconDns" : (windowsBeaconRoot / "BeaconDns.exe").string();
    if (!primaryListener && type == ListenerSmbType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconSmb" : (windowsBeaconRoot / "BeaconSmb.exe").string();
    return "";
}

grpc::Status TeamServerListenerArtifactService::handleInfoListener(
    const std::vector<std::string>& splitedCmd,
    const std::string& cmd,
    teamserverapi::TerminalCommandResponse* response) const
{
    m_logger->debug("infoListener {0}", cmd);

    if (splitedCmd.size() != 2)
    {
        setTerminalError(response, "Error: infoListener take one arguement.");
        return grpc::Status::OK;
    }

    const std::string& listenerHash = splitedCmd[1];
    for (const auto& listener : m_listeners)
    {
        const std::string& hash = listener->getListenerHash();
        if (hash.rfind(listenerHash, 0) == 0)
        {
            const std::string result = resolvePrimaryListenerInfo(listener);
            if (result.empty())
            {
                setTerminalError(response, "Error: No IP or Hostname in config.");
                return grpc::Status::OK;
            }

            m_logger->debug("infoListener found in primary listeners {0}", hash);
            setTerminalOk(response, result);
            return grpc::Status::OK;
        }

        const int nbSession = listener->getNumberOfSession();
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = listener->getSessionPtr(kk);
            if (session->isSessionKilled())
                continue;

            for (auto it = session->getListener().begin(); it != session->getListener().end(); ++it)
            {
                const std::string& secondaryHash = it->getListenerHash();
                if (secondaryHash.rfind(listenerHash, 0) != 0)
                    continue;

                std::string result = it->getType();
                result += "\n";
                result += it->getParam1();
                result += "\n";
                result += it->getParam2();
                result += "\n";
                result += "none";

                m_logger->debug("infoListener found in beacon listener {0} {1} {2}", it->getType(), it->getParam1(), it->getParam2());
                setTerminalOk(response, result);
                return grpc::Status::OK;
            }
        }
    }

    m_logger->error("Error: Listener {} not found.", listenerHash);
    setTerminalError(response, "Error: Listener not found.");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerArtifactService::handleGetBeaconBinary(
    const std::vector<std::string>& splitedCmd,
    const std::string& cmd,
    teamserverapi::TerminalCommandResponse* response) const
{
    m_logger->debug("getBeaconBinary {0}", cmd);

    if (splitedCmd.size() < 2 || splitedCmd.size() > 4)
    {
        setTerminalError(response, "Error: getBeaconBinary take one listener hash and optional OS/architecture arguments.");
        return grpc::Status::OK;
    }

    const std::string& listenerHash = splitedCmd[1];
    const std::string targetOsArg = splitedCmd.size() >= 3 ? lowerCopy(splitedCmd[2]) : "windows";
    const std::string targetOs = targetOsArg == "linux" ? "Linux" : "Windows";
    std::string targetArch = m_runtimeConfig.defaultWindowsArch;
    if (targetOs == "Windows")
    {
        if (splitedCmd.size() == 4)
            targetArch = TeamServerRuntimeConfig::normalizeWindowsArch(splitedCmd[3]);
        else
            targetArch = TeamServerRuntimeConfig::normalizeWindowsArch(targetArch);

        if (targetArch.empty())
        {
            setTerminalError(response, "Error: Unsupported architecture.");
            return grpc::Status::OK;
        }

        if (std::find(m_runtimeConfig.supportedWindowsArchs.begin(), m_runtimeConfig.supportedWindowsArchs.end(), targetArch)
            == m_runtimeConfig.supportedWindowsArchs.end())
        {
            setTerminalError(response, "Error: Unsupported architecture.");
            return grpc::Status::OK;
        }
    }

    for (const auto& listener : m_listeners)
    {
        const std::string& hash = listener->getListenerHash();
        if (hash.rfind(listenerHash, 0) == 0)
        {
            const std::string beaconFilePath = resolveBeaconBinaryPath(listener->getType(), targetOs, targetArch, true);
            std::ifstream beaconFile(beaconFilePath, std::ios::binary);
            if (!beaconFile.good())
            {
                m_logger->error("Error: Beacons {0} {1} {2} not found.", listener->getType(), targetOs, targetArch);
                setTerminalError(response, "Error: Beacons not found.");
                return grpc::Status::OK;
            }

            m_logger->info("getBeaconBinary found in primary listeners {0} {1} {2}", listener->getType(), targetOs, targetArch);
            response->set_data(readBinaryFile(beaconFilePath));
            setTerminalOk(response, "ok");
            return grpc::Status::OK;
        }

        const int nbSession = listener->getNumberOfSession();
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = listener->getSessionPtr(kk);
            if (session->isSessionKilled())
                continue;

            for (auto it = session->getListener().begin(); it != session->getListener().end(); ++it)
            {
                const std::string& secondaryHash = it->getListenerHash();
                if (secondaryHash.rfind(listenerHash, 0) != 0)
                    continue;

                const std::string beaconFilePath = resolveBeaconBinaryPath(it->getType(), targetOs, targetArch, false);
                std::ifstream beaconFile(beaconFilePath, std::ios::binary);
                if (!beaconFile.good())
                {
                    m_logger->error("Error: Beacons {0} {1} {2} not found.", it->getType(), targetOs, targetArch);
                    setTerminalError(response, "Error: Beacons not found.");
                    return grpc::Status::OK;
                }

                m_logger->info("getBeaconBinary found in beacon listeners {0} {1} {2}", it->getType(), targetOs, targetArch);
                response->set_data(readBinaryFile(beaconFilePath));
                setTerminalOk(response, "ok");
                return grpc::Status::OK;
            }
        }
    }

    setTerminalError(response, "Error: Listener not found.");
    return grpc::Status::OK;
}
