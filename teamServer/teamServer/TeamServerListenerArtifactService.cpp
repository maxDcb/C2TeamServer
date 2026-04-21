#include "TeamServerListenerArtifactService.hpp"

#include <fstream>

#include "listener/ListenerHttp.hpp"
#include "modules/ModuleCmd/CommonCommand.hpp"

namespace
{
const std::string InfoListenerInstruction = "infoListener";
const std::string GetBeaconBinaryInstruction = "getBeaconBinary";

std::string readBinaryFile(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
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
    const teamserverapi::TermCommand& command,
    teamserverapi::TermCommand* response) const
{
    response->set_cmd("");
    response->set_result("");
    response->set_data("");

    if (instruction == InfoListenerInstruction)
        return handleInfoListener(splitedCmd, command.cmd(), response);
    if (instruction == GetBeaconBinaryInstruction)
        return handleGetBeaconBinary(splitedCmd, command.cmd(), response);

    response->set_result("Error: not implemented.");
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
    bool primaryListener) const
{
    const bool linuxTarget = targetOs == "Linux";
    if (type == ListenerHttpType || type == ListenerHttpsType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconHttp" : m_runtimeConfig.windowsBeaconsDirectoryPath + "BeaconHttp.exe";
    if (type == ListenerTcpType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconTcp" : m_runtimeConfig.windowsBeaconsDirectoryPath + "BeaconTcp.exe";
    if (primaryListener && type == ListenerGithubType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconGithub" : m_runtimeConfig.windowsBeaconsDirectoryPath + "BeaconGithub.exe";
    if (primaryListener && type == ListenerDnsType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconDns" : m_runtimeConfig.windowsBeaconsDirectoryPath + "BeaconDns.exe";
    if (!primaryListener && type == ListenerSmbType)
        return linuxTarget ? m_runtimeConfig.linuxBeaconsDirectoryPath + "BeaconSmb" : m_runtimeConfig.windowsBeaconsDirectoryPath + "BeaconSmb.exe";
    return "";
}

grpc::Status TeamServerListenerArtifactService::handleInfoListener(
    const std::vector<std::string>& splitedCmd,
    const std::string& cmd,
    teamserverapi::TermCommand* response) const
{
    m_logger->debug("infoListener {0}", cmd);

    if (splitedCmd.size() != 2)
    {
        response->set_result("Error: infoListener take one arguement.");
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
                response->set_result("Error: No IP or Hostname in config.");
                return grpc::Status::OK;
            }

            m_logger->debug("infoListener found in primary listeners {0}", hash);
            response->set_result(result);
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
                response->set_result(result);
                return grpc::Status::OK;
            }
        }
    }

    m_logger->error("Error: Listener {} not found.", listenerHash);
    response->set_result("Error: Listener not found.");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerArtifactService::handleGetBeaconBinary(
    const std::vector<std::string>& splitedCmd,
    const std::string& cmd,
    teamserverapi::TermCommand* response) const
{
    m_logger->debug("getBeaconBinary {0}", cmd);

    if (splitedCmd.size() != 2 && splitedCmd.size() != 3)
    {
        response->set_result("Error: getBeaconBinary take one arguement.");
        return grpc::Status::OK;
    }

    const std::string& listenerHash = splitedCmd[1];
    const std::string targetOs = (splitedCmd.size() == 3 && splitedCmd[2] == "Linux") ? "Linux" : "Windows";

    for (const auto& listener : m_listeners)
    {
        const std::string& hash = listener->getListenerHash();
        if (hash.rfind(listenerHash, 0) == 0)
        {
            const std::string beaconFilePath = resolveBeaconBinaryPath(listener->getType(), targetOs, true);
            std::ifstream beaconFile(beaconFilePath, std::ios::binary);
            if (!beaconFile.good())
            {
                m_logger->error("Error: Beacons {0} {1} not found.", listener->getType(), targetOs);
                response->set_result("Error: Beacons not found.");
                return grpc::Status::OK;
            }

            m_logger->info("getBeaconBinary found in primary listeners {0} {1}", listener->getType(), targetOs);
            response->set_data(readBinaryFile(beaconFilePath));
            response->set_result("ok");
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

                const std::string beaconFilePath = resolveBeaconBinaryPath(it->getType(), targetOs, false);
                std::ifstream beaconFile(beaconFilePath, std::ios::binary);
                if (!beaconFile.good())
                {
                    m_logger->error("Error: Beacons {0} {1} not found.", it->getType(), targetOs);
                    response->set_result("Error: Beacons not found.");
                    return grpc::Status::OK;
                }

                m_logger->info("getBeaconBinary found in beacon listeners {0} {1}", it->getType(), targetOs);
                response->set_data(readBinaryFile(beaconFilePath));
                response->set_result("ok");
                return grpc::Status::OK;
            }
        }
    }

    response->set_result("Error: Listener not found.");
    return grpc::Status::OK;
}
