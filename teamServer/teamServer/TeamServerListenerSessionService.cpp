#include "TeamServerListenerSessionService.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <memory>
#include <openssl/md5.h>
#include <random>
#include <sstream>
#include <thread>

#include "listener/ListenerDns.hpp"
#include "listener/ListenerGithub.hpp"
#include "listener/ListenerHttp.hpp"
#include "listener/ListenerTcp.hpp"

namespace
{
std::string generateUUID8()
{
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t length = 8;
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, sizeof(charset) - 2);

    std::string uuid;
    for (size_t i = 0; i < length; ++i)
    {
        uuid += charset[distribution(generator)];
    }
    return uuid;
}

std::string computeBufferMd5(const std::string& buffer)
{
    if (buffer.empty())
        return "";

    unsigned char result[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, buffer.data(), buffer.size());
    MD5_Final(result, &ctx);

    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);

    return oss.str();
}

std::string extractClientId(const std::multimap<grpc::string_ref, grpc::string_ref>& metadata)
{
    for (const auto& meta : metadata)
    {
        if (std::string(meta.first.data(), meta.first.length()) == "clientid")
            return std::string(meta.second.data(), meta.second.length());
    }
    return "";
}
} // namespace

TeamServerListenerSessionService::TeamServerListenerSessionService(
    std::shared_ptr<spdlog::logger> logger,
    const nlohmann::json& config,
    std::vector<std::shared_ptr<Listener>>& listeners,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    CommonCommands& commonCommands,
    std::vector<teamserverapi::CommandResponse>& cmdResponses,
    std::unordered_map<std::string, std::vector<int>>& sentResponses,
    std::vector<BeaconCommandContext>& sentCommands,
    PrepMsgCallback prepMsg)
    : m_logger(std::move(logger)),
      m_config(config),
      m_listeners(listeners),
      m_moduleCmd(moduleCmd),
      m_commonCommands(commonCommands),
      m_cmdResponses(cmdResponses),
      m_sentResponses(sentResponses),
      m_sentCommands(sentCommands),
      m_prepMsg(std::move(prepMsg))
{
}

grpc::Status TeamServerListenerSessionService::streamListeners(const TeamServerListenerSessionService::ListenerEmitter& emit)
{
    m_logger->trace("GetListeners");

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        teamserverapi::Listener listener;
        listener.set_listenerhash(m_listeners[i]->getListenerHash());

        std::string type = m_listeners[i]->getType();
        listener.set_type(type);
        if (type == ListenerHttpType || type == ListenerHttpsType || type == ListenerTcpType)
        {
            listener.set_ip(m_listeners[i]->getParam1());
            listener.set_port(std::stoi(m_listeners[i]->getParam2()));
        }
        else if (type == ListenerSmbType)
        {
            listener.set_ip(m_listeners[i]->getParam1());
            listener.set_domain(m_listeners[i]->getParam2());
        }
        else if (type == ListenerGithubType)
        {
            listener.set_project(m_listeners[i]->getParam1());
            listener.set_token(m_listeners[i]->getParam2());
        }
        else if (type == ListenerDnsType)
        {
            listener.set_domain(m_listeners[i]->getParam1());
            listener.set_port(std::stoi(m_listeners[i]->getParam2()));
        }
        listener.set_numberofsession(m_listeners[i]->getNumberOfSession());

        if (!emit(listener))
            return grpc::Status::OK;

        int nbSession = static_cast<int>(m_listeners[i]->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
            if (!session || session->isSessionKilled())
                continue;

            for (auto it = session->getListener().begin(); it != session->getListener().end(); ++it)
            {
                m_logger->trace("|-> sessionListenerList {0} {1} {2}", it->getType(), it->getParam1(), it->getParam2());

                teamserverapi::Listener childListener;
                childListener.set_listenerhash(it->getListenerHash());
                childListener.set_beaconhash(session->getBeaconHash());
                std::string childType = it->getType();
                childListener.set_type(childType);
                if (childType == ListenerTcpType)
                {
                    childListener.set_ip(it->getParam1());
                    childListener.set_port(std::stoi(it->getParam2()));
                }
                else if (childType == ListenerSmbType)
                {
                    childListener.set_ip(it->getParam1());
                    childListener.set_domain(it->getParam2());
                }

                if (!emit(childListener))
                    return grpc::Status::OK;
            }
        }
    }

    m_logger->trace("GetListeners end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::addListener(const teamserverapi::Listener& listenerToCreate)
{
    m_logger->trace("AddListener");
    const std::string type = listenerToCreate.type();

    if (type == ListenerGithubType)
    {
        auto object = std::find_if(
            m_listeners.begin(),
            m_listeners.end(),
            [&](std::shared_ptr<Listener>& obj)
            {
                return obj->getType() == listenerToCreate.type() &&
                    obj->getParam1() == listenerToCreate.project() &&
                    obj->getParam2() == listenerToCreate.token();
            });

        if (object != m_listeners.end())
        {
            m_logger->warn("Add listener failed: Listener already exist");
            return grpc::Status::OK;
        }
    }
    else if (type == ListenerDnsType)
    {
        auto existingDns = std::find_if(
            m_listeners.begin(),
            m_listeners.end(),
            [&](std::shared_ptr<Listener>& obj)
            {
                return obj->getType() == ListenerDnsType &&
                    obj->getParam1() == listenerToCreate.domain() &&
                    obj->getParam2() == std::to_string(listenerToCreate.port());
            });

        if (existingDns != m_listeners.end())
        {
            m_logger->warn("Add listener failed: DNS listener already running on {0}:{1}",
                listenerToCreate.domain(),
                std::to_string(listenerToCreate.port()));
            return grpc::Status::OK;
        }
    }
    else
    {
        auto object = std::find_if(
            m_listeners.begin(),
            m_listeners.end(),
            [&](std::shared_ptr<Listener>& obj)
            {
                return obj->getType() == listenerToCreate.type() &&
                    obj->getParam1() == listenerToCreate.ip() &&
                    obj->getParam2() == std::to_string(listenerToCreate.port());
            });

        if (object != m_listeners.end())
        {
            m_logger->warn("Add listener failed: Listener already exist");
            return grpc::Status::OK;
        }
    }

    if (type == ListenerTcpType)
    {
        std::shared_ptr<ListenerTcp> listenerTcp = std::make_shared<ListenerTcp>(listenerToCreate.ip(), listenerToCreate.port(), m_config);
        if (listenerTcp->init() > 0)
        {
            listenerTcp->setIsPrimary();
            m_listeners.push_back(std::move(listenerTcp));
            m_logger->info("AddListener Tcp {0}:{1}", listenerToCreate.ip(), std::to_string(listenerToCreate.port()));
        }
        else
        {
            m_logger->error("Error: AddListener Tcp {0}:{1}", listenerToCreate.ip(), std::to_string(listenerToCreate.port()));
        }
    }
    else if (type == ListenerHttpType)
    {
        std::shared_ptr<ListenerHttp> listenerHttp = std::make_shared<ListenerHttp>(listenerToCreate.ip(), listenerToCreate.port(), m_config, false);
        if (listenerHttp->init() > 0)
        {
            listenerHttp->setIsPrimary();
            m_listeners.push_back(std::move(listenerHttp));
            m_logger->info("AddListener Http {0}:{1}", listenerToCreate.ip(), std::to_string(listenerToCreate.port()));
        }
        else
        {
            m_logger->error("Error: AddListener Http {0}:{1}", listenerToCreate.ip(), std::to_string(listenerToCreate.port()));
        }
    }
    else if (type == ListenerHttpsType)
    {
        std::shared_ptr<ListenerHttp> listenerHttps = std::make_shared<ListenerHttp>(listenerToCreate.ip(), listenerToCreate.port(), m_config, true);
        if (listenerHttps->init() > 0)
        {
            listenerHttps->setIsPrimary();
            m_listeners.push_back(std::move(listenerHttps));
            m_logger->info("AddListener Https {0}:{1}", listenerToCreate.ip(), std::to_string(listenerToCreate.port()));
        }
        else
        {
            m_logger->error("Error: AddListener Https {0}:{1}", listenerToCreate.ip(), std::to_string(listenerToCreate.port()));
        }
    }
    else if (type == ListenerGithubType)
    {
        std::shared_ptr<ListenerGithub> listenerGithub = std::make_shared<ListenerGithub>(listenerToCreate.project(), listenerToCreate.token(), m_config);
        listenerGithub->setIsPrimary();
        m_listeners.push_back(std::move(listenerGithub));
        m_logger->info("AddListener Github {0}:{1}", listenerToCreate.project(), listenerToCreate.token());
    }
    else if (type == ListenerDnsType)
    {
        std::shared_ptr<ListenerDns> listenerDns = std::make_shared<ListenerDns>(listenerToCreate.domain(), listenerToCreate.port(), m_config);
        listenerDns->setIsPrimary();
        m_listeners.push_back(std::move(listenerDns));
        m_logger->info("AddListener Dns {0}:{1}", listenerToCreate.domain(), std::to_string(listenerToCreate.port()));
    }

    m_logger->trace("AddListener end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::stopListener(const teamserverapi::Listener& listenerToStop, teamserverapi::Response* response)
{
    (void)response;
    m_logger->trace("StopListener");

    const std::string listenerHash = listenerToStop.listenerhash();
    bool removedPrimary = false;
    bool stopCommandSent = false;

    auto object = std::find_if(
        m_listeners.begin(),
        m_listeners.end(),
        [&](std::shared_ptr<Listener>& obj)
        { return obj->getListenerHash() == listenerHash; });

    if (object != m_listeners.end())
    {
        m_listeners.erase(std::remove(m_listeners.begin(), m_listeners.end(), *object), m_listeners.end());
        removedPrimary = true;
    }

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        int nbSession = static_cast<int>(m_listeners[i]->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
            if (!session)
                continue;

            std::vector<SessionListener> sessionListener = session->getListener();
            for (size_t j = 0; j < sessionListener.size(); j++)
            {
                if (listenerHash == sessionListener[j].getListenerHash())
                {
                    std::string input = "listener stop " + sessionListener[j].getListenerHash();
                    std::string beaconHash = session->getBeaconHash();

                    C2Message c2Message;
                    int res = m_prepMsg(input, c2Message, true, "x64");
                    if (res != 0)
                    {
                        std::string hint = c2Message.returnvalue();
                        response->set_message(hint);
                        response->set_status(teamserverapi::KO);
                    }

                    if (!c2Message.instruction().empty())
                    {
                        const std::string commandId = generateUUID8();
                        c2Message.set_uuid(commandId);
                        m_listeners[i]->queueTask(beaconHash, c2Message);

                        m_sentCommands.push_back(BeaconCommandContext{
                            commandId,
                            beaconHash,
                            session->getListenerHash(),
                            input,
                            c2Message.instruction(),
                        });
                        stopCommandSent = true;
                    }
                }
            }
        }
    }

    if (removedPrimary || stopCommandSent)
        m_logger->info("StopListener completed for {0} (primary removed: {1}, stop commands sent: {2})",
            listenerHash,
            removedPrimary ? "yes" : "no",
            stopCommandSent ? "yes" : "no");
    else
        m_logger->warn("StopListener request ignored: listener {0} not found", listenerHash);

    m_logger->trace("StopListener end");
    return grpc::Status::OK;
}

bool TeamServerListenerSessionService::isListenerAlive(const std::string& listenerHash) const
{
    m_logger->trace("isListenerAlive");

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        if (m_listeners[i]->getListenerHash() == listenerHash)
            return true;

        int nbSession = static_cast<int>(m_listeners[i]->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
            if (!session || session->isSessionKilled())
                continue;

            std::vector<SessionListener> sessionListenerList(session->getListener().begin(), session->getListener().end());
            for (size_t j = 0; j < sessionListenerList.size(); j++)
            {
                if (sessionListenerList[j].getListenerHash() == listenerHash)
                    return true;
            }
        }
    }

    m_logger->trace("isListenerAlive end");
    return false;
}

grpc::Status TeamServerListenerSessionService::streamSessions(const TeamServerListenerSessionService::SessionEmitter& emit)
{
    m_logger->trace("GetSessions");

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        m_logger->trace("Listener {0}", m_listeners[i]->getListenerHash());

        int nbSession = static_cast<int>(m_listeners[i]->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
            if (!session)
                continue;

            teamserverapi::Session sessionTmp;
            sessionTmp.set_listenerhash(session->getListenerHash());
            sessionTmp.set_beaconhash(session->getBeaconHash());
            sessionTmp.set_hostname(session->getHostname());
            sessionTmp.set_username(session->getUsername());
            sessionTmp.set_arch(session->getArch());
            sessionTmp.set_privilege(session->getPrivilege());
            sessionTmp.set_os(session->getOs());
            sessionTmp.set_lastproofoflife(session->getLastProofOfLife());
            sessionTmp.set_killed(session->isSessionKilled());
            sessionTmp.set_internalips(session->getInternalIps());
            sessionTmp.set_processid(session->getProcessId());
            sessionTmp.set_additionalinformation(session->getAdditionalInformation());

            if (!session->isSessionKilled() && isListenerAlive(session->getListenerHash()))
            {
                if (!emit(sessionTmp))
                    return grpc::Status::OK;
            }
        }
    }

    m_logger->trace("GetSessions end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::stopSession(const teamserverapi::Session& sessionToStop, teamserverapi::Response* response)
{
    m_logger->trace("StopSession");

    const std::string beaconHash = sessionToStop.beaconhash();
    const std::string listenerHash = sessionToStop.listenerhash();

    if (beaconHash.size() == SizeBeaconHash)
    {
        for (size_t i = 0; i < m_listeners.size(); i++)
        {
            if (m_listeners[i]->isSessionExist(beaconHash, listenerHash))
            {
                C2Message c2Message;
                int res = m_prepMsg(EndInstruction, c2Message, true, "x64");

                if (res != 0)
                {
                    std::string hint = c2Message.returnvalue();
                    response->set_message(hint);
                    response->set_status(teamserverapi::KO);
                }

                if (!c2Message.instruction().empty())
                {
                    m_listeners[i]->queueTask(beaconHash, c2Message);
                    m_listeners[i]->markSessionKilled(beaconHash);
                    m_logger->info("StopSession command queued for beacon {0} on listener {1}", beaconHash, listenerHash);
                }

                m_logger->trace("StopSession end");
                return grpc::Status::OK;
            }
        }
    }

    m_logger->warn("StopSession request ignored: session {0} on listener {1} not found", beaconHash, listenerHash);
    m_logger->trace("StopSession end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::sendCmdToSession(const teamserverapi::Command& command, teamserverapi::CommandAck* response)
{
    m_logger->trace("SendCmdToSession");

    const std::string input = command.cmd();
    const std::string beaconHash = command.beaconhash();
    const std::string listenerHash = command.listenerhash();
    const std::string commandId = command.commandid().empty() ? generateUUID8() : command.commandid();

    response->set_status(teamserverapi::KO);
    response->set_commandid(commandId);

    if (input.empty())
    {
        response->set_message("Empty command.");
        m_logger->trace("SendCmdToSession end");
        return grpc::Status::OK;
    }

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        if (!m_listeners[i]->isSessionExist(beaconHash, listenerHash))
            continue;

        std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(beaconHash, listenerHash);
        bool isWindows = session && session->getOs() == "Windows";
        std::string windowsArch = session ? session->getArch() : "x64";

        C2Message c2Message;
        int res = m_prepMsg(input, c2Message, isWindows, windowsArch);

        m_logger->debug("SendCmdToSession {0} {1} {2}", beaconHash, c2Message.instruction(), c2Message.cmd());

        if (res != 0)
        {
            std::string hint = c2Message.returnvalue();
            response->set_message(hint);
            m_logger->debug("SendCmdToSession Fail prepMsg {0}", hint);
            m_logger->trace("SendCmdToSession end");
            return grpc::Status::OK;
        }

        if (c2Message.instruction().empty())
        {
            response->set_message("Command did not produce a beacon task.");
            m_logger->trace("SendCmdToSession end");
            return grpc::Status::OK;
        }

        m_logger->info("Queued command {} for beacon {} -> '{}'", commandId, beaconHash.substr(0, 8), input);

        const std::string& inputFile = c2Message.inputfile();
        const std::string& payload = c2Message.data();
        if (!inputFile.empty() && !payload.empty())
        {
            std::string md5 = computeBufferMd5(payload);
            m_logger->info("File attached to task: '{}' | size={} bytes | MD5={}", inputFile, payload.size(), md5);
        }

        const std::string instruction = c2Message.instruction();
        c2Message.set_uuid(commandId);
        m_listeners[i]->queueTask(beaconHash, c2Message);

        m_sentCommands.push_back(BeaconCommandContext{
            commandId,
            beaconHash,
            listenerHash,
            input,
            instruction,
        });

        response->set_status(teamserverapi::OK);
        m_logger->trace("SendCmdToSession end");
        return grpc::Status::OK;
    }

    response->set_message("Session not found.");
    m_logger->trace("SendCmdToSession end");
    return grpc::Status::OK;
}

int TeamServerListenerSessionService::handleCmdResponse()
{
    m_logger->trace("handleCmdResponse");

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        int nbSession = static_cast<int>(m_listeners[i]->getNumberOfSession());
        for (int kk = 0; kk < nbSession; kk++)
        {
            std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
            if (!session)
                continue;

            std::string beaconHash = session->getBeaconHash();
            C2Message c2Message = m_listeners[i]->getTaskResult(beaconHash);
            while (!c2Message.instruction().empty())
            {
                m_logger->trace("GetResponseFromSession {0} {1} {2}", beaconHash, c2Message.instruction(), c2Message.cmd());

                std::string instructionCmd = c2Message.instruction();
                std::string errorMsg;

                if (instructionCmd == ListenerPollCmd)
                {
                    m_logger->debug("beaconHash {0} {1}", beaconHash, c2Message.returnvalue());
                    c2Message = m_listeners[i]->getTaskResult(beaconHash);
                    continue;
                }

                for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
                {
                    if (instructionCmd == (*it)->getName() || instructionCmd == std::to_string((*it)->getHash()))
                    {
                        (*it)->followUp(c2Message);
                        (*it)->errorCodeToMsg(c2Message, errorMsg);
                    }
                }

                std::string ccInstructionString = m_commonCommands.translateCmdToInstruction(instructionCmd);
                for (int ii = 0; ii < m_commonCommands.getNumberOfCommand(); ii++)
                {
                    if (ccInstructionString == m_commonCommands.getCommand(ii))
                        m_commonCommands.errorCodeToMsg(c2Message, errorMsg);
                }

                std::string commandId = c2Message.uuid();
                std::string listenerHash = session->getListenerHash();
                std::string commandLine = c2Message.cmd();
                std::string responseInstruction = instructionCmd;
                const std::string translatedInstruction = m_commonCommands.translateCmdToInstruction(instructionCmd);
                if (!translatedInstruction.empty())
                    responseInstruction = translatedInstruction;

                auto sentCommand = std::find_if(
                    m_sentCommands.begin(),
                    m_sentCommands.end(),
                    [&commandId](const BeaconCommandContext& context)
                    {
                        return context.commandId == commandId;
                    });
                bool trackedCommand = false;
                if (sentCommand != m_sentCommands.end())
                {
                    trackedCommand = true;
                    listenerHash = sentCommand->listenerHash;
                    commandLine = sentCommand->commandLine;
                    if (responseInstruction.empty())
                        responseInstruction = sentCommand->instruction;
                    m_sentCommands.erase(sentCommand);
                }

                teamserverapi::CommandResponse commandResponseTmp;
                commandResponseTmp.set_beaconhash(beaconHash);
                commandResponseTmp.set_listenerhash(listenerHash);
                commandResponseTmp.set_commandid(commandId);
                commandResponseTmp.set_instruction(responseInstruction);
                commandResponseTmp.set_cmd(commandLine);
                if (!errorMsg.empty())
                {
                    commandResponseTmp.set_response(errorMsg);
                    m_cmdResponses.push_back(commandResponseTmp);
                }
                else if (!c2Message.returnvalue().empty())
                {
                    commandResponseTmp.set_response(c2Message.returnvalue());
                    m_cmdResponses.push_back(commandResponseTmp);
                }
                else if (trackedCommand)
                {
                    commandResponseTmp.set_response("");
                    m_cmdResponses.push_back(commandResponseTmp);
                }
                else
                {
                    m_logger->debug("GetResponseFromSession no output");
                }

                c2Message = m_listeners[i]->getTaskResult(beaconHash);
            }
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    return 0;
}

grpc::Status TeamServerListenerSessionService::streamResponsesForSession(
    const teamserverapi::Session& targetSession,
    const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
    const TeamServerListenerSessionService::CommandResponseEmitter& emit)
{
    m_logger->trace("GetResponseFromSession");

    const std::string targetBeaconHash = targetSession.beaconhash();
    const std::string targetListenerHash = targetSession.listenerhash();
    const std::string clientId = extractClientId(metadata);
    if (clientId.empty())
        return grpc::Status::OK;

    if (m_sentResponses.find(clientId) == m_sentResponses.end())
        m_sentResponses[clientId] = {};

    std::vector<int>& sentIndices = m_sentResponses[clientId];
    for (size_t i = 0; i < m_cmdResponses.size(); ++i)
    {
        if (targetBeaconHash == m_cmdResponses[i].beaconhash()
            && targetListenerHash == m_cmdResponses[i].listenerhash())
        {
            if (std::find(sentIndices.begin(), sentIndices.end(), static_cast<int>(i)) == sentIndices.end())
            {
                if (!emit(m_cmdResponses[i]))
                    return grpc::Status::OK;
                sentIndices.push_back(static_cast<int>(i));
            }
        }
    }

    return grpc::Status::OK;
}
