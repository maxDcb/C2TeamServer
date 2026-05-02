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
    std::vector<teamserverapi::CommandResult>& cmdResponses,
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
    m_logger->trace("ListListeners");

    for (size_t i = 0; i < m_listeners.size(); i++)
    {
        teamserverapi::Listener listener;
        listener.set_listener_hash(m_listeners[i]->getListenerHash());

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
        listener.set_session_count(static_cast<int32_t>(m_listeners[i]->getNumberOfSession()));

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
                childListener.set_listener_hash(it->getListenerHash());
                childListener.set_beacon_hash(session->getBeaconHash());
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

    m_logger->trace("ListListeners end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::addListener(const teamserverapi::Listener& listenerToCreate, teamserverapi::OperationAck* response)
{
    m_logger->trace("AddListener");
    const std::string type = listenerToCreate.type();
    response->set_status(teamserverapi::KO);

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
            response->set_message("Listener already exists.");
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
            response->set_message("DNS listener already exists.");
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
            response->set_message("Listener already exists.");
            return grpc::Status::OK;
        }
    }

    bool created = false;

    if (type == ListenerTcpType)
    {
        std::shared_ptr<ListenerTcp> listenerTcp = std::make_shared<ListenerTcp>(listenerToCreate.ip(), listenerToCreate.port(), m_config);
        if (listenerTcp->init() > 0)
        {
            listenerTcp->setIsPrimary();
            m_listeners.push_back(std::move(listenerTcp));
            created = true;
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
            created = true;
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
            created = true;
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
        created = true;
        m_logger->info("AddListener Github {0}:{1}", listenerToCreate.project(), listenerToCreate.token());
    }
    else if (type == ListenerDnsType)
    {
        std::shared_ptr<ListenerDns> listenerDns = std::make_shared<ListenerDns>(listenerToCreate.domain(), listenerToCreate.port(), m_config);
        listenerDns->setIsPrimary();
        m_listeners.push_back(std::move(listenerDns));
        created = true;
        m_logger->info("AddListener Dns {0}:{1}", listenerToCreate.domain(), std::to_string(listenerToCreate.port()));
    }

    if (created)
    {
        response->set_status(teamserverapi::OK);
        response->set_message("Listener created.");
    }
    else if (response->message().empty())
    {
        response->set_message("Listener could not be created.");
    }

    m_logger->trace("AddListener end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::stopListener(const teamserverapi::ListenerSelector& listenerToStop, teamserverapi::OperationAck* response)
{
    m_logger->trace("StopListener");
    response->set_status(teamserverapi::KO);

    const std::string listenerHash = listenerToStop.listener_hash();
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
    {
        response->set_status(teamserverapi::OK);
        response->set_message("Listener stop requested.");
        m_logger->info("StopListener completed for {0} (primary removed: {1}, stop commands sent: {2})",
            listenerHash,
            removedPrimary ? "yes" : "no",
            stopCommandSent ? "yes" : "no");
    }
    else
    {
        response->set_message("Listener not found.");
        m_logger->warn("StopListener request ignored: listener {0} not found", listenerHash);
    }

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
    m_logger->trace("ListSessions");

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
            sessionTmp.set_listener_hash(session->getListenerHash());
            sessionTmp.set_beacon_hash(session->getBeaconHash());
            sessionTmp.set_hostname(session->getHostname());
            sessionTmp.set_username(session->getUsername());
            sessionTmp.set_arch(session->getArch());
            sessionTmp.set_privilege(session->getPrivilege());
            sessionTmp.set_os(session->getOs());
            sessionTmp.set_last_proof_of_life(session->getLastProofOfLife());
            sessionTmp.set_killed(session->isSessionKilled());
            sessionTmp.set_internal_ips(session->getInternalIps());
            sessionTmp.set_process_id(session->getProcessId());
            sessionTmp.set_additional_information(session->getAdditionalInformation());

            if (!session->isSessionKilled() && isListenerAlive(session->getListenerHash()))
            {
                if (!emit(sessionTmp))
                    return grpc::Status::OK;
            }
        }
    }

    m_logger->trace("ListSessions end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::stopSession(const teamserverapi::SessionSelector& sessionToStop, teamserverapi::OperationAck* response)
{
    m_logger->trace("StopSession");
    response->set_status(teamserverapi::KO);

    const std::string beaconHash = sessionToStop.beacon_hash();
    const std::string listenerHash = sessionToStop.listener_hash();

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
                    response->set_status(teamserverapi::OK);
                    response->set_message("Session stop command queued.");
                    m_logger->info("StopSession command queued for beacon {0} on listener {1}", beaconHash, listenerHash);
                }

                m_logger->trace("StopSession end");
                return grpc::Status::OK;
            }
        }
    }

    response->set_message("Session not found.");
    m_logger->warn("StopSession request ignored: session {0} on listener {1} not found", beaconHash, listenerHash);
    m_logger->trace("StopSession end");
    return grpc::Status::OK;
}

grpc::Status TeamServerListenerSessionService::sendSessionCommand(const teamserverapi::SessionCommandRequest& command, teamserverapi::CommandAck* response)
{
    m_logger->trace("SendSessionCommand");

    const std::string input = command.command();
    const std::string beaconHash = command.session().beacon_hash();
    const std::string listenerHash = command.session().listener_hash();
    const std::string commandId = command.command_id().empty() ? generateUUID8() : command.command_id();

    response->set_status(teamserverapi::KO);
    response->set_command_id(commandId);

    if (input.empty())
    {
        response->set_message("Empty command.");
        m_logger->trace("SendSessionCommand end");
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

        m_logger->debug("SendSessionCommand {0} {1} {2}", beaconHash, c2Message.instruction(), c2Message.cmd());

        if (res != 0)
        {
            std::string hint = c2Message.returnvalue();
            response->set_message(hint);
            m_logger->debug("SendSessionCommand Fail prepMsg {0}", hint);
            m_logger->trace("SendSessionCommand end");
            return grpc::Status::OK;
        }

        if (c2Message.instruction().empty())
        {
            response->set_message("Command did not produce a beacon task.");
            m_logger->trace("SendSessionCommand end");
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
        m_logger->trace("SendSessionCommand end");
        return grpc::Status::OK;
    }

    response->set_message("Session not found.");
    m_logger->trace("SendSessionCommand end");
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
                m_logger->trace("StreamSessionCommandResults {0} {1} {2}", beaconHash, c2Message.instruction(), c2Message.cmd());

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

                teamserverapi::CommandResult commandResponseTmp;
                commandResponseTmp.set_status(errorMsg.empty() ? teamserverapi::OK : teamserverapi::KO);
                commandResponseTmp.mutable_session()->set_beacon_hash(beaconHash);
                commandResponseTmp.mutable_session()->set_listener_hash(listenerHash);
                commandResponseTmp.set_command_id(commandId);
                commandResponseTmp.set_instruction(responseInstruction);
                commandResponseTmp.set_command(commandLine);
                if (!errorMsg.empty())
                {
                    commandResponseTmp.set_message(errorMsg);
                    commandResponseTmp.set_output(errorMsg);
                    m_cmdResponses.push_back(commandResponseTmp);
                }
                else if (!c2Message.returnvalue().empty())
                {
                    commandResponseTmp.set_output(c2Message.returnvalue());
                    m_cmdResponses.push_back(commandResponseTmp);
                }
                else if (trackedCommand)
                {
                    commandResponseTmp.set_output("");
                    m_cmdResponses.push_back(commandResponseTmp);
                }
                else
                {
                    m_logger->debug("StreamSessionCommandResults no output");
                }

                c2Message = m_listeners[i]->getTaskResult(beaconHash);
            }
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    return 0;
}

grpc::Status TeamServerListenerSessionService::streamResponsesForSession(
    const teamserverapi::SessionSelector& targetSession,
    const std::multimap<grpc::string_ref, grpc::string_ref>& metadata,
    const TeamServerListenerSessionService::CommandResultEmitter& emit)
{
    m_logger->trace("StreamSessionCommandResults");

    const std::string targetBeaconHash = targetSession.beacon_hash();
    const std::string targetListenerHash = targetSession.listener_hash();
    const std::string clientId = extractClientId(metadata);
    if (clientId.empty())
        return grpc::Status::OK;

    if (m_sentResponses.find(clientId) == m_sentResponses.end())
        m_sentResponses[clientId] = {};

    std::vector<int>& sentIndices = m_sentResponses[clientId];
    for (size_t i = 0; i < m_cmdResponses.size(); ++i)
    {
        if (targetBeaconHash == m_cmdResponses[i].session().beacon_hash()
            && targetListenerHash == m_cmdResponses[i].session().listener_hash())
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
