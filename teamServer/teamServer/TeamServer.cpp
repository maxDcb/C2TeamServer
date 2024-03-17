#include "TeamServer.hpp"

#include <functional>
#include <fstream>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

using namespace std;
using namespace std::placeholders;
namespace logging = boost::log;
using json = nlohmann::json;


TeamServer::TeamServer(const nlohmann::json& config) 
: m_config(config)
{
	std::unique_ptr<AssemblyExec> assemblyExec = std::make_unique<AssemblyExec>();
	m_moduleCmd.push_back(std::move(assemblyExec));

	std::unique_ptr<Upload> upload = std::make_unique<Upload>();
	m_moduleCmd.push_back(std::move(upload));

	std::unique_ptr<Run> run = std::make_unique<Run>();
	m_moduleCmd.push_back(std::move(run));

	std::unique_ptr<Download> download = std::make_unique<Download>();
	m_moduleCmd.push_back(std::move(download));

	std::unique_ptr<Inject> inject = std::make_unique<Inject>();
	m_moduleCmd.push_back(std::move(inject));
	
	std::unique_ptr<Script> script = std::make_unique<Script>();
	m_moduleCmd.push_back(std::move(script));

	std::unique_ptr<PrintWorkingDirectory> printWorkingDirectory = std::make_unique<PrintWorkingDirectory>();
	m_moduleCmd.push_back(std::move(printWorkingDirectory));

	std::unique_ptr<ChangeDirectory> changeDirectory = std::make_unique<ChangeDirectory>();
	m_moduleCmd.push_back(std::move(changeDirectory));

	std::unique_ptr<ListDirectory> listDirectory = std::make_unique<ListDirectory>();
	m_moduleCmd.push_back(std::move(listDirectory));

	std::unique_ptr<ListProcesses> listProcesses = std::make_unique<ListProcesses>();
	m_moduleCmd.push_back(std::move(listProcesses));

	std::unique_ptr<MakeToken> makeToken = std::make_unique<MakeToken>();
	m_moduleCmd.push_back(std::move(makeToken));
	
	std::unique_ptr<Rev2self> rev2self = std::make_unique<Rev2self>();
	m_moduleCmd.push_back(std::move(rev2self));

	std::unique_ptr<StealToken> stealToken = std::make_unique<StealToken>();
	m_moduleCmd.push_back(std::move(stealToken));

	std::unique_ptr<CoffLoader> coffLoader = std::make_unique<CoffLoader>();
	m_moduleCmd.push_back(std::move(coffLoader));

	std::unique_ptr<KerberosUseTicket> kerberosUseTicket = std::make_unique<KerberosUseTicket>();
	m_moduleCmd.push_back(std::move(kerberosUseTicket));

	std::unique_ptr<Powershell> powershell = std::make_unique<Powershell>();
	m_moduleCmd.push_back(std::move(powershell));

	std::unique_ptr<PsExec> psExec = std::make_unique<PsExec>();
	m_moduleCmd.push_back(std::move(psExec));

	std::unique_ptr<Chisel> chisel = std::make_unique<Chisel>();
	m_moduleCmd.push_back(std::move(chisel));

	std::unique_ptr<SpawnAs> spawnAs = std::make_unique<SpawnAs>();
	m_moduleCmd.push_back(std::move(spawnAs));

	std::unique_ptr<Evasion> evasion = std::make_unique<Evasion>();
	m_moduleCmd.push_back(std::move(evasion));

	std::unique_ptr<Cat> cat = std::make_unique<Cat>();
	m_moduleCmd.push_back(std::move(cat));

	std::unique_ptr<Tree> tree = std::make_unique<Tree>();
	m_moduleCmd.push_back(std::move(tree));

	std::unique_ptr<WmiExec> wmiExec = std::make_unique<WmiExec>();
	m_moduleCmd.push_back(std::move(wmiExec));

	// BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
    // BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
    // BOOST_LOG_TRIVIAL(info) << "An informational severity message";
    // BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
    // BOOST_LOG_TRIVIAL(error) << "An error severity message";
    // BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";
}


TeamServer::~TeamServer()
{
}


// Get the list of liseteners from primary listeners
// and from listeners runing on beacon through sessionListener
grpc::Status TeamServer::GetListeners(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Listener>* writer)
{
	BOOST_LOG_TRIVIAL(trace) << "GetListeners";

	for (int i = 0; i < m_listeners.size(); i++)
	{
		// For each primary listeners get the informations
		teamserverapi::Listener listener;
		listener.set_listenerhash(m_listeners[i]->getListenerHash());
		listener.set_type(m_listeners[i]->getType());
		listener.set_port(m_listeners[i]->getPort());
		listener.set_ip(m_listeners[i]->getHost());
		listener.set_numberofsession(m_listeners[i]->getNumberOfSession());	

		writer->Write(listener);

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
					teamserverapi::Listener listener;
					listener.set_listenerhash(sessionListenerList[j].getListenerHash());
					listener.set_type(sessionListenerList[j].getType());
					listener.set_port(sessionListenerList[j].getPort());
					listener.set_ip(sessionListenerList[j].getHost());

					writer->Write(listener);
				}
			}
		}
	}

	return grpc::Status::OK;
}


// Add listener that will run on the C2
// To add a listener to a beacon the process it to send a command to the beacon
grpc::Status TeamServer::AddListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToCreate,  teamserverapi::Response* response)
{
	BOOST_LOG_TRIVIAL(trace) << "AddListener";
	string type = listenerToCreate->type();

	try 
	{
		// TODO check if constructor completed befor the push_back
		if (type == ListenerTcpType)
		{
			int localPort = listenerToCreate->port();
			string localHost = listenerToCreate->ip();
			std::unique_ptr<ListenerTcp> listenerTcp = make_unique<ListenerTcp>(localHost, localPort);
			m_listeners.push_back(std::move(listenerTcp));

			BOOST_LOG_TRIVIAL(info) << "AddListener Tcp " << localHost << ":" << std::to_string(localPort);
		}
		else if (type == ListenerHttpType)
		{
			json configHttp = m_config["ListenerHttpConfig"];
			
			int localPort = listenerToCreate->port();
			string localHost = listenerToCreate->ip();
			std::unique_ptr<ListenerHttp> listenerHttp = make_unique<ListenerHttp>(localHost, localPort, configHttp, false);
			m_listeners.push_back(std::move(listenerHttp));

			BOOST_LOG_TRIVIAL(info) << "AddListener Http " << localHost << ":" << std::to_string(localPort);
		}
		else if (type == ListenerHttpsType)
		{
			json configHttps = m_config["ListenerHttpsConfig"];

			int localPort = listenerToCreate->port();
			string localHost = listenerToCreate->ip();
			std::unique_ptr<ListenerHttp> listenerHttps = make_unique<ListenerHttp>(localHost, localPort, configHttps, true);
			m_listeners.push_back(std::move(listenerHttps));

			BOOST_LOG_TRIVIAL(info) << "AddListener Https " << localHost << ":" << std::to_string(localPort);
		}
		else if (type == ListenerGithubType)
		{
			std::string token = listenerToCreate->token();
			std::string project = listenerToCreate->project();
			std::unique_ptr<ListenerGithub> listenerGithub = make_unique<ListenerGithub>(project, token);
			m_listeners.push_back(std::move(listenerGithub));

			BOOST_LOG_TRIVIAL(info) << "AddListener Github " << project << ":" << token;
		}
		else if (type == ListenerDnsType)
		{
			std::string domain = listenerToCreate->domain();
			int port = listenerToCreate->port();
			std::unique_ptr<ListenerDns> listenerDns = make_unique<ListenerDns>(domain, port);
			m_listeners.push_back(std::move(listenerDns));

			BOOST_LOG_TRIVIAL(info) << "AddListener Dns " << domain << ":" << std::to_string(port);
		}

	}
	catch (const std::exception &exc)
	{
		BOOST_LOG_TRIVIAL(error) << "Error: " << exc.what() << std::endl;
	}

	return grpc::Status::OK;
}


grpc::Status TeamServer::StopListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToStop,  teamserverapi::Response* response)
{
	BOOST_LOG_TRIVIAL(trace) << "StopListener";

	// Stop primary listener
	std::string listenerHash=listenerToStop->listenerhash();

	std::vector<unique_ptr<Listener>>::iterator object = 
		find_if(m_listeners.begin(), m_listeners.end(),
				[&](unique_ptr<Listener> & obj){ return obj->getListenerHash() == listenerHash;}
				);

	if(object!=m_listeners.end())
	{
		m_listeners.erase(std::remove(m_listeners.begin(), m_listeners.end(), *object));
		std::move(*object);
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

	return grpc::Status::OK;
}


bool TeamServer::isListenerAlive(std::string listenerHash)
{
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

	return result;
}


// Get the list of sessions on the primary listeners
// Primary listers old all the information about beacons linked to themeself and linked to beacon listerners
grpc::Status TeamServer::GetSessions(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer)
{
	BOOST_LOG_TRIVIAL(trace) << "GetSessions";

	for (int i = 0; i < m_listeners.size(); i++)
	{
		BOOST_LOG_TRIVIAL(trace) << "Listener " << m_listeners[i]->getListenerHash();

		int nbSession = m_listeners[i]->getNumberOfSession();
		for(int kk=0; kk<nbSession; kk++)
		{
			std::shared_ptr<Session> session = m_listeners[i]->getSessionPtr(kk);

			BOOST_LOG_TRIVIAL(trace) << "	Session " << session->getBeaconHash() << " From " << session->getListenerHash() << " " << session->getLastProofOfLife();

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

	return grpc::Status::OK;
}


grpc::Status TeamServer::StopSession(grpc::ServerContext* context, const teamserverapi::Session* sessionToStop,  teamserverapi::Response* response)
{
	BOOST_LOG_TRIVIAL(trace) << "StopSession";

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

	return grpc::Status::OK;
}


grpc::Status TeamServer::SendCmdToSession(grpc::ServerContext* context, const teamserverapi::Command* command,  teamserverapi::Response* response)
{
	BOOST_LOG_TRIVIAL(trace) << "SendCmdToSession";

	std::string input = command->cmd();
	std::string beaconHash = command->beaconhash();
	std::string listenerHash = command->listenerhash();
	
	for (int i = 0; i < m_listeners.size(); i++)
	{
		if (m_listeners[i]->isSessionExist(beaconHash, listenerHash))
		{
			BOOST_LOG_TRIVIAL(trace) << "SendCmdToSession: beaconHash " << beaconHash << " listenerHash " << listenerHash;
			if (!input.empty())
			{
				C2Message c2Message;
				int res = prepMsg(input, c2Message);

				BOOST_LOG_TRIVIAL(debug) << "SendCmdToSession " << beaconHash << " " << c2Message.instruction() << " " << c2Message.cmd();

				// echec init message
				if(res!=0)
				{
					std::string hint = c2Message.returnvalue();

					response->set_message(hint);
					response->set_status(teamserverapi::KO);

					BOOST_LOG_TRIVIAL(debug) << "SendCmdToSession Fail prepMsg " << hint;
				}

				if(!c2Message.instruction().empty())
					m_listeners[i]->queueTask(beaconHash, c2Message);
			}
		}
	}

	return grpc::Status::OK;
}


// TODO how do the followUp necessary for download
grpc::Status TeamServer::GetResponseFromSession(grpc::ServerContext* context, const teamserverapi::Session* session,  grpc::ServerWriter<teamserverapi::CommandResponse>* writer)
{
	BOOST_LOG_TRIVIAL(trace) << "GetResponseFromSession";

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
					for(auto it = m_moduleCmd.begin() ; it != m_moduleCmd.end(); ++it )
					{
						if (instruction == (*it)->getName())
						{
							BOOST_LOG_TRIVIAL(debug) << "Call followUp";

							// TODO to put in a separate thread
							(*it)->followUp(c2Message);
						}
					}

					if(instruction==ListenerPolCmd)
					{
						BOOST_LOG_TRIVIAL(debug) << "beaconHash " << beaconHash;
						BOOST_LOG_TRIVIAL(debug) << "returnvalue " << c2Message.returnvalue();
						c2Message = m_listeners[i]->getTaskResult(beaconHash);
						continue;
					}
					
					teamserverapi::CommandResponse commandResponseTmp;
					commandResponseTmp.set_beaconhash(beaconHash);
					commandResponseTmp.set_instruction(c2Message.instruction());
					commandResponseTmp.set_cmd(c2Message.cmd());
					commandResponseTmp.set_response(c2Message.returnvalue());

					BOOST_LOG_TRIVIAL(debug) << "GetResponseFromSession " 
					<< beaconHash << " " 
					<< c2Message.instruction() << " " 
					<< c2Message.cmd();

					writer->Write(commandResponseTmp);

					c2Message = m_listeners[i]->getTaskResult(beaconHash);
				}
			}
		}
	}

	return grpc::Status::OK;
}


grpc::Status TeamServer::GetHelp(grpc::ServerContext* context, const teamserverapi::Command* command,  teamserverapi::CommandResponse* commandResponse)
{
	BOOST_LOG_TRIVIAL(trace) << "GetHelp";

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


int TeamServer::prepMsg(std::string& input, C2Message& c2Message)
{
	BOOST_LOG_TRIVIAL(trace) << "prepMsg";

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
		BOOST_LOG_TRIVIAL(warning) << "Module " << instruction << " not found.";
	}

	return res;
}




int main(int argc, char* argv[])
{
	std::ifstream f("TeamServerConfig.json");
	json config = json::parse(f);

	std::string logLevel = config["LogLevel"].get<std::string>();
	logging::trivial::severity_level sev = logging::trivial::trace;
	if(logLevel=="trace")
		sev = logging::trivial::trace;
	else if(logLevel=="debug")
		sev = logging::trivial::debug;
	else if(logLevel=="info")
		sev = logging::trivial::info;
	else if(logLevel=="warning")
		sev = logging::trivial::warning;
	else if(logLevel=="error")
		sev = logging::trivial::error;
	else if(logLevel=="fatal")
		sev = logging::trivial::fatal;

	logging::core::get()->set_filter
    (		
		logging::trivial::severity >= sev
    );
	
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
		BOOST_LOG_TRIVIAL(fatal) << "Server ceritifcat file not found.";
		return -1;
	}
	std::string cert(std::istreambuf_iterator<char>(servCrtFile), {});

	std::string servKeyFilePath = config["ServKeyFile"].get<std::string>();
	std::ifstream servKeyFile(servKeyFilePath, std::ios::binary);
	if(!servKeyFile.good())
	{
		BOOST_LOG_TRIVIAL(fatal) << "Server key file not found.";
		return -1;
	}
	std::string key(std::istreambuf_iterator<char>(servKeyFile), {});

	std::string rootCA = config["RootCA"].get<std::string>();
	std::ifstream rootFile(rootCA, std::ios::binary);
	if(!rootFile.good())
	{
		BOOST_LOG_TRIVIAL(fatal) << "Root CA file not found.";
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

	BOOST_LOG_TRIVIAL(info) << "Team Server listening on " << serverAddress;

	server->Wait();
}

