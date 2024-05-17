#include "listener/ListenerTcp.hpp"
#include "listener/ListenerHttp.hpp"
#include "listener/ListenerGithub.hpp"
#include "listener/ListenerDns.hpp"

#include "modules/AssemblyExec/AssemblyExec.hpp"
#include "modules/Upload/Upload.hpp"
#include "modules/Download/Download.hpp"
#include "modules/Run/Run.hpp"
#include "modules/Script/Script.hpp"
#include "modules/Inject/Inject.hpp"
#include "modules/PrintWorkingDirectory/PrintWorkingDirectory.hpp"
#include "modules/ChangeDirectory/ChangeDirectory.hpp"
#include "modules/ListDirectory/ListDirectory.hpp"
#include "modules/ListProcesses/ListProcesses.hpp"
#include "modules/MakeToken/MakeToken.hpp"
#include "modules/Rev2self/Rev2self.hpp"
#include "modules/StealToken/StealToken.hpp"
#include "modules/CoffLoader/CoffLoader.hpp"
#include "modules/KerberosUseTicket/KerberosUseTicket.hpp"
#include "modules/Powershell/Powershell.hpp"
#include "modules/PsExec/PsExec.hpp"
#include "modules/Chisel/Chisel.hpp"
#include "modules/SpawnAs/SpawnAs.hpp"
#include "modules/Evasion/Evasion.hpp"
#include "modules/Cat/Cat.hpp"
#include "modules/Tree/Tree.hpp"
#include "modules/WmiExec/WmiExec.hpp"

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "TeamServerApi.pb.h"
#include "TeamServerApi.grpc.pb.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "nlohmann/json.hpp"


class TeamServer final : public teamserverapi::TeamServerApi::Service 
{

public:
	explicit TeamServer(const nlohmann::json& config);
	~TeamServer();

    grpc::Status GetListeners(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Listener>* writer);
    grpc::Status AddListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToCreate,  teamserverapi::Response* response);
    grpc::Status StopListener(grpc::ServerContext* context, const teamserverapi::Listener* listenerToStop,  teamserverapi::Response* response);
    
    grpc::Status GetSessions(grpc::ServerContext* context, const teamserverapi::Empty* empty, grpc::ServerWriter<teamserverapi::Session>* writer);
    grpc::Status StopSession(grpc::ServerContext* context, const teamserverapi::Session* sessionToStop,  teamserverapi::Response* response);

    grpc::Status SendCmdToSession(grpc::ServerContext* context, const teamserverapi::Command* command,  teamserverapi::Response* response);
    grpc::Status GetResponseFromSession(grpc::ServerContext* context, const teamserverapi::Session* session,  grpc::ServerWriter<teamserverapi::CommandResponse>* writer);

    grpc::Status GetHelp(grpc::ServerContext* context, const teamserverapi::Command* command,  teamserverapi::CommandResponse* commandResponse);

protected:
    bool isListenerAlive(std::string listenerHash);
    int prepMsg(std::string& input, C2Message& c2Message);

private:
    nlohmann::json m_config;

    std::shared_ptr<spdlog::logger> m_logger;

    std::vector<std::unique_ptr<Listener>> m_listeners;
    std::vector<std::unique_ptr<ModuleCmd>> m_moduleCmd;
    CommonCommands m_commonCommands;
};