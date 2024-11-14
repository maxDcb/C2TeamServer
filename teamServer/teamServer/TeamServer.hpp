#include "listener/ListenerTcp.hpp"
#include "listener/ListenerHttp.hpp"
#include "listener/ListenerGithub.hpp"
#include "listener/ListenerDns.hpp"

#include "modules/ModuleCmd/ModuleCmd.hpp"

#include "SocksServer.hpp"

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

    grpc::Status SendTermCmd(grpc::ServerContext* context, const teamserverapi::TermCommand* command,  teamserverapi::TermCommand* response);
    
protected:
    bool isListenerAlive(const std::string& listenerHash);
    int prepMsg(const std::string& input, C2Message& c2Message, bool isWindows=true);

private:
    bool m_isSocksServerRunning;
    void runSocksServer(int port, const std::string& listenerHash, const std::string& beaconHash);

    nlohmann::json m_config;

    std::shared_ptr<spdlog::logger> m_logger;

    std::vector<std::shared_ptr<Listener>> m_listeners;
    std::vector<std::unique_ptr<ModuleCmd>> m_moduleCmd;
    CommonCommands m_commonCommands;

    std::string m_teamServerModulesDirectoryPath;
    std::string m_linuxModulesDirectoryPath;
    std::string m_windowsModulesDirectoryPath;
    std::string m_linuxBeaconsDirectoryPath;
    std::string m_windowsBeaconsDirectoryPath;
    std::string m_toolsDirectoryPath;
    std::string m_scriptsDirectoryPath;
};
