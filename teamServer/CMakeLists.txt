
include_directories(../core)
include_directories(../core/modules/ModuleCmd)

set(SOURCES_TEAMSERVER
	teamServer/TeamServer.cpp
	../core/listener/Listener.cpp
	../core/listener/ListenerTcp.cpp	
	../core/listener/ListenerHttp.cpp
	../core/listener/ListenerGithub.cpp
	../core/listener/ListenerDns.cpp

	../../thirdParty/base64/base64.cpp

	../core/modules/AssemblyExec/AssemblyExec.cpp
	../core/modules/Upload/Upload.cpp
	../core/modules/Run/Run.cpp
	../core/modules/Script/Script.cpp
	../core/modules/Inject/Inject.cpp
	../core/modules/Download/Download.cpp
	../core/modules/PrintWorkingDirectory/PrintWorkingDirectory.cpp
	../core/modules/ChangeDirectory/ChangeDirectory.cpp
	../core/modules/ListDirectory/ListDirectory.cpp
	../core/modules/ListProcesses/ListProcesses.cpp
	../core/modules/MakeToken/MakeToken.cpp
	../core/modules/Rev2self/Rev2self.cpp
	../core/modules/StealToken/StealToken.cpp
	../core/modules/CoffLoader/CoffLoader.cpp
	../core/modules/KerberosUseTicket/KerberosUseTicket.cpp
	../core/modules/Powershell/Powershell.cpp
	../core/modules/PsExec/PsExec.cpp
	../core/modules/Chisel/Chisel.cpp
	../core/modules/SpawnAs/SpawnAs.cpp
	../core/modules/Evasion/Evasion.cpp
	../core/modules/Cat/Cat.cpp
	../core/modules/Tree/Tree.cpp
	../core/modules/WmiExec/WmiExec.cpp
)

## TeamServer
add_executable(TeamServer ${SOURCES_TEAMSERVER})
if(WIN32)
	target_link_libraries(TeamServer boost::boost Dnscommunication SocketHandler GrpcMessages ${Donut} CoffLoader CoffPacker openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(TeamServer boost::boost Dnscommunication SocketHandler GrpcMessages ${Donut} ${aplib64} pthread CoffLoader CoffPacker openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog nlohmann_json::nlohmann_json httplib::httplib)
endif()
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:TeamServer> "${CMAKE_SOURCE_DIR}/Release/TeamServer/$<TARGET_FILE_NAME:TeamServer>")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
${CMAKE_SOURCE_DIR}/teamServer/teamServer/TeamServerConfig.json "${CMAKE_SOURCE_DIR}/Release/TeamServer/TeamServerConfig.json")

if(WITH_TESTS)
add_executable(testsTestServer tests/testsTestServer.cpp )
target_link_libraries(testsTestServer boost::boost )

add_custom_command(TARGET testsTestServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsTestServer> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTestServer>")

add_test(NAME testsTestServer COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTestServer>")
endif()