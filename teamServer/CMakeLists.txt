
include_directories(../core)
include_directories(../core/modules/ModuleCmd)

set(SOURCES_TEAMSERVER
teamServer/TeamServer.cpp
teamServer/TeamServerAuth.cpp
teamServer/TeamServerRuntimeConfig.cpp
teamServer/TeamServerBootstrap.cpp
teamServer/main.cpp
../core/listener/Listener.cpp
../core/listener/ListenerTcp.cpp	
../core/listener/ListenerHttp.cpp
../core/listener/ListenerGithub.cpp
../core/listener/ListenerDns.cpp
../../thirdParty/base64/base64.cpp
)

## TeamServer
add_executable(TeamServer ${SOURCES_TEAMSERVER})
if(WIN32)
	target_link_libraries(TeamServer Dnscommunication SocketHandler GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog SocksServer)
else()
	target_link_libraries(TeamServer Dnscommunication SocketHandler GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib SocksServer Crow::Crow dl rt)
endif()

add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:TeamServer> "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/$<TARGET_FILE_NAME:TeamServer>")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
${CMAKE_SOURCE_DIR}/teamServer/teamServer/TeamServerConfig.json "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/TeamServerConfig.json")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
${CMAKE_SOURCE_DIR}/teamServer/teamServer/auth_credentials.json "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/auth_credentials.json")

if(WITH_TESTS)
	add_executable(testsTestServer
		tests/testsTestServer.cpp
		teamServer/TeamServerAuth.cpp
		teamServer/TeamServerRuntimeConfig.cpp
		teamServer/TeamServerBootstrap.cpp
	)
	target_include_directories(testsTestServer PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
		${CMAKE_SOURCE_DIR}/libs/libSocks5/src
	)
	if(WIN32)
		target_link_libraries(testsTestServer GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTestServer GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib Crow::Crow dl rt)
	endif()

	add_custom_command(TARGET testsTestServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTestServer> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTestServer>")

	add_test(NAME testsTestServer COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTestServer>")
endif()
