
include_directories(../core)
include_directories(../core/modules/ModuleCmd)

set(SOURCES_TEAMSERVER
teamServer/TeamServer.cpp
teamServer/TeamServerAuth.cpp
teamServer/TeamServerCommandPreparationService.cpp
teamServer/TeamServerHelpService.cpp
teamServer/TeamServerListenerArtifactService.cpp
teamServer/TeamServerModuleLoader.cpp
teamServer/TeamServerSocksService.cpp
teamServer/TeamServerTermLocalService.cpp
teamServer/TeamServerRuntimeConfig.cpp
teamServer/TeamServerBootstrap.cpp
teamServer/TeamServerListenerSessionService.cpp
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
	target_link_libraries(TeamServer Dnscommunication SocketHandler GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib SocksServer dl rt)
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
		teamServer/TeamServerHelpService.cpp
		teamServer/TeamServerRuntimeConfig.cpp
		teamServer/TeamServerBootstrap.cpp
		../core/listener/Listener.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTestServer PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
		${CMAKE_SOURCE_DIR}/libs/libSocks5/src
	)
	if(WIN32)
		target_link_libraries(testsTestServer GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTestServer GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTestServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTestServer> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTestServer>")

	add_test(NAME testsTestServer COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTestServer>")

	add_executable(testsTeamServerHelpService
		tests/TeamServerHelpServiceTests.cpp
		teamServer/TeamServerHelpService.cpp
		../core/listener/Listener.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerHelpService PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
	)
	if(WIN32)
		target_link_libraries(testsTeamServerHelpService GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTeamServerHelpService GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerHelpService POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerHelpService> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerHelpService>")

	add_test(NAME testsTeamServerHelpService COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerHelpService>")

	add_executable(testsTeamServerCommandPreparationService
		tests/TeamServerCommandPreparationServiceTests.cpp
		teamServer/TeamServerCommandPreparationService.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerCommandPreparationService PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
	)
	if(WIN32)
		target_link_libraries(testsTeamServerCommandPreparationService GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTeamServerCommandPreparationService GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerCommandPreparationService POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerCommandPreparationService> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerCommandPreparationService>")

	add_test(NAME testsTeamServerCommandPreparationService COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerCommandPreparationService>")

	add_executable(testsTeamServerListenerArtifactService
		tests/TeamServerListenerArtifactServiceTests.cpp
		teamServer/TeamServerListenerArtifactService.cpp
		../core/listener/Listener.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerListenerArtifactService PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
	)
	if(WIN32)
		target_link_libraries(testsTeamServerListenerArtifactService GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTeamServerListenerArtifactService GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerListenerArtifactService POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerListenerArtifactService> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerListenerArtifactService>")

	add_test(NAME testsTeamServerListenerArtifactService COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerListenerArtifactService>")

	add_executable(testsTeamServerSocksService
		tests/TeamServerSocksServiceTests.cpp
		teamServer/TeamServerSocksService.cpp
		../core/listener/Listener.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerSocksService PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
		${CMAKE_SOURCE_DIR}/libs/libSocks5/src
	)
	if(WIN32)
		target_link_libraries(testsTeamServerSocksService GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog SocksServer)
	else()
		target_link_libraries(testsTeamServerSocksService GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib SocksServer dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerSocksService POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerSocksService> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerSocksService>")

	add_test(NAME testsTeamServerSocksService COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerSocksService>")

	add_executable(testsTeamServerTermLocalService
		tests/TeamServerTermLocalServiceTests.cpp
		teamServer/TeamServerModuleLoader.cpp
		teamServer/TeamServerTermLocalService.cpp
		teamServer/TeamServerRuntimeConfig.cpp
		../core/listener/Listener.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerTermLocalService PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
	)
	if(WIN32)
		target_link_libraries(testsTeamServerTermLocalService GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTeamServerTermLocalService GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerTermLocalService POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerTermLocalService> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerTermLocalService>")

	add_test(NAME testsTeamServerTermLocalService COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerTermLocalService>")

	add_executable(testsTeamServerListenerSessionService
		tests/TeamServerListenerSessionServiceTests.cpp
		teamServer/TeamServerListenerSessionService.cpp
		../core/listener/Listener.cpp
		../core/listener/ListenerTcp.cpp
		../core/listener/ListenerHttp.cpp
		../core/listener/ListenerGithub.cpp
		../core/listener/ListenerDns.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerListenerSessionService PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/teamServer
		${CMAKE_SOURCE_DIR}/libs/libSocks5/src
		${CMAKE_SOURCE_DIR}/libs/libSocketHandler/src
		${CMAKE_SOURCE_DIR}/libs/libDns/src
	)
	if(WIN32)
		target_link_libraries(testsTeamServerListenerSessionService Dnscommunication SocketHandler GrpcMessages openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB grpc::grpc spdlog::spdlog)
	else()
		target_link_libraries(testsTeamServerListenerSessionService Dnscommunication SocketHandler GrpcMessages pthread openssl::openssl ZLIB::ZLIB grpc::grpc spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerListenerSessionService POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerListenerSessionService> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerListenerSessionService>")

	add_test(NAME testsTeamServerListenerSessionService COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerListenerSessionService>")

	add_executable(testsTeamServerHttpListenerTransport
		tests/TeamServerHttpListenerTransportTests.cpp
		../core/listener/Listener.cpp
		../core/listener/ListenerHttp.cpp
		../../thirdParty/base64/base64.cpp
	)
	target_include_directories(testsTeamServerHttpListenerTransport PRIVATE
		${CMAKE_SOURCE_DIR}/core
		${CMAKE_SOURCE_DIR}/core/listener
	)
	if(WIN32)
		target_link_libraries(testsTeamServerHttpListenerTransport openssl::openssl ${OPENSSL_CRYPTO_LIBRARY} ZLIB::ZLIB spdlog::spdlog httplib::httplib)
	else()
		target_link_libraries(testsTeamServerHttpListenerTransport pthread openssl::openssl ZLIB::ZLIB spdlog::spdlog httplib::httplib dl rt)
	endif()

	add_custom_command(TARGET testsTeamServerHttpListenerTransport POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
	$<TARGET_FILE:testsTeamServerHttpListenerTransport> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerHttpListenerTransport>")

	add_test(NAME testsTeamServerHttpListenerTransport COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerHttpListenerTransport>")
endif()
