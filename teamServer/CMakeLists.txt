include_directories(../core)
include_directories(../core/modules/ModuleCmd)

set(TEAMSERVER_CORE_SOURCES
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
    ../core/listener/Listener.cpp
    ../core/listener/ListenerTcp.cpp
    ../core/listener/ListenerHttp.cpp
    ../core/listener/ListenerGithub.cpp
    ../core/listener/ListenerDns.cpp
)

set(TEAMSERVER_COMMON_LINK_LIBS
    Dnscommunication
    SocketHandler
    GrpcMessages
    pthread
    openssl::openssl
    ZLIB::ZLIB
    grpc::grpc
    spdlog::spdlog
    httplib::httplib
    SocksServer
    dl
    rt
)

add_library(server_core STATIC ${TEAMSERVER_CORE_SOURCES})
target_include_directories(server_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/teamServer
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/core/listener
        ${CMAKE_SOURCE_DIR}/core/modules/ModuleCmd
)
target_link_libraries(server_core
    PUBLIC
        ${TEAMSERVER_COMMON_LINK_LIBS}
    PRIVATE
        c2_base64
)

add_executable(TeamServer teamServer/main.cpp)
target_link_libraries(TeamServer PRIVATE server_core)

add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:TeamServer> "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/$<TARGET_FILE_NAME:TeamServer>")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/teamServer/teamServer/TeamServerConfig.json "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/TeamServerConfig.json")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/teamServer/teamServer/auth_credentials.json "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/auth_credentials.json")

function(teamserver_add_test target_name)
    add_executable(${target_name} ${ARGN})
    target_link_libraries(${target_name} PRIVATE server_core)
    add_custom_command(TARGET ${target_name} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:${target_name}> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:${target_name}>")
    add_test(NAME ${target_name} COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:${target_name}>")
endfunction()

if(WITH_TESTS)
    teamserver_add_test(testsTestServer
        tests/testsTestServer.cpp
    )

    teamserver_add_test(testsTeamServerHelpService
        tests/TeamServerHelpServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerCommandPreparationService
        tests/TeamServerCommandPreparationServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerListenerArtifactService
        tests/TeamServerListenerArtifactServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerSocksService
        tests/TeamServerSocksServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerTermLocalService
        tests/TeamServerTermLocalServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerListenerSessionService
        tests/TeamServerListenerSessionServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerHttpListenerTransport
        tests/TeamServerHttpListenerTransportTests.cpp
    )
endif()
