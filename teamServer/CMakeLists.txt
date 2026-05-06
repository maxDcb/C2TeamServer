include_directories(../core)
include_directories(../core/modules/ModuleCmd)

set(TEAMSERVER_CORE_SOURCES
    teamServer/TeamServer.cpp
    teamServer/TeamServerAssemblyExecCommandPreparer.cpp
    teamServer/TeamServerArtifactCatalog.cpp
    teamServer/TeamServerArtifactService.cpp
    teamServer/TeamServerAuth.cpp
    teamServer/TeamServerChiselCommandPreparer.cpp
    teamServer/TeamServerCommandCatalog.cpp
    teamServer/TeamServerCommandCatalogService.cpp
    teamServer/TeamServerCommandPreparationService.cpp
    teamServer/TeamServerFileArtifactService.cpp
    teamServer/TeamServerFileTransferCommandPreparer.cpp
    teamServer/TeamServerGeneratedArtifactStore.cpp
    teamServer/TeamServerHelpService.cpp
    teamServer/TeamServerInjectCommandPreparer.cpp
    teamServer/TeamServerListenerArtifactService.cpp
    teamServer/TeamServerModuleLoader.cpp
    teamServer/TeamServerMiniDumpCommandPreparer.cpp
    teamServer/TeamServerScriptCommandPreparer.cpp
    teamServer/TeamServerShellcodeService.cpp
    teamServer/TeamServerSocksService.cpp
    teamServer/TeamServerTermLocalService.cpp
    teamServer/TeamServerRuntimeConfig.cpp
    teamServer/TeamServerBootstrap.cpp
    teamServer/TeamServerListenerSessionService.cpp
)

set(SERVER_LISTENER_TRANSPORT_SOURCES
    ../core/listener/Listener.cpp
    ../core/listener/ListenerTcp.cpp
    ../core/listener/ListenerHttp.cpp
    ../core/listener/ListenerGithub.cpp
    ../core/listener/ListenerDns.cpp
)

set(SERVER_LISTENER_TRANSPORT_LINK_LIBS
    Dnscommunication
    SocketHandler
    openssl::openssl
    spdlog::spdlog
    httplib::httplib
    pthread
    dl
    rt
)

set(TEAMSERVER_CORE_LINK_LIBS
    GrpcMessages
    pthread
    openssl::openssl
    ZLIB::ZLIB
    grpc::grpc
    spdlog::spdlog
    SocksServer
    Donut
    ${aplib64}
    dl
    rt
)

add_library(server_listener_transport STATIC ${SERVER_LISTENER_TRANSPORT_SOURCES})
target_include_directories(server_listener_transport
    PUBLIC
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/core/listener
        ${CMAKE_SOURCE_DIR}/core/modules/ModuleCmd
)
target_link_libraries(server_listener_transport
    PUBLIC
        ${SERVER_LISTENER_TRANSPORT_LINK_LIBS}
    PRIVATE
        c2_base64
)

add_library(server_core STATIC ${TEAMSERVER_CORE_SOURCES})
target_include_directories(server_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/teamServer
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/core/modules/ModuleCmd
)
target_link_libraries(server_core
    PUBLIC
        server_listener_transport
        ${TEAMSERVER_CORE_LINK_LIBS}
)

add_executable(TeamServer teamServer/main.cpp)
target_link_libraries(TeamServer PRIVATE server_core)

set(C2_COMMON_COMMAND_SPEC_ROOT "${CMAKE_SOURCE_DIR}/core/modules/ModuleCmd/CommandSpecs")
file(GLOB_RECURSE C2_COMMON_COMMAND_SPEC_FILES CONFIGURE_DEPENDS
    "${C2_COMMON_COMMAND_SPEC_ROOT}/*.json")
file(GLOB C2_MODULE_COMMAND_SPEC_FILES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/core/modules/*/*.json")
set(C2_COPY_MODULE_COMMAND_SPEC_COMMANDS)
foreach(C2_MODULE_COMMAND_SPEC_FILE IN LISTS C2_MODULE_COMMAND_SPEC_FILES)
    get_filename_component(C2_MODULE_COMMAND_SPEC_NAME "${C2_MODULE_COMMAND_SPEC_FILE}" NAME)
    list(APPEND C2_COPY_MODULE_COMMAND_SPEC_COMMANDS
        COMMAND ${CMAKE_COMMAND} -E copy
            "${C2_MODULE_COMMAND_SPEC_FILE}" "${C2_RUNTIME_ROOT}/CommandSpecs/modules/${C2_MODULE_COMMAND_SPEC_NAME}")
endforeach()
add_custom_target(teamserver_copy_command_specs
    COMMAND ${CMAKE_COMMAND} -E make_directory "${C2_RUNTIME_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${C2_RUNTIME_ROOT}/CommandSpecs"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${C2_COMMON_COMMAND_SPEC_ROOT}" "${C2_RUNTIME_ROOT}/CommandSpecs"
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${C2_RUNTIME_ROOT}/CommandSpecs/modules"
    ${C2_COPY_MODULE_COMMAND_SPEC_COMMANDS}
    DEPENDS ${C2_COMMON_COMMAND_SPEC_FILES} ${C2_MODULE_COMMAND_SPEC_FILES}
    VERBATIM
)
add_dependencies(TeamServer teamserver_copy_command_specs)

add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:TeamServer> "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/$<TARGET_FILE_NAME:TeamServer>")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/teamServer/teamServer/TeamServerConfig.json "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/TeamServerConfig.json")
add_custom_command(TARGET TeamServer POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/teamServer/teamServer/auth_credentials.json "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/auth_credentials.json")

function(teamserver_add_test target_name link_target)
    add_executable(${target_name} ${ARGN})
    target_link_libraries(${target_name} PRIVATE ${link_target})
    add_custom_command(TARGET ${target_name} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:${target_name}> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:${target_name}>")
    add_test(NAME ${target_name} COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:${target_name}>")
endfunction()

if(WITH_TESTS)
    teamserver_add_test(testsTestServer
        server_core
        tests/testsTestServer.cpp
    )

    teamserver_add_test(testsTeamServerHelpService
        server_core
        tests/TeamServerHelpServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerCommandPreparationService
        server_core
        tests/TeamServerCommandPreparationServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerListenerArtifactService
        server_core
        tests/TeamServerListenerArtifactServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerArtifactCatalog
        server_core
        tests/TeamServerArtifactCatalogTests.cpp
    )

    teamserver_add_test(testsTeamServerCommandCatalog
        server_core
        tests/TeamServerCommandCatalogTests.cpp
    )

    teamserver_add_test(testsTeamServerSocksService
        server_core
        tests/TeamServerSocksServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerTermLocalService
        server_core
        tests/TeamServerTermLocalServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerListenerSessionService
        server_core
        tests/TeamServerListenerSessionServiceTests.cpp
    )

    teamserver_add_test(testsTeamServerHttpListenerTransport
        server_listener_transport
        tests/TeamServerHttpListenerTransportTests.cpp
    )
endif()
