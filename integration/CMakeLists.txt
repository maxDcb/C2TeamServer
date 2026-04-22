find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(C2_INTEGRATION_RUNTIME_RELEASE_DIR "${C2_INTEGRATION_STAGING_DIR}/Release")

add_custom_target(stage_integration_runtime
  COMMAND ${CMAKE_COMMAND} -E rm -rf "${C2_INTEGRATION_STAGING_DIR}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${C2_INTEGRATION_RUNTIME_RELEASE_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${C2_RELEASE_STAGING_DIR}" "${C2_INTEGRATION_RUNTIME_RELEASE_DIR}"
  DEPENDS stage_release_bundle
  COMMENT "Preparing integration runtime from staged release bundle"
  VERBATIM
)

add_executable(testsTeamServerRuntimeIntegration
  tests/TeamServerRuntimeIntegrationTests.cpp
)

target_compile_definitions(testsTeamServerRuntimeIntegration PRIVATE
  C2_INTEGRATION_STAGING_DIR="${C2_INTEGRATION_STAGING_DIR}"
)

if(WIN32)
  target_link_libraries(testsTeamServerRuntimeIntegration
    GrpcMessages
    gRPC::grpc++
    protobuf::libprotobuf
    nlohmann_json::nlohmann_json
  )
else()
  target_link_libraries(testsTeamServerRuntimeIntegration
    GrpcMessages
    gRPC::grpc++
    protobuf::libprotobuf
    nlohmann_json::nlohmann_json
    pthread
  )
endif()

add_dependencies(testsTeamServerRuntimeIntegration stage_integration_runtime)

add_custom_command(TARGET testsTeamServerRuntimeIntegration POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
  $<TARGET_FILE:testsTeamServerRuntimeIntegration> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerRuntimeIntegration>")

add_test(NAME testsTeamServerRuntimeIntegration COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTeamServerRuntimeIntegration>")
