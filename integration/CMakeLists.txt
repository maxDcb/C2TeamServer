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

set(C2_JOB_TEST_PYTHON "" CACHE FILEPATH "Python interpreter with grpcio for the job end-to-end test")
if(NOT C2_JOB_TEST_PYTHON)
  if(EXISTS "${CMAKE_SOURCE_DIR}/C2Client/.venv/bin/python")
    set(C2_JOB_TEST_PYTHON "${CMAKE_SOURCE_DIR}/C2Client/.venv/bin/python")
  else()
    set(C2_JOB_TEST_PYTHON "${Python3_EXECUTABLE}")
  endif()
endif()
add_test(NAME testsJobRuntimeE2E
  COMMAND "${C2_JOB_TEST_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/JobRuntimeE2E.py"
    --runtime "${C2_INTEGRATION_RUNTIME_RELEASE_DIR}" --client-python "${C2_JOB_TEST_PYTHON}")
set_tests_properties(testsJobRuntimeE2E PROPERTIES DEPENDS testsTeamServerRuntimeIntegration TIMEOUT 120)

add_test(NAME testsInstalledRuntimeE2E
  COMMAND "${C2_JOB_TEST_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/InstalledRuntimeE2E.py"
    --release-root "${C2_INTEGRATION_RUNTIME_RELEASE_DIR}"
    --installer "${CMAKE_SOURCE_DIR}/packaging/exploration_install.py")
set_tests_properties(testsInstalledRuntimeE2E PROPERTIES DEPENDS testsTeamServerRuntimeIntegration TIMEOUT 120)
