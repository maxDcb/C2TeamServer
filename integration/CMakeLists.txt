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

# A Linux implant checkout can supply the two binaries needed for a real
# TeamServer -> parent beacon -> child beacon integration run.
set(C2_LINUX_BEACON_BINARY "" CACHE FILEPATH "Linux BeaconTcp binary for beacon flow E2E")
set(C2_LINUX_RPF_MODULE "" CACHE FILEPATH "Linux reverse port forward module for beacon flow E2E")
set(C2_BEACON_FLOW_THRESHOLDS "" CACHE FILEPATH "Optional JSON performance limits for beacon flow E2E")
if(NOT C2_LINUX_BEACON_BINARY AND EXISTS "${CMAKE_SOURCE_DIR}/../C2LinuxImplant/Release/Beacons/BeaconTcp")
  set(C2_LINUX_BEACON_BINARY "${CMAKE_SOURCE_DIR}/../C2LinuxImplant/Release/Beacons/BeaconTcp")
endif()
if(NOT C2_LINUX_RPF_MODULE AND EXISTS "${CMAKE_SOURCE_DIR}/../C2LinuxImplant/Release/Modules/libReversePortForward.so")
  set(C2_LINUX_RPF_MODULE "${CMAKE_SOURCE_DIR}/../C2LinuxImplant/Release/Modules/libReversePortForward.so")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND EXISTS "${C2_LINUX_BEACON_BINARY}" AND EXISTS "${C2_LINUX_RPF_MODULE}")
  set(C2_BEACON_FLOW_THRESHOLD_ARGS "")
  if(C2_BEACON_FLOW_THRESHOLDS)
    set(C2_BEACON_FLOW_THRESHOLD_ARGS --thresholds "${C2_BEACON_FLOW_THRESHOLDS}")
  endif()
  add_test(NAME testsLinuxBeaconFlowE2E
    COMMAND "${C2_JOB_TEST_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/BeaconFlowE2E.py"
      --runtime "${C2_INTEGRATION_RUNTIME_RELEASE_DIR}"
      --linux-beacon "${C2_LINUX_BEACON_BINARY}"
      --linux-module "${C2_LINUX_RPF_MODULE}"
      --output "${CMAKE_BINARY_DIR}/beacon-flow-metrics.json"
      ${C2_BEACON_FLOW_THRESHOLD_ARGS})
  set_tests_properties(testsLinuxBeaconFlowE2E PROPERTIES
    DEPENDS testsTeamServerRuntimeIntegration TIMEOUT 240 RUN_SERIAL TRUE LABELS "integration;beacon-flow")
endif()
