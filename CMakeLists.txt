cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)

project(C2TeamServer VERSION 0.0.0 LANGUAGES CXX C)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

#
# Repository boundaries.
#
# The repository still keeps a few historical directory names (`teamServer`,
# `C2Client`) but the root build treats them as the long-term monorepo areas
# below so a future repo split stays mechanical.
#
set(C2_PROTOCOL_DIR "${CMAKE_SOURCE_DIR}/protocol")
set(C2_SERVER_DIR "${CMAKE_SOURCE_DIR}/teamServer")
set(C2_CLIENT_DIR "${CMAKE_SOURCE_DIR}/C2Client")
set(C2_CORE_DIR "${CMAKE_SOURCE_DIR}/core")
set(C2_PACKAGING_DIR "${CMAKE_SOURCE_DIR}/packaging")
set(C2_CERTS_DIR "${CMAKE_SOURCE_DIR}/certs")
set(C2_THIRDPARTY_DIR "${CMAKE_SOURCE_DIR}/thirdParty")
set(C2_LIBS_DIR "${CMAKE_SOURCE_DIR}/libs")
set(C2_INTEGRATION_DIR "${CMAKE_SOURCE_DIR}/integration")

set(C2_BUILD_ARTIFACT_ROOT "${CMAKE_BINARY_DIR}/artifacts")
set(C2_RUNTIME_ROOT "${C2_BUILD_ARTIFACT_ROOT}/Release")
set(C2_TEAMSERVER_RUNTIME_OUTPUT_DIR "${C2_RUNTIME_ROOT}/TeamServer")
set(C2_RUNTIME_MODULE_OUTPUT_DIR "${C2_RUNTIME_ROOT}/TeamServerModules")
set(C2_TEST_BIN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/tests/bin")
set(C2_GENERATED_PYTHON_GRPC_DIR "${CMAKE_BINARY_DIR}/generated/python_grpc")
set(C2_RELEASE_STAGING_ROOT "${CMAKE_BINARY_DIR}/release-staging")
set(C2_RELEASE_STAGING_DIR "${C2_RELEASE_STAGING_ROOT}/Release")
set(C2_INTEGRATION_STAGING_ROOT "${CMAKE_BINARY_DIR}/integration-staging")
set(C2_INTEGRATION_STAGING_DIR "${C2_INTEGRATION_STAGING_ROOT}/runtime")

file(MAKE_DIRECTORY
    "${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}"
    "${C2_RUNTIME_MODULE_OUTPUT_DIR}"
    "${C2_TEST_BIN_OUTPUT_DIR}"
    "${C2_GENERATED_PYTHON_GRPC_DIR}"
    "${C2_RELEASE_STAGING_DIR}"
    "${C2_INTEGRATION_STAGING_DIR}"
)


##
## Conan Dependencies
##

set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

unset(Protobuf_PROTOC_EXECUTABLE CACHE)
unset(GRPC_CPP_PLUGIN_PROGRAM CACHE)
unset(GRPC_PYTHON_PLUGIN_PROGRAM CACHE)

find_package(gRPC REQUIRED)
find_package(Libssh2 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(protobuf REQUIRED)
find_package(ZLIB REQUIRED)
find_package(spdlog REQUIRED)
find_package(httplib REQUIRED)
find_package(nlohmann_json REQUIRED)

include_directories(${CMAKE_INCLUDE_PATH})

get_target_property(C2_NLOHMANN_JSON_INCLUDE_DIRS nlohmann_json::nlohmann_json INTERFACE_INCLUDE_DIRECTORIES)
include_directories(${C2_NLOHMANN_JSON_INCLUDE_DIRS})


##
## Config Tests et Logs
##

option(WITH_TESTS "Compile for tests" ON)
set(C2CORE_BUILD_TESTS ${WITH_TESTS})

option(BUILD_TEAMSERVER "Enable Teamserver config" ON)
add_definitions(-DBUILD_TEAMSERVER)

if(WITH_TESTS)
  set(SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG)
endif()


##
## Build
##

add_subdirectory("${C2_LIBS_DIR}")
add_subdirectory("${C2_PROTOCOL_DIR}")

add_subdirectory("${C2_THIRDPARTY_DIR}")
include_directories("${C2_THIRDPARTY_DIR}/base64")
include_directories("${C2_THIRDPARTY_DIR}/donut/include")

set(DONUT_BUILD_DIR "${CMAKE_BINARY_DIR}/thirdParty/donut")
add_library(Donut STATIC IMPORTED)
set_target_properties(Donut PROPERTIES
IMPORTED_LOCATION "${DONUT_BUILD_DIR}/lib/libdonut.a"
)

if(WITH_TESTS)
    enable_testing()
endif()

include_directories("${C2_CORE_DIR}/listener")
include_directories("${C2_CORE_DIR}/beacon")
include_directories("${C2_CORE_DIR}/modules/ModuleCmd")

add_subdirectory("${C2_SERVER_DIR}")
add_subdirectory("${C2_CORE_DIR}/modules")

add_subdirectory("${C2_CERTS_DIR}")
add_subdirectory("${C2_PACKAGING_DIR}")

if(WITH_TESTS)
  add_subdirectory("${C2_INTEGRATION_DIR}")
endif()



