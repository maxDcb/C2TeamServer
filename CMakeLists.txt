cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)

project(C2TeamServer VERSION 0.0.0 LANGUAGES CXX C)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 17)


##
## Conan Dependencies
##

set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

find_package(gRPC REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(protobuf REQUIRED)
find_package(ZLIB REQUIRED)
find_package(spdlog REQUIRED)
find_package(httplib REQUIRED)

include_directories(${CMAKE_INCLUDE_PATH})


##
## Config Tests et Logs
##

option(WITH_TESTS "Compile for tests" ON)

option(BUILD_TEAMSERVER "Enable Teamserver config" ON)
add_definitions(-DBUILD_TEAMSERVER)

if(WITH_TESTS)
  set(SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG)
endif()


##
## Build
##

include_directories(thirdParty)

add_subdirectory(libs)

add_subdirectory(thirdParty)
include_directories(thirdParty/base64)
include_directories(thirdParty/donut/include)

set(DONUT_BUILD_DIR "${CMAKE_BINARY_DIR}/thirdParty/donut")
add_library(Donut STATIC IMPORTED)
set_target_properties(Donut PROPERTIES
IMPORTED_LOCATION "${DONUT_BUILD_DIR}/lib/libdonut.a"
)

if(WITH_TESTS)
    enable_testing()
endif()

include_directories(core/listener)
include_directories(core/beacon)
include_directories(core/modules/ModuleCmd)

add_subdirectory(teamServer)
add_subdirectory(core/modules)

add_subdirectory(certs)




