cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)

project(C2TeamServer VERSION 0.0.0 LANGUAGES CXX C)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 20)


##
## Conan Dependencies
##


set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

find_package(Boost REQUIRED)  
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

add_definitions(-DBUILD_TEAMSERVER)
if(WITH_TESTS)
  add_definitions(-DBUILD_TESTS)
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
include_directories(thirdParty/coffLoader/coffLoader)
include_directories(thirdParty/coffLoader/coffPacker)

if(WITH_TESTS)
    enable_testing()
endif()

add_subdirectory(teamServer)

add_subdirectory(certs)

add_subdirectory(client)

if(WITH_TESTS)
    add_subdirectory(core/modules)
    add_subdirectory(core/beacon)
    add_subdirectory(core/beacon/tests)
    add_subdirectory(core/listener/tests)
endif()




