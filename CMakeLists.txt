cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)

project(C2TeamServer VERSION 0.0.0 LANGUAGES CXX C)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 17)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
	file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/master/conan.cmake" "${CMAKE_BINARY_DIR}/conan.cmake")
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)
conan_cmake_run(SETTINGS REQUIRES protobuf/3.21.4 boost/1.79.0 openssl/3.0.0 zlib/1.2.12 grpc/1.50.1 BASIC_SETUP CMAKE_TARGETS BUILD missing CONFIGURATION_TYPES "Release;" OPTIONS *:shared=False)

find_package(Protobuf REQUIRED)
include_directories(${CMAKE_INCLUDE_PATH})
Set(Boost_INSTALL_DIR ${CONAN_BOOST_ROOT})
find_package(Boost REQUIRED)
find_package(ZLIB REQUIRED)

add_subdirectory(libs)

add_subdirectory(thirdParty)
include_directories(thirdParty/nlohmann/single_include/nlohmann)
include_directories(thirdParty/base64)
include_directories(thirdParty/donut/include)
include_directories(thirdParty/coffLoader/coffLoader)
include_directories(thirdParty/coffLoader/coffPacker)
include_directories(thirdParty/cpp-httplib)

add_subdirectory(teamServer)

add_subdirectory(certs)

add_subdirectory(client)

