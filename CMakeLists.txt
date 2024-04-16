cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)

project(C2TeamServer VERSION 0.0.0 LANGUAGES CXX C)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 17)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
	file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/master/conan.cmake" "${CMAKE_BINARY_DIR}/conan.cmake")
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_configure(REQUIRES protobuf/3.21.12 boost/1.84.0 openssl/3.2.1 zlib/1.3.1 grpc/1.54.3 GENERATORS CMakeDeps)

#conan_cmake_autodetect(settings)

conan_cmake_install(PATH_OR_REFERENCE .
                    BUILD never
                    SETTINGS ${settings})

set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

find_package(Boost REQUIRED)  
find_package(gRPC REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(protobuf REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(${CMAKE_INCLUDE_PATH})

include_directories(thirdParty/nlohmann/single_include/nlohmann)

add_subdirectory(libs)

add_subdirectory(thirdParty)
include_directories(thirdParty/base64)
include_directories(thirdParty/donut/include)
include_directories(thirdParty/coffLoader/coffLoader)
include_directories(thirdParty/coffLoader/coffPacker)
include_directories(thirdParty/cpp-httplib)

enable_testing()

add_subdirectory(teamServer)

#add_subdirectory(certs)

add_subdirectory(client)

add_subdirectory(core/modules)
add_subdirectory(core/beacon)
add_subdirectory(core/beacon/tests)
add_subdirectory(core/listener/tests)




