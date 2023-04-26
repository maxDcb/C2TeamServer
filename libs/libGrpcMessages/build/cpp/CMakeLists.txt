cmake_minimum_required(VERSION 3.5)
project(GrpcMessages)

set(DEFAULT_BUILD_TYPE "Release")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/src/*.pb.cc)

include_directories(
./src/
${Protobuf_INCLUDE_DIRS}
)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/src)

message(${CMAKE_CURRENT_BINARY_DIR}/src)
