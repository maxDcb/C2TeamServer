cmake_minimum_required(VERSION 3.5)
project(SocketHandler VERSION 1.0.0 LANGUAGES CXX)

set(DEFAULT_BUILD_TYPE "Release")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_FILES
src/SocketHandler.cpp
)

include_directories(../src ${Boost_INCLUDE_DIRS})

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC src)

add_subdirectory(tests)