add_library(c2_base64 INTERFACE)

target_sources(c2_base64 INTERFACE
  ${CMAKE_SOURCE_DIR}/thirdParty/base64/base64.cpp
)

target_include_directories(c2_base64 INTERFACE
  ${CMAKE_SOURCE_DIR}/thirdParty/base64
)

# donut
file(COPY ${CMAKE_SOURCE_DIR}/thirdParty/donut DESTINATION ${CMAKE_BINARY_DIR}/thirdParty)
execute_process(
  COMMAND ${CMAKE_COMMAND} -DDONUT_SOURCE=${CMAKE_BINARY_DIR}/thirdParty/donut -P ${CMAKE_SOURCE_DIR}/cmake/PatchDonut.cmake
  COMMAND_ERROR_IS_FATAL ANY)
find_program(C2_OBJCOPY_EXECUTABLE NAMES objcopy REQUIRED)
execute_process(
  COMMAND ${CMAKE_COMMAND}
    -DDONUT_APLIB_ARCHIVE=${CMAKE_BINARY_DIR}/thirdParty/donut/lib/aplib64.a
    -DC2_OBJCOPY=${C2_OBJCOPY_EXECUTABLE}
    -P ${CMAKE_SOURCE_DIR}/cmake/HardenDonutArchive.cmake
  COMMAND_ERROR_IS_FATAL ANY)
execute_process(
  COMMAND make -f Makefile
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/thirdParty/donut
  COMMAND_ERROR_IS_FATAL ANY)
set(Donut "${CMAKE_BINARY_DIR}/thirdParty/donut/lib/libdonut.a" PARENT_SCOPE)
set(aplib64 "${CMAKE_BINARY_DIR}/thirdParty/donut/lib/aplib64.a" PARENT_SCOPE)
