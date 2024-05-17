# donut
file(COPY ${CMAKE_SOURCE_DIR}/thirdParty/donut DESTINATION ${CMAKE_BINARY_DIR}/thirdParty)
execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/thirdParty/donut && make -f Makefile")
set(Donut "${CMAKE_BINARY_DIR}/thirdParty/donut/lib/libdonut.a" PARENT_SCOPE)
set(aplib64 "${CMAKE_BINARY_DIR}/thirdParty/donut/lib/aplib64.a" PARENT_SCOPE)

## coffLoader
add_subdirectory(coffLoader)


