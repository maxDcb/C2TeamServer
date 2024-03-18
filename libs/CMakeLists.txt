## libs/libGrpcMessages
file(COPY ${CMAKE_SOURCE_DIR}/libs/libGrpcMessages/ DESTINATION ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/)

execute_process(COMMAND bash -c "${PROTOBUF_PROTOC_EXECUTABLE} -I=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/ --grpc_out=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/build/cpp/src --cpp_out=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/build/cpp/src --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PROGRAM} ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/*.proto" RESULT_VARIABLE ret)

if(ret EQUAL "1")
    message( FATAL_ERROR "Bad exit status")
endif()

execute_process(COMMAND bash -c "${PROTOBUF_PROTOC_EXECUTABLE} -I=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/ --grpc_out=${CMAKE_SOURCE_DIR}/Release/Client/libGrpcMessages/build/py --python_out=${CMAKE_SOURCE_DIR}/Release/Client/libGrpcMessages/build/py --plugin=protoc-gen-grpc=${GRPC_PYTHON_PLUGIN_PROGRAM} ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/*.proto" RESULT_VARIABLE ret)

if(ret EQUAL "1")
    message( FATAL_ERROR "Bad exit status")
endif()

add_subdirectory(libGrpcMessages)

## libs/libBoostSocketHandler
add_subdirectory(libBoostSocketHandler)

add_subdirectory(libDns)

add_subdirectory(libPipeHandlerDumy)