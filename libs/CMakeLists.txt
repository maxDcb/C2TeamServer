# Collect .proto files
file(COPY ${CMAKE_SOURCE_DIR}/libs/libGrpcMessages/ DESTINATION ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/)

file(GLOB PROTO_FILES "${CMAKE_SOURCE_DIR}/libs/libGrpcMessages/src/*.proto")

# Generate C++ gRPC files
execute_process(
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
        -I=${CMAKE_SOURCE_DIR}/libs/libGrpcMessages/src/
        --grpc_out=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/build/cpp/src
        --cpp_out=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/build/cpp/src
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PROGRAM}
        ${PROTO_FILES}
    RESULT_VARIABLE ret1
)

if(NOT ret1 EQUAL 0)
    message(FATAL_ERROR "C++ gRPC generation failed with status: ${ret1}")
endif()

# Generate Python gRPC files
execute_process(
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
        -I=${CMAKE_SOURCE_DIR}/libs/libGrpcMessages/src/
        --grpc_out=${CMAKE_SOURCE_DIR}/C2Client/C2Client/libGrpcMessages/build/py
        --python_out=${CMAKE_SOURCE_DIR}/C2Client/C2Client/libGrpcMessages/build/py
        --plugin=protoc-gen-grpc=${GRPC_PYTHON_PLUGIN_PROGRAM}
        ${PROTO_FILES}
    RESULT_VARIABLE ret2
)

if(NOT ret2 EQUAL 0)
    message(FATAL_ERROR "Python gRPC generation failed with status: ${ret2}")
endif()

add_subdirectory(libGrpcMessages)

add_subdirectory(libSocketHandler)

add_subdirectory(libDns)

add_subdirectory(libMemoryModuleDumy)
add_subdirectory(libPipeHandlerDumy)
add_subdirectory(libSocks5)