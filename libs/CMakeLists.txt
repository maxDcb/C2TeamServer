## libs/libGrpcMessages
file(COPY ${CMAKE_SOURCE_DIR}/libs/libGrpcMessages/ DESTINATION ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/)
execute_process(COMMAND bash -c "${CONAN_BIN_DIRS_PROTOBUF}/protoc -I=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/ --grpc_out=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/build/cpp/src --cpp_out=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/build/cpp/src --plugin=protoc-gen-grpc=${CONAN_BIN_DIRS_GRPC}/grpc_cpp_plugin ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/*.proto")
execute_process(COMMAND bash -c "${CONAN_BIN_DIRS_PROTOBUF}/protoc -I=${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/ --grpc_out=${CMAKE_SOURCE_DIR}/Release/Client/libGrpcMessages/build/py --python_out=${CMAKE_SOURCE_DIR}/Release/Client/libGrpcMessages/build/py --plugin=protoc-gen-grpc=${CONAN_BIN_DIRS_GRPC}/grpc_python_plugin ${CMAKE_BINARY_DIR}/libs/libGrpcMessages/src/*.proto")
add_subdirectory(libGrpcMessages)

## libs/libBoostSocketHandler
add_subdirectory(libBoostSocketHandler)