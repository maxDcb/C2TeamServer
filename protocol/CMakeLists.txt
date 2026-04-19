set(C2_PROTOCOL_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(C2_PROTOCOL_PROTO_FILE "${C2_PROTOCOL_PROTO_DIR}/TeamServerApi.proto")
set(C2_PROTOCOL_CPP_OUT_DIR "${CMAKE_BINARY_DIR}/generated/grpc/cpp")
set(C2_PROTOCOL_PYTHON_PACKAGE_ROOT "${CMAKE_BINARY_DIR}/generated/python_protocol")
set(C2_PROTOCOL_PYTHON_PACKAGE_DIR "${C2_PROTOCOL_PYTHON_PACKAGE_ROOT}/c2client_protocol")

set(C2_PROTOCOL_CPP_SRCS
  "${C2_PROTOCOL_CPP_OUT_DIR}/TeamServerApi.pb.cc"
  "${C2_PROTOCOL_CPP_OUT_DIR}/TeamServerApi.grpc.pb.cc"
)
set(C2_PROTOCOL_CPP_HDRS
  "${C2_PROTOCOL_CPP_OUT_DIR}/TeamServerApi.pb.h"
  "${C2_PROTOCOL_CPP_OUT_DIR}/TeamServerApi.grpc.pb.h"
)
set(C2_PROTOCOL_PY_SRCS
  "${C2_GENERATED_PYTHON_GRPC_DIR}/TeamServerApi_pb2.py"
  "${C2_GENERATED_PYTHON_GRPC_DIR}/TeamServerApi_pb2_grpc.py"
)
set(C2_PROTOCOL_PY_PACKAGE_FILES
  "${C2_PROTOCOL_PYTHON_PACKAGE_DIR}/__init__.py"
  "${C2_PROTOCOL_PYTHON_PACKAGE_DIR}/TeamServerApi_pb2.py"
  "${C2_PROTOCOL_PYTHON_PACKAGE_DIR}/TeamServerApi_pb2_grpc.py"
)

add_custom_command(
  OUTPUT ${C2_PROTOCOL_CPP_SRCS} ${C2_PROTOCOL_CPP_HDRS}
  COMMAND ${CMAKE_COMMAND} -E make_directory "${C2_PROTOCOL_CPP_OUT_DIR}"
  COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    --proto_path=${C2_PROTOCOL_PROTO_DIR}
    --cpp_out=${C2_PROTOCOL_CPP_OUT_DIR}
    --grpc_out=${C2_PROTOCOL_CPP_OUT_DIR}
    --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PROGRAM}
    ${C2_PROTOCOL_PROTO_FILE}
  DEPENDS ${C2_PROTOCOL_PROTO_FILE} ${Protobuf_PROTOC_EXECUTABLE} ${GRPC_CPP_PLUGIN_PROGRAM}
  VERBATIM
)

add_custom_command(
  OUTPUT ${C2_PROTOCOL_PY_SRCS}
  COMMAND ${CMAKE_COMMAND} -E make_directory "${C2_GENERATED_PYTHON_GRPC_DIR}"
  COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    --proto_path=${C2_PROTOCOL_PROTO_DIR}
    --python_out=${C2_GENERATED_PYTHON_GRPC_DIR}
    --grpc_out=${C2_GENERATED_PYTHON_GRPC_DIR}
    --plugin=protoc-gen-grpc=${GRPC_PYTHON_PLUGIN_PROGRAM}
    ${C2_PROTOCOL_PROTO_FILE}
  DEPENDS ${C2_PROTOCOL_PROTO_FILE} ${Protobuf_PROTOC_EXECUTABLE} ${GRPC_PYTHON_PLUGIN_PROGRAM}
  VERBATIM
)

add_custom_command(
  OUTPUT ${C2_PROTOCOL_PY_PACKAGE_FILES}
  COMMAND ${CMAKE_COMMAND}
    -DINPUT_PY_PB2=${C2_GENERATED_PYTHON_GRPC_DIR}/TeamServerApi_pb2.py
    -DINPUT_PY_GRPC=${C2_GENERATED_PYTHON_GRPC_DIR}/TeamServerApi_pb2_grpc.py
    -DOUTPUT_DIR=${C2_PROTOCOL_PYTHON_PACKAGE_DIR}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/PreparePythonGrpcPackage.cmake
  DEPENDS ${C2_PROTOCOL_PY_SRCS} ${CMAKE_CURRENT_SOURCE_DIR}/PreparePythonGrpcPackage.cmake
  VERBATIM
)

add_custom_target(protocol_python_stubs ALL DEPENDS ${C2_PROTOCOL_PY_PACKAGE_FILES})

add_library(GrpcMessages STATIC ${C2_PROTOCOL_CPP_SRCS})
add_dependencies(GrpcMessages protocol_python_stubs)
target_include_directories(GrpcMessages PUBLIC "${C2_PROTOCOL_CPP_OUT_DIR}")
target_link_libraries(GrpcMessages PUBLIC protobuf::libprotobuf grpc::grpc)
