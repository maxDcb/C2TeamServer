if(NOT DEFINED INPUT_PY_PB2 OR NOT DEFINED INPUT_PY_GRPC OR NOT DEFINED OUTPUT_DIR)
  message(FATAL_ERROR "PreparePythonGrpcPackage.cmake requires INPUT_PY_PB2, INPUT_PY_GRPC and OUTPUT_DIR.")
endif()

file(MAKE_DIRECTORY "${OUTPUT_DIR}")
file(COPY "${INPUT_PY_PB2}" DESTINATION "${OUTPUT_DIR}")

file(READ "${INPUT_PY_GRPC}" grpc_stub_content)
string(REPLACE
  "import TeamServerApi_pb2 as TeamServerApi__pb2"
  "from . import TeamServerApi_pb2 as TeamServerApi__pb2"
  grpc_stub_content
  "${grpc_stub_content}"
)
file(WRITE "${OUTPUT_DIR}/TeamServerApi_pb2_grpc.py" "${grpc_stub_content}")
file(WRITE "${OUTPUT_DIR}/__init__.py" "")
