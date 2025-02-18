import os
import grpc_tools.protoc

PROTO_DIR = "protos"
GENERATED_DIR = "C2Client/libGrpcMessages/build/py/"
os.makedirs(GENERATED_DIR, exist_ok=True)

proto_files = [os.path.join(PROTO_DIR, f) for f in os.listdir(PROTO_DIR) if f.endswith(".proto")]

for proto_file in proto_files:
    grpc_tools.protoc.main([
        "grpc_tools.protoc",
        f"-I{PROTO_DIR}",
        f"--python_out={GENERATED_DIR}",
        f"--grpc_python_out={GENERATED_DIR}",
        proto_file,
    ])
