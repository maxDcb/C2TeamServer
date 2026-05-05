import importlib
import sys


def test_protocol_bindings_loads_importable_package_without_build_tree(monkeypatch, tmp_path):
    package_dir = tmp_path / "c2client_protocol"
    package_dir.mkdir(parents=True)

    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "TeamServerApi_pb2.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package_dir / "TeamServerApi_pb2_grpc.py").write_text(
        "from . import TeamServerApi_pb2\n"
        "VALUE = TeamServerApi_pb2.VALUE\n",
        encoding="utf-8",
    )

    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delenv("C2_PROTOCOL_PYTHON_ROOT", raising=False)

    for module_name in (
        "C2Client.protocol_bindings",
        "c2client_protocol",
        "c2client_protocol.TeamServerApi_pb2",
        "c2client_protocol.TeamServerApi_pb2_grpc",
    ):
        sys.modules.pop(module_name, None)

    protocol_bindings = importlib.import_module("C2Client.protocol_bindings")

    assert protocol_bindings.TeamServerApi_pb2.VALUE == 1
    assert protocol_bindings.TeamServerApi_pb2_grpc.VALUE == 1
