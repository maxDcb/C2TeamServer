import importlib
import os
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


def test_protocol_bindings_skips_stale_generated_build(monkeypatch, tmp_path):
    protocol_bindings = importlib.import_module("C2Client.protocol_bindings")

    repo_root = tmp_path
    proto_file = repo_root / "protocol" / "TeamServerApi.proto"
    stale_root = repo_root / "build" / "generated" / "python_protocol"
    fresh_root = repo_root / "buildNew" / "generated" / "python_protocol"
    stale_package = stale_root / "c2client_protocol" / "TeamServerApi_pb2.py"
    fresh_package = fresh_root / "c2client_protocol" / "TeamServerApi_pb2.py"

    proto_file.parent.mkdir(parents=True)
    stale_package.parent.mkdir(parents=True)
    fresh_package.parent.mkdir(parents=True)
    proto_file.write_text("proto", encoding="utf-8")
    stale_package.write_text("stale", encoding="utf-8")
    fresh_package.write_text("fresh", encoding="utf-8")

    os.utime(proto_file, (200, 200))
    os.utime(stale_package, (100, 100))
    os.utime(fresh_package, (300, 300))

    search_path = []
    monkeypatch.setattr(protocol_bindings, "_repo_root", lambda: repo_root)
    monkeypatch.setattr(protocol_bindings, "env_path", lambda _name: None)
    monkeypatch.setattr(protocol_bindings.sys, "path", search_path)

    protocol_bindings._ensure_protocol_package_on_path()

    assert search_path == [str(fresh_root)]
