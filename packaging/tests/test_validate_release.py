from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

PACKAGING_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGING_ROOT))

import validate_release  # noqa: E402


def _write_file(path: Path, content: str = "x", *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable and os.name != "nt":
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _seed_base_release(root: Path) -> None:
    for filename in validate_release.EXPECTED_TEAMSERVER_FILES:
        _write_file(root / "TeamServer" / filename, executable=filename == "TeamServer")
    (root / "TeamServer" / "logs").mkdir(parents=True)

    for filename in validate_release.EXPECTED_TEAMSERVER_MODULES:
        _write_file(root / "TeamServerModules" / filename)

    for filename in validate_release.EXPECTED_COMMAND_SPECS_COMMON:
        _write_file(root / "CommandSpecs" / "common" / filename, "{}")
    for filename in validate_release.EXPECTED_COMMAND_SPECS_MODULES:
        _write_file(root / "CommandSpecs" / "modules" / filename, "{}")

    _write_file(root / "Client" / "README.md")
    _write_file(root / "Client" / "pyproject.toml")
    _write_file(root / "Client" / "requirements.txt")
    _write_file(root / "Client" / "run-client.sh", executable=True)
    _write_file(root / "Client" / "run-client.ps1")
    _write_file(root / "Client" / "c2client_protocol" / "__init__.py")
    _write_file(root / "Client" / "c2client_protocol" / "TeamServerApi_pb2.py")
    _write_file(root / "Client" / "c2client_protocol" / "TeamServerApi_pb2_grpc.py")


def test_validate_base_release_requires_command_specs(tmp_path):
    release_root = tmp_path / "Release"
    _seed_base_release(release_root)

    validate_release.validate_base_release(release_root)

    (release_root / "CommandSpecs" / "modules" / "taskScheduler.json").unlink()
    with pytest.raises(validate_release.ValidationError, match="taskScheduler.json"):
        validate_release.validate_base_release(release_root)
