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


def test_validate_base_release_rejects_runtime_data_roots(tmp_path):
    release_root = tmp_path / "Release"
    _seed_base_release(release_root)
    (release_root / "data" / "Tools").mkdir(parents=True)

    with pytest.raises(validate_release.ValidationError, match="runtime/operator data"):
        validate_release.validate_base_release(release_root)


def test_validate_implants_requires_linux_arch_layout(tmp_path):
    release_root = tmp_path / "Release"
    for arch in validate_release.EXPECTED_WINDOWS_ARCHES:
        for filename in validate_release.EXPECTED_WINDOWS_BEACONS:
            _write_file(release_root / "WindowsBeacons" / arch / filename)
        for filename in validate_release.EXPECTED_WINDOWS_MODULES:
            _write_file(release_root / "WindowsModules" / arch / filename)
    for arch in validate_release.EXPECTED_LINUX_ARCHES:
        for filename in validate_release.EXPECTED_LINUX_BEACONS:
            _write_file(release_root / "LinuxBeacons" / arch / filename)
        for filename in validate_release.EXPECTED_LINUX_MODULES:
            _write_file(release_root / "LinuxModules" / arch / filename)

    validate_release.validate_implants(release_root)

    flat_beacon = release_root / "LinuxBeacons" / "BeaconHttp"
    _write_file(flat_beacon)
    with pytest.raises(validate_release.ValidationError, match="unexpected file"):
        validate_release.validate_implants(release_root)
