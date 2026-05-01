from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from pathlib import Path

PACKAGING_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGING_ROOT))

import import_implant_releases  # noqa: E402
import validate_release  # noqa: E402


def _make_windows_archive(path: Path, arch: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for filename in validate_release.EXPECTED_WINDOWS_BEACONS:
            archive.writestr(f"Release/WindowsBeacons/{filename}", f"{arch}:{filename}")
        for filename in validate_release.EXPECTED_WINDOWS_MODULES:
            archive.writestr(f"Release/WindowsModules/{filename}", f"{arch}:{filename}")


def _make_linux_archive(path: Path) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for directory, expected_files in (
            ("LinuxBeacons", validate_release.EXPECTED_LINUX_BEACONS),
            ("LinuxModules", validate_release.EXPECTED_LINUX_MODULES),
        ):
            for filename in expected_files:
                data = f"linux:{filename}".encode("utf-8")
                info = tarfile.TarInfo(f"Release/{directory}/{filename}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def test_import_implant_releases_stages_all_windows_architectures(tmp_path, monkeypatch):
    source_root = tmp_path / "source"
    source_root.mkdir()
    for arch in validate_release.EXPECTED_WINDOWS_ARCHES:
        _make_windows_archive(source_root / f"C2Implant-windows-{arch}.zip", arch)
    _make_linux_archive(source_root / "Release.tar.gz")

    def fake_fetch_release_asset(repo, tag, asset_name, destination, token):
        del repo, tag, token
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source_root / asset_name).read_bytes())

    monkeypatch.setattr(import_implant_releases, "_fetch_release_asset", fake_fetch_release_asset)

    stage_root = tmp_path / "Release"
    stage_root.mkdir()
    exit_code = import_implant_releases.main(
        [
            "--stage-root",
            str(stage_root),
            "--import-root",
            str(tmp_path / "imports"),
            "--windows-tag",
            "test-windows",
            "--linux-tag",
            "test-linux",
        ]
    )

    assert exit_code == 0
    validate_release.validate_implants(stage_root)

    for arch in validate_release.EXPECTED_WINDOWS_ARCHES:
        beacon_path = stage_root / "WindowsBeacons" / arch / "BeaconHttp.exe"
        module_path = stage_root / "WindowsModules" / arch / "Inject.dll"
        assert beacon_path.read_text(encoding="utf-8") == f"{arch}:BeaconHttp.exe"
        assert module_path.read_text(encoding="utf-8") == f"{arch}:Inject.dll"

    assert not any((stage_root / "WindowsBeacons").glob("*.exe"))
    assert not any((stage_root / "WindowsModules").glob("*.dll"))


def test_import_implant_releases_rejects_missing_windows_arch_asset(tmp_path, monkeypatch):
    source_root = tmp_path / "source"
    source_root.mkdir()
    for arch in ("x86", "x64"):
        _make_windows_archive(source_root / f"C2Implant-windows-{arch}.zip", arch)
    _make_linux_archive(source_root / "Release.tar.gz")

    def fake_fetch_release_asset(repo, tag, asset_name, destination, token):
        del repo, tag, token
        source = source_root / asset_name
        if not source.is_file():
            raise RuntimeError(f"missing fake asset: {asset_name}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())

    monkeypatch.setattr(import_implant_releases, "_fetch_release_asset", fake_fetch_release_asset)

    stage_root = tmp_path / "Release"
    stage_root.mkdir()
    exit_code = import_implant_releases.main(
        [
            "--stage-root",
            str(stage_root),
            "--import-root",
            str(tmp_path / "imports"),
        ]
    )

    assert exit_code == 1
