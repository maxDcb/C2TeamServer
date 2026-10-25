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


def _make_windows_archive(path: Path, arch: str, extra_beacons: tuple[str, ...] = ()) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for filename in (*validate_release.EXPECTED_WINDOWS_BEACONS, *extra_beacons):
            archive.writestr(f"Release/WindowsBeacons/{filename}", f"{arch}:{filename}")
        for filename in validate_release.EXPECTED_WINDOWS_MODULES:
            archive.writestr(f"Release/WindowsModules/{filename}", f"{arch}:{filename}")


def _make_linux_archive(path: Path, extra_beacons: tuple[str, ...] = ()) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for directory, expected_files in (
            ("LinuxBeacons", (*validate_release.EXPECTED_LINUX_BEACONS, *extra_beacons)),
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

    linux_beacon_path = stage_root / "LinuxBeacons" / "x64" / "BeaconHttp"
    linux_module_path = stage_root / "LinuxModules" / "x64" / "libInject.so"
    assert linux_beacon_path.read_text(encoding="utf-8") == "linux:BeaconHttp"
    assert linux_module_path.read_text(encoding="utf-8") == "linux:libInject.so"

    assert not any((stage_root / "WindowsBeacons").glob("*.exe"))
    assert not any((stage_root / "WindowsModules").glob("*.dll"))
    assert not any((stage_root / "LinuxBeacons").glob("Beacon*"))
    assert not any((stage_root / "LinuxModules").glob("*.so"))


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


def test_import_excludes_known_unsupported_beacons(tmp_path, monkeypatch):
    source_root = tmp_path / "source"
    source_root.mkdir()
    for arch in validate_release.EXPECTED_WINDOWS_ARCHES:
        _make_windows_archive(
            source_root / f"C2Implant-windows-{arch}.zip", arch,
            import_implant_releases.EXCLUDED_WINDOWS_BEACONS,
        )
    _make_linux_archive(
        source_root / "Release.tar.gz", import_implant_releases.EXCLUDED_LINUX_BEACONS,
    )

    def fake_fetch_release_asset(_repo, _tag, asset_name, destination, _token):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source_root / asset_name).read_bytes())

    monkeypatch.setattr(import_implant_releases, "_fetch_release_asset", fake_fetch_release_asset)
    stage_root = tmp_path / "Release"
    stage_root.mkdir()
    assert import_implant_releases.main([
        "--stage-root", str(stage_root), "--import-root", str(tmp_path / "imports"),
    ]) == 0
    validate_release.validate_implants(stage_root)
    for arch in validate_release.EXPECTED_WINDOWS_ARCHES:
        for name in import_implant_releases.EXCLUDED_WINDOWS_BEACONS:
            assert not (stage_root / "WindowsBeacons" / arch / name).exists()
    for name in import_implant_releases.EXCLUDED_LINUX_BEACONS:
        assert not (stage_root / "LinuxBeacons" / "x64" / name).exists()


def test_import_rejects_unrecognized_source_beacon(tmp_path):
    source = tmp_path / "WindowsBeacons"
    source.mkdir()
    for name in validate_release.EXPECTED_WINDOWS_BEACONS:
        (source / name).write_bytes(b"beacon")
    (source / "UnknownBeacon.exe").write_bytes(b"unknown")

    try:
        import_implant_releases._require_source_dir(
            source, validate_release.EXPECTED_WINDOWS_BEACONS,
            import_implant_releases.EXCLUDED_WINDOWS_BEACONS,
        )
    except validate_release.ValidationError as error:
        assert "UnknownBeacon.exe" in str(error)
    else:
        raise AssertionError("Unknown source beacon should be rejected")
