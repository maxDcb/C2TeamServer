from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

from validate_release import (
    EXPECTED_LINUX_BEACONS,
    EXPECTED_LINUX_ARCHES,
    EXPECTED_LINUX_MODULES,
    EXPECTED_WINDOWS_ARCHES,
    EXPECTED_WINDOWS_BEACONS,
    EXPECTED_WINDOWS_MODULES,
    ValidationError,
    _require_directory_exact,
)


DEFAULT_WINDOWS_REPO = "maxDcb/C2Implant"
DEFAULT_LINUX_REPO = "maxDcb/C2LinuxImplant"
DEFAULT_LINUX_ARCH = EXPECTED_LINUX_ARCHES[0]


def _request(url: str, token: str | None = None) -> urllib.request.Request:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "C2TeamServer-release-packaging",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def _read_json(url: str, token: str | None) -> dict:
    try:
        with urllib.request.urlopen(_request(url, token), timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API request failed for {url}: HTTP {exc.code}: {detail}") from exc


def _release_api_url(repo: str, tag: str | None) -> str:
    if tag:
        return f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    return f"https://api.github.com/repos/{repo}/releases/latest"


def _find_asset_url(release_data: dict, asset_name: str, repo: str) -> str:
    for asset in release_data.get("assets", []):
        if asset.get("name") == asset_name:
            url = asset.get("browser_download_url")
            if not url:
                raise RuntimeError(f"Asset {asset_name} in {repo} has no browser_download_url")
            return url
    available = ", ".join(asset.get("name", "<unnamed>") for asset in release_data.get("assets", []))
    raise RuntimeError(f"Release for {repo} does not contain {asset_name}. Available assets: {available}")


def _download(url: str, destination: Path, token: str | None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(_request(url, token), timeout=120) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Download failed for {url}: HTTP {exc.code}: {detail}") from exc

    if destination.stat().st_size == 0:
        raise RuntimeError(f"Downloaded asset is empty: {destination}")


def _assert_safe_archive_member(base_dir: Path, member_name: str) -> None:
    member_path = (base_dir / member_name).resolve()
    if not str(member_path).startswith(str(base_dir.resolve()) + os.sep):
        raise RuntimeError(f"Archive contains unsafe path: {member_name}")


def _extract_zip(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            _assert_safe_archive_member(destination, member)
        archive.extractall(destination)


def _extract_tar(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            _assert_safe_archive_member(destination, member.name)
        try:
            archive.extractall(destination, filter="data")
        except TypeError:
            archive.extractall(destination)


def _copy_validated_dir(source: Path, destination: Path, expected_files: tuple[str, ...]) -> None:
    _require_directory_exact(source, expected_files)
    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)
    _require_directory_exact(destination, expected_files)


def _fetch_release_asset(
    repo: str,
    tag: str | None,
    asset_name: str,
    destination: Path,
    token: str | None,
) -> None:
    release_data = _read_json(_release_api_url(repo, tag), token)
    tag_label = release_data.get("tag_name", tag or "latest")
    asset_url = _find_asset_url(release_data, asset_name, repo)
    print(f"Downloading {repo} {tag_label} asset {asset_name}")
    _download(asset_url, destination, token)


StageCopy = tuple[Path, Path, tuple[str, ...]]


def _windows_asset_name(arch: str) -> str:
    return f"C2Implant-windows-{arch}.zip"


def _find_release_layout_root(extract_root: Path, required_directories: tuple[str, ...]) -> Path:
    candidates = (extract_root / "Release", extract_root)
    for candidate in candidates:
        if all((candidate / directory).is_dir() for directory in required_directories):
            return candidate

    checked = ", ".join(str(candidate) for candidate in candidates)
    required = ", ".join(required_directories)
    raise ValidationError(f"Could not find release layout containing {required}. Checked: {checked}")


def _prepare_windows(repo: str, tag: str | None, import_root: Path, stage_root: Path, token: str | None) -> list[StageCopy]:
    copy_plan: list[StageCopy] = []
    for arch in EXPECTED_WINDOWS_ARCHES:
        archive_path = import_root / _windows_asset_name(arch)
        extract_root = import_root / f"windows-{arch}"
        _fetch_release_asset(repo, tag, _windows_asset_name(arch), archive_path, token)
        _extract_zip(archive_path, extract_root)

        release_root = _find_release_layout_root(extract_root, ("WindowsBeacons", "WindowsModules"))
        windows_beacons = release_root / "WindowsBeacons"
        windows_modules = release_root / "WindowsModules"
        _require_directory_exact(windows_beacons, EXPECTED_WINDOWS_BEACONS)
        _require_directory_exact(windows_modules, EXPECTED_WINDOWS_MODULES)
        copy_plan.extend(
            [
                (windows_beacons, stage_root / "WindowsBeacons" / arch, EXPECTED_WINDOWS_BEACONS),
                (windows_modules, stage_root / "WindowsModules" / arch, EXPECTED_WINDOWS_MODULES),
            ]
        )

    return copy_plan


def _prepare_linux(repo: str, tag: str | None, import_root: Path, stage_root: Path, token: str | None) -> list[StageCopy]:
    archive_path = import_root / "C2LinuxImplant.tar.gz"
    extract_root = import_root / "linux"
    _fetch_release_asset(repo, tag, "Release.tar.gz", archive_path, token)
    _extract_tar(archive_path, extract_root)

    release_root = _find_release_layout_root(extract_root, ("LinuxBeacons", "LinuxModules"))
    linux_beacons = release_root / "LinuxBeacons"
    linux_modules = release_root / "LinuxModules"
    _require_directory_exact(linux_beacons, EXPECTED_LINUX_BEACONS)
    _require_directory_exact(linux_modules, EXPECTED_LINUX_MODULES)
    return [
        (linux_beacons, stage_root / "LinuxBeacons" / DEFAULT_LINUX_ARCH, EXPECTED_LINUX_BEACONS),
        (linux_modules, stage_root / "LinuxModules" / DEFAULT_LINUX_ARCH, EXPECTED_LINUX_MODULES),
    ]


def _none_if_blank(value: str | None) -> str | None:
    return value if value else None


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import C2Implant and C2LinuxImplant release assets into TeamServer staging."
    )
    parser.add_argument("--stage-root", required=True, help="Path to the staged TeamServer Release directory.")
    parser.add_argument("--import-root", required=True, help="Scratch directory used for downloads and extraction.")
    parser.add_argument("--windows-repo", default=DEFAULT_WINDOWS_REPO)
    parser.add_argument("--linux-repo", default=DEFAULT_LINUX_REPO)
    parser.add_argument("--windows-tag", default="")
    parser.add_argument("--linux-tag", default="")
    args = parser.parse_args(argv)

    stage_root = Path(args.stage_root).resolve()
    import_root = Path(args.import_root).resolve()
    token = os.environ.get("GITHUB_TOKEN")

    try:
        if not stage_root.is_dir():
            raise ValidationError(f"Stage root does not exist: {stage_root}")

        shutil.rmtree(import_root, ignore_errors=True)
        import_root.mkdir(parents=True, exist_ok=True)

        copy_plan: list[StageCopy] = []
        copy_plan.extend(
            _prepare_windows(
                args.windows_repo,
                _none_if_blank(args.windows_tag),
                import_root,
                stage_root,
                token,
            )
        )
        copy_plan.extend(
            _prepare_linux(
                args.linux_repo,
                _none_if_blank(args.linux_tag),
                import_root,
                stage_root,
                token,
            )
        )

        shutil.rmtree(stage_root / "WindowsBeacons", ignore_errors=True)
        shutil.rmtree(stage_root / "WindowsModules", ignore_errors=True)
        shutil.rmtree(stage_root / "LinuxBeacons", ignore_errors=True)
        shutil.rmtree(stage_root / "LinuxModules", ignore_errors=True)
        for source, destination, expected_files in copy_plan:
            _copy_validated_dir(source, destination, expected_files)
    except (RuntimeError, ValidationError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"Implant import failed: {exc}", file=sys.stderr)
        return 1

    print(f"Imported implant release assets into {stage_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
