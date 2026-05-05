from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def _copytree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _remove_matching(root: Path, pattern: str) -> None:
    for path in root.rglob(pattern):
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _build_client_bundle(source_root: Path, build_root: Path, release_root: Path) -> None:
    client_bundle_root = release_root / "Client"
    client_package_root = source_root / "C2Client" / "C2Client"
    protocol_package_root = build_root / "generated" / "python_protocol" / "c2client_protocol"

    if not protocol_package_root.exists():
        raise FileNotFoundError(
            f"Missing generated client protocol package: {protocol_package_root}. "
            "Build the project before staging the release.",
        )

    shutil.rmtree(client_bundle_root, ignore_errors=True)
    client_bundle_root.mkdir(parents=True, exist_ok=True)

    _copytree(client_package_root, client_bundle_root / "C2Client")
    _copytree(protocol_package_root, client_bundle_root / "c2client_protocol")

    for metadata_name in ("pyproject.toml", "requirements.txt"):
        shutil.copy2(source_root / "C2Client" / metadata_name, client_bundle_root / metadata_name)

    _write_text(
        client_bundle_root / "run-client.sh",
        """#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

exec python -m C2Client.GUI "$@"
""",
    )
    (client_bundle_root / "run-client.sh").chmod(0o755)

    _write_text(
        client_bundle_root / "run-client.ps1",
        """$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = \"$scriptDir;$env:PYTHONPATH\"
} else {
    $env:PYTHONPATH = $scriptDir
}

python -m C2Client.GUI @args
""",
    )

    _write_text(
        client_bundle_root / "README.md",
        """# C2Client

This bundle contains the Python client sources and the generated `c2client_protocol` package
produced from the repository's `protocol/TeamServerApi.proto`.

Typical local setup:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
./run-client.sh --ip 127.0.0.1 --port 50051
```

The launcher adds the bundle root to `PYTHONPATH`, so the generated protocol bindings are
resolved without relying on build-tree paths.
""",
    )


def assemble_release(source_root: Path, build_root: Path, output_root: Path) -> None:
    build_release_root = build_root / "artifacts" / "Release"
    teamserver_root = build_release_root / "TeamServer"
    modules_root = build_release_root / "TeamServerModules"
    command_specs_root = build_release_root / "CommandSpecs"

    if not teamserver_root.exists():
        raise FileNotFoundError(
            f"Missing TeamServer runtime artifacts: {teamserver_root}. "
            "Build the project before staging the release.",
        )
    if not modules_root.exists():
        raise FileNotFoundError(
            f"Missing TeamServer module artifacts: {modules_root}. "
            "Build the project before staging the release.",
        )
    if not command_specs_root.exists():
        raise FileNotFoundError(
            f"Missing TeamServer command specs: {command_specs_root}. "
            "Build the project before staging the release.",
        )

    shutil.rmtree(output_root, ignore_errors=True)
    output_root.parent.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)

    shutil.rmtree(output_root / "TeamServer", ignore_errors=True)
    shutil.rmtree(output_root / "TeamServerModules", ignore_errors=True)
    shutil.rmtree(output_root / "CommandSpecs", ignore_errors=True)
    shutil.rmtree(output_root / "Modules", ignore_errors=True)

    _copytree(teamserver_root, output_root / "TeamServer")
    _copytree(modules_root, output_root / "TeamServerModules")
    _copytree(command_specs_root, output_root / "CommandSpecs")
    shutil.rmtree(output_root / "TeamServer" / "logs", ignore_errors=True)
    (output_root / "TeamServer" / "logs").mkdir(parents=True, exist_ok=True)

    _build_client_bundle(source_root, build_root, output_root)

    _remove_matching(output_root, ".gitignore")
    _remove_matching(output_root, "__pycache__")


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage a release bundle from build outputs.")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()

    assemble_release(
        source_root=Path(args.source_root).resolve(),
        build_root=Path(args.build_root).resolve(),
        output_root=Path(args.output_root).resolve(),
    )


if __name__ == "__main__":
    main()
