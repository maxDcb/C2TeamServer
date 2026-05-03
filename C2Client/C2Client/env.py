from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable


def default_env_paths() -> list[Path]:
    package_root = Path(__file__).resolve().parents[1]

    explicit_path = os.getenv("C2_ENV_FILE")
    if explicit_path:
        return [Path(explicit_path).expanduser()]

    return [
        Path.cwd() / ".env",
        package_root / ".env",
    ]


def load_c2_env(paths: Iterable[Path] | None = None, *, override: bool = False) -> list[Path]:
    loaded: list[Path] = []
    seen: set[Path] = set()
    for raw_path in paths or default_env_paths():
        path = raw_path.expanduser().resolve()
        if path in seen:
            continue
        seen.add(path)
        if not path.exists() or not path.is_file():
            continue
        _load_env_file(path, override=override)
        loaded.append(path)
    return loaded


def _load_env_file(path: Path, *, override: bool) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key.removeprefix("export ").strip()
        if not key or (not override and key in os.environ):
            continue

        os.environ[key] = _parse_env_value(value.strip())


def _parse_env_value(value: str) -> str:
    if not value:
        return ""
    try:
        parts = shlex.split(value, comments=True, posix=True)
    except ValueError:
        return value.strip("\"'")
    if not parts:
        return ""
    return parts[0]
