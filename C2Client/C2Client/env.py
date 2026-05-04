from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable


PATH_ENV_KEYS = {
    "C2_CERT_PATH",
    "C2_PROTOCOL_PYTHON_ROOT",
    "C2_LOG_DIR",
    "C2_DROPPER_MODULES_DIR",
    "C2_DROPPER_MODULES_CONF",
    "C2_SHELLCODE_MODULES_DIR",
    "C2_SHELLCODE_MODULES_CONF",
}

TRUE_VALUES = {"1", "true", "yes", "y", "on"}
FALSE_VALUES = {"0", "false", "no", "n", "off"}

_AUTO_ENV_LOADED = False


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
    global _AUTO_ENV_LOADED

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
    _AUTO_ENV_LOADED = True
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

        parsed_value = _parse_env_value(value.strip())
        if key in PATH_ENV_KEYS:
            parsed_value = _resolve_env_path_value(path, parsed_value)
        os.environ[key] = parsed_value


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


def _resolve_env_path_value(env_file_path: Path, value: str) -> str:
    if not value:
        return ""

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = env_file_path.parent / candidate
    return str(candidate.resolve())


def ensure_c2_env_loaded() -> None:
    global _AUTO_ENV_LOADED

    if _AUTO_ENV_LOADED:
        return
    load_c2_env()


def env_value(key: str, default: str = "") -> str:
    ensure_c2_env_loaded()
    return os.getenv(key, default)


def env_bool(key: str, default: bool = False) -> bool:
    value = env_value(key, "")
    if not value:
        return default

    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    return default


def env_int(key: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    value = env_value(key, "")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default

    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def env_path(key: str, default: Path | None = None) -> Path | None:
    value = env_value(key, "")
    if not value:
        return default

    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()
