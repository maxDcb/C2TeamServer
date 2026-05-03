from __future__ import annotations

from pathlib import Path


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_storage_dir() -> Path:
    return package_root() / "logs" / "assistant_sessions"


def prompts_dir() -> Path:
    return package_root() / "assistant_agent" / "prompts"
