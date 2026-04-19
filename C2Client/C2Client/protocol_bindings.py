"""Helpers to load generated TeamServer gRPC bindings."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Tuple


def _candidate_protocol_roots() -> list[Path]:
    candidates: list[Path] = []

    env_value = os.getenv("C2_PROTOCOL_PYTHON_ROOT")
    if env_value:
        candidates.append(Path(env_value).expanduser())

    repo_root = Path(__file__).resolve().parents[2]
    candidates.extend(sorted(repo_root.glob("build*/generated/python_protocol")))
    candidates.append(repo_root / "build" / "generated" / "python_protocol")

    unique_candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        unique_candidates.append(candidate)
    return unique_candidates


def _ensure_protocol_package_on_path() -> None:
    for candidate in _candidate_protocol_roots():
        package_file = candidate / "c2client_protocol" / "TeamServerApi_pb2.py"
        if not package_file.exists():
            continue
        candidate_str = str(candidate)
        if candidate_str not in sys.path:
            sys.path.insert(0, candidate_str)
        return

    raise ModuleNotFoundError(
        "Unable to locate generated TeamServer protocol bindings. "
        "Run the CMake build first or set C2_PROTOCOL_PYTHON_ROOT.",
    )


def load_protocol_modules() -> Tuple[object, object]:
    _ensure_protocol_package_on_path()
    teamserverapi_pb2 = importlib.import_module("c2client_protocol.TeamServerApi_pb2")
    teamserverapi_pb2_grpc = importlib.import_module("c2client_protocol.TeamServerApi_pb2_grpc")
    return teamserverapi_pb2, teamserverapi_pb2_grpc


TeamServerApi_pb2, TeamServerApi_pb2_grpc = load_protocol_modules()
