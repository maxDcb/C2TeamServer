from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class C2ToolSpec:
    name: str
    description: str
    command_template: str
    parameters: dict[str, Any]
    source_path: Path


def default_schema_dir() -> Path:
    return Path(__file__).resolve().parent / "schemas"


def load_tool_specs(schema_dir: Path | None = None) -> list[C2ToolSpec]:
    schema_dir = schema_dir or default_schema_dir()
    specs = [_load_tool_spec(path) for path in sorted(schema_dir.glob("*.json"))]
    names = [spec.name for spec in specs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"Duplicate C2 assistant tool names: {', '.join(duplicates)}")
    return sorted(specs, key=lambda spec: spec.name)


def _load_tool_spec(path: Path) -> C2ToolSpec:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON tool schema: {path}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"Tool schema must be a JSON object: {path}")

    name = _required_string(payload, "name", path)
    description = _required_string(payload, "description", path)
    command_template = _required_string(payload, "command_template", path)
    parameters = payload.get("parameters")
    if not isinstance(parameters, dict) or parameters.get("type") != "object":
        raise ValueError(f"Tool schema parameters must be a JSON object schema: {path}")

    required = parameters.get("required")
    if not isinstance(required, list) or "beacon_hash" not in required or "listener_hash" not in required:
        raise ValueError(f"Tool schema must require beacon_hash and listener_hash: {path}")

    properties = parameters.get("properties")
    if not isinstance(properties, dict):
        raise ValueError(f"Tool schema parameters.properties must be an object: {path}")

    return C2ToolSpec(
        name=name,
        description=description,
        command_template=command_template,
        parameters=parameters,
        source_path=path,
    )


def _required_string(payload: dict[str, Any], key: str, path: Path) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Tool schema field {key} must be a non-empty string: {path}")
    return value.strip()
