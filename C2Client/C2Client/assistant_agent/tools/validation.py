"""Validate model-supplied tool arguments before any TeamServer RPC."""

from __future__ import annotations

import json
import math
from typing import Any

from agent_core.spi import ToolResult


def validate_tool_arguments(name: str, schema: dict[str, Any], arguments: Any) -> ToolResult | None:
    issues: list[dict[str, str]] = []
    _validate(schema, arguments, "$", issues)
    if not issues:
        return None

    error = {"code": "invalid_arguments", "tool": name, "details": issues}
    return ToolResult(
        ok=False,
        content=json.dumps(error, ensure_ascii=False),
        metadata={"status": "invalid_arguments", "error": error},
    )


def _validate(schema: dict[str, Any], value: Any, path: str, issues: list[dict[str, str]]) -> None:
    expected = schema.get("type")
    if expected is not None and not _matches_type(expected, value):
        issues.append({"path": path, "reason": f"expected {expected}"})
        return

    if "enum" in schema and not any(_same_json_value(value, choice) for choice in schema["enum"]):
        issues.append({"path": path, "reason": "value is not in the allowed enum"})

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                issues.append({"path": f"{path}.{key}", "reason": "required argument is missing"})
            elif isinstance(value[key], str) and not value[key].strip():
                issues.append({"path": f"{path}.{key}", "reason": "required argument is empty"})
        for key, item in value.items():
            child = properties.get(key)
            if child is None:
                if schema.get("additionalProperties") is False:
                    issues.append({"path": f"{path}.{key}", "reason": "unknown argument"})
            else:
                _validate(child, item, f"{path}.{key}", issues)
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                _validate(items, item, f"{path}[{index}]", issues)
    elif isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            issues.append({"path": path, "reason": "string is too short"})
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            issues.append({"path": path, "reason": "string is too long"})
    elif _matches_type("number", value):
        if "minimum" in schema and value < schema["minimum"]:
            issues.append({"path": path, "reason": "number is below minimum"})
        if "maximum" in schema and value > schema["maximum"]:
            issues.append({"path": path, "reason": "number is above maximum"})


def _matches_type(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if expected == "null":
        return value is None
    return False


def _same_json_value(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right
