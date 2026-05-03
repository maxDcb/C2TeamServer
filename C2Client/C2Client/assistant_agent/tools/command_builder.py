from __future__ import annotations

import re
from typing import Any

from .loader import C2ToolSpec

_PLACEHOLDER_RE = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::(?P<modifier>raw|q))?(?P<optional>\?)?\}")


def quote_argument(value: object) -> str:
    if value is None:
        return '""'

    text = str(value)
    if not text:
        return '""'

    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text

    if any(ch.isspace() for ch in text) or '"' in text:
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'

    return text


def build_command_line(spec: C2ToolSpec, arguments: dict[str, Any]) -> str:
    _validate_required_arguments(spec, arguments)

    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        modifier = match.group("modifier")
        optional = bool(match.group("optional"))

        if name not in arguments:
            if optional:
                return ""
            raise KeyError(f"Missing command template argument: {name}")

        value = arguments[name]
        if value is None or (isinstance(value, str) and not value.strip()):
            if optional:
                return ""
            raise ValueError(f"Argument must not be empty: {name}")

        if modifier == "raw":
            return str(value).strip()
        if modifier == "q":
            return quote_argument(str(value).strip())
        return str(value).strip()

    rendered = _PLACEHOLDER_RE.sub(replace, spec.command_template)
    return " ".join(rendered.split())


def _validate_required_arguments(spec: C2ToolSpec, arguments: dict[str, Any]) -> None:
    required = spec.parameters.get("required", [])
    if not isinstance(required, list):
        return
    missing = [key for key in required if key not in arguments]
    if missing:
        raise KeyError(f"Missing required argument(s) for `{spec.name}`: {', '.join(missing)}")
    for key in required:
        value = arguments.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValueError(f"Argument must not be empty: {key}")
