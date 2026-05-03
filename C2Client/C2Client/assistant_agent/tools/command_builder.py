from __future__ import annotations

import re
from typing import Any

from .loader import C2ToolSpec

_OPTIONAL_SEGMENT_RE = re.compile(r"\[(?P<body>[^\[\]]+)\]")
_PLACEHOLDER_RE = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::(?P<modifier>raw|q|flag))?(?P<optional>\?)?\}")


class _OmitOptionalSegment(Exception):
    pass


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

    def render_optional_segment(match: re.Match[str]) -> str:
        body = match.group("body")
        try:
            return _render_template_part(body, arguments, implicit_optional=True)
        except _OmitOptionalSegment:
            return ""

    template = _OPTIONAL_SEGMENT_RE.sub(render_optional_segment, spec.command_template)
    rendered = _render_template_part(template, arguments, implicit_optional=False)
    return " ".join(rendered.split())


def _render_template_part(template: str, arguments: dict[str, Any], *, implicit_optional: bool) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        modifier = match.group("modifier")
        optional = bool(match.group("optional")) or implicit_optional

        if name not in arguments:
            if optional:
                if implicit_optional:
                    raise _OmitOptionalSegment()
                return ""
            raise KeyError(f"Missing command template argument: {name}")

        value = arguments[name]
        if modifier == "flag":
            if value is True:
                return ""
            if optional:
                if implicit_optional:
                    raise _OmitOptionalSegment()
                return ""
            raise ValueError(f"Flag argument must be true: {name}")

        if value is None or (isinstance(value, str) and not value.strip()):
            if optional:
                if implicit_optional:
                    raise _OmitOptionalSegment()
                return ""
            raise ValueError(f"Argument must not be empty: {name}")

        if modifier == "raw":
            return str(value).strip()
        if modifier == "q":
            return quote_argument(str(value).strip())
        return str(value).strip()

    return _PLACEHOLDER_RE.sub(replace, template)


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
