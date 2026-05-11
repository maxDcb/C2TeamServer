from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from ...grpcClient import TeamServerApi_pb2

logger = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(
    r"\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::(?P<modifier>raw|q|flag))?(?P<optional>\?)?\}"
)
_OPTIONAL_SEGMENT_RE = re.compile(r"\[(?P<body>[^\[\]]+)\]")
_NON_IDENTIFIER_RE = re.compile(r"[^A-Za-z0-9_]+")
_SESSION_PROPERTIES = {
    "beacon_hash": {
        "type": "string",
        "description": "Full beacon hash for the target session.",
    },
    "listener_hash": {
        "type": "string",
        "description": "Full listener hash for the target session.",
    },
}


@dataclass(frozen=True, slots=True)
class C2CommandSpecToolSpec:
    name: str
    description: str
    command_template: str
    parameters: dict[str, Any]
    command_spec: Any


def load_command_tool_specs(grpc_client: Any) -> list[C2CommandSpecToolSpec]:
    """Load assistant tools from the TeamServer CommandSpec catalog."""

    if grpc_client is None or not hasattr(grpc_client, "listCommands"):
        return []

    try:
        commands = list(grpc_client.listCommands(TeamServerApi_pb2.CommandQuery()))
    except Exception as exc:
        logger.error("Unable to load assistant CommandSpecs from TeamServer: %s", exc)
        return []

    names = [str(getattr(command, "name", "") or "").strip() for command in commands]
    duplicates = sorted({name for name in names if name and names.count(name) > 1})
    if duplicates:
        raise ValueError(f"Duplicate TeamServer CommandSpec names: {', '.join(duplicates)}")

    return [
        command_spec_to_tool_spec(command)
        for command in sorted(commands, key=lambda item: str(getattr(item, "name", "") or ""))
        if str(getattr(command, "name", "") or "").strip()
    ]


def command_spec_to_tool_spec(command: Any) -> C2CommandSpecToolSpec:
    name = _required_text(command, "name")
    command_template = _required_text(command, "command_template")
    return C2CommandSpecToolSpec(
        name=name,
        description=_tool_description(command, command_template),
        command_template=command_template,
        parameters=_tool_parameters(command, command_template),
        command_spec=command,
    )


def command_arg_property_name(arg: Any) -> str:
    name = str(getattr(arg, "name", "") or "").strip()
    name = name.lstrip("-")
    name = name.replace("-", "_")
    name = _NON_IDENTIFIER_RE.sub("_", name).strip("_")
    if not name:
        name = "value"
    if name[0].isdigit():
        name = f"arg_{name}"
    return name


def _required_text(command: Any, field_name: str) -> str:
    value = str(getattr(command, field_name, "") or "").strip()
    if not value:
        command_name = str(getattr(command, "name", "") or "<unknown>")
        raise ValueError(f"CommandSpec `{command_name}` must define `{field_name}`")
    return value


def _tool_description(command: Any, command_template: str) -> str:
    lines = [str(getattr(command, "description", "") or "").strip()]
    details = []
    kind = str(getattr(command, "kind", "") or "").strip()
    target = str(getattr(command, "target", "") or "").strip()
    platforms = _joined(getattr(command, "platforms", []))
    archs = _joined(getattr(command, "archs", []))
    if kind:
        details.append(f"kind={kind}")
    if target:
        details.append(f"target={target}")
    if platforms:
        details.append(f"platforms={platforms}")
    if archs:
        details.append(f"archs={archs}")
    if details:
        lines.append("; ".join(details))
    if kind.lower() == "module":
        lines.append("Module command: call listLoadedModules first; load it with loadModule unless recent context confirms it is already loaded.")
    lines.append(f"Template: {command_template}")
    examples = [str(example).strip() for example in getattr(command, "examples", []) if str(example).strip()]
    if examples:
        lines.append("Examples: " + " | ".join(examples[:3]))
    return "\n".join(line for line in lines if line)


def _tool_parameters(command: Any, command_template: str) -> dict[str, Any]:
    placeholders = _template_placeholders(command_template)
    arg_by_property = {
        command_arg_property_name(arg): arg
        for arg in getattr(command, "args", [])
    }
    properties: dict[str, Any] = dict(_SESSION_PROPERTIES)
    required = ["beacon_hash", "listener_hash"]

    for placeholder in placeholders:
        if placeholder.name in properties:
            continue
        arg = arg_by_property.get(placeholder.name)
        properties[placeholder.name] = _property_schema(placeholder, arg)
        if not placeholder.optional:
            required.append(placeholder.name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _property_schema(placeholder: "_TemplatePlaceholder", arg: Any | None) -> dict[str, Any]:
    if placeholder.modifier == "flag":
        schema: dict[str, Any] = {"type": "boolean"}
    else:
        arg_type = str(getattr(arg, "type", "") or "").lower()
        if arg_type == "number":
            schema = {"type": "number"}
        else:
            schema = {"type": "string"}

    values = [str(value) for value in getattr(arg, "values", [])] if arg is not None else []
    if values and schema.get("type") == "string":
        schema["enum"] = values

    description_parts = []
    if arg is not None:
        arg_name = str(getattr(arg, "name", "") or "").strip()
        arg_description = str(getattr(arg, "description", "") or "").strip()
        if arg_name:
            description_parts.append(f"Command argument `{arg_name}`.")
        if arg_description:
            description_parts.append(arg_description)
        if _arg_has_artifact_filter(arg):
            description_parts.append("Select an artifact compatible with the CommandSpec artifact filter.")
        if bool(getattr(arg, "variadic", False)):
            description_parts.append("May contain spaces.")
    if placeholder.modifier == "raw":
        description_parts.append("Rendered raw without shell quoting.")
    if description_parts:
        schema["description"] = " ".join(description_parts)
    return schema


@dataclass(frozen=True, slots=True)
class _TemplatePlaceholder:
    name: str
    modifier: str
    optional: bool


def _template_placeholders(command_template: str) -> list[_TemplatePlaceholder]:
    optional_ranges: list[tuple[int, int]] = []
    for match in _OPTIONAL_SEGMENT_RE.finditer(command_template):
        optional_ranges.append((match.start(), match.end()))

    placeholders: list[_TemplatePlaceholder] = []
    seen: set[str] = set()
    for match in _PLACEHOLDER_RE.finditer(command_template):
        name = match.group("name")
        if name in seen:
            continue
        seen.add(name)
        optional = bool(match.group("optional")) or any(start <= match.start() < end for start, end in optional_ranges)
        placeholders.append(
            _TemplatePlaceholder(
                name=name,
                modifier=match.group("modifier") or "",
                optional=optional,
            )
        )
    return placeholders


def _arg_has_artifact_filter(arg: Any) -> bool:
    if getattr(arg, "artifact_filters", None):
        return True
    if not hasattr(arg, "artifact_filter"):
        return False
    if hasattr(arg, "HasField"):
        try:
            return bool(arg.HasField("artifact_filter"))
        except ValueError:
            return False
    return getattr(arg, "artifact_filter", None) is not None


def _joined(values: Any) -> str:
    try:
        return ", ".join(str(value) for value in values if str(value).strip())
    except TypeError:
        return ""
