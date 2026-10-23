from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2
from .validation import validate_tool_arguments


@dataclass(slots=True)
class C2LoadedModulesTool:
    grpc_client: Any

    name = "listLoadedModules"
    description = "List modules currently tracked for a beacon session. Use this before running module commands."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "Full beacon hash for the target session.",
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "Full listener hash for the target session.",
                    },
                },
                "required": ["beacon_hash", "listener_hash"],
                "additionalProperties": False,
            },
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        modules = list_loaded_modules(
            self.grpc_client,
            beacon_hash=arguments["beacon_hash"],
            listener_hash=arguments["listener_hash"],
        )
        return ToolResult(ok=True, content=format_loaded_modules(modules))


def list_loaded_modules(grpc_client: Any, *, beacon_hash: str, listener_hash: str) -> list[Any]:
    if grpc_client is None or not hasattr(grpc_client, "listModules"):
        return []
    session = TeamServerApi_pb2.SessionSelector(
        beacon_hash=beacon_hash,
        listener_hash=listener_hash,
    )
    return list(grpc_client.listModules(session))


def has_loaded_module(grpc_client: Any, *, beacon_hash: str, listener_hash: str, module_name: str) -> bool | None:
    if grpc_client is None or not hasattr(grpc_client, "listModules"):
        return None
    try:
        modules = list_loaded_modules(grpc_client, beacon_hash=beacon_hash, listener_hash=listener_hash)
    except Exception:
        return None

    module = find_module_record(modules, module_name)
    return module is not None and str(getattr(module, "state", "") or "").lower() == "loaded"


def find_module_record(modules: list[Any], module_name: str) -> Any | None:
    expected = _normalize_module_name(module_name)
    return next(
        (module for module in modules if _normalize_module_name(getattr(module, "name", "")) == expected),
        None,
    )


def format_loaded_modules(modules: list[Any]) -> str:
    rows = []
    for module in modules:
        name = str(getattr(module, "name", "") or "").strip()
        if not name:
            continue
        state = str(getattr(module, "state", "") or "unknown").strip() or "unknown"
        rows.append((name, state))

    if not rows:
        return "No loaded modules."

    name_width = max(len("name"), *(len(name) for name, _state in rows))
    lines = [f"{'name'.ljust(name_width)}  status"]
    for name, state in rows:
        lines.append(f"{name.ljust(name_width)}  {state}")
    return "\n".join(lines)


def _normalize_module_name(value: Any) -> str:
    text = str(value or "").strip()
    if "." in text:
        text = text.rsplit(".", 1)[0]
    if text.lower().startswith("lib") and len(text) > 3:
        text = text[3:]
    aliases = {
        "printworkingdirectory": "pwd",
        "changedirectory": "cd",
        "listdirectory": "ls",
        "listprocesses": "ps",
        "ipconfig": "ipConfig",
        "mkdir": "mkDir",
    }
    return aliases.get(text.lower(), text).lower()
