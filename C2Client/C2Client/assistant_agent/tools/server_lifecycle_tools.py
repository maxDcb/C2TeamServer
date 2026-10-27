"""Typed listener and session lifecycle operations shared with the Qt client."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2
from ...grpc_status import is_response_ok, response_message
from ...operations import TeamServerOperations
from .validation import validate_tool_arguments


def _ack_result(send: Any, details: dict[str, Any]) -> ToolResult:
    try:
        response = send()
    except Exception as error:
        return ToolResult(ok=False, content=f"TeamServer operation outcome unknown: {error}",
                          metadata={"outcome_unknown": True})
    if response is None or not hasattr(response, "status"):
        return ToolResult(ok=False, content="TeamServer operation outcome unknown: no acknowledgement.",
                          metadata={"outcome_unknown": True})
    if not is_response_ok(response):
        return ToolResult(ok=False, content=response_message(response, "TeamServer operation failed."))
    result = {**details, "message": response_message(response, "ok")}
    listener_hash = str(getattr(response, "listener_hash", "") or "")
    if listener_hash:
        result["listener_hash"] = listener_hash
    return ToolResult(ok=True, content=json.dumps(result, ensure_ascii=False))


@dataclass(slots=True)
class C2AddListenerTool:
    grpc_client: Any

    name = "addC2Listener"
    description = "Create a primary TeamServer HTTP, HTTPS, TCP, DNS, or GitHub listener."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "type": {"type": "string", "enum": ["http", "https", "tcp", "dns", "github"]},
                "ip": {"type": "string", "description": "Bind IP for HTTP, HTTPS or TCP."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "domain": {"type": "string", "description": "DNS domain for a DNS listener."},
                "project": {"type": "string", "description": "Repository for a GitHub listener."},
                "token": {"type": "string", "description": "GitHub listener token."},
            }, "required": ["type"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        listener_type = arguments["type"]
        fields = set(arguments)
        expected = ({"type", "ip", "port"} if listener_type in {"http", "https", "tcp"}
                    else {"type", "domain", "port"} if listener_type == "dns"
                    else {"type", "project", "token"})
        if fields != expected or any(not str(arguments[key]).strip() for key in expected - {"type", "port"}):
            return ToolResult(ok=False, content=f"{listener_type} requires exactly {', '.join(sorted(expected))}.")
        supported = getattr(self.grpc_client, "available_listener_types", None)
        if supported is not None and listener_type not in supported:
            return ToolResult(ok=False, content=f"Listener type {listener_type} is unavailable on this TeamServer.")
        request = TeamServerApi_pb2.Listener(**arguments)
        return _ack_result(lambda: TeamServerOperations(self.grpc_client).add_listener(request),
                           {key: value for key, value in arguments.items() if key != "token"})


@dataclass(slots=True)
class C2StopListenerTool:
    grpc_client: Any

    name = "stopC2Listener"
    description = "Stop a TeamServer listener by its full hash."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {"listener_hash": {"type": "string"}},
            "required": ["listener_hash"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        selector = TeamServerApi_pb2.ListenerSelector(listener_hash=arguments["listener_hash"])
        return _ack_result(lambda: TeamServerOperations(self.grpc_client).stop_listener(selector),
                           {"listener_hash": arguments["listener_hash"]})


@dataclass(slots=True)
class C2StopSessionTool:
    grpc_client: Any

    name = "stopC2Session"
    description = "Queue a stop request for an exact beacon and listener route."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "beacon_hash": {"type": "string"}, "listener_hash": {"type": "string"},
            }, "required": ["beacon_hash", "listener_hash"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        selector = TeamServerApi_pb2.SessionSelector(**arguments)
        return _ack_result(lambda: TeamServerOperations(self.grpc_client).stop_session(selector),
                           {"beacon_hash": arguments["beacon_hash"], "listener_hash": arguments["listener_hash"]})


@dataclass(slots=True)
class C2SessionHistoryTool:
    grpc_client: Any

    name = "listC2SessionHistory"
    description = "List current and archived TeamServer sessions."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {"beacon_prefix": {"type": "string"}},
            "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        try:
            sessions = TeamServerOperations(self.grpc_client).list_session_history()
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not list session history: {error}")
        prefix = arguments.get("beacon_prefix", "")
        matches = [item for item in sessions if str(item.beacon_hash).startswith(prefix)]
        return ToolResult(ok=True, content=json.dumps({
            "sessions": [{
                "beacon_hash": str(item.beacon_hash), "listener_hash": str(item.listener_hash),
                "hostname": str(item.hostname), "username": str(item.username),
                "state": TeamServerApi_pb2.SessionState.Name(int(item.state)),
                "archived": bool(item.archived), "last_seen_at_ms": int(item.last_seen_at_ms),
            } for item in matches[:100]],
            "total": len(matches), "truncated": len(matches) > 100,
        }, ensure_ascii=False))
