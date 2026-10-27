"""Typed terminal operations with no Qt or arbitrary command surface."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2
from ...grpc_status import is_response_ok, terminal_response_text


def _terminal_token(value: str) -> str:
    if not isinstance(value, str) or not value or "'" in value or any(ord(char) < 32 for char in value):
        raise ValueError("Terminal arguments must be nonempty and contain no apostrophes or control characters.")
    return f"'{value}'" if " " in value else value


@dataclass(slots=True)
class C2HostArtifactTool:
    grpc_client: Any

    name = "hostArtifact"
    description = "Host an existing TeamServer artifact through an HTTP or HTTPS listener."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={
                "type": "object", "properties": {
                    "artifact_reference": {"type": "string", "description": "Artifact ID or exact artifact name."},
                    "listener_hash": {"type": "string", "description": "Full HTTP/HTTPS listener hash."},
                    "hosted_filename": {"type": "string", "description": "Optional URL filename."},
                }, "required": ["artifact_reference", "listener_hash"],
                "additionalProperties": False,
            },
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        if set(arguments) - {"artifact_reference", "listener_hash", "hosted_filename"}:
            return ToolResult(ok=False, content="Unknown hostArtifact argument.")
        try:
            tokens = [
                "hostArtifact", _terminal_token(arguments["listener_hash"]),
                _terminal_token(arguments["artifact_reference"]),
            ]
            if "hosted_filename" in arguments:
                tokens.append(_terminal_token(arguments["hosted_filename"]))
            response = self.grpc_client.executeTerminalCommand(
                TeamServerApi_pb2.TerminalCommandRequest(command=" ".join(tokens)),
            )
        except (KeyError, ValueError, TypeError) as error:
            return ToolResult(ok=False, content=f"Invalid hostArtifact arguments: {error}")
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not host artifact: {error}")
        content = terminal_response_text(response).strip()
        if not is_response_ok(response):
            return ToolResult(ok=False, content=content)
        if not content.startswith(("https://", "http://")):
            return ToolResult(ok=False, content="TeamServer did not return a hosted artifact URL.")
        return ToolResult(ok=True, content=content)


@dataclass(slots=True)
class C2SocksControlTool:
    grpc_client: Any

    name = "socksControl"
    description = "Start, stop, bind or unbind the TeamServer SOCKS bridge."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={
                "type": "object", "properties": {
                    "action": {"type": "string", "enum": ["start", "stop", "bind", "unbind"]},
                    "beacon_hash": {"type": "string", "description": "Full beacon hash, required for bind."},
                }, "required": ["action"], "additionalProperties": False,
            },
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        action = arguments.get("action")
        if set(arguments) - {"action", "beacon_hash"} or not isinstance(action, str) \
                or action not in {"start", "stop", "bind", "unbind"}:
            return ToolResult(ok=False, content="Invalid SOCKS action or arguments.")
        if (action == "bind") != bool(arguments.get("beacon_hash")):
            return ToolResult(ok=False, content="beacon_hash is required only for bind.")
        try:
            command = f"socks {action}"
            if action == "bind":
                command += " " + _terminal_token(arguments["beacon_hash"])
            response = self.grpc_client.executeTerminalCommand(
                TeamServerApi_pb2.TerminalCommandRequest(command=command),
            )
        except (ValueError, TypeError) as error:
            return ToolResult(ok=False, content=f"Invalid SOCKS argument: {error}")
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not control SOCKS: {error}")
        return ToolResult(ok=is_response_ok(response), content=terminal_response_text(response))
