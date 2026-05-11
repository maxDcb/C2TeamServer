from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core.execution_context import ExecutionContext
from agent_core.llm.base import LLMToolDefinition
from agent_core.tools import build_tool_definition
from agent_core.types import ToolResult

from ...grpcClient import TeamServerApi_pb2


@dataclass(slots=True)
class C2CommandHelpTool:
    grpc_client: Any

    name = "getCommandHelp"
    description = "Fetch exact command help from the TeamServer CommandSpec catalog. Pass a bare command name such as sleep or assemblyExec."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "Optional full beacon hash for platform-aware help.",
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "Optional full listener hash for platform-aware help.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command name to document.",
                    },
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        command = _help_command(arguments["command"])
        request = TeamServerApi_pb2.CommandHelpRequest(
            session=TeamServerApi_pb2.SessionSelector(
                beacon_hash=arguments.get("beacon_hash", ""),
                listener_hash=arguments.get("listener_hash", ""),
            ),
            command=command,
        )
        response = self.grpc_client.getCommandHelp(request)
        if getattr(response, "status", TeamServerApi_pb2.OK) != TeamServerApi_pb2.OK:
            message = getattr(response, "message", "") or "Command help was rejected by TeamServer."
            return ToolResult(ok=False, content=message)
        return ToolResult(ok=True, content=getattr(response, "help", "") or getattr(response, "message", ""))


def _help_command(command: str) -> str:
    command = str(command or "").strip()
    if not command:
        return "help"
    if command.lower() == "help" or command.lower().startswith("help "):
        return command
    return f"help {command}"
