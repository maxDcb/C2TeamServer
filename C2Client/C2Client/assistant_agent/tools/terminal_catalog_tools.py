"""Typed TeamServer inventory operations shared by conversation and skills.

These operations expose data also used by the terminal without invoking Qt or
allowing the model to send an arbitrary terminal command string.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2


@dataclass(slots=True)
class C2ListenersTool:
    grpc_client: Any

    name = "listC2Listeners"
    description = "List TeamServer listeners, their addresses, state and session counts."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        if arguments:
            return ToolResult(ok=False, content="listC2Listeners takes no arguments.")
        try:
            listeners = list(self.grpc_client.listListeners())
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not list listeners: {error}")
        entries = [{
            "listener_hash": str(item.listener_hash),
            "type": str(item.type), "ip": str(item.ip), "port": int(item.port),
            "domain": str(item.domain),
            "state": TeamServerApi_pb2.ListenerState.Name(int(item.state)),
            "session_count": int(item.session_count),
        } for item in listeners[:100]]
        return ToolResult(ok=True, content=json.dumps({
            "listeners": entries, "total": len(listeners), "truncated": len(listeners) > 100,
        }, ensure_ascii=False))


@dataclass(slots=True)
class C2ArtifactsTool:
    grpc_client: Any

    name = "listC2Artifacts"
    description = "List TeamServer artifact metadata without downloading artifact bytes."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={
                "type": "object", "properties": {
                    "name_contains": {"type": "string", "description": "Optional artifact name filter."},
                }, "additionalProperties": False,
            },
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        if set(arguments) - {"name_contains"} or not isinstance(arguments.get("name_contains", ""), str):
            return ToolResult(ok=False, content="Invalid listC2Artifacts arguments.")
        query = TeamServerApi_pb2.ArtifactQuery(name_contains=arguments.get("name_contains", ""))
        try:
            artifacts = list(self.grpc_client.listArtifacts(query))
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not list artifacts: {error}")
        entries = [{
            "artifact_id": str(item.artifact_id), "name": str(item.name),
            "display_name": str(item.display_name), "category": str(item.category),
            "platform": str(item.platform), "arch": str(item.arch),
            "size": int(item.size), "description": str(item.description),
        } for item in artifacts[:100]]
        return ToolResult(ok=True, content=json.dumps({
            "artifacts": entries, "total": len(artifacts), "truncated": len(artifacts) > 100,
        }, ensure_ascii=False))
