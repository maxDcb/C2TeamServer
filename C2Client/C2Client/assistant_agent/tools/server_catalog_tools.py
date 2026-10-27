"""Typed TeamServer inventory operations shared by conversation and skills.

These operations expose data also used by the terminal without invoking Qt or
allowing the model to send an arbitrary terminal command string.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2
from ...operations import TeamServerOperations
from ...grpc_status import is_response_ok, response_message


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
            listeners = TeamServerOperations(self.grpc_client).list_listeners()
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
            artifacts = TeamServerOperations(self.grpc_client).list_artifacts(query)
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


@dataclass(slots=True)
class C2ListenerInfoTool:
    grpc_client: Any

    name = "infoListener"
    description = "Read the resolved address and download URI of one TeamServer listener."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {
                "listener_hash": {"type": "string"},
            }, "required": ["listener_hash"], "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        listener_hash = arguments.get("listener_hash")
        if set(arguments) != {"listener_hash"} or not isinstance(listener_hash, str) or not listener_hash:
            return ToolResult(ok=False, content="A listener hash is required.")
        try:
            response = TeamServerOperations(self.grpc_client).get_listener_info(listener_hash)
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read listener info: {error}")
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Listener lookup failed."))
        return ToolResult(ok=True, content=json.dumps({
            "listener_hash": listener_hash, "type": response.type,
            "address": response.address, "port": response.port,
            "download_uri": response.download_uri,
        }, ensure_ascii=False))


@dataclass(slots=True)
class C2BeaconBinaryInfoTool:
    grpc_client: Any

    name = "getBeaconBinary"
    description = "Check that a beacon binary exists and return its byte count and SHA-256 digest."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {
                "listener_hash": {"type": "string"},
                "target_os": {"type": "string", "enum": ["windows", "linux"]},
                "target_arch": {"type": "string", "description": "Optional architecture; server default when omitted."},
            }, "required": ["listener_hash", "target_os"], "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        listener_hash = arguments.get("listener_hash")
        target_os = arguments.get("target_os")
        target_arch = arguments.get("target_arch", "")
        if set(arguments) - {"listener_hash", "target_os", "target_arch"} \
                or not isinstance(listener_hash, str) or not listener_hash \
                or target_os not in {"windows", "linux"} or not isinstance(target_arch, str):
            return ToolResult(ok=False, content="Invalid beacon binary lookup arguments.")
        try:
            response = TeamServerOperations(self.grpc_client).get_beacon_binary(
                listener_hash, target_os, target_arch)
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read beacon binary: {error}")
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Beacon binary lookup failed."))
        data = bytes(response.data)
        return ToolResult(ok=True, content=json.dumps({
            "listener_hash": listener_hash, "target_os": target_os,
            "target_arch": target_arch or "server default", "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }, ensure_ascii=False))
