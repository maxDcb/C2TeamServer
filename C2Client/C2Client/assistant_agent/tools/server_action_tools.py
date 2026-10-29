"""Typed TeamServer actions available to the assistant."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...operations import TeamServerOperations


def _tool_result(outcome: Any) -> ToolResult:
    return ToolResult(
        ok=outcome.ok, content=outcome.output,
        metadata={"job_id": outcome.job_id, "outcome_unknown": outcome.outcome_unknown},
    )


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

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        if set(arguments) - {"artifact_reference", "listener_hash", "hosted_filename"}:
            return ToolResult(ok=False, content="Unknown hostArtifact argument.")
        listener = arguments.get("listener_hash")
        artifact = arguments.get("artifact_reference")
        filename = arguments.get("hosted_filename", "")
        if not isinstance(listener, str) or not listener or not isinstance(artifact, str) or not artifact \
                or not isinstance(filename, str):
            return ToolResult(ok=False, content="Invalid hostArtifact arguments.")
        outcome = TeamServerOperations(self.grpc_client).host_artifact(
            listener, artifact, filename, job_id=operation_id, origin="assistant")
        return _tool_result(outcome)


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

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        action = arguments.get("action")
        beacon = arguments.get("beacon_hash", "")
        if set(arguments) - {"action", "beacon_hash"} or action not in {"start", "stop", "bind", "unbind"} \
                or not isinstance(beacon, str) or (action == "bind") != bool(beacon):
            return ToolResult(ok=False, content="Invalid SOCKS action or arguments.")
        outcome = TeamServerOperations(self.grpc_client).control_socks(
            action, beacon, job_id=operation_id, origin="assistant")
        return _tool_result(outcome)


@dataclass(slots=True)
class C2ReloadModulesTool:
    grpc_client: Any

    name = "reloadModules"
    description = "Reload TeamServer command modules from disk."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        if arguments:
            return ToolResult(ok=False, content="reloadModules takes no arguments.")
        outcome = TeamServerOperations(self.grpc_client).reload_modules(
            job_id=operation_id, origin="assistant")
        return _tool_result(outcome)
