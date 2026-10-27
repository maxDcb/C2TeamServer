"""Upload a local file chosen by the skill into the TeamServer artifact catalog."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2
from ...grpc_status import is_response_ok, response_message
from ...operations import TeamServerOperations


@dataclass(slots=True)
class C2ArtifactUploadTool:
    grpc_client: Any
    artifact_name: str

    name = "uploadC2Artifact"
    description = "Upload a local file named in the operator's task context as a TeamServer artifact."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {
                "source_file": {"type": "string", "description": "Absolute path to the local source file."},
            }, "required": ["source_file"], "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        source_file = arguments.get("source_file") if isinstance(arguments, dict) else None
        if not isinstance(arguments, dict) or set(arguments) != {"source_file"} \
                or not isinstance(source_file, str) or not source_file.strip():
            return ToolResult(ok=False, content="Choose a local source_file from the operator's context.")
        source = Path(source_file).expanduser()
        if not source.is_absolute() or not source.is_file():
            return ToolResult(ok=False, content="source_file must be an absolute path to an existing local file.")
        try:
            data = source.read_bytes()
        except OSError as error:
            return ToolResult(ok=False, content=f"Could not read source_file: {error}")
        digest = hashlib.sha256(data).hexdigest()

        operations = TeamServerOperations(self.grpc_client)
        try:
            response = operations.upload_artifact(self.artifact_name, data, "any", "any")
        except Exception as error:
            return ToolResult(ok=False, content=f"Artifact upload outcome unknown: {error}",
                              metadata={"outcome_unknown": True, "upload_attempted": True})
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Artifact upload failed."),
                              metadata={"upload_attempted": True})

        try:
            artifacts = operations.list_artifacts(
                TeamServerApi_pb2.ArtifactQuery(name_contains=self.artifact_name))
        except Exception as error:
            return ToolResult(ok=False, content=f"Artifact was accepted but catalog lookup failed: {error}",
                              metadata={"outcome_unknown": True, "upload_attempted": True})
        matches = [item for item in artifacts
                   if str(item.name) == self.artifact_name
                   and str(item.category) == "upload"
                   and str(item.scope) == "operator"
                   and str(item.target) == "beacon"
                   and int(item.size) == len(data)
                   and str(item.sha256) == digest]
        if len(matches) != 1:
            return ToolResult(ok=False, content="Artifact was accepted but its exact catalog entry could not be verified.",
                              metadata={"outcome_unknown": True, "upload_attempted": True})
        artifact_id = str(matches[0].artifact_id)
        return ToolResult(ok=True, content=json.dumps({
            "artifact_id": artifact_id, "artifact_name": self.artifact_name,
            "source_file": str(source), "size": len(data), "sha256": digest,
        }, ensure_ascii=False), metadata={
            "artifact_id": artifact_id, "source_file": str(source), "upload_attempted": True,
        })
