"""Upload the operator-selected local file into the TeamServer artifact catalog."""

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
    source_path: str
    source_sha256: str
    artifact_name: str

    name = "uploadC2Artifact"
    description = "Upload the local file selected by the operator as a TeamServer artifact."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        if arguments:
            return ToolResult(ok=False, content="uploadC2Artifact takes no arguments.")
        try:
            data = Path(self.source_path).read_bytes()
        except OSError as error:
            return ToolResult(ok=False, content=f"Could not read selected file: {error}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != self.source_sha256:
            return ToolResult(ok=False, content="The selected file changed after this skill started.")

        operations = TeamServerOperations(self.grpc_client)
        try:
            response = operations.upload_artifact(self.artifact_name, data, "any", "any")
        except Exception as error:
            return ToolResult(ok=False, content=f"Artifact upload outcome unknown: {error}",
                              metadata={"outcome_unknown": True})
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Artifact upload failed."))

        try:
            artifacts = operations.list_artifacts(
                TeamServerApi_pb2.ArtifactQuery(name_contains=self.artifact_name))
        except Exception as error:
            return ToolResult(ok=False, content=f"Artifact was accepted but catalog lookup failed: {error}",
                              metadata={"outcome_unknown": True})
        matches = [item for item in artifacts
                   if str(item.name) == self.artifact_name
                   and str(item.category) == "upload"
                   and str(item.scope) == "operator"
                   and str(item.target) == "beacon"
                   and int(item.size) == len(data)
                   and str(item.sha256) == digest]
        if len(matches) != 1:
            return ToolResult(ok=False, content="Artifact was accepted but its exact catalog entry could not be verified.",
                              metadata={"outcome_unknown": True})
        artifact_id = str(matches[0].artifact_id)
        return ToolResult(ok=True, content=json.dumps({
            "artifact_id": artifact_id, "artifact_name": self.artifact_name,
            "source_file": self.source_path, "size": len(data), "sha256": digest,
        }, ensure_ascii=False), metadata={"artifact_id": artifact_id})
