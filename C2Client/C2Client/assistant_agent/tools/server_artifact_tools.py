"""Artifact download and deletion actions exposed to conversation and skills."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpc_status import is_response_ok, response_message
from ...operations import TeamServerOperations
from .artifact_upload_tool import upload_verified_artifact
from .validation import validate_tool_arguments


@dataclass(slots=True)
class C2ArtifactDownloadTool:
    grpc_client: Any

    name = "downloadC2Artifact"
    description = "Save one TeamServer artifact to an explicit local absolute file path."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "artifact_id": {"type": "string"},
                "destination_path": {"type": "string", "description": "Absolute path on the operator's computer."},
                "overwrite": {"type": "boolean", "description": "Allow replacing an existing local file."},
            }, "required": ["artifact_id", "destination_path"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        destination = Path(arguments["destination_path"]).expanduser()
        if not destination.is_absolute() or not destination.parent.is_dir():
            return ToolResult(ok=False, content="destination_path must be an absolute file path with an existing parent directory.")
        if destination.exists() and not arguments.get("overwrite", False):
            return ToolResult(ok=False, content="The destination already exists; set overwrite to true to replace it.")
        try:
            response = TeamServerOperations(self.grpc_client).download_artifact(arguments["artifact_id"])
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not download artifact: {error}")
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Artifact download failed."))
        data = bytes(response.data)
        try:
            with destination.open("wb" if arguments.get("overwrite", False) else "xb") as stream:
                stream.write(data)
        except OSError as error:
            return ToolResult(ok=False, content=f"Could not save artifact locally: {error}")
        return ToolResult(ok=True, content=json.dumps({
            "artifact_id": arguments["artifact_id"], "destination_path": str(destination),
            "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        }, ensure_ascii=False))


@dataclass(slots=True)
class C2ArtifactDeleteTool:
    grpc_client: Any

    name = "deleteC2Artifact"
    description = "Delete a generated, hosted, or operator-uploaded TeamServer artifact by ID."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {"artifact_id": {"type": "string"}},
            "required": ["artifact_id"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        try:
            response = TeamServerOperations(self.grpc_client).delete_artifact(arguments["artifact_id"])
        except Exception as error:
            return ToolResult(ok=False, content=f"Artifact deletion outcome unknown: {error}",
                              metadata={"outcome_unknown": True})
        if response is None or not hasattr(response, "status"):
            return ToolResult(ok=False, content="Artifact deletion outcome unknown: no acknowledgement.",
                              metadata={"outcome_unknown": True})
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Artifact deletion failed."))
        return ToolResult(ok=True, content=json.dumps({
            "artifact_id": arguments["artifact_id"], "message": response_message(response, "deleted"),
        }, ensure_ascii=False))


@dataclass(slots=True)
class C2ArtifactPromoteTool:
    grpc_client: Any

    name = "promoteC2Artifact"
    description = ("Copy a downloaded or generated TeamServer artifact into the operator upload "
                   "catalog so its new ID can be sent to a beacon session. No local path is needed.")

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "artifact_id": {"type": "string", "description": "Source TeamServer artifact ID."},
                "name": {"type": "string", "description": "Name for the upload artifact; defaults to source name."},
                "platform": {"type": "string", "description": "Target platform; defaults to any."},
                "arch": {"type": "string", "description": "Target architecture; defaults to any."},
            }, "required": ["artifact_id"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        source_id = arguments["artifact_id"]
        if not source_id.strip():
            return ToolResult(ok=False, content="artifact_id must be nonempty.")
        try:
            source = TeamServerOperations(self.grpc_client).download_artifact(source_id)
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read source artifact: {error}")
        if not is_response_ok(source):
            return ToolResult(ok=False, content=response_message(source, "Source artifact download failed."))
        if source.artifact_id and source.artifact_id != source_id:
            return ToolResult(ok=False, content="Source artifact ID did not match the requested ID.")
        name = arguments.get("name") or str(source.name or source.display_name or source_id)
        result = upload_verified_artifact(self.grpc_client, name=name, data=bytes(source.data),
                                          platform=arguments.get("platform", "any"),
                                          arch=arguments.get("arch", "any"))
        if not result.ok:
            return result
        payload = json.loads(result.content)
        payload["source_artifact_id"] = source_id
        return ToolResult(ok=True, content=json.dumps(payload, ensure_ascii=False), metadata={
            **result.metadata, "source_artifact_id": source_id,
        })
