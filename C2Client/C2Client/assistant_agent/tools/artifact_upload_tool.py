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


def upload_verified_artifact(grpc_client: Any, *, name: str, data: bytes,
                             platform: str = "any", arch: str = "any") -> ToolResult:
    """Upload bytes and return only an exact, usable operator-upload catalog ID."""
    digest = hashlib.sha256(data).hexdigest()
    operations = TeamServerOperations(grpc_client)
    try:
        response = operations.upload_artifact(name, data, platform, arch)
    except Exception as error:
        return ToolResult(ok=False, content=f"Artifact upload outcome unknown: {error}",
                          metadata={"outcome_unknown": True, "upload_attempted": True})
    if response is None or not hasattr(response, "status"):
        return ToolResult(ok=False, content="Artifact upload outcome unknown: no acknowledgement.",
                          metadata={"outcome_unknown": True, "upload_attempted": True})
    if not is_response_ok(response):
        return ToolResult(ok=False, content=response_message(response, "Artifact upload failed."),
                          metadata={"upload_attempted": True})
    try:
        artifacts = operations.list_artifacts(TeamServerApi_pb2.ArtifactQuery(name_contains=name))
    except Exception as error:
        return ToolResult(ok=False, content=f"Artifact was accepted but catalog lookup failed: {error}",
                          metadata={"outcome_unknown": True, "upload_attempted": True})
    acknowledged_id = str(getattr(response, "artifact_id", ""))
    matches = [item for item in artifacts
               if str(item.name) == name
               and (not acknowledged_id or str(item.artifact_id) == acknowledged_id)
               and str(getattr(item, "platform", platform)) == platform
               and str(getattr(item, "arch", arch)) == arch
               and str(item.category) == "upload" and str(item.scope) == "operator"
               and str(item.target) == "beacon" and int(item.size) == len(data)
               and str(item.sha256) == digest]
    if len(matches) != 1:
        return ToolResult(ok=False, content="Artifact was accepted but its exact catalog entry could not be verified.",
                          metadata={"outcome_unknown": True, "upload_attempted": True})
    artifact_id = str(matches[0].artifact_id)
    return ToolResult(ok=True, content=json.dumps({
        "artifact_id": artifact_id, "artifact_name": name,
        "size": len(data), "sha256": digest,
    }, ensure_ascii=False), metadata={"artifact_id": artifact_id, "upload_attempted": True})


@dataclass(slots=True)
class C2ArtifactUploadTool:
    grpc_client: Any
    artifact_name: str = ""

    name = "uploadC2Artifact"
    description = ("Upload the exact local absolute file named by the operator as a TeamServer artifact; "
                   "this transfer tool can read outside the generic code roots.")

    def schema(self) -> LLMToolDefinition:
        properties = {
            "source_file": {"type": "string", "description": "Absolute path to the local source file."},
        }
        if not self.artifact_name:
            properties.update({
                "name": {"type": "string", "description": "Optional artifact name; defaults to source filename."},
                "platform": {"type": "string", "description": "Target platform; defaults to any."},
                "arch": {"type": "string", "description": "Target architecture; defaults to any."},
            })
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": properties,
                        "required": ["source_file"], "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        source_file = arguments.get("source_file") if isinstance(arguments, dict) else None
        permitted = {"source_file"} if self.artifact_name else {"source_file", "name", "platform", "arch"}
        if not isinstance(arguments, dict) or set(arguments) - permitted \
                or not isinstance(source_file, str) or not source_file.strip():
            return ToolResult(ok=False, content="Choose a local source_file from the operator's context.")
        for key in permitted - {"source_file"}:
            if key in arguments and (not isinstance(arguments[key], str) or not arguments[key].strip()):
                return ToolResult(ok=False, content=f"{key} must be nonempty text.")
        source = Path(source_file).expanduser()
        if not source.is_absolute() or not source.is_file():
            return ToolResult(ok=False, content="source_file must be an absolute path to an existing local file.")
        try:
            data = source.read_bytes()
        except OSError as error:
            return ToolResult(ok=False, content=f"Could not read source_file: {error}")
        artifact_name = self.artifact_name or arguments.get("name", source.name)
        platform = arguments.get("platform", "any")
        arch = arguments.get("arch", "any")
        result = upload_verified_artifact(self.grpc_client, name=artifact_name, data=data,
                                          platform=platform, arch=arch)
        if not result.ok:
            return result
        payload = json.loads(result.content)
        payload["source_file"] = str(source)
        return ToolResult(ok=True, content=json.dumps(payload, ensure_ascii=False), metadata={
            **result.metadata, "source_file": str(source),
        })
