"""Typed file operations using existing TeamServer artifacts as byte sources."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpc_status import is_response_ok, response_message
from ...operations import TeamServerOperations


_FILENAME = re.compile(r"[A-Za-z0-9_.-]+\Z")


def _valid_filename(value: Any) -> bool:
    return isinstance(value, str) and value not in {"", ".", ".."} and bool(_FILENAME.fullmatch(value))


def _artifact_data(operations: TeamServerOperations, artifact_id: str) -> bytes:
    response = operations.download_artifact(artifact_id)
    if not is_response_ok(response):
        raise ValueError(response_message(response, "Artifact download failed."))
    return bytes(response.data)


def _write_result(send: Any, details: dict[str, Any]) -> ToolResult:
    try:
        response = send()
    except Exception as error:
        return ToolResult(ok=False, content=f"TeamServer operation outcome unknown: {error}",
                          metadata={"outcome_unknown": True})
    if not is_response_ok(response):
        return ToolResult(ok=False, content=response_message(response, "TeamServer operation failed."))
    return ToolResult(ok=True, content=json.dumps({
        **details, "message": response_message(response, "ok"),
    }, ensure_ascii=False))


@dataclass(slots=True)
class C2UploadListenerFileTool:
    grpc_client: Any

    name = "uploadListenerFile"
    description = "Copy an existing TeamServer artifact into a listener's download directory."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {
                "listener_hash": {"type": "string"},
                "artifact_id": {"type": "string", "description": "Existing TeamServer artifact ID."},
                "filename": {"type": "string", "description": "Exact destination basename."},
            }, "required": ["listener_hash", "artifact_id", "filename"],
                "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        if set(arguments) != {"listener_hash", "artifact_id", "filename"} \
                or not isinstance(arguments.get("listener_hash"), str) or not arguments["listener_hash"] \
                or not isinstance(arguments.get("artifact_id"), str) or not arguments["artifact_id"] \
                or not _valid_filename(arguments.get("filename")):
            return ToolResult(ok=False, content="Invalid listener file arguments.")
        operations = TeamServerOperations(self.grpc_client)
        try:
            data = _artifact_data(operations, arguments["artifact_id"])
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read artifact: {error}")
        return _write_result(lambda: operations.upload_listener_file(
            arguments["listener_hash"], arguments["filename"], data), {
                "listener_hash": arguments["listener_hash"], "artifact_id": arguments["artifact_id"],
                "filename": arguments["filename"], "size": len(data),
            })


@dataclass(slots=True)
class C2InstallToolTool:
    grpc_client: Any

    name = "installTool"
    description = "Install an existing TeamServer artifact as a named server tool."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {
                "artifact_id": {"type": "string", "description": "Existing TeamServer artifact ID."},
                "filename": {"type": "string", "description": "Exact destination basename."},
            }, "required": ["artifact_id", "filename"], "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        if set(arguments) != {"artifact_id", "filename"} \
                or not isinstance(arguments.get("artifact_id"), str) or not arguments["artifact_id"] \
                or not _valid_filename(arguments.get("filename")):
            return ToolResult(ok=False, content="Invalid tool installation arguments.")
        operations = TeamServerOperations(self.grpc_client)
        try:
            data = _artifact_data(operations, arguments["artifact_id"])
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read artifact: {error}")
        return _write_result(lambda: operations.install_tool(arguments["filename"], data), {
            "artifact_id": arguments["artifact_id"], "filename": arguments["filename"], "size": len(data),
        })


@dataclass(slots=True)
class C2InstallToolBundleTool:
    grpc_client: Any

    name = "installToolBundle"
    description = "Install several existing TeamServer artifacts as one tool bundle."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {
                "files": {"type": "array", "minItems": 1, "maxItems": 16, "items": {
                    "type": "object", "properties": {
                        "artifact_id": {"type": "string"}, "filename": {"type": "string"},
                    }, "required": ["artifact_id", "filename"], "additionalProperties": False,
                }},
            }, "required": ["files"], "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        files = arguments.get("files")
        if set(arguments) != {"files"} or not isinstance(files, list) or not 1 <= len(files) <= 16 \
                or any(not isinstance(item, dict) or set(item) != {"artifact_id", "filename"}
                       or not isinstance(item.get("artifact_id"), str) or not item["artifact_id"]
                       or not _valid_filename(item.get("filename")) for item in files) \
                or len({item["filename"] for item in files}) != len(files):
            return ToolResult(ok=False, content="Invalid tool bundle manifest.")
        operations = TeamServerOperations(self.grpc_client)
        try:
            payloads = [(item["filename"], _artifact_data(operations, item["artifact_id"])) for item in files]
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read bundle artifact: {error}")
        return _write_result(lambda: operations.install_tool_bundle(payloads), {
            "files": [{"artifact_id": item["artifact_id"], "filename": item["filename"],
                       "size": len(data)} for item, (_, data) in zip(files, payloads)],
        })
