"""Typed TeamServer credential vault operations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2
from ...grpc_status import is_response_ok, response_message
from ...operations import TeamServerOperations
from .validation import validate_tool_arguments


_METADATA_FIELDS = (
    "display_name", "type", "username", "domain", "realm", "target",
    "protocol", "tags", "description", "expires_at",
)
_METADATA_PROPERTIES = {
    field: ({"type": "array", "items": {"type": "string"}} if field == "tags" else {"type": "string"})
    for field in _METADATA_FIELDS
}
_SECRETS_PROPERTY = {"type": "array", "items": {
    "type": "object", "properties": {"name": {"type": "string"}, "value": {"type": "string"}},
    "required": ["name", "value"], "additionalProperties": False,
}}


def _valid_secrets(value: Any, *, require_nonempty: bool) -> bool:
    return isinstance(value, list) and (bool(value) or not require_nonempty) and all(
        isinstance(item, dict) and set(item) == {"name", "value"}
        and all(isinstance(item[key], str) and item[key].strip() for key in ("name", "value"))
        for item in value
    )


def _summary(item: Any) -> dict:
    return {
        field: list(getattr(item, field)) if field in {"tags", "secret_fields"}
        else str(getattr(item, field, ""))
        for field in ("credential_id", *_METADATA_FIELDS, "secret_fields", "created_at", "updated_at")
        if field != "expires_at" or hasattr(item, field)
    }


def _request(arguments: dict, *, update: bool) -> Any:
    request = TeamServerApi_pb2.CredentialUpsertRequest()
    if update:
        request.credential_id = arguments["credential_id"]
    for field in _METADATA_FIELDS:
        if field not in arguments:
            continue
        if field == "tags":
            request.tags.extend(arguments[field])
        else:
            setattr(request, field, arguments[field])
        if update:
            request.update_fields.append(field)
    for secret in arguments.get("secrets", []):
        request.secrets.add(name=secret["name"], value=secret["value"])
    if update:
        request.replace_secrets = arguments.get("replace_secrets", "secrets" in arguments)
    else:
        request.replace_secrets = True
    return request


def _mutation(send: Any, details: dict) -> ToolResult:
    try:
        response = send()
    except Exception as error:
        return ToolResult(ok=False, content=f"Credential operation outcome unknown: {error}",
                          metadata={"outcome_unknown": True})
    if response is None or not hasattr(response, "status"):
        return ToolResult(ok=False, content="Credential operation outcome unknown: no acknowledgement.",
                          metadata={"outcome_unknown": True})
    if not is_response_ok(response):
        return ToolResult(ok=False, content=response_message(response, "Credential operation failed."))
    return ToolResult(ok=True, content=json.dumps({
        **details, "message": response_message(response, "ok"),
    }, ensure_ascii=False))


@dataclass(slots=True)
class C2CredentialsTool:
    grpc_client: Any

    name = "listC2Credentials"
    description = "List credential metadata without secret values."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "type": {"type": "string"}, "username": {"type": "string"},
                "name_contains": {"type": "string"}, "include_expired": {"type": "boolean"},
            }, "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        try:
            items = TeamServerOperations(self.grpc_client).list_credentials(
                TeamServerApi_pb2.CredentialQuery(**arguments))
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not list credentials: {error}")
        return ToolResult(ok=True, content=json.dumps({
            "credentials": [_summary(item) for item in items[:100]],
            "total": len(items), "truncated": len(items) > 100,
        }, ensure_ascii=False))


@dataclass(slots=True)
class C2CredentialTool:
    grpc_client: Any

    name = "getC2Credential"
    description = "Read one credential; reveal_secret must be true to include secret values."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "credential_id": {"type": "string"}, "reveal_secret": {"type": "boolean"},
            }, "required": ["credential_id"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        reveal = arguments.get("reveal_secret", False)
        try:
            response = TeamServerOperations(self.grpc_client).get_credential(
                arguments["credential_id"], reveal_secret=reveal)
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not read credential: {error}")
        if not is_response_ok(response):
            return ToolResult(ok=False, content=response_message(response, "Credential lookup failed."))
        return ToolResult(ok=True, content=json.dumps({
            "credential": _summary(response.summary),
            "secrets": [{"name": str(item.name), "value": str(item.value)}
                        for item in response.secrets] if reveal else [],
        }, ensure_ascii=False))


@dataclass(slots=True)
class C2AddCredentialTool:
    grpc_client: Any

    name = "addC2Credential"
    description = "Create a TeamServer credential with explicit metadata and secret fields."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {**_METADATA_PROPERTIES, "secrets": _SECRETS_PROPERTY},
            "required": ["display_name", "type", "username", "secrets"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        if not _valid_secrets(arguments["secrets"], require_nonempty=True):
            return ToolResult(ok=False, content="At least one named secret value is required.")
        request = _request(arguments, update=False)
        return _mutation(lambda: TeamServerOperations(self.grpc_client).add_credential(request),
                         {"display_name": arguments["display_name"], "type": arguments["type"]})


@dataclass(slots=True)
class C2UpdateCredentialTool:
    grpc_client: Any

    name = "updateC2Credential"
    description = "Update specific metadata fields or replace secrets in one credential."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "credential_id": {"type": "string"}, **_METADATA_PROPERTIES,
                "secrets": _SECRETS_PROPERTY, "replace_secrets": {"type": "boolean"},
            }, "required": ["credential_id"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        if set(arguments) == {"credential_id"} or ("secrets" in arguments and not _valid_secrets(
                arguments["secrets"], require_nonempty=False)):
            return ToolResult(ok=False, content="Specify metadata fields or a valid secrets list to update.")
        if "replace_secrets" in arguments and "secrets" not in arguments and not arguments["replace_secrets"]:
            return ToolResult(ok=False, content="replace_secrets alone has no effect.")
        request = _request(arguments, update=True)
        return _mutation(lambda: TeamServerOperations(self.grpc_client).update_credential(request),
                         {"credential_id": arguments["credential_id"],
                          "updated_fields": list(request.update_fields),
                          "secrets_replaced": request.replace_secrets})


@dataclass(slots=True)
class C2DeleteCredentialTool:
    grpc_client: Any

    name = "deleteC2Credential"
    description = "Delete one TeamServer credential by ID."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {"credential_id": {"type": "string"}},
            "required": ["credential_id"], "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        return _mutation(lambda: TeamServerOperations(self.grpc_client).delete_credential(
            arguments["credential_id"]), {"credential_id": arguments["credential_id"]})
