from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from .command_builder import build_command_line
from .command_specs import C2CommandSpecToolSpec
from .module_state_tool import has_loaded_module
from .validation import validate_tool_arguments
from ..domain.command_outcome import CommandOutcome

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ...grpcClient import TeamServerApi_pb2


@dataclass(slots=True)
class C2CommandTool:
    spec: C2CommandSpecToolSpec
    grpc_client: Any

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def description(self) -> str:
        return self.spec.description

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.spec.name,
            description=self.spec.description,
            parameters=self.spec.parameters,
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.spec.parameters, arguments)
        if invalid is not None:
            return invalid
        beacon_hash = arguments["beacon_hash"]
        listener_hash = arguments["listener_hash"]
        command_line = build_command_line(self.spec, arguments)
        module_loaded = self._module_loaded(beacon_hash=beacon_hash, listener_hash=listener_hash)
        if module_loaded is not True:
            return CommandOutcome(
                state="failed", command_id="", beacon_hash=beacon_hash,
                listener_hash=listener_hash, command_line=command_line,
                error_code="module_not_loaded" if module_loaded is False else "module_state_unavailable",
                error_message=(
                    f"Module `{self.spec.name}` is not loaded on this beacon. Use `loadModule {self.spec.name}` first, then retry the command."
                    if module_loaded is False else f"Could not verify that module `{self.spec.name}` is loaded."
                ),
            ).to_tool_result()

        command_id = uuid.uuid4().hex
        command = TeamServerApi_pb2.SessionCommandRequest(
            session=TeamServerApi_pb2.SessionSelector(
                beacon_hash=beacon_hash,
                listener_hash=listener_hash,
            ),
            command=command_line,
            command_id=command_id,
        )
        try:
            ack = self.grpc_client.sendSessionCommand(command)
        except Exception as exc:
            return CommandOutcome(
                state="failed", command_id=command_id, beacon_hash=beacon_hash,
                listener_hash=listener_hash, command_line=command_line,
                error_code="rpc_error", error_message=str(exc) or type(exc).__name__,
            ).to_tool_result()

        command_id = getattr(ack, "command_id", command_id) or command_id
        if getattr(ack, "status", None) != TeamServerApi_pb2.OK:
            message = getattr(ack, "message", "")
            if isinstance(message, bytes):
                message = message.decode("utf-8", errors="replace")
            return CommandOutcome(
                state="failed", command_id=command_id, beacon_hash=beacon_hash,
                listener_hash=listener_hash, command_line=command_line,
                error_code="teamserver_rejected",
                error_message=message or "Command was rejected by TeamServer.",
            ).to_tool_result()

        return CommandOutcome(
            state="pending", command_id=command_id, beacon_hash=beacon_hash,
            listener_hash=listener_hash, command_line=command_line,
        ).to_tool_result()

    def _module_loaded(self, *, beacon_hash: str, listener_hash: str) -> bool | None:
        command_spec = self.spec.command_spec
        if str(getattr(command_spec, "kind", "") or "").lower() != "module":
            return True
        return has_loaded_module(
            self.grpc_client,
            beacon_hash=beacon_hash,
            listener_hash=listener_hash,
            module_name=self.spec.name,
        )
