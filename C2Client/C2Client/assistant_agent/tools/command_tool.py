from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from .command_builder import build_command_line
from .command_specs import C2CommandSpecToolSpec
from .module_state_tool import has_loaded_module

from agent_core.execution_context import ExecutionContext
from agent_core.llm.base import LLMToolDefinition
from agent_core.tools import build_tool_definition
from agent_core.types import ToolResult

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
        beacon_hash = arguments["beacon_hash"]
        listener_hash = arguments["listener_hash"]
        module_loaded = self._module_loaded(beacon_hash=beacon_hash, listener_hash=listener_hash)
        if module_loaded is False:
            return ToolResult(
                ok=False,
                content=f"Module `{self.spec.name}` is not loaded on this beacon. Use `loadModule {self.spec.name}` first, then retry the command.",
            )

        command_line = build_command_line(self.spec, arguments)
        command_id = uuid.uuid4().hex
        command = TeamServerApi_pb2.SessionCommandRequest(
            session=TeamServerApi_pb2.SessionSelector(
                beacon_hash=beacon_hash,
                listener_hash=listener_hash,
            ),
            command=command_line,
            command_id=command_id,
        )
        ack = self.grpc_client.sendSessionCommand(command)
        if getattr(ack, "status", TeamServerApi_pb2.OK) != TeamServerApi_pb2.OK:
            message = getattr(ack, "message", b"")
            if isinstance(message, bytes):
                message = message.decode("utf-8", errors="replace")
            return ToolResult(ok=False, content=message or "Command was rejected by TeamServer.")

        command_id = getattr(ack, "command_id", command_id) or command_id
        return ToolResult.pending_result(
            f'Sent `{command_line}` to beacon `{beacon_hash[:8]}`. Waiting for command output.',
            metadata={
                "command_id": command_id,
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "command_line": command_line,
            },
        )

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
