from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from .command_builder import build_command_line
from .command_specs import C2CommandSpecToolSpec, load_command_tool_specs
from .module_state_tool import find_module_record, list_loaded_modules
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
        module_state, loading_command_id = self._module_state(
            beacon_hash=beacon_hash, listener_hash=listener_hash,
        )
        if module_state == "missing":
            loader = next(
                (spec for spec in load_command_tool_specs(self.grpc_client) if spec.name == "loadModule"),
                None,
            )
            if loader is None:
                return self._failure(
                    beacon_hash, listener_hash, command_line,
                    "module_loader_unavailable", "TeamServer does not offer loadModule.",
                )
            load_command = build_command_line(loader, {
                "beacon_hash": beacon_hash, "listener_hash": listener_hash,
                "module": self.spec.name,
            })
            return self._send_command(
                load_command, beacon_hash, listener_hash,
                continuation_command_line=command_line,
            )
        if module_state == "loading" and loading_command_id:
            outcome = CommandOutcome(
                state="pending", command_id=loading_command_id,
                beacon_hash=beacon_hash, listener_hash=listener_hash,
                command_line=f"loadModule {self.spec.name}",
            )
            return ToolResult.pending_result(
                outcome.tool_content(),
                metadata={**outcome.metadata(), "continuation_command_line": command_line},
            )
        if module_state != "loaded":
            return CommandOutcome(
                state="failed", command_id="", beacon_hash=beacon_hash,
                listener_hash=listener_hash, command_line=command_line,
                error_code="module_state_unavailable",
                error_message=f"Could not establish that module `{self.spec.name}` is ready (state: {module_state}).",
            ).to_tool_result()

        return self._send_command(command_line, beacon_hash, listener_hash)

    def _send_command(
        self, command_line: str, beacon_hash: str, listener_hash: str,
        *, continuation_command_line: str = "",
    ) -> ToolResult:
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

        outcome = CommandOutcome(
            state="pending", command_id=command_id, beacon_hash=beacon_hash,
            listener_hash=listener_hash, command_line=command_line,
        )
        if continuation_command_line:
            return ToolResult.pending_result(
                outcome.tool_content(),
                metadata={**outcome.metadata(), "continuation_command_line": continuation_command_line},
            )
        return outcome.to_tool_result()

    def _module_state(self, *, beacon_hash: str, listener_hash: str) -> tuple[str, str]:
        command_spec = self.spec.command_spec
        if str(getattr(command_spec, "kind", "") or "").lower() != "module":
            return "loaded", ""
        if not hasattr(self.grpc_client, "listModules"):
            return "unavailable", ""
        try:
            modules = list_loaded_modules(
                self.grpc_client, beacon_hash=beacon_hash, listener_hash=listener_hash,
            )
        except Exception:
            return "unavailable", ""
        module = find_module_record(modules, self.spec.name)
        if module is None:
            return "missing", ""
        return str(getattr(module, "state", "") or "").lower(), str(getattr(module, "command_id", "") or "")

    def _failure(
        self, beacon_hash: str, listener_hash: str, command_line: str,
        code: str, message: str,
    ) -> ToolResult:
        return CommandOutcome(
            state="failed", command_id="", beacon_hash=beacon_hash,
            listener_hash=listener_hash, command_line=command_line,
            error_code=code, error_message=message,
        ).to_tool_result()
