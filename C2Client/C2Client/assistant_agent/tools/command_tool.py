from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..bootstrap import ensure_agent_core_path
from .command_builder import build_command_line
from .loader import C2ToolSpec

ensure_agent_core_path()

from agent_core.execution_context import ExecutionContext
from agent_core.llm.base import LLMToolDefinition
from agent_core.tools import build_tool_definition
from agent_core.types import ToolResult

from ...grpcClient import TeamServerApi_pb2


@dataclass(slots=True)
class C2CommandTool:
    spec: C2ToolSpec
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
        command_line = build_command_line(self.spec, arguments)
        command = TeamServerApi_pb2.Command(
            beaconHash=beacon_hash,
            listenerHash=listener_hash,
            cmd=command_line,
        )
        self.grpc_client.sendCmdToSession(command)
        return ToolResult.pending_result(
            f'Sent `{command_line}` to beacon `{beacon_hash[:8]}`. Waiting for command output.',
            metadata={
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "command_line": command_line,
            },
        )
