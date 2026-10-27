"""Run-bound adapters for structured Agent Skills."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from ..tools.command_specs import C2CommandSpecToolSpec


@dataclass(slots=True)
class BoundBeaconTool:
    service: Any
    skill_run_id: str
    spec: C2CommandSpecToolSpec

    @property
    def name(self) -> str:
        return self.spec.name

    def schema(self) -> LLMToolDefinition:
        parameters = dict(self.spec.parameters)
        parameters["properties"] = {
            key: value for key, value in parameters["properties"].items()
            if key not in {"beacon_hash", "listener_hash"}
        }
        parameters["required"] = [
            key for key in parameters.get("required", [])
            if key not in {"beacon_hash", "listener_hash"}
        ]
        return build_tool_definition(
            name=self.name,
            description=self.spec.description + " The target is the session selected for this skill run.",
            parameters=parameters,
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        if context.run_id != f"agentic-{self.skill_run_id}":
            return ToolResult(ok=False, content="Tool call belongs to a different skill run.")
        return self.service.dispatch_agentic_command(self.skill_run_id, self.name, arguments)


@dataclass(slots=True)
class BoundCatalogTool:
    service: Any
    skill_run_id: str
    tool: Any

    @property
    def name(self) -> str:
        return self.tool.name

    def schema(self) -> LLMToolDefinition:
        return self.tool.schema()

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        if context.run_id != f"agentic-{self.skill_run_id}":
            return ToolResult(ok=False, content="Tool call belongs to a different skill run.")
        return self.service.dispatch_catalog_tool(self.skill_run_id, self.tool, arguments, context)
