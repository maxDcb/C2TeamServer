"""One session-bound tool exposed to the structured identity skill."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition


@dataclass(slots=True)
class BoundWhoamiTool:
    service: Any
    skill_run_id: str

    name = "whoami"
    description = "Run whoami once on the operator-selected beacon session and wait for its result."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name, description=self.description,
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        if arguments or context.run_id != f"agentic-{self.skill_run_id}":
            return ToolResult(ok=False, content="Invalid identity tool call.")
        return self.service.dispatch_identity_tool(self.skill_run_id)
