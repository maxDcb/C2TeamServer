"""Shared command outcome for tool dispatch and delayed console results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from agent_core.spi import ToolResult

CommandState = Literal["pending", "succeeded", "failed", "outcome_unknown", "stopped"]


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    state: CommandState
    command_id: str
    beacon_hash: str
    listener_hash: str
    command_line: str
    output: str = ""
    error_code: str = ""
    error_message: str = ""

    @property
    def ok(self) -> bool:
        return self.state == "succeeded"

    def metadata(self) -> dict[str, str | dict[str, str]]:
        data: dict[str, str | dict[str, str]] = {
            "status": self.state,
            "command_id": self.command_id,
            "beacon_hash": self.beacon_hash,
            "listener_hash": self.listener_hash,
            "command_line": self.command_line,
        }
        if self.error_code or self.error_message:
            data["error"] = {"code": self.error_code, "message": self.error_message}
        return data

    def tool_content(self) -> str:
        """Preserve the full remote output and machine-readable failure details."""
        return json.dumps({**self.metadata(), "output": self.output}, ensure_ascii=False)

    def to_tool_result(self) -> ToolResult:
        if self.state == "pending":
            return ToolResult.pending_result(self.tool_content(), metadata=self.metadata())
        return ToolResult(ok=self.ok, content=self.tool_content(), metadata=self.metadata())
