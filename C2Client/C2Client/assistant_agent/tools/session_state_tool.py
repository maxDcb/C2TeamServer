from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_core.execution_context import ExecutionContext
from agent_core.llm.base import LLMToolDefinition
from agent_core.tools import build_tool_definition
from agent_core.types import ToolResult


@dataclass(slots=True)
class C2LiveSessionsTool:
    grpc_client: Any

    name = "listLiveSessions"
    description = "List live C2 sessions known by the TeamServer, with full beacon and listener hashes."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "beacon_prefix": {
                        "type": "string",
                        "description": "Optional beacon hash prefix to resolve an operator short reference.",
                    },
                    "include_killed": {
                        "type": "boolean",
                        "description": "Include killed sessions in the result.",
                    },
                },
                "additionalProperties": False,
            },
        )

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        sessions = list_sessions(
            self.grpc_client,
            beacon_prefix=arguments.get("beacon_prefix", ""),
            include_killed=bool(arguments.get("include_killed", False)),
        )
        return ToolResult(ok=True, content=format_sessions(sessions))


def list_sessions(
    grpc_client: Any,
    *,
    beacon_prefix: str = "",
    include_killed: bool = False,
) -> list[Any]:
    if grpc_client is None or not hasattr(grpc_client, "listSessions"):
        return []

    prefix = str(beacon_prefix or "").strip()
    sessions = []
    for session in grpc_client.listSessions():
        beacon_hash = str(getattr(session, "beacon_hash", "") or "")
        killed = _is_truthy(getattr(session, "killed", False))
        if killed and not include_killed:
            continue
        if prefix and not beacon_hash.startswith(prefix):
            continue
        sessions.append(session)
    return sessions


def format_sessions(sessions: list[Any]) -> str:
    rows = []
    for session in sessions:
        beacon_hash = str(getattr(session, "beacon_hash", "") or "").strip()
        listener_hash = str(getattr(session, "listener_hash", "") or "").strip()
        if not beacon_hash:
            continue
        rows.append(
            {
                "short": beacon_hash[:8],
                "beacon": beacon_hash,
                "listener": listener_hash,
                "host": str(getattr(session, "hostname", "") or "").strip() or "-",
                "user": str(getattr(session, "username", "") or "").strip() or "-",
                "arch": str(getattr(session, "arch", "") or "").strip() or "-",
                "os": str(getattr(session, "os", "") or "").strip() or "-",
                "state": "killed" if _is_truthy(getattr(session, "killed", False)) else "live",
            }
        )

    if not rows:
        return "No matching live sessions."

    lines = ["short     state   beacon_hash                       listener_hash                     host  user  arch  os"]
    for row in rows:
        lines.append(
            "{short:<8}  {state:<6}  {beacon:<32}  {listener:<32}  {host}  {user}  {arch}  {os}".format(**row)
        )
    return "\n".join(lines)


def _is_truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "killed", "dead", "stop", "stopped"}
    return bool(value)
