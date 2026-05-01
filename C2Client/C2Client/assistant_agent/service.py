from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .bootstrap import ensure_agent_core_path
from .c2_tools import C2CommandTool, TOOL_SCHEMAS

ensure_agent_core_path()

from agent_core import (
    AgentOrchestrator,
    AgentTurnResult,
    CoreSettings,
    DomainHooks,
    PolicyEngine,
    SessionManager,
    SessionRepository,
    ToolRegistry,
)
from agent_core.llm.openai_provider import OpenAIProvider


C2_SYSTEM_PROMPT = """You are Data, a Red Team operator assistant embedded in the Exploration C2 framework.
You support authorized offensive security engagements by reasoning over session metadata and command output.

Operational rules:
- Use exactly one C2 tool call at a time, then wait for the beacon output before continuing.
- Prefer low-noise enumeration before intrusive actions.
- Make assumptions explicit when target context is incomplete.
- Use full beacon_hash and listener_hash values from the known session context when calling tools.
- Ask the operator for missing scope or authorization details rather than guessing.
"""

TASK_STATE_PROMPT = """Synthesize a compact operational state for a C2-assisted security engagement.
Return only valid JSON matching the requested schema. Preserve concrete facts, current objective,
open questions, constraints, relevant artifacts, and the next useful action."""

SESSION_SUMMARY_PROMPT = """Summarize older C2 assistant history into durable operational memory.
Return only valid JSON matching the requested schema. Preserve confirmed facts, decisions,
completed actions, pending actions, relevant artifacts, and open hypotheses."""

SESSION_SUMMARY_MERGE_PROMPT = """Merge the previous session summary with the new summary delta.
Return only valid JSON matching the requested schema. Keep durable facts concise and avoid duplicating items."""


class C2DomainHooks(DomainHooks):
    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        self.recent_observations: list[dict[str, str]] = []

    def record_session_event(
        self,
        *,
        action: str,
        beacon_hash: str,
        listener_hash: str,
        hostname: str,
        username: str,
        arch: str,
        privilege: str,
        os_name: str,
    ) -> None:
        if action == "start":
            self.sessions[beacon_hash] = {
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "hostname": hostname,
                "username": username,
                "arch": arch,
                "privilege": privilege,
                "os": os_name,
            }
        elif action == "stop":
            self.sessions.pop(beacon_hash, None)

    def record_console_observation(
        self,
        *,
        beacon_hash: str,
        listener_hash: str,
        command: str,
        output: str,
    ) -> None:
        if not command and not output:
            return
        self.recent_observations.append(
            {
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "command": command[:500],
                "output_preview": output[:2000],
            }
        )
        self.recent_observations = self.recent_observations[-10:]

    def build_system_prompt_blocks(self, *, settings, session_manager) -> list[str]:
        lines = ["C2 runtime context:"]
        if self.sessions:
            lines.append("Known sessions:")
            for session in self.sessions.values():
                lines.append(
                    "- beacon_hash={beacon_hash}, listener_hash={listener_hash}, host={hostname}, "
                    "user={username}, arch={arch}, privilege={privilege}, os={os}".format(**session)
                )
        else:
            lines.append("Known sessions: none. Ask the operator to select or provide a session before using C2 tools.")

        if self.recent_observations:
            lines.append("Recent console observations:")
            for observation in self.recent_observations:
                lines.append(
                    "- beacon_hash={beacon_hash}, listener_hash={listener_hash}, command={command}, output_preview={output_preview}".format(
                        **observation
                    )
                )
        return ["\n".join(lines)]


class C2AssistantAgent:
    def __init__(self, grpc_client: Any, *, storage_dir: Path | None = None) -> None:
        package_root = Path(__file__).resolve().parents[1]
        if storage_dir is None:
            storage_dir = package_root / "logs" / "assistant_sessions"
        storage_dir.mkdir(parents=True, exist_ok=True)

        model = os.getenv("C2_ASSISTANT_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o"))
        memory_model = os.getenv("C2_ASSISTANT_MEMORY_MODEL", model)
        settings = CoreSettings(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            model=model,
            memory_model=memory_model,
            temperature=float(os.getenv("C2_ASSISTANT_TEMPERATURE", "0.05")),
            memory_temperature=float(os.getenv("C2_ASSISTANT_MEMORY_TEMPERATURE", "0.0")),
            max_tool_calls_per_turn=int(os.getenv("C2_ASSISTANT_MAX_TOOL_CALLS", "10")),
            session_file=storage_dir / "session.json",
            reports_directory=storage_dir / "reports",
            prompts_dir=storage_dir / "prompts",
            knowledge_base_dir=storage_dir / "knowledge",
            allowed_read_roots=[Path.cwd()],
            allowed_http_hosts=[],
            allowed_http_methods=[],
            base_system_prompt=C2_SYSTEM_PROMPT,
            task_state_synthesis_prompt=TASK_STATE_PROMPT,
            session_summary_synthesis_prompt=SESSION_SUMMARY_PROMPT,
            session_summary_merge_prompt=SESSION_SUMMARY_MERGE_PROMPT,
        )

        registry = ToolRegistry()
        for tool_name in TOOL_SCHEMAS:
            registry.register(C2CommandTool(tool_name, grpc_client))

        self.domain_hooks = C2DomainHooks()
        self.session_manager = SessionManager(SessionRepository(settings.session_file), default_session_id="default")
        self.orchestrator = AgentOrchestrator(
            settings=settings,
            provider=OpenAIProvider(api_key=settings.openai_api_key),
            registry=registry,
            session_manager=self.session_manager,
            policy_engine=PolicyEngine(),
            domain_hooks=self.domain_hooks,
        )

    def run_user_turn(self, user_input: str, *, session_id: str = "default") -> AgentTurnResult:
        return self.orchestrator.run_turn_result(user_input=user_input, session_id=session_id)

    def resume_pending_tool(
        self,
        *,
        pending_id: str,
        tool_content: str,
        ok: bool = True,
        session_id: str = "default",
    ) -> AgentTurnResult:
        return self.orchestrator.resume_turn(
            pending_id=pending_id,
            tool_content=tool_content,
            ok=ok,
            session_id=session_id,
        )
