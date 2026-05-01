from __future__ import annotations

from pathlib import Path
from typing import Any

from ..bootstrap import ensure_agent_core_path
from ..tools.registry import build_c2_tool_registry
from .hooks import C2DomainHooks
from .settings import build_c2_agent_settings

ensure_agent_core_path()

from agent_core import AgentOrchestrator, AgentTurnResult, PolicyEngine, SessionManager, SessionRepository
from agent_core.llm.openai_provider import OpenAIProvider


class C2AssistantAgent:
    def __init__(self, grpc_client: Any, *, storage_dir: Path | None = None) -> None:
        settings = build_c2_agent_settings(storage_dir=storage_dir)
        self.domain_hooks = C2DomainHooks()
        self.session_manager = SessionManager(SessionRepository(settings.session_file), default_session_id="default")
        self.orchestrator = AgentOrchestrator(
            settings=settings,
            provider=OpenAIProvider(api_key=settings.openai_api_key),
            registry=build_c2_tool_registry(grpc_client),
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
