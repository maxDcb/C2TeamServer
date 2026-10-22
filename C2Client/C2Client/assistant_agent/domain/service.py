from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_core import RunContext
from agent_core.conversation import AgentOrchestrator, AgentTurnResult, SessionManager, SessionRepository
from agent_core.spi import PolicyEngine, build_memory_provider, build_provider

from ..storage.migration import import_legacy_sessions
from ..tools.registry import build_c2_tool_registry
from .hooks import C2DomainHooks
from .settings import build_c2_agent_settings


class C2AssistantAgent:
    def __init__(self, grpc_client: Any, *, storage_dir: Path | None = None) -> None:
        settings = build_c2_agent_settings(storage_dir=storage_dir)
        self.domain_hooks = C2DomainHooks()
        session_repo = SessionRepository(settings.session_file)
        import_legacy_sessions(session_repo, settings.session_file.parent)
        self.session_manager = SessionManager(session_repo, default_session_id="default")
        self.orchestrator = AgentOrchestrator(
            settings=settings,
            provider=build_provider(settings),
            memory_provider=build_memory_provider(settings),
            registry=build_c2_tool_registry(grpc_client),
            session_manager=self.session_manager,
            policy_engine=PolicyEngine(),
            domain_hooks=self.domain_hooks,
        )

    def run_user_turn(self, user_input: str, *, session_id: str = "default") -> AgentTurnResult:
        return self.orchestrator.run_turn_result(
            user_input=user_input,
            thread_id=session_id,
            context=RunContext(namespace_id="c2client", thread_id=session_id),
        )

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
            thread_id=session_id,
            context=RunContext(namespace_id="c2client", thread_id=session_id),
        )
