from __future__ import annotations

import json

from agent_core.llm.base import LLMCompletionResult, LLMToolCall
from agent_core.orchestrator import AgentOrchestrator
from agent_core.policy_engine import PolicyEngine
from agent_core.session_manager import SessionManager
from agent_core.session_repo import SessionRepository
from agent_core.settings import CoreSettings
from agent_core.tool_registry import ToolRegistry
from agent_core.tools import build_tool_definition
from agent_core.types import ToolResult


class FakeProvider:
    def __init__(self):
        self.responses = [
            LLMCompletionResult(
                content="",
                tool_calls=[
                    LLMToolCall(
                        id="call-1",
                        name="delayed_tool",
                        arguments_json=json.dumps({"value": "whoami"}),
                    )
                ],
            ),
            LLMCompletionResult(content="final after tool output"),
        ]

    def complete_with_tools(self, *, messages, tools, model, temperature):
        return self.responses.pop(0)

    def complete_text(self, *, messages, model, temperature):
        return json.dumps(
            {
                "run_id": "run-0000",
                "objective": "Use delayed tool",
                "scope": [],
                "source_code_locations": [],
                "domain_extensions": {},
                "open_questions": [],
                "next_action": None,
                "stop_conditions": [],
                "constraints": [],
                "relevant_artifacts": [],
                "status": "active",
            }
        )


class DelayedTool:
    name = "delayed_tool"
    description = "Returns pending first."

    def schema(self):
        return build_tool_definition(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
            },
        )

    def execute(self, arguments, context):
        return ToolResult.pending_result("waiting", metadata={"value": arguments["value"]})


def build_orchestrator(tmp_path):
    settings = CoreSettings(
        openai_api_key="test",
        model="test-model",
        memory_model="test-model",
        session_file=tmp_path / "session.json",
        base_system_prompt="system",
        task_state_synthesis_prompt="task",
        session_summary_synthesis_prompt="summary",
        session_summary_merge_prompt="merge",
    )
    registry = ToolRegistry()
    registry.register(DelayedTool())
    return AgentOrchestrator(
        settings=settings,
        provider=FakeProvider(),
        registry=registry,
        session_manager=SessionManager(SessionRepository(settings.session_file)),
        policy_engine=PolicyEngine(),
    )


def test_agent_core_can_resume_pending_tool_result(tmp_path):
    orchestrator = build_orchestrator(tmp_path)

    pending = orchestrator.run_turn_result("call the delayed tool")

    assert pending.status == "pending_tool_result"
    assert pending.pending_id
    assert pending.tool_name == "delayed_tool"

    completed = orchestrator.resume_turn(
        pending_id=pending.pending_id,
        tool_content="tool output",
    )

    assert completed.status == "completed"
    assert completed.content == "final after tool output"
    assert [block.kind for block in orchestrator.session_manager.get_context_blocks()] == [
        "tool_exchange",
        "conversation_turn",
    ]
