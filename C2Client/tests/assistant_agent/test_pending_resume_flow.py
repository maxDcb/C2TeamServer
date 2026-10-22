from __future__ import annotations

import json

import pytest

from agent_core import CoreSettings, RunContext
from agent_core.conversation import AgentOrchestrator, SessionManager, SessionRepository
from agent_core.spi import LLMCompletionResult, LLMToolCall, PolicyEngine, ToolRegistry, ToolResult, build_tool_definition


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
        return LLMCompletionResult(
            content=json.dumps({
                "turn_summary": "The delayed tool returned its output.",
                "next_handoff": "The delayed tool completed; no command remains pending.",
            })
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
        artifacts_directory=tmp_path / "artifacts",
        base_system_prompt="system",
        turn_memory_synthesis_prompt="Create a bounded turn summary and handoff.",
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


@pytest.mark.parametrize("ok", [True, False])
def test_agent_core_can_resume_pending_tool_result(tmp_path, ok):
    orchestrator = build_orchestrator(tmp_path)

    context = RunContext(namespace_id="c2client-test", thread_id="default")
    pending = orchestrator.run_turn_result(
        user_input="call the delayed tool", thread_id="default", context=context
    )

    assert pending.status == "pending_tool_result"
    assert pending.pending_id
    assert pending.tool_name == "delayed_tool"

    completed = orchestrator.resume_turn(
        pending_id=pending.pending_id,
        tool_content="tool output",
        ok=ok,
        thread_id="default",
        context=context,
    )

    assert completed.status == "completed"
    assert completed.content == "final after tool output"
    assert [block.kind for block in orchestrator.session_manager.get_context_blocks()] == [
        "tool_exchange",
        "conversation_turn",
    ]
    assert orchestrator.session_manager.get_state()["tool_history"][-1]["status"] == (
        "ok" if ok else "tool_error"
    )
