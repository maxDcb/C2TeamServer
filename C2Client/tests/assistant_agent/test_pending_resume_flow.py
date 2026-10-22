from __future__ import annotations

import json

import pytest

from agent_core import CoreSettings, RunContext, ToolArtifactPolicy
from agent_core.conversation import AgentOrchestrator, SessionManager, SessionRepository
from agent_core.spi import LLMCompletionResult, LLMToolCall, PolicyEngine, ToolRegistry, ToolResult, build_tool_definition


class FakeProvider:
    def __init__(self, *, tool_name="delayed_tool"):
        self.calls = []
        self.responses = [
            LLMCompletionResult(
                content="",
                tool_calls=[
                    LLMToolCall(
                        id="call-1",
                        name=tool_name,
                        arguments_json=json.dumps({"value": "whoami"}),
                    )
                ],
            ),
            LLMCompletionResult(content="final after tool output"),
        ]

    def complete_with_tools(self, *, messages, tools, model, temperature):
        self.calls.append((list(messages), list(tools)))
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


class ImmediateTool(DelayedTool):
    name = "immediate_tool"

    def __init__(self, output):
        self.output = output

    def execute(self, arguments, context):
        return ToolResult(ok=True, content=self.output)


def build_orchestrator(tmp_path, *, policy=None, provider=None, tool=None):
    settings = CoreSettings(
        openai_api_key="test",
        model="test-model",
        memory_model="test-model",
        session_file=tmp_path / "session.json",
        artifacts_directory=tmp_path / "artifacts",
        tool_artifact_policy=policy or ToolArtifactPolicy(),
        base_system_prompt="system",
        turn_memory_synthesis_prompt="Create a bounded turn summary and handoff.",
    )
    registry = ToolRegistry()
    registry.register(tool or DelayedTool())
    return AgentOrchestrator(
        settings=settings,
        provider=provider or FakeProvider(),
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


def _tool_envelope(provider):
    messages, tools = provider.calls[1]
    tool_messages = [message for message in messages if message.role == "tool"]
    return json.loads(tool_messages[-1].content), {tool.name for tool in tools}


def _small_policy():
    return ToolArtifactPolicy(
        hot_context_bytes=2048,
        max_complete_result_bytes=128,
        preview_bytes=32,
        max_read_bytes=64,
        max_reads_per_run=2,
        max_total_read_bytes=96,
    )


@pytest.mark.parametrize("size, materialization", [(24, "complete"), (500, "preview")])
def test_immediate_result_is_stored_exactly_and_projected_by_threshold(tmp_path, size, materialization):
    output = "résultat:" + "x" * size
    provider = FakeProvider(tool_name="immediate_tool")
    orchestrator = build_orchestrator(
        tmp_path, policy=_small_policy(), provider=provider, tool=ImmediateTool(output)
    )

    result = orchestrator.run_turn_result(
        user_input="run immediate tool",
        thread_id="default",
        context=RunContext(namespace_id="c2client-test", thread_id="default"),
    )

    assert result.status == "completed"
    envelope, tool_names = _tool_envelope(provider)
    assert envelope["kind"] == "artifact_result"
    assert envelope["status"] == "ok"
    assert envelope["materialization"] == materialization
    assert envelope["read_tool"] == "agent_core_read_artifact"
    assert "agent_core_read_artifact" in tool_names
    artifact_id = envelope["artifact"]["artifact_id"]
    assert orchestrator.artifact_store.read_all_text(
        namespace_id="c2client-test", artifact_id=artifact_id
    ) == output
    if materialization == "complete":
        assert envelope["content"] == output
        assert envelope["complete"] is True
    else:
        assert envelope["content"] == output.encode("utf-8")[:32].decode("utf-8")
        assert envelope["complete"] is False
        assert envelope["next_offset"] == 32
        assert envelope["next_read"]["arguments"]["continuation"]


@pytest.mark.parametrize("ok, status", [(True, "ok"), (False, "tool_error")])
def test_deferred_large_result_preserves_status_and_exact_output(tmp_path, ok, status):
    provider = FakeProvider()
    orchestrator = build_orchestrator(tmp_path, policy=_small_policy(), provider=provider)
    context = RunContext(namespace_id="c2client-test", thread_id="default")
    pending = orchestrator.run_turn_result(
        user_input="run delayed tool", thread_id="default", context=context
    )
    output = "sortie différée:" + "z" * 500

    result = orchestrator.resume_turn(
        pending_id=pending.pending_id,
        tool_content=output,
        ok=ok,
        thread_id="default",
        context=context,
    )

    assert result.status == "completed"
    envelope, tool_names = _tool_envelope(provider)
    assert envelope["status"] == status
    assert envelope["materialization"] == "preview"
    assert "agent_core_read_artifact" in tool_names
    assert orchestrator.artifact_store.read_all_text(
        namespace_id="c2client-test", artifact_id=envelope["artifact"]["artifact_id"]
    ) == output
    assert orchestrator.session_manager.get_state()["tool_history"][-1]["status"] == status


class ReadingProvider(FakeProvider):
    def __init__(self):
        super().__init__(tool_name="immediate_tool")
        self.artifact_id = None

    def complete_with_tools(self, *, messages, tools, model, temperature):
        self.calls.append((list(messages), list(tools)))
        if len(self.calls) == 1:
            return self.responses[0]
        if len(self.calls) == 2:
            envelope = json.loads([message for message in messages if message.role == "tool"][-1].content)
            self.artifact_id = envelope["artifact"]["artifact_id"]
            return LLMCompletionResult(
                content="",
                tool_calls=[
                    LLMToolCall(
                        id="call-read",
                        name="agent_core_read_artifact",
                        arguments_json=json.dumps({"artifact_id": self.artifact_id, "offset": 0, "limit": 500}),
                    )
                ],
            )
        return LLMCompletionResult(content="final after artifact read")


def test_native_artifact_reader_clamps_requested_bytes(tmp_path):
    output = "0123456789" * 50
    provider = ReadingProvider()
    orchestrator = build_orchestrator(
        tmp_path, policy=_small_policy(), provider=provider, tool=ImmediateTool(output)
    )

    result = orchestrator.run_turn_result(
        user_input="read the output",
        thread_id="default",
        context=RunContext(namespace_id="c2client-test", thread_id="default"),
    )

    assert result.status == "completed"
    read_messages = [message for message in provider.calls[2][0] if message.tool_call_id == "call-read"]
    chunk = json.loads(read_messages[-1].content)
    assert chunk["kind"] == "artifact_chunk"
    assert chunk["artifact_id"] == provider.artifact_id
    assert chunk["returned_bytes"] == 64
    assert chunk["content"] == output[:64]
    assert chunk["next_offset"] == 64
    assert chunk["next_read"]["arguments"]["continuation"]
