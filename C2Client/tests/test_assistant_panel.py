from __future__ import annotations

from types import SimpleNamespace

from C2Client.AssistantPanel import Assistant


class FakeDomainHooks:
    def __init__(self):
        self.observations = []

    def record_session_event(self, **kwargs):
        pass

    def record_console_observation(self, **kwargs):
        self.observations.append(kwargs)


class FakeAssistantAgent:
    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.domain_hooks = FakeDomainHooks()


def build_assistant(qtbot, monkeypatch, *, timeout_ms=300000):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("C2_ASSISTANT_PENDING_TIMEOUT_MS", str(timeout_ms))
    monkeypatch.setattr("C2Client.AssistantPanel.C2AssistantAgent", FakeAssistantAgent)

    assistant = Assistant(None, object())
    qtbot.addWidget(assistant)
    return assistant


def build_assistant_with_default_timeout(qtbot, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("C2_ASSISTANT_PENDING_TIMEOUT_MS", raising=False)
    monkeypatch.setattr("C2Client.AssistantPanel.C2AssistantAgent", FakeAssistantAgent)

    assistant = Assistant(None, object())
    qtbot.addWidget(assistant)
    return assistant


def pending_message():
    return SimpleNamespace(
        content="",
        is_pending=True,
        pending_id="pending-1",
        metadata={
            "command_id": "cmd-1",
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-1",
            "command_line": "run touch /tmp/hello",
        },
        tool_arguments={},
    )


def test_help_command_shows_local_commands(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)

    assistant.commandEditor.setText("/help")
    assistant.runCommand()

    output = assistant.editorOutput.toPlainText()
    assert "Assistant commands:" in output
    assert "/help - Show AssistantPanel local commands." in output
    assert "/status - Show the current assistant pending command state." in output
    assert "/cancel - Cancel the current pending beacon result wait." in output
    assert "/reset - Alias for /cancel." in output


def test_default_pending_timeout_is_two_minutes(qtbot, monkeypatch):
    assistant = build_assistant_with_default_timeout(qtbot, monkeypatch)

    assert assistant.pending_tool_timeout_ms == 120000


def test_cancel_command_clears_pending_state(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1",
        "beacon_hash": "beacon-1",
        "listener_hash": "listener-1",
    }

    assistant.commandEditor.setText("/cancel")
    assistant.runCommand()

    assert assistant.awaiting_tool_result is False
    assert assistant.pending_tool_id is None
    assert assistant.pending_tool_context is None
    assert assistant.pending_tool_timer.isActive() is False
    assert "Pending command wait cancelled." in assistant.editorOutput.toPlainText()


def test_cancel_command_reports_when_nothing_is_pending(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)

    assistant.commandEditor.setText("/cancel")
    assistant.runCommand()

    assert "No pending command wait to cancel." in assistant.editorOutput.toPlainText()


def test_help_command_is_available_while_pending(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1",
        "beacon_hash": "beacon-1",
        "listener_hash": "listener-1",
    }

    assistant.commandEditor.setText("/help")
    assistant.runCommand()

    assert assistant.awaiting_tool_result is True
    assert assistant.pending_tool_id == "pending-1"
    assert "Assistant commands:" in assistant.editorOutput.toPlainText()


def test_status_command_reports_no_pending_state(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)

    assistant.commandEditor.setText("/status")
    assistant.runCommand()

    assert "No pending beacon command result." in assistant.editorOutput.toPlainText()


def test_status_command_reports_pending_context(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant._process_assistant_response(pending_message())

    assistant.commandEditor.setText("/status")
    assistant.runCommand()

    output = assistant.editorOutput.toPlainText()
    assert "Pending command: run touch /tmp/hello" in output
    assert "Command ID: cmd-1" in output
    assert "Beacon: beacon-12345678" in output
    assert "Listener: listener-1" in output


def test_console_receive_resumes_matching_pending_command_id(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    resume_calls = []
    monkeypatch.setattr(
        assistant,
        "_start_agent_resume",
        lambda pending_id, tool_output: resume_calls.append((pending_id, tool_output)),
    )
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1",
        "beacon_hash": "beacon-1",
        "listener_hash": "listener-1",
    }

    assistant.consoleAssistantMethod(
        "receive",
        "beacon-1",
        "listener-1",
        "context",
        "run touch /tmp/hello",
        "",
        "cmd-1",
    )

    assert len(resume_calls) == 1
    assert resume_calls[0][0] == "pending-1"
    assert "command_id: cmd-1" in resume_calls[0][1]
    assert "beacon_hash: beacon-1" in resume_calls[0][1]
    assert "listener_hash: listener-1" in resume_calls[0][1]
    assert "command: run touch /tmp/hello" in resume_calls[0][1]
    assert "[no output]" in resume_calls[0][1]
    assert assistant.awaiting_tool_result is False
    assert assistant.pending_tool_id is None
    assert assistant.pending_tool_context is None
    assert assistant.pending_tool_timer.isActive() is False


def test_console_receive_ignores_mismatched_pending_command_id(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    resume_calls = []
    monkeypatch.setattr(
        assistant,
        "_start_agent_resume",
        lambda pending_id, tool_output: resume_calls.append((pending_id, tool_output)),
    )
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1",
        "beacon_hash": "beacon-1",
        "listener_hash": "listener-1",
    }

    assistant.consoleAssistantMethod(
        "receive",
        "beacon-1",
        "listener-1",
        "context",
        "whoami",
        "user",
        "cmd-2",
    )

    assert resume_calls == []
    assert assistant.awaiting_tool_result is True
    assert assistant.agent.domain_hooks.observations == [
        {
            "beacon_hash": "beacon-1",
            "listener_hash": "listener-1",
            "command": "whoami",
            "output": "user",
        }
    ]


def test_pending_response_starts_timeout_timer(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch, timeout_ms=1000)

    assistant._process_assistant_response(pending_message())

    assert assistant.awaiting_tool_result is True
    assert assistant.pending_tool_id == "pending-1"
    assert assistant.pending_tool_context["command_id"] == "cmd-1"
    assert assistant.pending_tool_context["command_line"] == "run touch /tmp/hello"
    assert assistant.pending_tool_timer.isActive() is True
    assert "Waiting for beacon command result." in assistant.editorOutput.toPlainText()
    assert "Command ID: cmd-1" in assistant.editorOutput.toPlainText()


def test_pending_timeout_clears_state_and_reports(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch, timeout_ms=1000)
    assistant._process_assistant_response(pending_message())

    assistant._handle_pending_tool_timeout()

    output = assistant.editorOutput.toPlainText()
    assert assistant.awaiting_tool_result is False
    assert assistant.pending_tool_id is None
    assert assistant.pending_tool_context is None
    assert assistant.pending_tool_timer.isActive() is False
    assert "Timed out waiting for result of `run touch /tmp/hello` on beacon beacon-1." in output


def test_pending_timeout_can_be_disabled(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch, timeout_ms=0)

    assistant._process_assistant_response(pending_message())

    assert assistant.awaiting_tool_result is True
    assert assistant.pending_tool_timer.isActive() is False
