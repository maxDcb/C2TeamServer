from __future__ import annotations

import json
from types import SimpleNamespace

from C2Client.AssistantPanel import Assistant
from C2Client.assistant_agent.domain.command_outcome import CommandOutcome
from C2Client.command_event_hub import CommandEventHub, CommandResultWorker
from C2Client.grpcClient import TeamServerApi_pb2


class FakeDomainHooks:
    def __init__(self):
        self.observations = []
        self.active_sessions = []

    def record_session_event(self, **kwargs):
        pass

    def record_active_session(self, **kwargs):
        self.active_sessions.append(kwargs)

    def record_console_observation(self, **kwargs):
        self.observations.append(kwargs)


class FakeAssistantAgent:
    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.domain_hooks = FakeDomainHooks()
        self.turns = []
        self.resumes = []
        self.stopped_waits = []

    def run_user_turn(self, user_input):
        self.turns.append(user_input)
        return SimpleNamespace(content="ok", is_pending=False)

    def resume_pending_tool(self, **kwargs):
        self.resumes.append(kwargs)
        return SimpleNamespace(content="resumed", is_pending=False)

    def stop_pending_tool_wait(self, **kwargs):
        self.stopped_waits.append(kwargs)
        return True


def build_assistant(qtbot, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
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
            "command_id": "4078543f88cc4403aa587856afdfbfea",
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
    assert "/stop - Stop this assistant wait; the remote command continues." in output
    assert "/cancel and /reset - Aliases for /stop." in output
    assert "no automatic assistant wait timeout" in output


def test_skills_share_active_session_without_changing_conversation(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assert [assistant.modeTabs.tabText(index) for index in range(assistant.modeTabs.count())] == [
        "Conversation", "Tasks",
    ]
    assert assistant.skillsPanel.startButton.text() == "Start"
    assert "Fixed ·" in assistant.skillsPanel.skillSelector.currentText()
    assert "Missing modules are loaded first" in assistant.skillsPanel.skillHelpButton.toolTip()
    assert assistant.skillsPanel.runSelector.currentText() == "No runs yet"
    assistant.setActiveSession("beacon-12345678", "listener-1")
    assert assistant.skillsPanel.active_beacon == "beacon-12345678"
    assert assistant.skillsPanel.active_listener == "listener-1"
    assert assistant.agent.domain_hooks.active_sessions[-1]["beacon_hash"] == "beacon-12345678"


def test_assistant_console_uses_role_badges_without_default_marker(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant.editorOutput.clear()

    assistant.printInTerminal("System", "ready")
    assistant.printInTerminal("User:", "hello")
    assistant.printInTerminal("Analysis:", "ok")

    output = assistant.editorOutput.toPlainText()
    assert "[system]\nready" in output
    assert "[user]\nhello" in output
    assert "[assistant]\nok" in output
    assert "[+]" not in output
    assert "color:#d0d5dd" in assistant.editorOutput.toHtml()


def test_unknown_slash_command_redirects_to_help_without_calling_assistant(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)

    assistant.commandEditor.setText("/unknown")
    assistant.runCommand()

    output = assistant.editorOutput.toPlainText()
    assert "Unknown local assistant command `/unknown`." in output
    assert "Assistant commands:" in output
    assert assistant.agent.turns == []


def test_stop_command_clears_only_assistant_wait(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1",
        "beacon_hash": "beacon-1",
        "listener_hash": "listener-1",
    }

    assistant.commandEditor.setText("/stop")
    assistant.runCommand()

    assert assistant.awaiting_tool_result is False
    assert assistant.pending_tool_id is None
    assert assistant.pending_tool_context is None
    assert ("cmd-1", "beacon-1", "listener-1") in assistant._stopped_command_keys
    assert assistant.agent.stopped_waits == [{"pending_id": "pending-1"}]
    assert "remote command was not cancelled or marked failed" in assistant.editorOutput.toPlainText()
    starts = []
    monkeypatch.setattr(assistant, "_start_agent_turn", starts.append)
    assistant.commandEditor.setText("new request")
    assistant.runCommand()
    assert starts == ["new request"]


def test_cancel_command_reports_when_nothing_is_pending(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)

    assistant.commandEditor.setText("/cancel")
    assistant.runCommand()

    assert "No pending assistant wait to stop." in assistant.editorOutput.toPlainText()


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
    assert "Command `run touch /tmp/hello` on beacon `beacon-1` (cmd `4078543f`, no automatic timeout)." in output
    assert "listener-1" not in output


def test_console_receive_resumes_matching_pending_command_id(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    resume_calls = []
    monkeypatch.setattr(
        assistant,
        "_start_agent_resume",
        lambda pending_id, tool_output, ok: resume_calls.append((pending_id, tool_output, ok)),
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
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="cmd-1", beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="run touch /tmp/hello", output="",
    ))

    assert len(resume_calls) == 1
    assert resume_calls[0][0] == "pending-1"
    content = json.loads(resume_calls[0][1])
    assert content["command_id"] == "cmd-1"
    assert content["beacon_hash"] == "beacon-1"
    assert content["listener_hash"] == "listener-1"
    assert content["command_line"] == "run touch /tmp/hello"
    assert content["output"] == ""
    assert resume_calls[0][2] is True
    assert assistant.awaiting_tool_result is False
    assert assistant.pending_tool_id is None
    assert assistant.pending_tool_context is None


def test_console_receive_ignores_mismatched_pending_command_id(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    resume_calls = []
    monkeypatch.setattr(
        assistant,
        "_start_agent_resume",
        lambda pending_id, tool_output, ok: resume_calls.append((pending_id, tool_output, ok)),
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
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="cmd-2", beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="whoami", output="user",
    ))

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


def test_failed_command_resumes_with_failed_status_and_full_output(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1", "beacon_hash": "beacon-1", "listener_hash": "listener-1",
    }
    calls = []
    monkeypatch.setattr(assistant, "_start_agent_resume", lambda *args: calls.append(args))

    assistant.receiveCommandOutcome(CommandOutcome(
        state="failed", command_id="cmd-1", beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="whoami", output="raw failure",
        error_code="teamserver_command_failed", error_message="Command failed.",
    ))

    assert calls[0][0] == "pending-1"
    assert calls[0][2] is False
    assert json.loads(calls[0][1])["output"] == "raw failure"
    assert "failed: Command failed." in assistant.editorOutput.toPlainText()
    assistant._agent_resume_worker(*calls[0])
    assert assistant.agent.resumes[0]["ok"] is False


def test_command_result_requires_exact_id_and_target(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1", "beacon_hash": "beacon-1", "listener_hash": "listener-1",
    }
    calls = []
    monkeypatch.setattr(assistant, "_start_agent_resume", lambda *args: calls.append(args))

    for command_id, beacon_hash, listener_hash in (
        ("", "beacon-1", "listener-1"),
        ("cmd-1", "beacon-2", "listener-1"),
        ("cmd-1", "beacon-1", "listener-2"),
    ):
        assistant.receiveCommandOutcome(CommandOutcome(
            state="succeeded", command_id=command_id, beacon_hash=beacon_hash,
            listener_hash=listener_hash, command_line="whoami", output="user",
        ))
    assert calls == []
    assert assistant.awaiting_tool_result is True


def test_pending_response_has_no_automatic_timeout(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)

    message = pending_message()
    message.content = '{"status":"pending"}'
    assistant._process_assistant_response(message)

    assert assistant.awaiting_tool_result is True
    assert assistant.pending_tool_id == "pending-1"
    assert assistant.pending_tool_context["command_id"] == "4078543f88cc4403aa587856afdfbfea"
    assert assistant.pending_tool_context["command_line"] == "run touch /tmp/hello"
    assert not hasattr(assistant, "pending_tool_timer")
    output = assistant.editorOutput.toPlainText()
    assert "Waiting for beacon command result. Command `run touch /tmp/hello` on beacon `beacon-1` (cmd `4078543f`, no automatic timeout)." in output
    assert "4078543f88cc4403aa587856afdfbfea" not in output
    assert '{"status":"pending"}' not in output


def test_late_result_after_manual_stop_does_not_resume_new_wait(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant._process_assistant_response(pending_message())
    assistant.commandEditor.setText("/stop")
    assistant.runCommand()
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-2"
    assistant.pending_tool_context = {
        "command_id": "cmd-2", "beacon_hash": "beacon-2", "listener_hash": "listener-2",
    }
    calls = []
    monkeypatch.setattr(assistant, "_start_agent_resume", lambda *args: calls.append(args))
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="4078543f88cc4403aa587856afdfbfea",
        beacon_hash="beacon-12345678", listener_hash="listener-1",
        command_line="old", output="late",
    ))
    assert calls == []
    assert assistant.awaiting_tool_result is True
    assert assistant.pending_tool_id == "pending-2"
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="cmd-2", beacon_hash="beacon-2",
        listener_hash="listener-2", command_line="new", output="new result",
    ))
    assert calls[0][0] == "pending-2"


def test_result_waits_for_active_worker_then_resumes(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant._process_assistant_response(pending_message())
    assistant._response_thread = SimpleNamespace(is_alive=lambda: True)
    calls = []
    monkeypatch.setattr(assistant, "_start_agent_resume", lambda *args: calls.append(args))
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="4078543f88cc4403aa587856afdfbfea",
        beacon_hash="beacon-12345678", listener_hash="listener-1",
        command_line="whoami", output="result",
    ))
    assert calls == []
    assert assistant._deferred_resume is not None
    assistant._response_thread = None
    assistant._drain_deferred_resume()
    assert calls[0][0] == "pending-1"
    assert assistant._deferred_resume is None


def test_cached_hub_result_resumes_when_pending_state_arrives_late(qtbot, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("C2Client.AssistantPanel.C2AssistantAgent", FakeAssistantAgent)
    monkeypatch.setattr(CommandResultWorker, "start", lambda self: None)
    hub = CommandEventHub(object())
    assistant = Assistant(None, object(), command_event_hub=hub)
    qtbot.addWidget(assistant)
    assistant.setActiveSession("beacon-12345678", "listener-1")
    hub.ingest_response(
        "beacon-12345678", "listener-1",
        SimpleNamespace(
            status=TeamServerApi_pb2.OK,
            session=SimpleNamespace(beacon_hash="beacon-12345678", listener_hash="listener-1"),
            command="whoami", instruction="", command_id="4078543f88cc4403aa587856afdfbfea",
            output=b"user", message="",
        ),
    )
    assert assistant.agent.domain_hooks.active_sessions == [
        {"beacon_hash": "beacon-12345678", "listener_hash": "listener-1"}
    ]
    calls = []
    monkeypatch.setattr(assistant, "_start_agent_resume", lambda *args: calls.append(args))

    assistant._process_assistant_response(pending_message())

    assert len(calls) == 1
    assert calls[0][0] == "pending-1"
    assert json.loads(calls[0][1])["output"] == "user"
    assert assistant.awaiting_tool_result is False
    assistant.close()
    hub.shutdown()


def test_module_load_result_dispatches_requested_command_before_resuming(qtbot, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("C2Client.AssistantPanel.C2AssistantAgent", FakeAssistantAgent)
    sent = []

    def send(command):
        sent.append(command)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, command_id=command.command_id)

    grpc_client = SimpleNamespace(
        listModules=lambda session: [SimpleNamespace(name="whoami", state="loaded")],
        sendSessionCommand=send,
    )
    assistant = Assistant(None, grpc_client)
    qtbot.addWidget(assistant)
    assistant._process_assistant_response(SimpleNamespace(
        content="", is_pending=True, pending_id="pending-load",
        metadata={
            "command_id": "load-1", "beacon_hash": "beacon-1", "listener_hash": "listener-1",
            "command_line": "loadModule whoami", "continuation_command_line": "whoami",
        },
        tool_arguments={},
    ))
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="load-1", beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="loadModule whoami", output="loaded",
    ))
    qtbot.waitUntil(lambda: assistant.pending_tool_context["command_id"] != "load-1")
    assert [request.command for request in sent] == ["whoami"]
    assert assistant.agent.resumes == []

    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id=sent[0].command_id, beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="whoami", output="operator",
    ))
    qtbot.waitUntil(lambda: len(assistant.agent.resumes) == 1)
    assert json.loads(assistant.agent.resumes[0]["tool_content"])["output"] == "operator"


def test_module_already_loaded_result_continues_conversation(qtbot, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("C2Client.AssistantPanel.C2AssistantAgent", FakeAssistantAgent)
    sent = []

    def send(command):
        sent.append(command)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, command_id=command.command_id)

    grpc_client = SimpleNamespace(listModules=lambda session: [], sendSessionCommand=send)
    assistant = Assistant(None, grpc_client)
    qtbot.addWidget(assistant)
    assistant._process_assistant_response(SimpleNamespace(
        content="", is_pending=True, pending_id="pending-load",
        metadata={
            "command_id": "load-1", "beacon_hash": "beacon-1", "listener_hash": "listener-1",
            "command_line": "loadModule whoami", "continuation_command_line": "whoami",
        },
        tool_arguments={},
    ))
    assistant.receiveCommandOutcome(CommandOutcome(
        state="failed", command_id="load-1", beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="loadModule whoami",
        error_code="command_failed", error_message="Error: Module already loaded",
    ))
    qtbot.waitUntil(lambda: len(sent) == 1)
    qtbot.waitUntil(lambda: assistant.pending_tool_context["command_id"] != "load-1")
    assert sent[0].command == "whoami"
    assert assistant.agent.resumes == []

    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id=sent[0].command_id, beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="whoami", output="operator",
    ))
    qtbot.waitUntil(lambda: len(assistant.agent.resumes) == 1)
    assert json.loads(assistant.agent.resumes[0]["tool_content"])["output"] == "operator"


def test_uncertain_beacon_result_keeps_conversation_pending(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant._process_assistant_response(pending_message())
    assistant.receiveCommandOutcome(CommandOutcome(
        state="outcome_unknown", command_id="4078543f88cc4403aa587856afdfbfea",
        beacon_hash="beacon-12345678", listener_hash="listener-1",
        command_line="whoami", error_code="outcome_unknown",
    ))
    assert assistant.awaiting_tool_result is True
    assert assistant.agent.resumes == []


def test_stop_during_module_load_prevents_follow_up_command(qtbot, monkeypatch):
    assistant = build_assistant(qtbot, monkeypatch)
    assistant._process_assistant_response(SimpleNamespace(
        content="", is_pending=True, pending_id="pending-load",
        metadata={
            "command_id": "load-1", "beacon_hash": "beacon-1", "listener_hash": "listener-1",
            "command_line": "loadModule whoami", "continuation_command_line": "whoami",
        },
        tool_arguments={},
    ))
    dispatched = []
    monkeypatch.setattr(assistant, "_start_module_continuation", lambda *args: dispatched.append(args))
    assistant.commandEditor.setText("/stop")
    assistant.runCommand()
    assistant.receiveCommandOutcome(CommandOutcome(
        state="succeeded", command_id="load-1", beacon_hash="beacon-1",
        listener_hash="listener-1", command_line="loadModule whoami", output="loaded",
    ))
    assert dispatched == []
    assert assistant.agent.resumes == []
