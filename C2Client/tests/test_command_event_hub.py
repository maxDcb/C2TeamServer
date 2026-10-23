from __future__ import annotations

import json
from types import SimpleNamespace

from PyQt6.QtCore import QThread

from C2Client.command_event_hub import CommandEventHub, CommandResultWorker
from C2Client.ConsolePanel import ConsolesTab, SYSTEM_TAB_COUNT
from C2Client.grpcClient import TeamServerApi_pb2


def result(command_id="cmd-1", *, beacon="beacon", listener="listener", output=b"user", status=None,
           event_id=0, job_state=""):
    return SimpleNamespace(
        status=TeamServerApi_pb2.OK if status is None else status,
        session=SimpleNamespace(beacon_hash=beacon, listener_hash=listener),
        command="whoami",
        instruction="",
        command_id=command_id,
        output=output,
        message="Command failed." if status == TeamServerApi_pb2.KO else "",
        event_id=event_id,
        job_state=job_state,
    )


class StubGrpc:
    def __init__(self):
        self.calls = 0

    def streamSessionCommandResults(self, session):
        self.calls += 1
        return []

    def listCommands(self, query=None):
        return iter([])

    def listModules(self, session):
        return iter([])

    def listSessions(self):
        return iter([])

    def listListeners(self):
        return iter([])


def test_one_worker_fans_out_once_to_two_subscribers_and_deduplicates(qtbot, monkeypatch):
    starts = []
    monkeypatch.setattr(CommandResultWorker, "start", lambda self: starts.append(self))
    hub = CommandEventHub(StubGrpc())
    first, second = [], []
    sub1 = hub.subscribe("beacon", "listener", first.append)
    sub2 = hub.subscribe("beacon", "listener", second.append)

    assert len(starts) == 1
    assert len(hub._streams) == 1
    hub.ingest_response("beacon", "listener", result())
    hub.ingest_response("beacon", "listener", result())
    assert len(first) == len(second) == 1
    assert first[0] is second[0]
    assert first[0].outcome.output == "user"
    assert hub.recent_event("beacon", "listener", "cmd-1") is first[0]

    sub1.close()
    hub.ingest_response("beacon", "listener", result("cmd-2"))
    assert len(first) == 1
    assert len(second) == 2
    assert len(hub._streams) == 1
    sub2.close()
    assert hub._streams == {}


def test_late_result_updates_outcome_unknown_with_new_event_id(monkeypatch):
    monkeypatch.setattr(CommandResultWorker, "start", lambda self: None)
    hub = CommandEventHub(StubGrpc())
    received = []
    hub.subscribe("beacon", "listener", received.append)
    hub.ingest_response("beacon", "listener", result(
        status=TeamServerApi_pb2.KO, output=b"", event_id=10, job_state="outcome_unknown"))
    hub.ingest_response("beacon", "listener", result(event_id=11, job_state="succeeded"))
    hub.ingest_response("beacon", "listener", result(event_id=11, job_state="succeeded"))
    assert [event.outcome.state for event in received] == ["outcome_unknown", "succeeded"]
    assert [event.event_id for event in received] == [10, 11]
    hub.shutdown()


def test_session_keys_are_isolated_and_mismatched_responses_are_rejected(monkeypatch):
    monkeypatch.setattr(CommandResultWorker, "start", lambda self: None)
    hub = CommandEventHub(StubGrpc())
    left, right = [], []
    hub.subscribe("beacon", "listener-a", left.append)
    hub.subscribe("beacon", "listener-b", right.append)
    assert len(hub._streams) == 2

    hub.ingest_response("beacon", "listener-a", result(listener="listener-b"))
    assert left == right == []
    hub.ingest_response("beacon", "listener-a", result(listener="listener-a"))
    hub.ingest_response("beacon", "listener-b", result(listener="listener-b"))
    assert len(left) == len(right) == 1
    assert left[0].session_key == ("listener-a", "beacon")
    assert right[0].session_key == ("listener-b", "beacon")
    hub.shutdown()


def test_duplicate_callback_subscriptions_unsubscribe_independently(monkeypatch):
    monkeypatch.setattr(CommandResultWorker, "start", lambda self: None)
    hub = CommandEventHub(StubGrpc())
    received = []
    first = hub.subscribe("beacon", "listener", received.append)
    hub.subscribe("beacon", "listener", received.append)
    hub.ingest_response("beacon", "listener", result())
    assert len(received) == 2

    first.close()
    hub.ingest_response("beacon", "listener", result("cmd-2"))
    assert len(received) == 3
    hub.shutdown()


def test_worker_reconnects_without_starting_a_second_worker(qtbot):
    class FlakyGrpc(StubGrpc):
        def streamSessionCommandResults(self, session):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("temporary disconnect")
            return [result("cmd-reconnected")] if self.calls == 2 else []

    grpc = FlakyGrpc()
    hub = CommandEventHub(grpc)
    seen = []
    hub.subscribe("beacon", "listener", lambda event: seen.append((event, QThread.currentThread())))
    worker = hub._streams[("listener", "beacon")].worker

    qtbot.waitUntil(lambda: len(seen) == 1, timeout=4000)
    assert grpc.calls >= 2
    assert hub._streams[("listener", "beacon")].worker is worker
    assert seen[0][0].outcome.command_id == "cmd-reconnected"
    assert seen[0][1] is hub.thread()
    hub.shutdown()
    assert not worker.isRunning()


def test_shutdown_stops_all_session_workers(qtbot):
    hub = CommandEventHub(StubGrpc())
    hub.subscribe("beacon-a", "listener", lambda event: None)
    hub.subscribe("beacon-b", "listener", lambda event: None)
    workers = [stream.worker for stream in hub._streams.values()]
    qtbot.waitUntil(lambda: all(worker.isRunning() for worker in workers), timeout=1000)

    hub.shutdown()

    assert hub._streams == {}
    assert all(not worker.isRunning() for worker in workers)
    hub.shutdown()


def test_closing_console_keeps_assistant_subscription_and_pending_result(tmp_path, qtbot, monkeypatch):
    from C2Client import ConsolePanel
    from C2Client import AssistantPanel

    class PanelStub(ConsolePanel.QWidget):
        def __init__(self, parent=None, *_args, **_kwargs):
            super().__init__(parent)

        def consoleScriptMethod(self, *args):
            pass

    class FakeAgent:
        def __init__(self, grpc_client):
            self.domain_hooks = SimpleNamespace(
                record_active_session=lambda **kwargs: None,
                record_console_observation=lambda **kwargs: None,
            )

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(AssistantPanel, "C2AssistantAgent", FakeAgent)
    monkeypatch.setattr(CommandResultWorker, "start", lambda self: None)
    monkeypatch.setattr(ConsolePanel, "Terminal", PanelStub)
    monkeypatch.setattr(ConsolePanel, "Script", PanelStub)
    monkeypatch.setattr(ConsolePanel, "Artifacts", PanelStub)
    monkeypatch.setattr(ConsolePanel, "Commands", PanelStub)
    monkeypatch.setattr(ConsolePanel, "logsDir", str(tmp_path))

    consoles = ConsolesTab(None, StubGrpc())
    qtbot.addWidget(consoles)
    consoles.addConsole("beacon", "listener", "host", "user")
    assistant = consoles.assistant
    key = ("listener", "beacon")
    assert len(consoles.command_result_hub._streams[key].subscribers) == 2
    assistant.awaiting_tool_result = True
    assistant.pending_tool_id = "pending-1"
    assistant.pending_tool_context = {
        "command_id": "cmd-1", "beacon_hash": "beacon", "listener_hash": "listener",
    }
    resumes = []
    monkeypatch.setattr(assistant, "_start_agent_resume", lambda *args: resumes.append(args))

    consoles.closeTab(SYSTEM_TAB_COUNT)
    assert len(consoles.command_result_hub._streams[key].subscribers) == 1
    consoles.command_result_hub.ingest_response("beacon", "listener", result())

    assert len(resumes) == 1
    assert resumes[0][0] == "pending-1"
    assert json.loads(resumes[0][1])["output"] == "user"
    consoles.addConsole("beacon", "listener", "host", "user")
    reopened = consoles.consoleFromTab(SYSTEM_TAB_COUNT)
    assert reopened.commandStatusById["cmd-1"]["status"] == "done"
    assert "user" in reopened.editorOutput.toPlainText()
    assert 'result: "whoami"' in (tmp_path / "host_user_beacon.log").read_text()
    consoles.shutdown()
