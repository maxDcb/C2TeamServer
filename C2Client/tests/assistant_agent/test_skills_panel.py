from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.skills.panel import SkillsPanel


def session(beacon: str, listener: str, *, killed: bool = False):
    return SimpleNamespace(
        beacon_hash=beacon, listener_hash=listener,
        hostname=f"host-{beacon}", username="operator", killed=killed,
    )


class FakeGrpc:
    def __init__(self, sessions):
        self.sessions = sessions

    def listSessions(self):
        return list(self.sessions)

    def submitJob(self):
        pass

    def getJobExecution(self):
        pass

    def listCommands(self):
        pass

    def listModules(self):
        pass


class FakeService:
    def __init__(self, grpc_client, on_change):
        self.calls = []

    def list_runs(self):
        return []

    def start(self, skill_id, beacon_hash, listener_hash):
        self.calls.append((skill_id, beacon_hash, listener_hash))


def make_panel(qtbot, monkeypatch, sessions):
    monkeypatch.setattr("C2Client.assistant_agent.skills.panel.C2SkillService", FakeService)
    grpc_client = FakeGrpc(sessions)
    panel = SkillsPanel(None, grpc_client)
    qtbot.addWidget(panel)
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    return panel, grpc_client


def test_task_auto_selects_only_live_session_and_starts_without_console(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])

    assert panel.sessionSelector.currentData() == ("beacon-1", "listener-1")
    assert panel.startButton.isEnabled()
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("inventory_local", "beacon-1", "listener-1")]
    panel.shutdown()


def test_task_selects_from_multiple_sessions_and_preserves_choice(qtbot, monkeypatch):
    panel, grpc_client = make_panel(qtbot, monkeypatch, [
        session("beacon-1", "listener-1"),
        session("beacon-2", "listener-2"),
        session("beacon-3", "listener-3", killed=True),
    ])

    assert panel.sessionSelector.count() == 3
    assert not panel.startButton.isEnabled()
    panel.sessionSelector.setCurrentIndex(2)
    assert (panel.active_beacon, panel.active_listener) == ("beacon-2", "listener-2")
    assert panel.startButton.isEnabled()
    grpc_client.sessions = list(reversed(grpc_client.sessions))
    panel.refreshSessionsButton.click()
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    assert panel.sessionSelector.currentData() == ("beacon-2", "listener-2")
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("inventory_local", "beacon-2", "listener-2")]
    panel.shutdown()


def test_task_clears_stopped_session_and_accepts_console_selection(qtbot, monkeypatch):
    panel, grpc_client = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])

    panel.set_active_session("beacon-1", "listener-1")
    assert panel.sessionSelector.currentData() == ("beacon-1", "listener-1")
    grpc_client.sessions = [session("beacon-1", "listener-1", killed=True)]
    panel.refreshSessionsButton.click()
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    assert panel.sessionSelector.currentData() is None
    assert not panel.startButton.isEnabled()
    panel.shutdown()
