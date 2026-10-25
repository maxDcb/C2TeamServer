from datetime import datetime
from threading import Event
from types import SimpleNamespace

import pytest
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QHeaderView, QMessageBox, QWidget

import C2Client.SessionPanel as session_panel
from C2Client.SessionPanel import (
    SESSION_STATE_ALIVE,
    SESSION_STATE_KILLED,
    SESSION_STATE_STALE,
    SESSION_STATE_UNKNOWN,
    Session,
    Sessions,
    humanize_last_seen,
    last_seen_age_ms,
    normalize_os_label,
    parse_last_seen,
    resolve_session_state,
)
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.stop_ack = None
        self.stopped_sessions = []
        self.listeners = []

    def listSessions(self):
        return []

    def stopSession(self, session):
        self.stopped_sessions.append(session)
        return self.stop_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Session stop command queued."})()

    def listListeners(self):
        return self.listeners


@pytest.fixture(autouse=True)
def accept_beacon_stop_confirmation(monkeypatch):
    monkeypatch.setattr(session_panel.QMessageBox, "question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes)


def test_sessions_table_labels_arch_as_beacon_process(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    sessions.listSessionObject = []
    qtbot.addWidget(sessions)

    assert "#0b1117" in sessions.styleSheet()
    assert "#263241" in sessions.styleSheet()

    sessions.printSessions()

    arch_header = sessions.listSession.horizontalHeaderItem(4)
    assert arch_header.text() == "Arch"
    assert arch_header.toolTip() == "Architecture du process beacon"


def test_session_state_helpers_humanize_lifecycle():
    now = datetime(2026, 5, 4, 12, 0, 0, 100000)

    assert resolve_session_state(False, "2026-05-04T12:00:00.090000", staleAfterMs=30, now=now)[0] == SESSION_STATE_ALIVE
    assert resolve_session_state(False, "2026-05-04T11:59:58", staleAfterMs=30, now=now)[0] == SESSION_STATE_STALE
    assert resolve_session_state(True, "2026-05-04T12:00:00.090000", staleAfterMs=30, now=now)[0] == SESSION_STATE_KILLED
    assert resolve_session_state(False, "-1", staleAfterMs=30, now=now)[0] == SESSION_STATE_UNKNOWN

    label, tooltip, _ = humanize_last_seen("2026-05-04T11:58:00", now=now)
    assert label == "2m ago"
    assert tooltip == "Last proof of life: 2026-05-04T11:58:00"
    assert normalize_os_label("Microsoft Windows 11 Pro 10.0.22631") == "Windows"
    assert normalize_os_label("Linux version 6.8.0") == "Linux"


def test_last_seen_parser_accepts_teamserver_age_seconds(monkeypatch):
    class FixedDateTime(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 5, 4, 12, 30, 0, 500000)

    monkeypatch.setattr(session_panel, "datetime", FixedDateTime)

    parsed = parse_last_seen("2.5")

    assert parsed == datetime(2026, 5, 4, 12, 29, 58)


def test_teamserver_age_seconds_drive_last_seen_and_state(monkeypatch):
    class FixedDateTime(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 5, 4, 12, 30, 0)

    monkeypatch.setattr(session_panel, "datetime", FixedDateTime)

    label, tooltip, _ = humanize_last_seen("0.010000")
    state, stateTooltip = resolve_session_state(False, "0.010000", staleAfterMs=30)
    almostNowLabel, _, _ = humanize_last_seen("1.999000")
    almostNowState, almostNowTooltip = resolve_session_state(False, "1.999000", staleAfterMs=30)
    staleLabel, _, _ = humanize_last_seen("2.000000")
    staleState, staleTooltip = resolve_session_state(False, "2.000000", staleAfterMs=30)

    assert last_seen_age_ms("0.010000") == (10, True)
    assert label == "now"
    assert tooltip == "Last proof of life: 0.010000"
    assert state == SESSION_STATE_ALIVE
    assert stateTooltip == "Last seen now. Stale after 30 ms."
    assert almostNowLabel == "now"
    assert almostNowState == SESSION_STATE_ALIVE
    assert almostNowTooltip == "Last seen now. Stale after 30 ms."
    assert staleLabel == "2s ago"
    assert staleState == SESSION_STATE_STALE
    assert staleTooltip == "Last seen 2s ago. Stale after 30 ms."


def test_stop_session_ack_message_is_displayed(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    grpc.stop_ack = type("Ack", (), {"status": TeamServerApi_pb2.KO, "message": "Session not found."})()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.listSessionObject = []
    qtbot.addWidget(sessions)

    sessions.stopSession("beacon", "listener")

    qtbot.waitUntil(lambda: sessions.statusLabel.text() == "Stop session: Session not found.")
    assert sessions.statusLabel.text() == "Stop session: Session not found."
    assert "#b00020" in sessions.statusLabel.styleSheet()


def test_session_toolbar_actions_use_selected_session(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.listSessionObject = [
        Session(
            0,
            "listener-full-hash",
            "beacon-full-hash",
            "host1",
            "user1",
            "x64",
            "HIGH",
            "Windows",
            "2026-05-04T12:00:00",
            False,
            "10.0.0.5",
            "1234",
            "",
        )
    ]
    qtbot.addWidget(sessions)

    emitted = []
    sessions.interactWithSession.connect(lambda *args: emitted.append(args))

    sessions.printSessions()
    assert sessions.interactButton.isEnabled() is False
    assert sessions.stopButton.isEnabled() is False
    assert sessions.copySessionIdButton.isEnabled() is False
    assert sessions.interactButton.text() == "Open"
    assert sessions.copySessionIdButton.text() == "Copy"
    assert sessions.listSession.horizontalHeader().sectionResizeMode(8) == QHeaderView.ResizeMode.Stretch

    sessions.listSession.selectRow(0)

    assert sessions.interactButton.isEnabled() is True
    assert sessions.stopButton.isEnabled() is True
    assert sessions.copySessionIdButton.isEnabled() is True

    sessions.interactButton.click()
    assert emitted == [("beacon-full-hash", "listener-full-hash", "host1", "user1", False)]

    sessions.copySessionIdButton.click()
    assert QApplication.clipboard().text() == "beacon-full-hash"
    assert sessions.statusLabel.text() == "Beacon ID copied to clipboard."

    sessions.stopButton.click()
    qtbot.waitUntil(lambda: bool(grpc.stopped_sessions))
    assert grpc.stopped_sessions[-1].beacon_hash == "beacon-full-hash"
    assert grpc.stopped_sessions[-1].listener_hash == "listener-full-hash"


def test_stop_targets_only_the_current_session_row(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    qtbot.addWidget(sessions)
    sessions.listSessionObject = [
        Session(0, "parent-route", "parent-beacon", "host", "user", "x64", "user", "Linux", "0", False, "", "101", ""),
        Session(1, "child-route", "child-beacon", "host", "user", "x64", "user", "Linux", "0", False, "", "102", ""),
    ]
    sessions.printSessions()
    sessions.listSessionObject.reverse()  # Simulate a refresh that changes the backing order.

    assert sessions.listSession.selectionMode() == QAbstractItemView.SelectionMode.SingleSelection
    sessions.listSession.selectRow(0)
    sessions.listSession.selectRow(1)
    assert [index.row() for index in sessions.listSession.selectionModel().selectedRows()] == [1]

    sessions.stopButton.click()
    qtbot.waitUntil(lambda: bool(grpc.stopped_sessions))
    assert grpc.stopped_sessions[0].beacon_hash == "child-beacon"
    assert grpc.stopped_sessions[0].listener_hash == "child-route"
    qtbot.waitUntil(lambda: not sessions._stop_pending)
    assert "child-be / child-ro" in sessions.statusLabel.text()


def test_session_script_snapshot_exposes_beacon_context(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    sessions.sessionStaleAfterMs = 1_000_000
    sessions.listSessionObject = [
        Session(
            0,
            "listener-full-hash",
            "beacon-full-hash",
            "host1",
            "user1",
            "x64",
            "HIGH",
            "Windows",
            datetime.now().isoformat(),
            False,
            "10.0.0.5, 192.168.56.20",
            "1234",
            "note",
        )
    ]
    qtbot.addWidget(sessions)

    snapshot = sessions.scriptSnapshot()

    assert snapshot == [
        {
            "id": 0,
            "beacon_hash": "beacon-full-hash",
            "listener_hash": "listener-full-hash",
            "hostname": "host1",
            "username": "user1",
            "arch": "x64",
            "privilege": "HIGH",
            "os": "Windows",
            "last_proof_of_life": sessions.listSessionObject[0].lastProofOfLife,
            "killed": False,
            "internal_ips": ["10.0.0.5", "192.168.56.20"],
            "internal_ips_text": "10.0.0.5, 192.168.56.20",
            "process_id": "1234",
            "additional_information": "note",
            "state": SESSION_STATE_ALIVE,
            "state_detail": snapshot[0]["state_detail"],
        }
    ]
    assert snapshot[0]["state_detail"].startswith("Last seen now.")


def test_session_table_keeps_user_column_width_after_refresh(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    sessions.listSessionObject = [
        Session(
            0,
            "listener-full-hash",
            "beacon-full-hash",
            "host1",
            "user1",
            "x64",
            "HIGH",
            "Windows",
            "2026-05-04T12:00:00",
            False,
            "10.0.0.5, 192.168.56.20",
            "1234",
            "",
        )
    ]
    qtbot.addWidget(sessions)

    sessions.printSessions()
    sessions.listSession.setColumnWidth(2, 224)
    sessions.printSessions()

    assert sessions.listSession.columnWidth(2) == 224
    assert sessions.listSession.item(0, 8).text() == "10.0.0.5, 192.168.56.20"
    assert sessions.listSession.item(0, 8).toolTip() == "10.0.0.5, 192.168.56.20"


def test_session_table_humanizes_state_last_seen_and_os(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    full_os = "Microsoft Windows 11 Pro 10.0.22631"
    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    sessions.sessionStaleAfterMs = 1_000_000
    sessions.listSessionObject = [
        Session(
            0,
            "listener-full-hash",
            "beacon-full-hash",
            "host1",
            "user1",
            "x64",
            "HIGH",
            full_os,
            datetime.now().isoformat(),
            False,
            "10.0.0.5",
            "1234",
            "",
        )
    ]
    qtbot.addWidget(sessions)

    sessions.printSessions()

    assert sessions.listSession.horizontalHeaderItem(10).text() == "State"
    assert sessions.listSession.item(0, 6).text() == "Windows"
    assert sessions.listSession.item(0, 6).toolTip() == full_os
    assert sessions.listSession.item(0, 9).text() == "now"
    assert sessions.listSession.item(0, 10).text() == SESSION_STATE_ALIVE
    assert sessions.listSession.item(0, 10).toolTip().startswith("Last seen now.")


def test_session_refresh_replaces_removed_listener_route(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    qtbot.addWidget(sessions)
    events = []
    sessions.sessionScriptSignal.connect(lambda *args: events.append(args))

    def snapshot(listener_hash):
        return SimpleNamespace(
            beacon_hash="beacon-full-hash", listener_hash=listener_hash,
            hostname="host", username="user", arch="x64", privilege="user",
            os="Linux", last_proof_of_life="0.1", killed=False,
            internal_ips="", process_id="123", additional_information="",
        )

    sessions._applySessions([snapshot("old-listener")])
    sessions.listSession.selectRow(0)
    sessions._applySessions([])
    assert sessions.listSession.rowCount() == 1
    assert sessions.listSession.item(0, 10).text() == "Unavailable"
    assert sessions.listSessionObject[0].available is False
    assert sessions.selectedSession() is not None
    assert sessions.interactButton.text() == "History"
    assert not sessions.stopButton.isEnabled()
    assert sessions.statusLabel.text() == "No active sessions on TeamServer; waiting for beacon check-in."
    assert any(event[0:3] == ("retire", "beacon-full-hash", "old-listener") for event in events)
    assert not any(event[0] == "stop" for event in events)

    sessions._applySessions([snapshot("new-listener")])
    assert sessions.listSession.rowCount() == 2
    assert sessions.listSessionObject[0].listenerHash == "new-listener"
    assert sessions.listSessionObject[1].listenerHash == "old-listener"
    assert sessions.selectedSession().listenerHash == "old-listener"
    assert not any(event[0] == "start" for event in events)


def test_stop_session_runs_outside_gui_and_prevents_duplicate_request(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    class DelayedGrpc(StubGrpc):
        def __init__(self):
            super().__init__()
            self.started = Event()
            self.release = Event()

        def stopSession(self, session):
            self.started.set()
            self.release.wait(timeout=3)
            return super().stopSession(session)

    grpc = DelayedGrpc()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    qtbot.addWidget(sessions)
    sessions.stopSession("beacon", "listener")
    qtbot.waitUntil(grpc.started.is_set)
    assert sessions._stop_pending is True
    assert "waiting for TeamServer" in sessions.statusLabel.text()
    sessions.stopSession("beacon", "listener")
    assert grpc.stopped_sessions == []
    grpc.release.set()
    qtbot.waitUntil(lambda: not sessions._stop_pending)
    assert len(grpc.stopped_sessions) == 1


def test_stop_session_transport_error_is_visible_and_not_replayed(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    class FailedGrpc(StubGrpc):
        def stopSession(self, session):
            self.stopped_sessions.append(session)
            raise RuntimeError("deadline exceeded")

    grpc = FailedGrpc()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    qtbot.addWidget(sessions)
    sessions.stopSession("beacon", "listener")
    qtbot.waitUntil(lambda: not sessions._stop_pending)
    assert "did not confirm" in sessions.statusLabel.text()
    assert "deadline exceeded" in sessions.statusLabel.text()
    assert len(grpc.stopped_sessions) == 1


def test_stop_confirmation_warns_about_hosted_listeners_and_cancel_sends_nothing(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    grpc.listeners = [
        SimpleNamespace(beacon_hash="parent-beacon", listener_hash="child-listener-full", type="tcp"),
        SimpleNamespace(beacon_hash="other-beacon", listener_hash="unrelated-listener", type="tcp"),
    ]
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.setParent(None)
    qtbot.addWidget(sessions)
    sessions.listSessionObject = [
        Session(0, "parent-route", "parent-beacon", "host", "user", "x64", "user", "Linux", "0", False, "", "101", ""),
    ]
    sessions.printSessions()
    dialogs = []

    def decline(_parent, title, message, buttons, default):
        dialogs.append((title, message, buttons, default))
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(session_panel.QMessageBox, "question", decline)
    sessions.stopSession("parent-beacon", "parent-route")
    qtbot.waitUntil(lambda: bool(dialogs) and not sessions._stop_pending)

    assert "parent-beacon" in dialogs[0][1]
    assert "PID: 101" in dialogs[0][1]
    assert "1 child listener" in dialogs[0][1]
    assert "child-li" in dialogs[0][1]
    assert "unrelated" not in dialogs[0][1]
    assert dialogs[0][3] == QMessageBox.StandardButton.No
    assert grpc.stopped_sessions == []


def test_stop_confirmation_is_required_without_child_listener(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.setParent(None)
    qtbot.addWidget(sessions)
    messages = []

    def decline(_parent, _title, message, _buttons, _default):
        messages.append(message)
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(session_panel.QMessageBox, "question", decline)
    sessions.stopSession("beacon", "listener")
    qtbot.waitUntil(lambda: bool(messages) and not sessions._stop_pending)
    assert "No hosted child listener was reported" in messages[0]
    assert grpc.stopped_sessions == []


def test_stop_confirmation_reports_unknown_child_listener_state(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    class FailedLookup(StubGrpc):
        def listListeners(self):
            raise RuntimeError("listener listing unavailable")

    grpc = FailedLookup()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.setParent(None)
    qtbot.addWidget(sessions)
    messages = []

    def decline(_parent, _title, message, _buttons, _default):
        messages.append(message)
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(session_panel.QMessageBox, "question", decline)
    sessions.stopSession("beacon", "listener")
    qtbot.waitUntil(lambda: bool(messages) and not sessions._stop_pending)
    assert "could not be checked" in messages[0]
    assert grpc.stopped_sessions == []


def test_context_action_targets_full_session_key_with_prefix_collision(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    qtbot.addWidget(sessions)
    sessions.listSessionObject = [
        Session(0, "route-one", "abcdefgh-one", "host1", "user", "x64", "user", "Linux", "0", False, "", "1", ""),
        Session(1, "route-two", "abcdefgh-two", "host2", "user", "x64", "user", "Linux", "0", False, "", "2", ""),
    ]
    class FakeMenu:
        def __init__(self):
            self.labels = []
            self.triggered = SimpleNamespace(connect=lambda callback: None)

        def addAction(self, label):
            self.labels.append(label)
            return SimpleNamespace(setEnabled=lambda enabled: None)

        def exec(self, position):
            return None

    menu = FakeMenu()
    monkeypatch.setattr(session_panel, "create_dark_context_menu", lambda parent: menu)
    sessions.printSessions()
    sessions.listSessionObject.reverse()  # The visible second row must keep its own identity.
    sessions.show()
    position = sessions.listSession.visualItemRect(sessions.listSession.item(1, 0)).center()
    sessions.showContextMenu(position)
    assert menu.labels == ["Interact", "Stop abcdefgh (PID 2)"]
    assert sessions._context_session_key == ("abcdefgh-two", "route-two")
    emitted = []
    sessions.interactWithSession.connect(lambda *args: emitted.append(args))
    sessions.actionClicked(SimpleNamespace(text=lambda: "Interact"))
    assert emitted == [("abcdefgh-two", "route-two", "host2", "user", False)]
    sessions.actionClicked(SimpleNamespace(text=lambda: "Delete"))
    assert len(sessions.listSessionObject) == 2


def test_context_stop_keeps_clicked_session_when_menu_context_changes(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.setParent(None)
    qtbot.addWidget(sessions)
    sessions.listSessionObject = [
        Session(0, "parent-route", "parent-beacon", "host", "user", "x64", "user", "Linux", "0", False, "", "101", ""),
        Session(1, "child-route", "child-beacon", "host", "user", "x64", "user", "Linux", "0", False, "", "102", ""),
    ]
    sessions.printSessions()
    sessions.show()

    class FakeMenu:
        def __init__(self):
            self.callback = None
            self.triggered = SimpleNamespace(connect=self._connect)

        def _connect(self, callback):
            self.callback = callback

        def addAction(self, label):
            return SimpleNamespace(setEnabled=lambda enabled: None)

        def exec(self, position):
            return None

    menu = FakeMenu()
    monkeypatch.setattr(session_panel, "create_dark_context_menu", lambda parent: menu)
    position = sessions.listSession.visualItemRect(sessions.listSession.item(1, 0)).center()
    sessions.showContextMenu(position)
    sessions._context_session_key = ("parent-beacon", "parent-route")
    menu.callback(SimpleNamespace(text=lambda: "Stop child-be (PID 102)"))

    qtbot.waitUntil(lambda: bool(grpc.stopped_sessions))
    assert grpc.stopped_sessions[0].beacon_hash == "child-beacon"
    assert grpc.stopped_sessions[0].listener_hash == "child-route"


def test_session_hooks_use_confirmed_transitions_and_ignore_poll_age(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    grpc.auth_generation = 1
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    qtbot.addWidget(sessions)
    events = []
    sessions.sessionScriptSignal.connect(lambda *args: events.append(args))
    start_snapshots = []
    sessions.sessionScriptSignal.connect(
        lambda action, *_args: start_snapshots.append(sessions.scriptSnapshot()) if action == "start" else None
    )

    def snapshot(route="listener", age="0.1", state=TeamServerApi_pb2.SESSION_STATE_RUNNING, user="user", beacon="beacon"):
        return SimpleNamespace(
            beacon_hash=beacon, listener_hash=route, hostname="host", username=user,
            arch="x64", privilege="user", os="Linux", last_proof_of_life=age,
            killed=state == TeamServerApi_pb2.SESSION_STATE_STOPPED,
            internal_ips="", process_id="1", additional_information="", state=state,
        )

    sessions._applySessions([snapshot()])
    assert [event[0] for event in events] == ["sync"]
    sessions._applySessions([snapshot(age="1.1")])
    assert [event[0] for event in events] == ["sync"]
    sessions._applySessions([snapshot(user="changed")])
    assert events[-1][0] == "update"
    grpc.auth_generation = 2
    sessions._applySessions([snapshot(route="new-listener")])
    assert [event[0] for event in events[-2:]] == ["retire", "sync"]
    sessions._applySessions([snapshot(route="new-listener", state=TeamServerApi_pb2.SESSION_STATE_STOPPING)])
    assert events[-1][0] == "update"
    sessions._applySessions([snapshot(route="new-listener", state=TeamServerApi_pb2.SESSION_STATE_STOP_FAILED)])
    assert sessions.listSession.item(0, 10).text() == "Stop unconfirmed"
    assert "may have exited" in sessions.listSession.item(0, 10).toolTip()
    assert "no final confirmation" in sessions.statusLabel.text()
    assert events[-1][0] == "update"
    sessions._applySessions([snapshot(route="new-listener", state=TeamServerApi_pb2.SESSION_STATE_STOPPED)])
    assert events[-1][0] == "stop"
    assert sessions.statusLabel.text() == "Stop session: beacon confirmed termination."
    sessions._applySessions([])
    assert events[-1][0] == "retire"
    assert sum(event[0] == "stop" for event in events) == 1
    sessions._applySessions([snapshot(beacon="new-beacon")])
    assert events[-1][0] == "start"
    assert any(item["beacon_hash"] == "new-beacon" for item in start_snapshots[-1])


def test_hide_inactive_filters_stop_and_unavailable_rows_without_changing_snapshots(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    qtbot.addWidget(sessions)
    events = []
    sessions.sessionScriptSignal.connect(lambda *args: events.append(args))

    def snapshot(beacon, state, killed=False, archived=False, age="0.1"):
        return SimpleNamespace(
            beacon_hash=beacon, listener_hash="listener", hostname="host", username="user",
            arch="x64", privilege="user", os="Linux", last_proof_of_life=age,
            killed=killed or state == TeamServerApi_pb2.SESSION_STATE_STOPPED,
            internal_ips="", process_id="1", additional_information="", state=state,
            archived=archived,
        )

    sessions._applySessions([
        snapshot("stopped", TeamServerApi_pb2.SESSION_STATE_STOPPED),
        snapshot("unconfirmed", TeamServerApi_pb2.SESSION_STATE_STOP_FAILED),
        snapshot("stopping", TeamServerApi_pb2.SESSION_STATE_STOPPING),
        snapshot("legacy-killed", TeamServerApi_pb2.SESSION_STATE_UNSPECIFIED, killed=True),
        snapshot("unavailable", TeamServerApi_pb2.SESSION_STATE_RUNNING, archived=True),
        snapshot("running", TeamServerApi_pb2.SESSION_STATE_RUNNING),
        snapshot("stale", TeamServerApi_pb2.SESSION_STATE_RUNNING, age="120"),
    ])
    sessions.listSession.selectRow(0)
    before_toggle = len(events)

    sessions.hideInactiveButton.click()
    assert sessions.hideInactiveButton.text() == "Show inactive"
    assert all(sessions.listSession.isRowHidden(row) for row in range(5))
    assert not sessions.listSession.isRowHidden(5)
    assert not sessions.listSession.isRowHidden(6)
    assert sessions.listSession.item(6, 10).text() == "Stale"
    assert sessions.selectedSession() is None
    assert not sessions.copySessionIdButton.isEnabled()
    assert len(sessions.scriptSnapshot()) == 6
    assert len(events) == before_toggle

    sessions._applySessions([
        snapshot("stopped", TeamServerApi_pb2.SESSION_STATE_STOPPED),
        snapshot("unconfirmed", TeamServerApi_pb2.SESSION_STATE_STOP_FAILED),
        snapshot("stopping", TeamServerApi_pb2.SESSION_STATE_STOPPING),
        snapshot("legacy-killed", TeamServerApi_pb2.SESSION_STATE_UNSPECIFIED, killed=True),
        snapshot("unavailable", TeamServerApi_pb2.SESSION_STATE_RUNNING, archived=True),
        snapshot("running", TeamServerApi_pb2.SESSION_STATE_RUNNING),
        snapshot("stale", TeamServerApi_pb2.SESSION_STATE_RUNNING, age="120"),
    ])
    assert all(sessions.listSession.isRowHidden(row) for row in range(5))

    sessions.hideInactiveButton.click()
    assert sessions.hideInactiveButton.text() == "Hide inactive"
    assert all(not sessions.listSession.isRowHidden(row) for row in range(7))


def test_stopped_session_history_survives_refresh_and_client_restart(tmp_path, qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    monkeypatch.setenv("C2_LOG_DIR", str(tmp_path))
    grpc = StubGrpc()
    grpc.endpoint = "127.0.0.1:50051"
    grpc.username = "operator"
    snapshot = SimpleNamespace(
        beacon_hash="beacon", listener_hash="route", hostname="host", username="user",
        arch="x64", privilege="user", os="Linux", last_proof_of_life="2.0",
        killed=True, internal_ips="", process_id="1", additional_information="",
        state=TeamServerApi_pb2.SESSION_STATE_STOPPED,
    )
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    qtbot.addWidget(sessions)
    sessions._applySessions([snapshot])
    sessions._applySessions([])
    assert sessions.listSession.rowCount() == 1
    assert sessions.listSession.item(0, 10).text() == "Stopped"
    sessions.listSession.selectRow(0)
    assert sessions.interactButton.text() == "History"
    assert not sessions.stopButton.isEnabled()
    opened = []
    sessions.interactWithSession.connect(lambda *args: opened.append(args))
    sessions.interactButton.click()
    assert opened == [("beacon", "route", "host", "user", True)]

    reopened_parent = QWidget()
    reopened = Sessions(reopened_parent, grpc)
    qtbot.addWidget(reopened)
    assert reopened.listSession.rowCount() == 1
    assert reopened.listSession.item(0, 10).text() == "Stopped"
    assert reopened.scriptSnapshot() == []
    reopened.listSession.selectRow(0)
    assert reopened.interactButton.text() == "History"


def test_server_archived_session_is_read_only_and_not_an_active_route(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)
    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    qtbot.addWidget(sessions)
    refreshed = []
    sessions.sessionsRefreshed.connect(lambda items: refreshed.append(items))
    sessions._applySessions([SimpleNamespace(
        beacon_hash="beacon", listener_hash="route", hostname="host", username="user",
        arch="x64", privilege="user", os="Linux", last_proof_of_life="2.0",
        last_seen_at_ms=1_700_000_000_000, killed=True, internal_ips="", process_id="1",
        additional_information="", state=TeamServerApi_pb2.SESSION_STATE_STOPPED,
        archived=True, archived_at_ms=1_700_000_005_000,
    )])
    assert sessions.listSession.rowCount() == 1
    assert sessions.listSessionObject[0].available is False
    assert "Archived:" in sessions.listSession.item(0, 10).toolTip()
    assert refreshed[-1] == []
    assert sessions.scriptSnapshot() == []
