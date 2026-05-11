from datetime import datetime

from PyQt6.QtWidgets import QApplication, QHeaderView, QWidget

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

    def listSessions(self):
        return []

    def stopSession(self, session):
        self.stopped_sessions.append(session)
        return self.stop_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Session stop command queued."})()


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
    assert emitted == [("beacon-full-hash", "listener-full-hash", "host1", "user1")]

    sessions.copySessionIdButton.click()
    assert QApplication.clipboard().text() == "beacon-full-hash"
    assert sessions.statusLabel.text() == "Beacon ID copied to clipboard."

    sessions.stopButton.click()
    assert grpc.stopped_sessions[-1].beacon_hash == "beacon-full-hash"
    assert grpc.stopped_sessions[-1].listener_hash == "listener-full-hash"


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
