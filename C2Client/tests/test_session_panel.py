from PyQt6.QtWidgets import QApplication, QWidget

from C2Client.SessionPanel import Session, Sessions
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

    sessions.printSessions()

    arch_header = sessions.listSession.horizontalHeaderItem(4)
    assert arch_header.text() == "Beacon Arch"
    assert arch_header.toolTip() == "Architecture du process beacon"


def test_stop_session_ack_message_is_displayed(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    grpc.stop_ack = type("Ack", (), {"status": TeamServerApi_pb2.KO, "message": "Session not found."})()
    parent = QWidget()
    sessions = Sessions(parent, grpc)
    sessions.listSessionObject = []
    qtbot.addWidget(sessions)

    sessions.stopSession("beacon", "listener")

    assert sessions.statusLabel.text() == "Session not found."
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
