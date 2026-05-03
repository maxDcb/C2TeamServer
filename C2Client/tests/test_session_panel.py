from PyQt6.QtWidgets import QWidget

from C2Client.SessionPanel import Sessions
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.stop_ack = None

    def listSessions(self):
        return []

    def stopSession(self, session):
        return self.stop_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Session stop command queued."})()


def test_sessions_table_labels_arch_as_beacon_process(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
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
    qtbot.addWidget(sessions)

    sessions.stopSession("beacon", "listener")

    assert sessions.statusLabel.text() == "Session not found."
    assert "#b00020" in sessions.statusLabel.styleSheet()
