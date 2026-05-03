from PyQt6.QtWidgets import QWidget

from C2Client.ListenerPanel import Listeners
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.add_ack = None
        self.stop_ack = None

    def listListeners(self):
        return []

    def addListener(self, listener):
        return self.add_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Listener created."})()

    def stopListener(self, listener):
        return self.stop_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Listener stopped."})()


def test_add_listener_ack_message_is_displayed(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    grpc.add_ack = type("Ack", (), {"status": TeamServerApi_pb2.KO, "message": "Listener already exists."})()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    qtbot.addWidget(listeners)

    listeners.addListener(["https", "0.0.0.0", "8443"])

    assert listeners.statusLabel.text() == "Listener already exists."
    assert "#b00020" in listeners.statusLabel.styleSheet()
