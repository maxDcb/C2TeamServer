from PyQt6.QtWidgets import QApplication, QHeaderView, QWidget

from C2Client.ListenerPanel import Listener, Listeners
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.add_ack = None
        self.stop_ack = None
        self.stopped_listeners = []

    def listListeners(self):
        return []

    def addListener(self, listener):
        return self.add_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Listener created."})()

    def stopListener(self, listener):
        self.stopped_listeners.append(listener)
        return self.stop_ack or type("Ack", (), {"status": TeamServerApi_pb2.OK, "message": "Listener stopped."})()


def test_add_listener_ack_message_is_displayed(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    grpc.add_ack = type("Ack", (), {"status": TeamServerApi_pb2.KO, "message": "Listener already exists."})()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listListenerObject = []
    qtbot.addWidget(listeners)

    listeners.addListener(["https", "0.0.0.0", "8443"])

    assert listeners.statusLabel.text() == "Listener already exists."
    assert "#b00020" in listeners.statusLabel.styleSheet()


def test_listener_toolbar_actions_use_selected_listener(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listListenerObject = [
        Listener(0, "listener-full-hash", "https", "0.0.0.0", 8443, 0)
    ]
    qtbot.addWidget(listeners)

    listeners.printListeners()
    assert listeners.addListenerButton.isEnabled() is True
    assert listeners.stopListenerButton.isEnabled() is False
    assert listeners.copyListenerIdButton.isEnabled() is False
    assert listeners.addListenerButton.text() == "Add"
    assert listeners.copyListenerIdButton.text() == "Copy"
    assert listeners.listListener.horizontalHeaderItem(0).text() == "ID"
    assert listeners.listListener.horizontalHeader().sectionResizeMode(2) == QHeaderView.ResizeMode.Stretch

    listeners.listListener.selectRow(0)

    assert listeners.stopListenerButton.isEnabled() is True
    assert listeners.copyListenerIdButton.isEnabled() is True

    listeners.copyListenerIdButton.click()
    assert QApplication.clipboard().text() == "listener-full-hash"
    assert listeners.statusLabel.text() == "Listener ID copied to clipboard."

    listeners.stopListenerButton.click()
    assert grpc.stopped_listeners[-1].listener_hash == "listener-full-hash"


def test_listener_table_keeps_user_column_width_after_refresh(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    parent = QWidget()
    listeners = Listeners(parent, StubGrpc())
    listeners.listListenerObject = [
        Listener(0, "listener-full-hash", "https", "192.168.56.120", 8443, 0)
    ]
    qtbot.addWidget(listeners)

    listeners.printListeners()
    listeners.listListener.setColumnWidth(0, 123)
    listeners.printListeners()

    assert listeners.listListener.columnWidth(0) == 123
    assert listeners.listListener.item(0, 2).text() == "192.168.56.120"
    assert listeners.listListener.item(0, 2).toolTip() == "192.168.56.120"
