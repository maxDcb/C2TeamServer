from PyQt6.QtWidgets import QApplication, QHeaderView, QWidget

from C2Client.ListenerPanel import (
    CreateListner,
    DnsType,
    GithubType,
    HttpsType,
    Listener,
    Listeners,
    validate_listener_fields,
)
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.add_ack = None
        self.stop_ack = None
        self.added_listeners = []
        self.stopped_listeners = []

    def listListeners(self):
        return []

    def addListener(self, listener):
        self.added_listeners.append(listener)
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

    assert listeners.statusLabel.text() == "Add listener: Listener already exists."
    assert "#b00020" in listeners.statusLabel.styleSheet()


def test_listener_validation_rejects_bad_network_fields():
    assert validate_listener_fields(HttpsType, "127.0.0.1", "8443") == (True, "")
    assert validate_listener_fields(HttpsType, "999.1.1.1", "8443") == (
        False,
        "IP must be a valid IPv4 or IPv6 address.",
    )
    assert validate_listener_fields(HttpsType, "127.0.0.1", "70000") == (
        False,
        "Port must be a number between 1 and 65535.",
    )
    assert validate_listener_fields(DnsType, "https://example.com", "53") == (
        False,
        "Domain must be a valid DNS name.",
    )
    assert validate_listener_fields(GithubType, "owner/repo", "token") == (True, "")


def test_add_listener_invalid_fields_are_not_sent(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listListenerObject = []
    qtbot.addWidget(listeners)

    listeners.addListener(["https", "999.1.1.1", "8443"])

    assert grpc.added_listeners == []
    assert listeners.statusLabel.text() == "Add listener: IP must be a valid IPv4 or IPv6 address."
    assert "#b00020" in listeners.statusLabel.styleSheet()


def test_add_listener_form_blocks_invalid_port(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)
    emitted = []
    form.procDone.connect(lambda values: emitted.append(values))

    form.qcombo.setCurrentText(HttpsType)
    form.param1.setText("127.0.0.1")
    form.param2.setText("70000")
    form.checkAndSend()

    assert emitted == []
    assert form.errorLabel.isHidden() is False
    assert form.errorLabel.text() == "Port must be a number between 1 and 65535."


def test_add_listener_form_emits_trimmed_valid_values(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)
    emitted = []
    form.procDone.connect(lambda values: emitted.append(values))

    form.qcombo.setCurrentText(HttpsType)
    form.param1.setText(" 127.0.0.1 ")
    form.param2.setText(" 8443 ")
    form.checkAndSend()

    assert emitted == [[HttpsType, "127.0.0.1", "8443"]]


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


def test_listener_script_snapshot_exposes_listener_context(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    parent = QWidget()
    listeners = Listeners(parent, StubGrpc())
    listeners.listListenerObject = [
        Listener(0, "listener-full-hash", "https", "0.0.0.0", 8443, 2)
    ]
    qtbot.addWidget(listeners)

    assert listeners.scriptSnapshot() == [
        {
            "id": 0,
            "listener_hash": "listener-full-hash",
            "type": "https",
            "host": "0.0.0.0",
            "port": 8443,
            "session_count": 2,
        }
    ]


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
