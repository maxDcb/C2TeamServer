from types import SimpleNamespace

from PyQt6.QtWidgets import QApplication, QHeaderView, QLineEdit, QWidget

from C2Client.ListenerPanel import (
    CreateListner,
    DnsType,
    GithubType,
    HttpType,
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


def test_add_listener_blocks_tcp_bound_port_conflict(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listListenerObject = [
        Listener(0, "https-listener-full-hash", HttpsType, "0.0.0.0", 8443, 0),
        Listener(1, "child-listener-full-hash", "tcp", "0.0.0.0", 4444, 0, "beacon-full-hash"),
    ]
    qtbot.addWidget(listeners)

    listeners.addListener(["tcp", "0.0.0.0", "8443"])

    assert grpc.added_listeners == []
    assert listeners.statusLabel.text() == "Add listener: Port 8443 is already used by https listener https-li."
    assert "#b00020" in listeners.statusLabel.styleSheet()

    listeners.addListener(["tcp", "0.0.0.0", "4444"])
    assert len(grpc.added_listeners) == 1


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


def test_add_listener_form_blocks_tcp_bound_port_conflict(qtbot):
    form = CreateListner(lambda: [
        Listener(0, "https-listener-full-hash", HttpsType, "0.0.0.0", 8443, 0)
    ])
    qtbot.addWidget(form)
    emitted = []
    form.procDone.connect(lambda values: emitted.append(values))

    form.qcombo.setCurrentText("tcp")
    form.param1.setText("0.0.0.0")
    form.param2.setText("8443")

    assert form.buttonOk.isEnabled() is False

    form.checkAndSend()

    assert emitted == []
    assert form.errorLabel.isHidden() is False
    assert form.errorLabel.text() == "Port 8443 is already used by https listener https-li."


def test_add_listener_form_updates_fields_by_type(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)

    assert form.qcombo.currentText() == HttpsType
    assert form.labelIP.text() == "IP"
    assert form.param1.text() == "0.0.0.0"
    assert form.param2.text() == "8443"
    assert form.buttonOk.isEnabled() is True
    assert "HTTPS listener" in form.helpLabel.text()

    form.qcombo.setCurrentText(DnsType)

    assert form.labelIP.text() == "Domain"
    assert form.labelPort.text() == "Port"
    assert form.param1.text() == ""
    assert form.param2.text() == "53"
    assert form.buttonOk.isEnabled() is False

    form.param1.setText("example.com")
    assert form.buttonOk.isEnabled() is True


def test_add_listener_form_masks_github_token_and_requires_values(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)

    form.qcombo.setCurrentText(GithubType)

    assert form.labelIP.text() == "Project"
    assert form.labelPort.text() == "Token"
    assert form.param2.echoMode() == QLineEdit.EchoMode.Password
    assert form.buttonOk.isEnabled() is False

    form.param1.setText("owner/repo")
    form.param2.setText("token")

    assert form.buttonOk.isEnabled() is True


def test_add_listener_form_resets_incompatible_values_when_type_changes(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)

    form.qcombo.setCurrentText(GithubType)
    form.param1.setText("owner/repo")
    form.param2.setText("token")
    form.qcombo.setCurrentText(HttpType)

    assert form.param1.text() == "0.0.0.0"
    assert form.param2.text() == "8080"
    assert form.buttonOk.isEnabled() is True


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

    assert "#0b1117" in listeners.styleSheet()
    assert "#263241" in listeners.styleSheet()

    listeners.printListeners()
    assert listeners.addListenerButton.isEnabled() is True
    assert listeners.stopListenerButton.isEnabled() is False
    assert listeners.copyListenerIdButton.isEnabled() is False
    assert listeners.addListenerButton.text() == "Add"
    assert listeners.copyListenerIdButton.text() == "Copy"
    assert listeners.listListener.horizontalHeaderItem(0).text() == "ID"
    assert listeners.listListener.horizontalHeaderItem(2).text() == "Host/Beacon"
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
            "beacon_hash": "",
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


def test_child_listener_displays_beacon_id_in_host_column(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    class ChildListenerGrpc(StubGrpc):
        def listListeners(self):
            return [
                SimpleNamespace(
                    listener_hash="child-listener-full-hash",
                    beacon_hash="beacon-full-hash",
                    type="tcp",
                    ip="0.0.0.0",
                    port=4444,
                    session_count=0,
                )
            ]

    parent = QWidget()
    listeners = Listeners(parent, ChildListenerGrpc())
    qtbot.addWidget(listeners)

    listeners.listListeners()

    assert listeners.listListener.item(0, 2).text() == "beacon-f"
    assert "Beacon ID: beacon-full-hash" in listeners.listListener.item(0, 2).toolTip()
    assert "Endpoint: 0.0.0.0:4444" in listeners.listListener.item(0, 2).toolTip()
    assert listeners.scriptSnapshot()[0]["beacon_hash"] == "beacon-full-hash"
