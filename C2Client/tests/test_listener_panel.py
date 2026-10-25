from types import SimpleNamespace
from threading import Event

import pytest
from PyQt6.QtCore import Qt
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
    qtbot.waitUntil(lambda: not listeners._mutation_pending)

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
    qtbot.waitUntil(lambda: len(grpc.added_listeners) == 1)
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


@pytest.mark.parametrize("listener_type", ["tcp", "http", "https"])
def test_add_listener_type_popup_closes_after_click(qtbot, listener_type):
    form = CreateListner()
    qtbot.addWidget(form)
    form.show()
    collapsed_height = form.height()

    qtbot.mouseClick(form.qcombo.button, Qt.MouseButton.LeftButton)
    assert form.qcombo.options.isVisible()
    assert form.qcombo.options.window() is form
    assert form.height() > collapsed_height
    item = form.qcombo.options.item(form.qcombo.findText(listener_type))
    qtbot.mouseClick(
        form.qcombo.options.viewport(), Qt.MouseButton.LeftButton,
        pos=form.qcombo.options.visualItemRect(item).center(),
    )

    assert form.qcombo.currentText() == listener_type
    assert not form.qcombo.options.isVisible()
    qtbot.waitUntil(lambda: form.height() <= collapsed_height + 30, timeout=1000)


def test_add_listener_type_change_closes_visible_popup_before_relayout(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)
    form.show()
    form.qcombo.toggleOptions()
    assert form.qcombo.options.isVisible()

    form.qcombo.setCurrentText("tcp")

    assert not form.qcombo.options.isVisible()
    assert form.labelIP.text() == "IP"
    assert form.param2.text() == "4444"


def test_add_listener_type_list_closes_with_escape(qtbot):
    form = CreateListner()
    qtbot.addWidget(form)
    form.show()
    form.qcombo.toggleOptions()

    qtbot.keyClick(form.qcombo.options, Qt.Key.Key_Escape)

    assert not form.qcombo.options.isVisible()
    assert form.qcombo.currentText() == HttpsType


def test_add_listener_form_masks_github_token_and_requires_values(qtbot):
    form = CreateListner(availableTypes=[HttpType, HttpsType, "tcp", GithubType, DnsType])
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
    form = CreateListner(availableTypes=[HttpType, HttpsType, "tcp", GithubType, DnsType])
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
    qtbot.waitUntil(lambda: len(grpc.stopped_listeners) == 1)
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


def test_listener_refresh_removes_all_missing_rows(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)
    parent = QWidget()
    listeners = Listeners(parent, StubGrpc())
    qtbot.addWidget(listeners)
    listeners.listListenerObject = [
        Listener(0, "old-one", HttpsType, "127.0.0.1", 8443, 0),
        Listener(1, "old-two", HttpsType, "127.0.0.1", 8444, 0),
        Listener(2, "current", HttpsType, "127.0.0.1", 8445, 0),
    ]
    events = []
    listeners.listenerScriptSignal.connect(lambda *args: events.append(args))
    listeners.printListeners()
    listeners.listListener.selectRow(0)
    listeners._has_snapshot = True

    listeners._applyListeners([SimpleNamespace(
        listener_hash="current", type=HttpsType, ip="127.0.0.1",
        port=8445, session_count=0, beacon_hash="",
    )])

    assert [item.listenerHash for item in listeners.listListenerObject] == ["current"]
    assert listeners.listListener.rowCount() == 1
    assert listeners.selectedListener() is None
    assert {event[1] for event in events if event[0] == "stop"} == {"old-one", "old-two"}

    listeners._applyListeners([])
    assert listeners.listListener.rowCount() == 0
    assert listeners.statusLabel.text() == "No active listeners on TeamServer; add a listener to resume sessions."


def test_listener_mutation_keeps_gui_responsive_and_form_open_until_ack(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    class DelayedGrpc(StubGrpc):
        def __init__(self):
            super().__init__()
            self.entered = Event()
            self.release = Event()

        def addListener(self, listener):
            self.entered.set()
            assert self.release.wait(2)
            return super().addListener(listener)

    grpc = DelayedGrpc()
    grpc.add_ack = TeamServerApi_pb2.OperationAck(
        status=TeamServerApi_pb2.OK, message="Listener created.",
        listener_hash="new-listener", listener_state=TeamServerApi_pb2.LISTENER_STATE_RUNNING,
    )
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listenerForm()
    form = listeners.createListenerWindow
    qtbot.addWidget(form)
    form.checkAndSend()
    try:
        assert grpc.entered.wait(1)
        assert listeners._mutation_pending
        assert form.isVisible()
        assert not form.buttonOk.isEnabled()
        assert not listeners.addListenerButton.isEnabled()
    finally:
        grpc.release.set()
    qtbot.waitUntil(lambda: not listeners._mutation_pending)
    assert not form.isVisible()
    assert len(grpc.added_listeners) == 1
    assert listeners.statusLabel.text() == "Add listener: Listener created."


def test_failed_mutation_keeps_form_and_does_not_replay(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)

    class FailingGrpc(StubGrpc):
        def addListener(self, listener):
            self.added_listeners.append(listener)
            raise RuntimeError("server unavailable")

    grpc = FailingGrpc()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listenerForm()
    form = listeners.createListenerWindow
    qtbot.addWidget(form)
    form.checkAndSend()
    qtbot.waitUntil(lambda: not listeners._mutation_pending)
    assert form.isVisible()
    assert "did not confirm" in listeners.statusLabel.text()
    assert len(grpc.added_listeners) == 1


def test_rejected_add_keeps_form_open_with_server_reason(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    grpc.add_ack = TeamServerApi_pb2.OperationAck(
        status=TeamServerApi_pb2.KO, message="Port is already in use.",
    )
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    listeners.listenerForm()
    form = listeners.createListenerWindow
    qtbot.addWidget(form)
    form.checkAndSend()
    qtbot.waitUntil(lambda: not listeners._mutation_pending)
    assert form.isVisible()
    assert form.errorLabel.text() == "Port is already in use."
    assert listeners.statusLabel.text() == "Add listener: Port is already in use."


def test_context_stop_uses_full_hash_when_prefixes_collide(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    qtbot.addWidget(listeners)
    listeners.listListenerObject = [
        Listener(0, "12345678-first", HttpsType, "127.0.0.1", 8443, 0),
        Listener(1, "12345678-second", HttpsType, "127.0.0.1", 8444, 0),
    ]
    listeners.item = listeners.listListenerObject[1].listenerHash
    listeners.actionClicked(SimpleNamespace(text=lambda: "Stop"))
    qtbot.waitUntil(lambda: not listeners._mutation_pending)
    assert [item.listener_hash for item in grpc.stopped_listeners] == ["12345678-second"]


def test_initial_and_reauthenticated_snapshots_do_not_fire_listener_hooks(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)
    grpc = StubGrpc()
    grpc.auth_generation = 1
    parent = QWidget()
    listeners = Listeners(parent, grpc)
    qtbot.addWidget(listeners)
    events = []
    listeners.listenerScriptSignal.connect(lambda *args: events.append(args))

    def snapshot(listener_hash):
        return SimpleNamespace(
            listener_hash=listener_hash, type=HttpsType, ip="127.0.0.1",
            port=8443, session_count=0, beacon_hash="",
            state=TeamServerApi_pb2.LISTENER_STATE_RUNNING,
        )

    listeners._applyListeners([snapshot("old")])
    assert events == []
    grpc.auth_generation = 2
    listeners._applyListeners([snapshot("new")])
    assert events == []
    listeners._applyListeners([snapshot("latest")])
    assert [(event[0], event[1]) for event in events] == [
        ("stop", "new"), ("start", "latest"),
    ]


def test_listener_state_and_available_types_are_displayed(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ListenerPanel.QThread.start", lambda self: None)
    default = CreateListner()
    qtbot.addWidget(default)
    assert default.qcombo.findText(GithubType) == -1
    enabled = CreateListner(availableTypes=[HttpType, GithubType])
    qtbot.addWidget(enabled)
    assert enabled.qcombo.findText(GithubType) >= 0

    parent = QWidget()
    listeners = Listeners(parent, StubGrpc())
    qtbot.addWidget(listeners)
    listeners._applyListeners([SimpleNamespace(
        listener_hash="child", beacon_hash="beacon", type="tcp", ip="127.0.0.1",
        port=4444, session_count=0, state=TeamServerApi_pb2.LISTENER_STATE_STOP_FAILED,
    )])
    assert listeners.listListener.item(0, 4).text() == "Stop failed"
    listeners.listListener.selectRow(0)
    assert listeners.stopListenerButton.isEnabled()
    listeners._applyListeners([SimpleNamespace(
        listener_hash="child", beacon_hash="beacon", type="tcp", ip="127.0.0.1",
        port=4444, session_count=0, state=TeamServerApi_pb2.LISTENER_STATE_STOPPING,
    )])
    assert listeners.listListener.item(0, 4).text() == "Stopping"
    assert not listeners.stopListenerButton.isEnabled()
    listeners._applyListeners([SimpleNamespace(
        listener_hash="child", beacon_hash="beacon", type="tcp", ip="127.0.0.1",
        port=4444, session_count=0, state=TeamServerApi_pb2.LISTENER_STATE_UNAVAILABLE,
    )])
    assert listeners.listListener.item(0, 4).text() == "Unavailable"
    assert listeners.stopListenerButton.isEnabled()
