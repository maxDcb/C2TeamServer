from types import SimpleNamespace

from PyQt6.QtWidgets import QWidget

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client import GUI


class DummySignal:
    def connect(self, *args, **kwargs):
        pass


class DummyWidget(QWidget):
    sessionScriptSignal = DummySignal()
    listenerScriptSignal = DummySignal()
    interactWithSession = DummySignal()

    def __init__(self, parent=None, *_args, **_kwargs):
        super().__init__(parent)

    def scriptSnapshot(self):
        return [{"source": self.__class__.__name__}]


class DummyScript:
    def __init__(self):
        self.provider = None
        self.sessionScriptMethod = lambda *a, **k: None
        self.listenerScriptMethod = lambda *a, **k: None
        self.mainScriptMethod = lambda *a, **k: None

    def setClientStateProvider(self, provider):
        self.provider = provider


class DummyConsole(QWidget):
    def __init__(self, parent=None, *_args, **_kwargs):
        super().__init__(parent)
        self.script = DummyScript()
        self.assistant = SimpleNamespace(sessionAssistantMethod=lambda *a, **k: None)

    def addConsole(self, *args, **kwargs):
        pass


def test_gui_startup(qtbot, monkeypatch):
    monkeypatch.setattr(GUI, 'GrpcClient', lambda *args, **kwargs: object())

    def fake_top(self):
        self.sessionsWidget = DummyWidget()
        self.listenersWidget = DummyWidget()

    def fake_bot(self):
        self.consoleWidget = DummyConsole()

    monkeypatch.setattr(GUI.App, 'topLayout', fake_top)
    monkeypatch.setattr(GUI.App, 'botLayout', fake_bot)

    app = GUI.App('127.0.0.1', 50051, False)
    qtbot.addWidget(app)

    assert isinstance(app.consoleWidget, DummyConsole)
    assert isinstance(app.listenersWidget, DummyWidget)
    assert isinstance(app.sessionsWidget, DummyWidget)
    assert app.consoleWidget.script.provider() == {
        "sessions": [{"source": "DummyWidget"}],
        "listeners": [{"source": "DummyWidget"}],
    }
    assert "Connected | 127.0.0.1:50051" in app.connectionStatusLabel.text()
    assert app.rpcStatusLabel.text() == "Last RPC: none"


def test_gui_shell_uses_dark_single_column_layout(qtbot, monkeypatch):
    monkeypatch.setattr(GUI, 'GrpcClient', lambda *args, **kwargs: object())
    monkeypatch.setattr(GUI, 'Sessions', DummyWidget)
    monkeypatch.setattr(GUI, 'Listeners', DummyWidget)
    monkeypatch.setattr(GUI, 'Graph', DummyWidget)
    monkeypatch.setattr(GUI, 'ConsolesTab', DummyConsole)

    app = GUI.App('127.0.0.1', 50051, False)
    qtbot.addWidget(app)

    assert app.objectName() == "C2MainWindow"
    assert app.centralWidget().objectName() == "C2CentralWidget"
    assert app.topWidget.objectName() == "C2TopTabs"
    assert app.m_main.objectName() == "C2MainTab"
    assert "#070b10" in app.styleSheet()
    assert "#263241" in app.styleSheet()
    assert app.mainLayout.itemAtPosition(0, 0).widget() is app.topWidget
    assert app.mainLayout.itemAtPosition(1, 0).widget() is app.consoleWidget
    assert app.mainLayout.itemAtPosition(1, 1) is None


def test_gui_status_bar_updates_rpc_status(qtbot, monkeypatch):
    monkeypatch.setattr(GUI, 'GrpcClient', lambda *args, **kwargs: object())

    def fake_top(self):
        self.sessionsWidget = DummyWidget()
        self.listenersWidget = DummyWidget()

    def fake_bot(self):
        self.consoleWidget = DummyConsole()

    monkeypatch.setattr(GUI.App, 'topLayout', fake_top)
    monkeypatch.setattr(GUI.App, 'botLayout', fake_bot)

    app = GUI.App('127.0.0.1', 50051, False)
    qtbot.addWidget(app)

    app.updateRpcStatus("ListSessions", False, "deadline exceeded")

    assert "RPC error" in app.connectionStatusLabel.text()
    assert "Last RPC: ListSessions" in app.rpcStatusLabel.text()
    assert "ListSessions: deadline exceeded" in app.errorStatusLabel.text()


def test_parse_client_args_uses_env_defaults(monkeypatch):
    monkeypatch.setenv("C2_IP", "10.10.10.5")
    monkeypatch.setenv("C2_PORT", "5443")
    monkeypatch.setenv("C2_DEV_MODE", "true")

    args = GUI.parse_client_args([])

    assert args.ip == "10.10.10.5"
    assert args.port == 5443
    assert args.dev is True


def test_parse_client_args_keeps_cli_priority(monkeypatch):
    monkeypatch.setenv("C2_IP", "10.10.10.5")
    monkeypatch.setenv("C2_PORT", "5443")
    monkeypatch.setenv("C2_DEV_MODE", "true")

    args = GUI.parse_client_args(["--ip", "127.0.0.2", "--port", "6000", "--no-dev"])

    assert args.ip == "127.0.0.2"
    assert args.port == 6000
    assert args.dev is False
