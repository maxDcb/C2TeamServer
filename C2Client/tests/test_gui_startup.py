from types import SimpleNamespace

from PyQt5.QtWidgets import QWidget

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class DummyConsole(QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.script = SimpleNamespace(
            sessionScriptMethod=lambda *a, **k: None,
            listenerScriptMethod=lambda *a, **k: None,
            mainScriptMethod=lambda *a, **k: None,
        )
        self.assistant = SimpleNamespace(sessionAssistantMethod=lambda *a, **k: None)

    def addConsole(self, *args, **kwargs):
        pass


def test_gui_startup(qtbot, monkeypatch):
    monkeypatch.setattr(GUI, 'GrpcClient', lambda ip, port, dev: object())

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
