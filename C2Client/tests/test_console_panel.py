import os
from types import SimpleNamespace

from PyQt6.QtWidgets import QWidget

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client.ConsolePanel import Console, ConsolesTab
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.reject_commands = False
        self.responses = []
        self.sent_commands = []

    def getCommandHelp(self, command):
        return SimpleNamespace(status=TeamServerApi_pb2.OK, command=command.command, help="help", message="")

    def sendSessionCommand(self, command):
        self.sent_commands.append(command)
        if self.reject_commands:
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="Session not found.", command_id=command.command_id)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="", command_id=command.command_id)

    def streamSessionCommandResults(self, session):
        return self.responses


class DummyPanel(QWidget):
    def __init__(self, parent=None, *_args, **_kwargs):
        super().__init__(parent)


def test_command_history_and_logging(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    parent = QWidget()
    console = Console(parent, StubGrpc(), 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.commandEditor.setText('help')
    console.runCommand()

    history_file = tmp_path / '.cmdHistory'
    assert history_file.read_text() == 'help\n'

    log_file = tmp_path / 'host_user_beacon.log'
    assert 'send: "help"' in log_file.read_text()


def test_command_ack_error_is_displayed_without_pending_emit(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    grpc.reject_commands = True
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    emitted = []
    console.consoleScriptSignal.connect(lambda *args: emitted.append(args))

    console.commandEditor.setText('whoami')
    console.runCommand()

    assert emitted == []
    output = console.editorOutput.toPlainText()
    assert "Session not found." in output
    assert "[error]" in output
    assert "[<<]" not in output
    command_id = grpc.sent_commands[0].command_id
    assert console.commandStatusById[command_id]["status"] == "error"
    assert 'rejected: "whoami"' in (tmp_path / 'host_user_beacon.log').read_text()


def test_command_result_error_uses_message_for_display(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    grpc.responses = [
        SimpleNamespace(
            status=TeamServerApi_pb2.KO,
            session=SimpleNamespace(listener_hash="listener"),
            command="whoami",
            instruction="",
            command_id="cmd-1",
            output=b"raw failure",
            message="Command failed.",
        )
    ]
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    emitted = []
    console.consoleScriptSignal.connect(lambda *args: emitted.append(args))

    console.displayResponse()

    assert "Command failed." in console.editorOutput.toPlainText()
    assert "raw failure" not in console.editorOutput.toPlainText()
    assert console.commandStatusById["cmd-1"]["status"] == "error"
    assert emitted[0][-2] == "Command failed."


def test_console_tracks_command_status_and_resend(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.commandEditor.setText('whoami')
    console.runCommand()

    first_command_id = grpc.sent_commands[0].command_id
    assert console.lastCommandLine == 'whoami'
    assert console.commandStatusById[first_command_id]["status"] == "queued"
    output = console.editorOutput.toPlainText()
    assert "[queued]" in output
    assert "[>>]" not in output

    console.resendLastCommand()

    assert len(grpc.sent_commands) == 2
    assert grpc.sent_commands[1].command == 'whoami'

    grpc.responses = [
        SimpleNamespace(
            status=TeamServerApi_pb2.OK,
            session=SimpleNamespace(listener_hash="listener"),
            command="whoami",
            instruction="",
            command_id=first_command_id,
            output=b"user",
            message="",
        )
    ]

    console.displayResponse()

    assert console.commandStatusById[first_command_id]["status"] == "done"
    output = console.editorOutput.toPlainText()
    assert "[done]" in output
    assert "[<<]" not in output
    assert output.index("[done]") < output.index("user")


def test_console_search_clear_and_export_controls(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    parent = QWidget()
    console = Console(parent, StubGrpc(), 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.printInTerminal("whoami", "", "")
    console.printInTerminal("", "whoami", "needle output")

    console.searchInput.setText("needle")
    assert console.findNextSearchMatch() is True
    assert console.consoleNoticeLabel.text() in {"Match found.", "Search wrapped."}

    export_path = console.exportConsoleOutput()
    assert os.path.exists(export_path)
    with open(export_path, encoding="utf-8") as exportFile:
        assert "needle output" in exportFile.read()

    console.clearConsoleOutput()
    assert console.editorOutput.toPlainText() == ""


def test_console_replays_structured_log_on_reopen(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.commandEditor.setText('whoami')
    console.runCommand()
    command_id = grpc.sent_commands[0].command_id
    grpc.responses = [
        SimpleNamespace(
            status=TeamServerApi_pb2.OK,
            session=SimpleNamespace(listener_hash="listener"),
            command="whoami",
            instruction="",
            command_id=command_id,
            output=b"user",
            message="",
        )
    ]
    console.displayResponse()

    log_text = (tmp_path / 'host_user_beacon.log').read_text()
    assert '[console]' in log_text

    reopened = Console(parent, StubGrpc(), 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(reopened)

    output = reopened.editorOutput.toPlainText()
    assert "[queued]" in output
    assert "[done]" in output
    assert "[>>]" not in output
    assert "whoami" in output
    assert "user" in output
    assert reopened.commandStatusById[command_id]["status"] == "done"
    assert command_id in reopened.renderedResponseIds


def test_consoles_tab_uses_dark_flush_pages(qtbot, monkeypatch):
    monkeypatch.setattr('C2Client.ConsolePanel.Terminal', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Script', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Artifacts', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Assistant', DummyPanel)

    parent = QWidget()
    consoles = ConsolesTab(parent, StubGrpc())
    qtbot.addWidget(consoles)

    assert consoles.objectName() == "C2ConsolesTab"
    assert consoles.tabs.objectName() == "C2ConsoleTabs"
    assert consoles.tabs.tabText(1) == "Hooks"
    assert consoles.tabs.tabText(2) == "Artifacts"
    assert consoles.tabs.tabText(3) == "Data AI"
    assert "#0b1117" in consoles.styleSheet()
    assert "#070b10" in consoles.styleSheet()
    assert consoles.layout.contentsMargins().left() == 0
    assert consoles.layout.spacing() == 0

    protected_count = consoles.tabs.count()
    consoles.closeTab(2)
    assert consoles.tabs.count() == protected_count

    for index in range(consoles.tabs.count()):
        page = consoles.tabs.widget(index)
        assert page.objectName() == "C2ConsolePage"
        assert page.layout().contentsMargins().left() == 0
        assert page.layout().contentsMargins().top() == 0
        assert page.layout().spacing() == 0
