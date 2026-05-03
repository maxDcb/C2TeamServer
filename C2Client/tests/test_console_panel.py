import os
from types import SimpleNamespace

import pytest
from PyQt6.QtWidgets import QWidget

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client.ConsolePanel import Console
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.reject_commands = False
        self.responses = []

    def getCommandHelp(self, command):
        return SimpleNamespace(status=TeamServerApi_pb2.OK, command=command.command, help="help", message="")

    def sendSessionCommand(self, command):
        if self.reject_commands:
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="Session not found.", command_id=command.command_id)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="", command_id=command.command_id)

    def streamSessionCommandResults(self, session):
        return self.responses


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
    assert "Session not found." in console.editorOutput.toPlainText()
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
    assert emitted[0][-2] == "Command failed."
