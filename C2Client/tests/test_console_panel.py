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
    def getHelp(self, command):
        return SimpleNamespace(cmd=command.cmd, response=b"help")

    def sendCmdToSession(self, command):
        return SimpleNamespace(message=b"")

    def getResponseFromSession(self, session):
        return []


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
