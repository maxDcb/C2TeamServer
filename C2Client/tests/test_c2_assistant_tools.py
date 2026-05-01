from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.c2_tools import C2CommandTool, build_command_line


class StubGrpc:
    def __init__(self):
        self.commands = []

    def sendCmdToSession(self, command):
        self.commands.append(command)
        return SimpleNamespace(message=b"")


def test_build_command_line_quotes_paths_with_spaces():
    assert build_command_line("cat", {"path": "C:\\Users\\Public\\notes.txt"}) == 'cat C:\\Users\\Public\\notes.txt'
    assert build_command_line("ls", {"path": "C:\\Program Files"}) == 'ls "C:\\Program Files"'


def test_c2_command_tool_sends_command_and_returns_pending():
    grpc = StubGrpc()
    tool = C2CommandTool("ls", grpc)

    result = tool.execute(
        {
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-12345678",
            "path": "C:\\Program Files",
        },
        context=None,
    )

    assert result.pending is True
    assert grpc.commands[0].beaconHash == "beacon-12345678"
    assert grpc.commands[0].listenerHash == "listener-12345678"
    assert grpc.commands[0].cmd == 'ls "C:\\Program Files"'
