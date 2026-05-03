from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.tools.command_tool import C2CommandTool
from C2Client.assistant_agent.tools.loader import load_tool_specs
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.commands = []
        self.reject = False

    def sendSessionCommand(self, command):
        self.commands.append(command)
        if self.reject:
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="Session not found.")
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message=b"", command_id=command.command_id)


def spec_by_name(name):
    return {spec.name: spec for spec in load_tool_specs()}[name]


def test_c2_command_tool_sends_command_and_returns_pending():
    grpc = StubGrpc()
    tool = C2CommandTool(spec_by_name("ls"), grpc)

    result = tool.execute(
        {
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-12345678",
            "path": "C:\\Program Files",
        },
        context=None,
    )

    assert result.pending is True
    assert result.metadata["command_line"] == 'ls "C:\\Program Files"'
    assert result.metadata["command_id"]
    assert grpc.commands[0].session.beacon_hash == "beacon-12345678"
    assert grpc.commands[0].session.listener_hash == "listener-12345678"
    assert grpc.commands[0].command == 'ls "C:\\Program Files"'
    assert grpc.commands[0].command_id == result.metadata["command_id"]


def test_c2_command_tool_returns_error_when_command_is_rejected():
    grpc = StubGrpc()
    grpc.reject = True
    tool = C2CommandTool(spec_by_name("whoami"), grpc)

    result = tool.execute(
        {
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-12345678",
        },
        context=None,
    )

    assert result.ok is False
    assert result.pending is False
    assert result.content == "Session not found."
