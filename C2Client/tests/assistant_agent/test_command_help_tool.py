from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.tools.command_help_tool import C2CommandHelpTool
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.requests = []
        self.reject = False

    def getCommandHelp(self, request):
        self.requests.append(request)
        if self.reject:
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="Unknown command.", help="")
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="", help="sleep\nUsage: sleep <seconds>")


def test_command_help_tool_calls_teamserver_help_rpc():
    grpc = StubGrpc()
    tool = C2CommandHelpTool(grpc)

    result = tool.execute(
        {
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-12345678",
            "command": "sleep",
        },
        context=None,
    )

    assert result.ok is True
    assert "Usage: sleep" in result.content
    assert grpc.requests[0].session.beacon_hash == "beacon-12345678"
    assert grpc.requests[0].session.listener_hash == "listener-12345678"
    assert grpc.requests[0].command == "help sleep"


def test_command_help_tool_can_fetch_specific_help_without_session_hashes():
    grpc = StubGrpc()
    tool = C2CommandHelpTool(grpc)

    result = tool.execute({"command": "screenShot"}, context=None)

    assert result.ok is True
    assert grpc.requests[0].session.beacon_hash == ""
    assert grpc.requests[0].session.listener_hash == ""
    assert grpc.requests[0].command == "help screenShot"


def test_command_help_tool_returns_teamserver_error():
    grpc = StubGrpc()
    grpc.reject = True
    tool = C2CommandHelpTool(grpc)

    result = tool.execute(
        {
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-12345678",
            "command": "missing",
        },
        context=None,
    )

    assert result.ok is False
    assert result.content == "Unknown command."
