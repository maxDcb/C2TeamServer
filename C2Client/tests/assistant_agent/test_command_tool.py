from __future__ import annotations

import json
from types import SimpleNamespace

from C2Client.assistant_agent.tools.command_tool import C2CommandTool
from C2Client.assistant_agent.tools.command_specs import command_spec_to_tool_spec
from C2Client.grpcClient import TeamServerApi_pb2

from helpers import arg, command_spec


class StubGrpc:
    def __init__(self):
        self.commands = []
        self.reject = False
        self.rpc_error = None
        self.modules = [
            SimpleNamespace(name="ls", state="loaded"),
            SimpleNamespace(name="whoami", state="loaded"),
        ]

    def sendSessionCommand(self, command):
        self.commands.append(command)
        if self.rpc_error is not None:
            raise self.rpc_error
        if self.reject:
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="Session not found.")
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message=b"", command_id=command.command_id)

    def listModules(self, session):
        return iter(self.modules)

    def listCommands(self, query):
        _ = query
        loader = command_spec("loadModule", "loadModule {module:q}", [arg("module", required=True)])
        loader.kind = "common"
        return [loader]


def spec_by_name(name):
    commands = {
        "ls": command_spec("ls", "ls {path:q?}", [arg("path", arg_type="path")]),
        "whoami": command_spec("whoami", "whoami"),
    }
    return command_spec_to_tool_spec(commands[name])


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
    assert json.loads(result.content)["status"] == "pending"
    assert result.metadata["command_line"] == "ls 'C:\\Program Files'"
    assert result.metadata["command_id"]
    assert grpc.commands[0].session.beacon_hash == "beacon-12345678"
    assert grpc.commands[0].session.listener_hash == "listener-12345678"
    assert grpc.commands[0].command == "ls 'C:\\Program Files'"
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
    assert result.metadata["error"] == {"code": "teamserver_rejected", "message": "Session not found."}
    assert json.loads(result.content)["error"] == result.metadata["error"]
    assert result.metadata["command_id"] == grpc.commands[0].command_id


def test_c2_command_tool_reports_rpc_exception_as_failed_outcome():
    grpc = StubGrpc()
    grpc.rpc_error = RuntimeError("transport unavailable")
    result = C2CommandTool(spec_by_name("whoami"), grpc).execute(
        {"beacon_hash": "beacon-12345678", "listener_hash": "listener-12345678"},
        context=None,
    )
    assert result.ok is False
    assert result.pending is False
    assert result.metadata["error"] == {"code": "rpc_error", "message": "transport unavailable"}
    assert result.metadata["command_id"] == grpc.commands[0].command_id


def test_c2_command_tool_loads_missing_module_before_requested_command():
    grpc = StubGrpc()
    grpc.modules = []
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
    assert result.metadata["command_line"] == "loadModule ls"
    assert result.metadata["continuation_command_line"] == "ls 'C:\\Program Files'"
    assert [command.command for command in grpc.commands] == ["loadModule ls"]


def test_c2_command_tool_waits_for_existing_module_load_without_duplicate():
    grpc = StubGrpc()
    grpc.modules = [SimpleNamespace(name="ls", state="loading", command_id="load-123")]
    result = C2CommandTool(spec_by_name("ls"), grpc).execute(
        {"beacon_hash": "beacon-12345678", "listener_hash": "listener-12345678", "path": "C:\\"},
        context=None,
    )
    assert result.pending is True
    assert result.metadata["command_id"] == "load-123"
    assert result.metadata["continuation_command_line"] == "ls C:\\"
    assert grpc.commands == []


def test_c2_command_tool_does_not_send_when_module_state_is_unavailable():
    grpc = StubGrpc()
    grpc.listModules = lambda session: (_ for _ in ()).throw(RuntimeError("unavailable"))
    result = C2CommandTool(spec_by_name("ls"), grpc).execute(
        {"beacon_hash": "beacon-12345678", "listener_hash": "listener-12345678"},
        context=None,
    )
    assert result.metadata["error"]["code"] == "module_state_unavailable"
    assert grpc.commands == []
