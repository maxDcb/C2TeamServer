from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from C2Client.assistant_agent.tools.command_help_tool import C2CommandHelpTool
from C2Client.assistant_agent.tools.command_specs import command_spec_to_tool_spec
from C2Client.assistant_agent.tools.command_tool import C2CommandTool
from C2Client.assistant_agent.tools.module_state_tool import C2LoadedModulesTool
from C2Client.assistant_agent.tools.session_state_tool import C2LiveSessionsTool

from helpers import arg, command_spec


class StubGrpc:
    def __init__(self):
        self.commands = []
        self.module_calls = 0

    def sendSessionCommand(self, request):
        self.commands.append(request)
        return SimpleNamespace(status=0, command_id=request.command_id)

    def listSessions(self):
        raise AssertionError("invalid arguments reached listSessions")

    def listModules(self, request):
        self.module_calls += 1
        return iter([SimpleNamespace(name="demo", state="loaded")])

    def getCommandHelp(self, request):
        raise AssertionError("invalid arguments reached getCommandHelp")


def dynamic_tool(grpc):
    spec = command_spec(
        "demo",
        "demo --mode {mode} [--count {count}] [--verbose {verbose:flag}] [-- {tail:raw}]",
        [
            arg("mode", values=["safe", "quiet"]),
            arg("count", arg_type="number"),
            arg("verbose"),
            arg("tail", variadic=True),
        ],
    )
    return C2CommandTool(command_spec_to_tool_spec(spec), grpc)


@pytest.mark.parametrize(
    ("change", "expected_path"),
    [
        ({"beacon_hash": None}, "$.beacon_hash"),
        ({"listener_hash": ""}, "$.listener_hash"),
        ({"mode": "unsupported"}, "$.mode"),
        ({"mode": 7}, "$.mode"),
        ({"count": True}, "$.count"),
        ({"verbose": 1}, "$.verbose"),
        ({"unknown": "value"}, "$.unknown"),
    ],
)
def test_dynamic_tool_rejects_invalid_arguments_before_rpc(change, expected_path):
    grpc = StubGrpc()
    arguments = {"beacon_hash": "beacon", "listener_hash": "listener", "mode": "safe"}
    arguments.update(change)

    result = dynamic_tool(grpc).execute(arguments, context=None)

    assert result.ok is False
    assert result.pending is False
    assert result.metadata["status"] == "invalid_arguments"
    assert expected_path in [issue["path"] for issue in result.metadata["error"]["details"]]
    assert json.loads(result.content) == result.metadata["error"]
    assert grpc.commands == []


def test_dynamic_tool_requires_object_and_required_fields():
    grpc = StubGrpc()
    tool = dynamic_tool(grpc)

    for arguments in ([], {"beacon_hash": "beacon", "listener_hash": "listener"}):
        result = tool.execute(arguments, context=None)
        assert result.metadata["status"] == "invalid_arguments"
    assert grpc.commands == []


def test_dynamic_tool_accepts_numeric_optional_flag_and_variadic_tail():
    grpc = StubGrpc()
    result = dynamic_tool(grpc).execute(
        {
            "beacon_hash": "beacon",
            "listener_hash": "listener",
            "mode": "safe",
            "count": 2,
            "verbose": True,
            "tail": "two words",
        },
        context=None,
    )

    assert result.pending is True
    assert len(grpc.commands) == 1
    assert grpc.commands[0].command == "demo --mode safe --count 2 --verbose -- two words"


def test_required_flag_must_be_true_before_rpc():
    grpc = StubGrpc()
    spec = command_spec_to_tool_spec(command_spec("demo", "demo {enabled:flag}", [arg("enabled")]))
    result = C2CommandTool(spec, grpc).execute(
        {"beacon_hash": "beacon", "listener_hash": "listener", "enabled": False},
        context=None,
    )
    assert result.metadata["status"] == "invalid_arguments"
    assert grpc.commands == []


@pytest.mark.parametrize(
    ("tool_type", "arguments"),
    [
        (C2LiveSessionsTool, {"include_killed": 1}),
        (C2LoadedModulesTool, {"beacon_hash": "beacon"}),
        (C2CommandHelpTool, {"command": "help", "extra": "unexpected"}),
    ],
)
def test_static_tools_reject_invalid_arguments_before_rpc(tool_type, arguments):
    grpc = StubGrpc()
    result = tool_type(grpc).execute(arguments, context=None)
    assert result.metadata["status"] == "invalid_arguments"
    assert grpc.module_calls == 0
