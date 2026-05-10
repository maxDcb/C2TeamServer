from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.tools.module_state_tool import C2LoadedModulesTool, has_loaded_module


class StubGrpc:
    def __init__(self):
        self.sessions = []
        self.modules = [
            SimpleNamespace(name="ls", state="loaded"),
            SimpleNamespace(name="pwd", state="loading"),
        ]

    def listModules(self, session):
        self.sessions.append(session)
        return iter(self.modules)


def test_loaded_modules_tool_formats_loaded_modules():
    grpc = StubGrpc()
    tool = C2LoadedModulesTool(grpc)

    result = tool.execute(
        {
            "beacon_hash": "beacon-12345678",
            "listener_hash": "listener-12345678",
        },
        context=None,
    )

    assert result.ok is True
    assert "ls" in result.content
    assert "pwd" in result.content
    assert grpc.sessions[0].beacon_hash == "beacon-12345678"
    assert grpc.sessions[0].listener_hash == "listener-12345678"


def test_has_loaded_module_requires_loaded_state():
    grpc = StubGrpc()

    assert has_loaded_module(grpc, beacon_hash="b", listener_hash="l", module_name="ls") is True
    assert has_loaded_module(grpc, beacon_hash="b", listener_hash="l", module_name="pwd") is False
    assert has_loaded_module(grpc, beacon_hash="b", listener_hash="l", module_name="cat") is False
