from __future__ import annotations

from C2Client.assistant_agent.tools.registry import build_c2_tool_registry

from helpers import arg, command_spec


class StubGrpc:
    def __init__(self):
        self.commands = [
            command_spec("whoami", "whoami"),
            command_spec("ls", "ls {path:q?}", [arg("path", arg_type="path")]),
        ]

    def listCommands(self, query):
        return iter(self.commands)

    def sendSessionCommand(self, command):
        return None

    def getCommandHelp(self, command):
        return None

    def listModules(self, session):
        return iter([])

    def listSessions(self):
        return iter([])


def test_tool_registry_registers_teamserver_command_specs():
    registry = build_c2_tool_registry(StubGrpc())

    assert registry.list_tool_names() == ["getCommandHelp", "listLiveSessions", "listLoadedModules", "ls", "whoami"]
