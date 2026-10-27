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

    assert registry.list_tool_names() == ["getCommandHelp", "listC2Commands", "listLiveSessions", "listLoadedModules", "ls", "whoami"]


def test_conversation_keeps_new_catalog_commands_without_a_skill_bundle():
    grpc = StubGrpc()
    grpc.commands.append(command_spec("futureModule", "futureModule"))
    registry = build_c2_tool_registry(grpc)
    assert "futureModule" in registry.list_tool_names()
