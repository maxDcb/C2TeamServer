from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.domain.service import C2AssistantAgent

from helpers import command_spec


def test_service_bootstrap_registers_only_c2_tools(tmp_path):
    grpc = SimpleNamespace(
        listCommands=lambda query: iter([
            command_spec("whoami", "whoami"),
            command_spec("pwd", "pwd"),
        ]),
        sendSessionCommand=lambda command: None,
        getCommandHelp=lambda command: None,
        listModules=lambda session: iter([]),
        listSessions=lambda: iter([]),
    )

    service = C2AssistantAgent(grpc, storage_dir=tmp_path)

    assert service.orchestrator.registry.list_tool_names() == [
        "getCommandHelp",
        "listLiveSessions",
        "listLoadedModules",
        "pwd",
        "whoami",
    ]
    assert service.session_manager.session_id == "default"
