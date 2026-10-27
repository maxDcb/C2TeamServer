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
        "listC2Commands",
        "listLiveSessions",
        "listLoadedModules",
        "pwd",
        "whoami",
    ]
    assert service.session_manager.session_id == "default"


def test_service_passes_run_context_for_new_and_resumed_turns(tmp_path):
    service = C2AssistantAgent(None, storage_dir=tmp_path)
    calls = []
    expected = object()

    def run_turn_result(**kwargs):
        calls.append(("run", kwargs))
        return expected

    def resume_turn(**kwargs):
        calls.append(("resume", kwargs))
        return expected

    service.orchestrator = SimpleNamespace(
        run_turn_result=run_turn_result,
        resume_turn=resume_turn,
    )

    assert service.run_user_turn("inspect", session_id="operator-thread") is expected
    assert service.resume_pending_tool(
        pending_id="pending-1",
        tool_content="command failed",
        ok=False,
        session_id="operator-thread",
    ) is expected

    assert calls[0][1]["user_input"] == "inspect"
    assert calls[1][1]["pending_id"] == "pending-1"
    assert calls[1][1]["ok"] is False
    for _kind, kwargs in calls:
        assert kwargs["thread_id"] == "operator-thread"
        assert kwargs["context"].thread_id == "operator-thread"
        assert kwargs["context"].namespace_id == "c2client"


def test_manual_stop_discards_only_matching_wait_checkpoint(tmp_path):
    service = C2AssistantAgent(None, storage_dir=tmp_path)
    key = service.orchestrator.PENDING_TURN_META_KEY
    service.session_manager.set_meta_value(key, {"pending_id": "pending-1"})
    service.session_manager.append_tool_history({"status": "pending", "tool_name": "demo"})

    assert service.stop_pending_tool_wait(pending_id="other") is False
    assert service.session_manager.get_state()["meta"][key]["pending_id"] == "pending-1"
    assert service.stop_pending_tool_wait(pending_id="pending-1") is True
    state = service.session_manager.get_state()
    assert key not in state["meta"]
    assert state["tool_history"][-1]["status"] == "pending"
