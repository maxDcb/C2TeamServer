from __future__ import annotations

import json

from C2Client.assistant_agent.domain.service import C2AssistantAgent


def test_imports_legacy_session_history_without_replaying_pending_call(tmp_path):
    legacy_file = tmp_path / "session.json"
    legacy = {
        "context_blocks": [
            {
                "block_id": "turn-0001",
                "kind": "conversation_turn",
                "content": {
                    "user_message": {"role": "user", "content": "Inspect the session"},
                    "assistant_message": {"role": "assistant", "content": "Observed a response"},
                },
                "token_estimate": 20,
                "metadata": {"turn_index": 1},
            },
            {
                "block_id": "old-summary",
                "kind": "summary",
                "content": {"summary": {"facts_confirmed": ["old fact"]}},
                "token_estimate": 10,
            },
        ],
        "active_block_ids": ["turn-0001", "old-summary"],
        "overflow_block_ids": [],
        "summary": {"facts_confirmed": ["old fact"]},
        "task_state": {"objective": "inspect"},
        "tool_history": [{"tool_name": "listLiveSessions"}],
        "domain_state": {"c2": {"selected": "beacon"}},
        "meta": {"schema_version": 4, "pending_agent_turn": {"pending_id": "old-pending"}},
    }
    legacy_file.write_text(json.dumps(legacy), encoding="utf-8")

    service = C2AssistantAgent(None, storage_dir=tmp_path)
    migrated = service.session_manager.get_state()

    assert legacy_file.read_text(encoding="utf-8") == json.dumps(legacy)
    assert (tmp_path / "default" / "default.json").is_file()
    assert [block["kind"] for block in migrated["context_blocks"]] == ["conversation_turn"]
    assert migrated["active_block_ids"] == ["turn-0001"]
    assert migrated["tool_history"] == legacy["tool_history"]
    assert migrated["domain_state"] == legacy["domain_state"]
    assert migrated["meta"]["schema_version"] == 5
    assert migrated["meta"]["legacy_pending_incompatible"] is True
    assert "pending_agent_turn" not in migrated["meta"]

    assert service.session_manager.reconcile_memory(
        max_handoff_chars=6000,
        max_turn_summary_chars=4000,
    ) is True
    assert "Observed a response" in service.session_manager.get_memory_journal().session_view.content

    C2AssistantAgent(None, storage_dir=tmp_path)
    assert len(json.loads((tmp_path / "default" / "default.json").read_text())["context_blocks"]) == 1
