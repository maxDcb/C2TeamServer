from __future__ import annotations

from C2Client.assistant_agent.domain.settings import build_c2_agent_settings


def test_prompt_files_are_loaded_into_settings(tmp_path):
    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert "Exploration C2" in settings.base_system_prompt
    assert "operational state" in settings.task_state_synthesis_prompt
    assert "durable operational memory" in settings.session_summary_synthesis_prompt
    assert "Merge the previous session summary" in settings.session_summary_merge_prompt
