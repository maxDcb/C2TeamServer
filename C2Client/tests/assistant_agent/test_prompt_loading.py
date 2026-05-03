from __future__ import annotations

from C2Client.assistant_agent.domain.settings import DEFAULT_MEMORY_MODEL, build_c2_agent_settings


def test_prompt_files_are_loaded_into_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    monkeypatch.delenv("C2_ASSISTANT_MEMORY_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MEMORY_MODEL", raising=False)
    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert "Exploration C2" in settings.base_system_prompt
    assert "local release-side module" in settings.base_system_prompt
    assert "operational state" in settings.task_state_synthesis_prompt
    assert "durable operational memory" in settings.session_summary_synthesis_prompt
    assert "Merge the previous session summary" in settings.session_summary_merge_prompt
    assert settings.memory_model == DEFAULT_MEMORY_MODEL


def test_memory_model_can_be_configured_independently(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    monkeypatch.setenv("C2_ASSISTANT_MODEL", "main-model")
    monkeypatch.setenv("C2_ASSISTANT_MEMORY_MODEL", "memory-model")

    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert settings.model == "main-model"
    assert settings.memory_model == "memory-model"


def test_memory_model_accepts_openai_memory_model_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    monkeypatch.setenv("C2_ASSISTANT_MODEL", "main-model")
    monkeypatch.delenv("C2_ASSISTANT_MEMORY_MODEL", raising=False)
    monkeypatch.setenv("OPENAI_MEMORY_MODEL", "fallback-memory-model")

    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert settings.model == "main-model"
    assert settings.memory_model == "fallback-memory-model"


def test_settings_load_values_from_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "OPENAI_API_KEY=test-key",
                "C2_ASSISTANT_MODEL=main-from-file",
                "C2_ASSISTANT_MEMORY_MODEL=memory-from-file",
                "C2_ASSISTANT_MAX_TOOL_CALLS=3",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("C2_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MODEL", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MEMORY_MODEL", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MAX_TOOL_CALLS", raising=False)

    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert settings.openai_api_key == "test-key"
    assert settings.model == "main-from-file"
    assert settings.memory_model == "memory-from-file"
    assert settings.max_tool_calls_per_turn == 3
