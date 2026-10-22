from __future__ import annotations

import pytest

from agent_core import ToolArtifactPolicy

from C2Client.assistant_agent.domain.settings import DEFAULT_MEMORY_MODEL, build_c2_agent_settings


def test_prompt_files_are_loaded_into_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    monkeypatch.delenv("C2_ASSISTANT_MEMORY_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MEMORY_MODEL", raising=False)
    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert "Exploration C2" in settings.base_system_prompt
    assert "local release-side module" in settings.base_system_prompt
    assert "compact handoff" in settings.turn_memory_synthesis_prompt
    assert settings.artifacts_directory == tmp_path / "artifacts"
    assert settings.memory_model == DEFAULT_MEMORY_MODEL
    assert settings.max_active_context_tokens == 64000


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
                "C2_ASSISTANT_MAX_ACTIVE_CONTEXT_TOKENS=32000",
                "C2_ASSISTANT_LOG_SYNTHESIS_PAYLOADS=true",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("C2_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MODEL", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MEMORY_MODEL", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MAX_TOOL_CALLS", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MAX_ACTIVE_CONTEXT_TOKENS", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_LOG_SYNTHESIS_PAYLOADS", raising=False)

    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert settings.openai_api_key == "test-key"
    assert settings.model == "main-from-file"
    assert settings.memory_model == "memory-from-file"
    assert settings.max_tool_calls_per_turn == 3
    assert settings.max_active_context_tokens == 32000
    assert settings.log_synthesis_payloads is True


def test_tool_artifact_policy_preserves_native_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    for name in ToolArtifactPolicy().to_dict():
        monkeypatch.delenv(f"C2_ASSISTANT_ARTIFACT_{name.upper()}", raising=False)

    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert settings.tool_artifact_policy == ToolArtifactPolicy()


def test_tool_artifact_policy_accepts_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_HOT_CONTEXT_BYTES", "8192")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_COMPLETE_RESULT_BYTES", "512")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_PREVIEW_BYTES", "128")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_READ_BYTES", "256")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_READS_PER_RUN", "3")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_TOTAL_READ_BYTES", "1024")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_NAVIGATION_SOURCE_BYTES", "4096")
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_NAVIGATION_CACHE_BYTES", "8192")

    settings = build_c2_agent_settings(storage_dir=tmp_path)

    assert settings.tool_artifact_policy == ToolArtifactPolicy(
        hot_context_bytes=8192,
        max_complete_result_bytes=512,
        preview_bytes=128,
        max_read_bytes=256,
        max_reads_per_run=3,
        max_total_read_bytes=1024,
        max_navigation_source_bytes=4096,
        max_navigation_cache_bytes=8192,
    )


@pytest.mark.parametrize("value", ["nope", "0", "-1"])
def test_tool_artifact_policy_rejects_invalid_limits(tmp_path, monkeypatch, value):
    monkeypatch.setenv("C2_ENV_FILE", str(tmp_path / "missing.env"))
    monkeypatch.setenv("C2_ASSISTANT_ARTIFACT_MAX_READ_BYTES", value)

    with pytest.raises(ValueError):
        build_c2_agent_settings(storage_dir=tmp_path)
