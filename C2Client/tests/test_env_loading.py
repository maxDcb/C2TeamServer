from __future__ import annotations

import os

from C2Client.env import load_c2_env


def test_load_c2_env_reads_dotenv_without_overriding_existing_values(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "OPENAI_API_KEY=from-file",
                "C2_ASSISTANT_MODEL=gpt-4o",
                "C2_ASSISTANT_MEMORY_MODEL='gpt-4.1-mini'",
                "C2_ASSISTANT_MAX_TOOL_CALLS=5 # local override",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "from-env")
    monkeypatch.delenv("C2_ASSISTANT_MODEL", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MEMORY_MODEL", raising=False)
    monkeypatch.delenv("C2_ASSISTANT_MAX_TOOL_CALLS", raising=False)

    loaded = load_c2_env([env_file])

    assert loaded == [env_file.resolve()]
    assert os.environ["OPENAI_API_KEY"] == "from-env"
    assert os.environ["C2_ASSISTANT_MODEL"] == "gpt-4o"
    assert os.environ["C2_ASSISTANT_MEMORY_MODEL"] == "gpt-4.1-mini"
    assert os.environ["C2_ASSISTANT_MAX_TOOL_CALLS"] == "5"


def test_load_c2_env_can_override_when_requested(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", "from-env")

    load_c2_env([env_file], override=True)

    assert os.environ["OPENAI_API_KEY"] == "from-file"
