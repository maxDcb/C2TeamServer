from __future__ import annotations

import os

from C2Client.env import env_bool, env_int, env_path, load_c2_env


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


def test_load_c2_env_resolves_path_values_relative_to_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / "nested" / ".env"
    env_file.parent.mkdir()
    env_file.write_text(
        "\n".join(
            [
                "C2_CERT_PATH=certs/server.crt",
                "C2_LOG_DIR=./logs",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("C2_CERT_PATH", raising=False)
    monkeypatch.delenv("C2_LOG_DIR", raising=False)

    load_c2_env([env_file])

    assert os.environ["C2_CERT_PATH"] == str((env_file.parent / "certs/server.crt").resolve())
    assert os.environ["C2_LOG_DIR"] == str((env_file.parent / "logs").resolve())


def test_env_helpers_parse_typed_values(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "C2_DEV_MODE=yes",
                "C2_PORT=4444",
                "C2_LOG_DIR=logs",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("C2_DEV_MODE", raising=False)
    monkeypatch.delenv("C2_PORT", raising=False)
    monkeypatch.delenv("C2_LOG_DIR", raising=False)

    load_c2_env([env_file])

    assert env_bool("C2_DEV_MODE") is True
    assert env_int("C2_PORT", 50051, minimum=1, maximum=65535) == 4444
    assert env_path("C2_LOG_DIR") == (tmp_path / "logs").resolve()
