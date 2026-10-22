from __future__ import annotations

import os
from pathlib import Path

from ...env import load_c2_env
from ..storage.paths import default_storage_dir, prompts_dir

from agent_core import CoreSettings, ToolArtifactPolicy
from agent_core.spi import load_prompt

DEFAULT_MEMORY_MODEL = "gpt-4.1-mini"

_ARTIFACT_POLICY_ENV = {
    "hot_context_bytes": "C2_ASSISTANT_ARTIFACT_HOT_CONTEXT_BYTES",
    "max_complete_result_bytes": "C2_ASSISTANT_ARTIFACT_MAX_COMPLETE_RESULT_BYTES",
    "preview_bytes": "C2_ASSISTANT_ARTIFACT_PREVIEW_BYTES",
    "max_read_bytes": "C2_ASSISTANT_ARTIFACT_MAX_READ_BYTES",
    "max_reads_per_run": "C2_ASSISTANT_ARTIFACT_MAX_READS_PER_RUN",
    "max_total_read_bytes": "C2_ASSISTANT_ARTIFACT_MAX_TOTAL_READ_BYTES",
    "max_navigation_source_bytes": "C2_ASSISTANT_ARTIFACT_MAX_NAVIGATION_SOURCE_BYTES",
    "max_navigation_cache_bytes": "C2_ASSISTANT_ARTIFACT_MAX_NAVIGATION_CACHE_BYTES",
}


def build_tool_artifact_policy() -> ToolArtifactPolicy:
    values = ToolArtifactPolicy().to_dict()
    for field_name, env_name in _ARTIFACT_POLICY_ENV.items():
        raw = os.getenv(env_name)
        if raw is None:
            continue
        try:
            values[field_name] = int(raw)
        except ValueError as exc:
            raise ValueError(f"{env_name} must be a positive integer") from exc
    return ToolArtifactPolicy.from_any(values)


def build_c2_agent_settings(*, storage_dir: Path | None = None) -> CoreSettings:
    load_c2_env()

    if storage_dir is None:
        storage_dir = default_storage_dir()
    storage_dir.mkdir(parents=True, exist_ok=True)

    prompt_root = prompts_dir()
    model = os.getenv("C2_ASSISTANT_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o"))
    memory_model = os.getenv(
        "C2_ASSISTANT_MEMORY_MODEL",
        os.getenv("OPENAI_MEMORY_MODEL", DEFAULT_MEMORY_MODEL),
    )

    return CoreSettings(
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        model=model,
        memory_model=memory_model,
        temperature=float(os.getenv("C2_ASSISTANT_TEMPERATURE", "0.05")),
        memory_temperature=float(os.getenv("C2_ASSISTANT_MEMORY_TEMPERATURE", "0.0")),
        max_tool_calls_per_turn=int(os.getenv("C2_ASSISTANT_MAX_TOOL_CALLS", "10")),
        max_active_context_tokens=int(os.getenv("C2_ASSISTANT_MAX_ACTIVE_CONTEXT_TOKENS", "64000")),
        log_synthesis_payloads=os.getenv("C2_ASSISTANT_LOG_SYNTHESIS_PAYLOADS", "").lower() in {"1", "true", "yes", "y"},
        session_file=storage_dir / "session.json",
        reports_directory=storage_dir / "reports",
        artifacts_directory=storage_dir / "artifacts",
        tool_artifact_policy=build_tool_artifact_policy(),
        prompts_dir=prompt_root,
        knowledge_base_dir=storage_dir / "knowledge",
        allowed_read_roots=[Path.cwd()],
        allowed_http_hosts=[],
        allowed_http_methods=[],
        base_system_prompt=load_prompt(prompt_root, "system/main_agent.md"),
        turn_memory_synthesis_prompt=load_prompt(prompt_root, "memory/turn_memory.md"),
    )
