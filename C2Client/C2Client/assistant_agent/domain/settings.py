from __future__ import annotations

import os
from pathlib import Path

from ..storage.paths import default_storage_dir, prompts_dir

from agent_core import CoreSettings
from agent_core.prompt_repository import load_prompt


def build_c2_agent_settings(*, storage_dir: Path | None = None) -> CoreSettings:
    if storage_dir is None:
        storage_dir = default_storage_dir()
    storage_dir.mkdir(parents=True, exist_ok=True)

    prompt_root = prompts_dir()
    model = os.getenv("C2_ASSISTANT_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o"))
    memory_model = os.getenv("C2_ASSISTANT_MEMORY_MODEL", model)

    return CoreSettings(
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        model=model,
        memory_model=memory_model,
        temperature=float(os.getenv("C2_ASSISTANT_TEMPERATURE", "0.05")),
        memory_temperature=float(os.getenv("C2_ASSISTANT_MEMORY_TEMPERATURE", "0.0")),
        max_tool_calls_per_turn=int(os.getenv("C2_ASSISTANT_MAX_TOOL_CALLS", "10")),
        session_file=storage_dir / "session.json",
        reports_directory=storage_dir / "reports",
        prompts_dir=prompt_root,
        knowledge_base_dir=storage_dir / "knowledge",
        allowed_read_roots=[Path.cwd()],
        allowed_http_hosts=[],
        allowed_http_methods=[],
        base_system_prompt=load_prompt(prompt_root, "system/main_agent.md"),
        task_state_synthesis_prompt=load_prompt(prompt_root, "memory/task_state.md"),
        session_summary_synthesis_prompt=load_prompt(prompt_root, "memory/session_summary.md"),
        session_summary_merge_prompt=load_prompt(prompt_root, "memory/session_summary_merge.md"),
    )
