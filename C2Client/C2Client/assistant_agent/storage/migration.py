"""Import pre-0.6 agent-core conversation files without changing the originals."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_core.conversation import SessionRepository

logger = logging.getLogger(__name__)
_CURRENT_BLOCK_KINDS = {"conversation_turn", "tool_exchange", "retrieved_memory"}


def import_legacy_sessions(repo: SessionRepository, storage_dir: Path) -> None:
    """Copy v0.1 flat session files into the v0.6 per-thread layout once.

    The old summary and task-state schemas have no v0.6 equivalent. Their
    source file remains untouched, while compatible raw conversation blocks
    are retained for the new memory journal's recovery path.
    """
    imported = set(repo.list_session_ids())
    for source in storage_dir.glob("*.json"):
        session_id = "default" if source.name == "session.json" else source.stem
        if session_id in imported:
            continue
        try:
            legacy = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Skipping unreadable legacy assistant session %s: %s", source, exc)
            continue
        if not _is_legacy_session(legacy):
            continue

        blocks = [
            block for block in legacy["context_blocks"]
            if isinstance(block, dict) and block.get("kind") in _CURRENT_BLOCK_KINDS
        ]
        block_ids = {block.get("block_id") for block in blocks}
        meta = {
            key: value for key, value in legacy["meta"].items()
            if key not in {"schema_version", "pending_agent_turn"}
        }
        if legacy["meta"].get("pending_agent_turn"):
            meta["legacy_pending_incompatible"] = True
        migrated = {
            "context_blocks": blocks,
            "active_block_ids": _retained_ids(legacy.get("active_block_ids"), block_ids),
            "overflow_block_ids": _retained_ids(legacy.get("overflow_block_ids"), block_ids),
            "tool_history": legacy.get("tool_history", []),
            "domain_state": legacy.get("domain_state", {}),
            "meta": meta,
        }
        repo.save(session_id, migrated)
        repo.save(session_id, repo.load(session_id))
        imported.add(session_id)
        logger.info("Imported legacy assistant session %s", session_id)


def _is_legacy_session(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    meta = payload.get("meta")
    blocks = payload.get("context_blocks")
    return (
        isinstance(meta, dict)
        and isinstance(meta.get("schema_version"), int)
        and meta["schema_version"] < 5
        and isinstance(blocks, list)
    )


def _retained_ids(values: object, block_ids: set[object]) -> list[str]:
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str) and value in block_ids]
