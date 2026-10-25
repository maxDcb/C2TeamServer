"""Private, metadata-only audit trail for operator gRPC actions."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from .env import env_path

logger = logging.getLogger(__name__)
_write_lock = threading.Lock()


def audit_path() -> Path:
    directory = env_path("C2_LOG_DIR") or Path(__file__).parent / "logs"
    return Path(directory) / "Client.audit.jsonl"


def record_client_audit(*, client_id: str, username: str, endpoint: str,
                        action: str, outcome: str, details: dict | None = None) -> None:
    record = {
        "timestamp_ms": time.time_ns() // 1_000_000,
        "client_id": client_id,
        "actor": username,
        "endpoint": endpoint,
        "action": action,
        "outcome": outcome,
        "details": details or {},
    }
    try:
        payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        path = audit_path()
        with _write_lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.chmod(path, 0o600)
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("Audit write made no progress")
                    offset += written
            finally:
                os.close(descriptor)
    except (OSError, TypeError, ValueError):
        logger.exception("Could not write client audit entry")
