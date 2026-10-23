"""Atomic local snapshots for client-owned skill runs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import RLock


class SkillRunStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def _path(self, run_id: str) -> Path:
        if not run_id or not all(char.isalnum() or char in "-_" for char in run_id):
            raise ValueError("Invalid skill run id")
        return self.root / f"{run_id}.json"

    def get(self, run_id: str) -> dict:
        with self._lock:
            payload = json.loads(self._path(run_id).read_text(encoding="utf-8"))
            if payload.get("schema_version") != 1 or payload.get("run_id") != run_id:
                raise ValueError(f"Invalid skill run snapshot: {run_id}")
            return payload

    def list(self) -> list[dict]:
        with self._lock:
            return sorted(
                (self.get(path.stem) for path in self.root.glob("*.json")),
                key=lambda run: run["created_at"], reverse=True,
            )

    def save(self, run: dict) -> None:
        path = self._path(run["run_id"])
        with self._lock:
            temporary: Path | None = None
            try:
                with NamedTemporaryFile("w", encoding="utf-8", dir=self.root, delete=False) as stream:
                    temporary = Path(stream.name)
                    json.dump(run, stream, ensure_ascii=False, sort_keys=True, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
