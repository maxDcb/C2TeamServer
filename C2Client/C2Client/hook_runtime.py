"""Bounded, non-UI execution and metadata-only audit for local hooks."""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

from .grpc_status import is_response_ok
from .grpcClient import GrpcClient

logger = logging.getLogger(__name__)
HOOK_TIMEOUT_SECONDS = 10
HOOK_QUEUE_SIZE = 64
HOOK_WORKERS = 4
MAX_HOOK_OUTPUT_CHARS = 8192


def hook_config_path(name: str, environment: str) -> Path:
    configured = os.getenv(environment)
    if configured:
        return Path(configured).expanduser().resolve()
    return Path.home() / ".config" / "c2client" / name


class HookAudit:
    def __init__(self, path: Path | None = None):
        self.path = path or hook_config_path("hook-audit.jsonl", "C2_HOOK_AUDIT_PATH")
        self._lock = threading.Lock()

    def record(self, **fields) -> None:
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), **fields}
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    output.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError:
            logger.exception("Could not write hook audit")


class AuditedGrpcClient:
    """Expose the existing client to a hook and record calls without request bodies."""

    def __init__(self, client, audit: HookAudit, origin: dict):
        self._client = client
        self._audit = audit
        self._origin = origin

    def __getattr__(self, name):
        member = getattr(self._client, name)
        if not callable(member) or name.startswith("_"):
            return member

        def audited(*args, **kwargs):
            request = args[0] if args else None
            request_id = (getattr(request, "command_id", "") or getattr(request, "job_id", "")
                          or (str(request) if name == "submitJob" and request is not None else ""))
            if isinstance(self._client, GrpcClient) and name in {"sendSessionCommand", "submitJob"}:
                source = re.sub(r"[^A-Za-z0-9._:-]", "_", self._origin["script"][-80:])
                kwargs.setdefault("origin", "hook:" + source + ":"
                                  + self._origin["hook"] + ":" + self._origin["invocation_id"])
            try:
                result = member(*args, **kwargs)
            except Exception as exc:
                self._audit.record(**self._origin, event="rpc", method=name,
                                   request_id=request_id, status="exception", error_type=type(exc).__name__)
                raise
            # Streaming calls are lazy; opening the stream is not an acknowledged action.
            if not hasattr(result, "__next__"):
                accepted = (is_response_ok(result)
                            and getattr(result, "state", "") not in {"failed", "outcome_unknown"})
                self._audit.record(**self._origin, event="rpc", method=name,
                                   request_id=request_id,
                                   status="ok" if accepted else "rejected")
            return result

        return audited


class HookRuntime(QObject):
    finished = pyqtSignal(object)

    def __init__(self, client, operator: str, audit: HookAudit, parent=None):
        super().__init__(parent)
        self.client = client
        self.operator = operator
        self.audit = audit
        self._queue = queue.Queue(maxsize=HOOK_QUEUE_SIZE)
        self._slots = threading.Semaphore(HOOK_WORKERS)
        self._closed = False
        self._dispatcher = threading.Thread(target=self._dispatch_loop, daemon=True, name="hook-dispatcher")
        self._dispatcher.start()

    def submit(self, script_name: str, hook_name: str, hook, context: dict, *, immediate=False):
        if self._closed:
            return None
        invocation_id = uuid.uuid4().hex
        origin = {
            "invocation_id": invocation_id,
            "operator": self.operator,
            "script": script_name,
            "hook": hook_name,
            "trigger": context.get("trigger", ""),
            "object_type": context.get("object_type", ""),
            "object_id": context.get("object_id", ""),
            "listener_hash": context.get("event", {}).get("listener_hash", ""),
            "command_id": context.get("event", {}).get("command_id", ""),
        }
        task = (origin, hook, context, threading.Event())
        self.audit.record(**origin, event="submitted")
        try:
            if immediate:
                self._start(task, reserve_slot=False)
            else:
                self._queue.put_nowait(task)
        except queue.Full:
            self.audit.record(**origin, event="dropped", status="queue_full")
            return None
        return task[3]

    def _dispatch_loop(self):
        while True:
            task = self._queue.get()
            if task is None:
                return
            self._slots.acquire()
            self._start(task, reserve_slot=True)

    def _start(self, task, *, reserve_slot):
        thread = threading.Thread(target=self._run, args=(task, reserve_slot), daemon=True,
                                  name="hook-invocation")
        thread.start()

    def _run(self, task, reserve_slot):
        origin, hook, context, completion = task
        report_lock = threading.Lock()
        reported = False

        def report(status, output, error_type=""):
            nonlocal reported
            with report_lock:
                if reported:
                    return
                reported = True
            self.audit.record(**origin, event="finished", status=status, error_type=error_type)
            if not self._closed:
                self._emit_finished((origin, status, output))

        def timeout():
            if not completion.is_set():
                report("timeout_unknown", "Hook exceeded 10 seconds; outcome unknown.")

        timer = threading.Timer(HOOK_TIMEOUT_SECONDS, timeout)
        timer.daemon = True
        timer.start()
        error_type = ""
        try:
            client = AuditedGrpcClient(self.client, self.audit, origin)
            output = hook(client, context)
            output = str(output)[:MAX_HOOK_OUTPUT_CHARS] if output is not None else ""
            status = "ok"
        except Exception as exc:
            logger.exception("Hook %s.%s failed", origin["script"], origin["hook"])
            output = str(exc)[:MAX_HOOK_OUTPUT_CHARS]
            status = "error"
            error_type = type(exc).__name__
        finally:
            completion.set()
            timer.cancel()
            if reserve_slot:
                self._slots.release()
        report(status, output, error_type)

    def _emit_finished(self, payload):
        try:
            self.finished.emit(payload)
        except RuntimeError:
            # The panel may have been destroyed while a daemon hook was in flight.
            pass

    def close(self):
        self._closed = True
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
