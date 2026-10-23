"""One command-result reader per session, with Qt fan-out to GUI consumers."""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Event
from typing import Any, Callable

from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot

from .assistant_agent.domain.command_outcome import CommandOutcome
from .grpcClient import TeamServerApi_pb2
from .grpc_status import is_response_ok, response_message

logger = logging.getLogger(__name__)
SessionKey = tuple[str, str]  # listener_hash, beacon_hash


@dataclass(frozen=True, slots=True)
class CommandResultEvent:
    session_key: SessionKey
    outcome: CommandOutcome
    raw_output: bytes
    display_output: str
    event_id: int = 0


class CommandResultWorker(QThread):
    """Poll one session until stopped; gRPC calls have a client-side deadline."""

    responseReady = pyqtSignal(object)

    def __init__(self, grpc_client: Any, session_key: SessionKey, parent: QObject) -> None:
        super().__init__(parent)
        self.grpc_client = grpc_client
        self.session_key = session_key
        self._stop = Event()

    def run(self) -> None:
        listener_hash, beacon_hash = self.session_key
        session = TeamServerApi_pb2.SessionSelector(
            beacon_hash=beacon_hash, listener_hash=listener_hash,
        )
        while not self._stop.is_set():
            try:
                for response in self.grpc_client.streamSessionCommandResults(session):
                    if self._stop.is_set():
                        break
                    self.responseReady.emit((self.session_key, response))
            except Exception as exc:
                if not self._stop.is_set():
                    logger.debug("Command result polling failed for %s: %s", beacon_hash[:8], exc)
            self._stop.wait(1)

    def stop(self) -> None:
        self._stop.set()


class _SessionChannel(QObject):
    resultReady = pyqtSignal(object)


@dataclass(slots=True)
class _SessionStream:
    channel: _SessionChannel
    worker: CommandResultWorker
    subscribers: dict[int, Callable[[CommandResultEvent], None]] = field(default_factory=dict)
    seen_command_ids: set[str] = field(default_factory=set)
    last_event_id: int = 0
    recent: OrderedDict[str, CommandResultEvent] = field(default_factory=OrderedDict)


@dataclass(slots=True)
class HubSubscription:
    hub: CommandEventHub | None
    session_key: SessionKey
    subscriber_id: int

    def close(self) -> None:
        hub = self.hub
        self.hub = None
        if hub is not None:
            hub.unsubscribe(self)


class CommandEventHub(QObject):
    """Application-owned collector and generic subscription point for command results.

    The hub lives in the GUI thread. Workers only emit raw responses; normalization,
    deduplication, and per-session signal delivery all happen in the GUI thread.
    """

    def __init__(self, grpc_client: Any, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.grpc_client = grpc_client
        self._streams: dict[SessionKey, _SessionStream] = {}
        self._next_subscriber_id = 0
        self._closed = False

    def subscribe(
        self,
        beacon_hash: str,
        listener_hash: str,
        callback: Callable[[CommandResultEvent], None],
    ) -> HubSubscription:
        if self._closed:
            raise RuntimeError("Command event hub is closed")
        if not beacon_hash or not listener_hash:
            raise ValueError("A complete session key is required")
        key = (listener_hash, beacon_hash)
        stream = self._streams.get(key)
        if stream is None:
            channel = _SessionChannel(self)
            worker = CommandResultWorker(self.grpc_client, key, self)
            worker.responseReady.connect(self._on_worker_response)
            stream = _SessionStream(channel=channel, worker=worker)
            self._streams[key] = stream
            start_worker = True
        else:
            start_worker = False

        self._next_subscriber_id += 1
        subscriber_id = self._next_subscriber_id

        def deliver(event: CommandResultEvent) -> None:
            callback(event)

        stream.channel.resultReady.connect(deliver)
        stream.subscribers[subscriber_id] = deliver
        subscription = HubSubscription(self, key, subscriber_id)
        if start_worker:
            stream.worker.start()
        return subscription

    def unsubscribe(self, subscription: HubSubscription) -> None:
        stream = self._streams.get(subscription.session_key)
        if stream is None:
            return
        callback = stream.subscribers.pop(subscription.subscriber_id, None)
        if callback is None:
            return
        stream.channel.resultReady.disconnect(callback)
        if not stream.subscribers:
            self._stop_stream(subscription.session_key, stream)

    def recent_event(self, beacon_hash: str, listener_hash: str, command_id: str) -> CommandResultEvent | None:
        stream = self._streams.get((listener_hash, beacon_hash))
        return stream.recent.get(command_id) if stream is not None and command_id else None

    def recent_events(self, beacon_hash: str, listener_hash: str) -> list[CommandResultEvent]:
        stream = self._streams.get((listener_hash, beacon_hash))
        return list(stream.recent.values()) if stream is not None else []

    @pyqtSlot(object)
    def _on_worker_response(self, payload: object) -> None:
        key, response = payload
        self.ingest_response(key[1], key[0], response)

    def ingest_response(self, beacon_hash: str, listener_hash: str, response: Any) -> None:
        """Normalize one streamed response and publish it once to every subscriber."""
        key = (listener_hash, beacon_hash)
        stream = self._streams.get(key)
        if stream is None or self._closed:
            return
        response_session = getattr(response, "session", None)
        actual_beacon = getattr(response_session, "beacon_hash", "") or beacon_hash
        actual_listener = getattr(response_session, "listener_hash", "") or listener_hash
        if (actual_listener, actual_beacon) != key:
            logger.warning("Ignoring command result for a different session")
            return

        command_id = getattr(response, "command_id", "") or ""
        event_id = int(getattr(response, "event_id", 0) or 0)
        if event_id and event_id <= stream.last_event_id:
            return
        if not event_id and command_id and command_id in stream.seen_command_ids:
            return
        output = getattr(response, "output", b"") or b""
        raw_output = output if isinstance(output, bytes) else str(output).encode("utf-8", "replace")
        text_output = raw_output.decode("utf-8", "replace")
        ok = is_response_ok(response)
        display_output = text_output if ok else response_message(response) or text_output or "Command failed."
        command_line = getattr(response, "command", "") or getattr(response, "instruction", "") or ""
        outcome = CommandOutcome(
            state=(getattr(response, "job_state", "") or ("succeeded" if ok else "failed")),
            command_id=command_id,
            beacon_hash=beacon_hash,
            listener_hash=listener_hash,
            command_line=command_line,
            output=text_output,
            error_code="" if ok else ("outcome_unknown" if getattr(response, "job_state", "") == "outcome_unknown"
                else "teamserver_command_failed"),
            error_message="" if ok else response_message(response, "Command failed."),
        )
        event = CommandResultEvent(key, outcome, raw_output, display_output, event_id)
        if event_id:
            stream.last_event_id = event_id
        if command_id:
            if not event_id:
                stream.seen_command_ids.add(command_id)
            stream.recent[command_id] = event
            while len(stream.recent) > 256:
                stream.recent.popitem(last=False)
        stream.channel.resultReady.emit(event)

    def _stop_stream(self, key: SessionKey, stream: _SessionStream) -> None:
        stream.worker.stop()
        if not stream.worker.wait(3500):
            # Keep the worker registered so a second reader cannot start.
            logger.error("Command result worker did not stop for %s", key[1][:8])
            return
        self._streams.pop(key, None)
        stream.worker.deleteLater()
        stream.channel.deleteLater()

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        streams = list(self._streams.items())
        for _key, stream in streams:
            for callback in stream.subscribers.values():
                stream.channel.resultReady.disconnect(callback)
            stream.subscribers.clear()
            stream.worker.stop()
        for key, stream in streams:
            self._stop_stream(key, stream)
