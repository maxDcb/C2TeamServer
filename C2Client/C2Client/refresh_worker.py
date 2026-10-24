"""Fetch a panel snapshot away from the Qt GUI thread, with bounded retry delay."""

from __future__ import annotations

import logging
from threading import Event
from typing import Any, Callable, Iterable

from PyQt6.QtCore import QObject, pyqtSignal


logger = logging.getLogger(__name__)


class RefreshWorker(QObject):
    ready = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fetch: Callable[[], Iterable[Any]], interval_ms: int) -> None:
        super().__init__()
        self.fetch = fetch
        self.interval_seconds = interval_ms / 1000
        self._stop = Event()
        self._wake = Event()

    def run(self) -> None:
        delay = self.interval_seconds
        while not self._stop.is_set():
            try:
                self.ready.emit(list(self.fetch()))
                delay = self.interval_seconds
            except Exception as exc:
                logger.debug("Panel refresh failed: %s", exc)
                self.failed.emit(str(exc))
                delay = min(max(delay * 2, self.interval_seconds), 15.0)
            self._wake.wait(delay)
            self._wake.clear()

    def request_refresh(self) -> None:
        self._wake.set()

    def quit(self) -> None:
        self._stop.set()
        self._wake.set()
