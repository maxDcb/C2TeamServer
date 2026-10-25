import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtCore import QObject, QRunnable, Qt, QThread, QThreadPool, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QHeaderView,
    QAbstractItemView,
    QSizePolicy,
)

from .grpcClient import TeamServerApi_pb2
from .env import env_int, env_path
from .grpc_status import is_response_ok, operation_ack_text
from .panel_style import apply_dark_panel_style, create_dark_context_menu
from .refresh_worker import RefreshWorker
from .ui_status import apply_status, format_action_status, status_kind_for_ok

logger = logging.getLogger(__name__)

SESSION_STATE_ALIVE = "Alive"
SESSION_STATE_STALE = "Stale"
SESSION_STATE_KILLED = "Killed"
SESSION_STATE_STOPPED = "Stopped"
SESSION_STATE_UNKNOWN = "Unknown"
SESSION_STATE_STOPPING = "Stopping"
SESSION_STATE_STOP_FAILED = "Stop unconfirmed"
SESSION_STATE_UNAVAILABLE = "Unavailable"
HIDDEN_STOP_STATES = {
    TeamServerApi_pb2.SESSION_STATE_STOPPING,
    TeamServerApi_pb2.SESSION_STATE_STOP_FAILED,
    TeamServerApi_pb2.SESSION_STATE_STOPPED,
}
SESSION_STATE_COLORS = {
    SESSION_STATE_ALIVE: "#0a7f2e",
    SESSION_STATE_STALE: "#a05a00",
    SESSION_STATE_KILLED: "#b00020",
    SESSION_STATE_STOPPED: "#6b7280",
    SESSION_STATE_UNKNOWN: "#6b7280",
    SESSION_STATE_STOPPING: "#a05a00",
    SESSION_STATE_STOP_FAILED: "#a05a00",
    SESSION_STATE_UNAVAILABLE: "#6b7280",
}
HIGH_PRIVILEGE_COLOR = "#a05a00"
DEFAULT_SESSION_STALE_AFTER_MS = 30000
DISPLAY_NOW_UNDER_MS = 2000
HIGH_PRIVILEGE_VALUES = {"high", "root", "administrator", "admin", "system"}


def _to_text(value):
    return str(value or "").strip()


def _to_text_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    try:
        return [_to_text(item) for item in value if _to_text(item)]
    except TypeError:
        text = _to_text(value)
        return [text] if text else []


def _is_truthy(value):
    if isinstance(value, bool):
        return value
    return _to_text(value).lower() in {"1", "true", "yes", "y", "killed"}


def parse_last_seen(value):
    text = _to_text(value)
    if not text or text == "-1":
        return None

    try:
        ageSeconds = float(text)
    except ValueError:
        ageSeconds = None
    if ageSeconds is not None:
        if ageSeconds < 0:
            return None
        return datetime.now() - timedelta(seconds=ageSeconds)

    normalized = text.replace("Z", "+00:00")
    candidates = [normalized]
    if "." in normalized:
        candidates.append(normalized.split(".", 1)[0])

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone().replace(tzinfo=None)
        return parsed
    return None


def _numeric_age_ms(value):
    text = _to_text(value)
    try:
        ageSeconds = float(text)
    except ValueError:
        return None
    if ageSeconds < 0:
        return None
    return max(0, int(ageSeconds * 1000))


def last_seen_age_ms(value, now=None):
    numericAgeMs = _numeric_age_ms(value)
    if numericAgeMs is not None:
        return numericAgeMs, True

    lastSeen = parse_last_seen(value)
    if lastSeen is None:
        return None, False

    now = now or datetime.now()
    return max(0, int((now - lastSeen).total_seconds() * 1000)), False


def format_relative_age(ageSeconds):
    if ageSeconds < 1:
        return "now"
    if ageSeconds < 60:
        return f"{ageSeconds}s ago"
    if ageSeconds < 3600:
        return f"{ageSeconds // 60}m ago"
    if ageSeconds < 86400:
        return f"{ageSeconds // 3600}h ago"
    return f"{ageSeconds // 86400}d ago"


def format_relative_age_ms(ageMs, *, precise_subsecond=False):
    if ageMs < DISPLAY_NOW_UNDER_MS:
        return "now"
    return format_relative_age(ageMs // 1000)


def humanize_last_seen(value, now=None):
    text = _to_text(value)
    ageMs, preciseSubsecond = last_seen_age_ms(text, now=now)
    if ageMs is None:
        return "unknown", "Last proof of life unavailable.", None

    label = format_relative_age_ms(ageMs, precise_subsecond=preciseSubsecond)
    return label, f"Last proof of life: {text}", parse_last_seen(text)


def resolve_session_state(killed, lastProofOfLife, staleAfterMs=DEFAULT_SESSION_STALE_AFTER_MS, now=None, serverState=None):
    if serverState == TeamServerApi_pb2.SESSION_STATE_STOPPING:
        return SESSION_STATE_STOPPING, "Stop request queued; waiting for beacon confirmation."
    if serverState == TeamServerApi_pb2.SESSION_STATE_STOP_FAILED:
        return SESSION_STATE_STOP_FAILED, "No final stop result was received. The beacon may have exited; retry only if it is still running."
    if serverState == TeamServerApi_pb2.SESSION_STATE_STOPPED:
        return SESSION_STATE_STOPPED, "Beacon confirmed stop; command history remains available."
    if _is_truthy(killed):
        return SESSION_STATE_KILLED, "Killed flag set by TeamServer."

    ageMs, preciseSubsecond = last_seen_age_ms(lastProofOfLife, now=now)
    if ageMs is None:
        return SESSION_STATE_UNKNOWN, "No valid last proof of life."

    label = format_relative_age_ms(ageMs, precise_subsecond=preciseSubsecond)
    aliveCutoffMs = max(staleAfterMs, DISPLAY_NOW_UNDER_MS - 1)
    if ageMs <= aliveCutoffMs:
        return SESSION_STATE_ALIVE, f"Last seen {label}. Stale after {staleAfterMs} ms."
    return SESSION_STATE_STALE, f"Last seen {label}. Stale after {staleAfterMs} ms."


def normalize_os_label(osDescription):
    text = _to_text(osDescription)
    lowered = text.lower()
    if not text:
        return "Unknown"
    if "windows" in lowered:
        return "Windows"
    if "linux" in lowered:
        return "Linux"
    return text.split()[0]


def color_table_item(item, color):
    item.setForeground(QColor(color))
    return item


#
# Session
#
class Session():

    def __init__(self, id, listenerHash, beaconHash, hostname, username, arch, privilege, os, lastProofOfLife, killed, internalIps, processId, additionalInformation, state=None, available=True, archivedAtMs=0):
        self.id = id
        self.listenerHash = listenerHash
        self.beaconHash = beaconHash
        self.hostname = hostname
        self.username = username
        self.arch = arch
        self.privilege = privilege
        self.os = os
        self.lastProofOfLife = lastProofOfLife
        self.killed = killed
        self.internalIps = internalIps
        self.processId = processId
        self.additionalInformation = additionalInformation
        self.state = state
        self.available = available
        self.archivedAtMs = archivedAtMs


class SessionStopSignals(QObject):
    finished = pyqtSignal(object, str)


class SessionStopLookupSignals(QObject):
    finished = pyqtSignal(str, str, object, str)


class SessionStopLookupWorker(QRunnable):
    def __init__(self, grpc_client, beacon_hash, listener_hash, signals):
        super().__init__()
        self.grpc_client = grpc_client
        self.beacon_hash = beacon_hash
        self.listener_hash = listener_hash
        self.signals = signals

    def run(self):
        try:
            listeners = list(self.grpc_client.listListeners())
            self.signals.finished.emit(self.beacon_hash, self.listener_hash, listeners, "")
        except Exception as exc:
            self.signals.finished.emit(self.beacon_hash, self.listener_hash, [], str(exc))


class SessionStopWorker(QRunnable):
    def __init__(self, grpc_client, request, signals):
        super().__init__()
        self.grpc_client = grpc_client
        self.request = request
        self.signals = signals

    def run(self):
        try:
            self.signals.finished.emit(self.grpc_client.stopSession(self.request), "")
        except Exception as exc:
            self.signals.finished.emit(None, str(exc))


class Sessions(QWidget):

    interactWithSession = pyqtSignal(str, str, str, str, bool)
    sessionScriptSignal = pyqtSignal(str, str, str, str, str, str, str, str, str, bool)
    sessionsRefreshed = pyqtSignal(object)

    idSession = 0
    listSessionObject = []
    COLUMN_WIDTHS = [76, 76, 140, 116, 62, 84, 92, 64, 156, 92, 130]
    STRETCH_COLUMN = 8


    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)

        self.grpcClient = grpcClient
        self.idSession = 0
        self.listSessionObject = []
        self._history_path = self._sessionHistoryPath(grpcClient)
        self._stop_pending = False
        self._pending_stop_key = None
        self._has_snapshot = False
        self._seen_beacons = set()
        self._snapshot_auth_generation = getattr(grpcClient, "auth_generation", None)
        self._stop_signals = SessionStopSignals()
        self._stop_signals.finished.connect(self._onStopFinished)
        self._stop_lookup_signals = SessionStopLookupSignals()
        self._stop_lookup_signals.finished.connect(self._onStopLookupFinished)
        apply_dark_panel_style(self)
        self.sessionStaleAfterMs = env_int(
            "C2_SESSION_STALE_AFTER_MS",
            DEFAULT_SESSION_STALE_AFTER_MS,
            minimum=1,
        )

        widget = QWidget(self)
        self.layout = QGridLayout(widget)
        self.layout.setContentsMargins(4, 4, 4, 4)
        self.layout.setHorizontalSpacing(6)
        self.layout.setVerticalSpacing(4)
        self.layout.setColumnStretch(0, 1)
        self.layout.setRowStretch(2, 1)

        self.label = QLabel('Sessions')
        self.headerLayout = QHBoxLayout()
        self.headerLayout.setSpacing(4)
        self.headerLayout.addWidget(self.label)
        self.headerLayout.addStretch(1)

        self.interactButton = self.createToolbarButton("Open", "Open an interactive console for the selected session.", width=72)
        self.interactButton.setToolTip("Open an interactive console for the selected session.")
        self.interactButton.clicked.connect(self.interactWithSelectedSession)
        self.headerLayout.addWidget(self.interactButton)

        self.stopButton = self.createToolbarButton("Stop", "Queue a stop command for the selected session.")
        self.stopButton.clicked.connect(self.stopSelectedSession)
        self.headerLayout.addWidget(self.stopButton)

        self.copySessionIdButton = self.createToolbarButton("Copy", "Copy the selected beacon hash.")
        self.copySessionIdButton.clicked.connect(self.copySelectedSessionId)
        self.headerLayout.addWidget(self.copySessionIdButton)

        self.refreshButton = self.createToolbarButton("Refresh", "Refresh sessions now.", width=70)
        self.refreshButton.clicked.connect(self.requestRefresh)
        self.headerLayout.addWidget(self.refreshButton)

        self.hideInactiveButton = self.createToolbarButton(
            "Hide inactive", "Hide stopped, unconfirmed, and unavailable sessions.", width=112,
        )
        self.hideInactiveButton.setCheckable(True)
        self.hideInactiveButton.setStyleSheet(
            "QPushButton:checked { background-color: #17343b; color: #d5f7ef; border-color: #317f75; }"
        )
        self.hideInactiveButton.toggled.connect(self._onHideInactiveToggled)
        self.headerLayout.addWidget(self.hideInactiveButton)
        self.layout.addLayout(self.headerLayout, 0, 0)

        self.statusLabel = QLabel("")
        self.statusLabel.setMinimumHeight(18)
        self.layout.addWidget(self.statusLabel, 1, 0)

        # List of sessions
        self.listSession = QTableWidget()
        self.listSession.setShowGrid(False)
        self.listSession.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.listSession.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.listSession.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.listSession.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.listSession.setRowCount(0)
        self.listSession.setColumnCount(11)

        self.listSession.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.listSession.customContextMenuRequested.connect(self.showContextMenu)
        self.listSession.itemSelectionChanged.connect(self.updateActionButtons)

        self.listSession.verticalHeader().setVisible(False)
        self.configureTableColumns()
        self.layout.addWidget(self.listSession, 2, 0)
        self._loadSessionHistory()
        self.printSessions()

        # Thread to fetch sessions every second
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self._refresh_failed = False
        self.getSessionsWorker = GetSessionsWorker(self.grpcClient)
        self.getSessionsWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getSessionsWorker.run)
        self.getSessionsWorker.ready.connect(self._applySessions)
        self.getSessionsWorker.failed.connect(self._onRefreshFailure)
        self.thread.start()

        self.setLayout(self.layout)
        self.updateActionButtons()

    def createToolbarButton(self, text, tooltip, width=58):
        button = QPushButton(text)
        button.setToolTip(tooltip)
        button.setFixedHeight(26)
        button.setMinimumWidth(width)
        button.setMaximumWidth(width)
        return button

    def configureTableColumns(self):
        header = self.listSession.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(44)
        for index, width in enumerate(self.COLUMN_WIDTHS):
            if index == self.STRETCH_COLUMN:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
                self.listSession.setColumnWidth(index, width)

    @staticmethod
    def _sessionHistoryPath(grpcClient):
        endpoint = _to_text(getattr(grpcClient, "endpoint", ""))
        if not endpoint:
            return None
        identity = endpoint + "\n" + _to_text(getattr(grpcClient, "username", ""))
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        directory = env_path("C2_LOG_DIR") or Path(__file__).parent / "logs"
        return Path(directory) / f"sessions_{suffix}.json"

    def _loadSessionHistory(self):
        path = self._history_path
        if path is None or not path.exists():
            return
        try:
            records = json.loads(path.read_text(encoding="utf-8")).get("sessions", [])
            for record in records:
                beacon_hash = _to_text(record.get("beacon_hash"))
                listener_hash = _to_text(record.get("listener_hash"))
                if not beacon_hash or not listener_hash:
                    continue
                self.listSessionObject.append(Session(
                    self.idSession, listener_hash, beacon_hash,
                    *(_to_text(record.get(field)) for field in (
                        "hostname", "username", "arch", "privilege", "os", "last_proof_of_life")),
                    _is_truthy(record.get("killed")),
                    *(_to_text(record.get(field)) for field in (
                        "internal_ips", "process_id", "additional_information")),
                    record.get("state"), available=False,
                    archivedAtMs=int(record.get("archived_at_ms") or 0),
                ))
                self.idSession += 1
                self._seen_beacons.add(beacon_hash)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            self.setInlineStatus(f"Session history could not be loaded: {exc}", False)

    def _saveSessionHistory(self):
        path = self._history_path
        if path is None:
            return
        records = []
        for item in self.listSessionObject:
            last_seen = parse_last_seen(item.lastProofOfLife)
            records.append({
                "beacon_hash": item.beaconHash,
                "listener_hash": item.listenerHash,
                "hostname": item.hostname,
                "username": item.username,
                "arch": item.arch,
                "privilege": item.privilege,
                "os": item.os,
                "last_proof_of_life": last_seen.isoformat() if last_seen else item.lastProofOfLife,
                "killed": _is_truthy(item.killed),
                "internal_ips": item.internalIps,
                "process_id": item.processId,
                "additional_information": item.additionalInformation,
                "state": item.state,
                "archived_at_ms": item.archivedAtMs,
            })
        temp_name = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump({"version": 1, "sessions": records}, output, ensure_ascii=False)
            os.replace(temp_name, path)
        except OSError as exc:
            self.setInlineStatus(f"Session history could not be saved: {exc}", False)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)

    @staticmethod
    def _canSendCommands(session):
        return bool(session and session.available and not _is_truthy(session.killed)
                    and session.state in {
                        None, TeamServerApi_pb2.SESSION_STATE_UNSPECIFIED,
                        TeamServerApi_pb2.SESSION_STATE_RUNNING,
                    })

    def setStatusMessage(self, ack, successFallback, action="Operation"):
        message = operation_ack_text(ack, successFallback)
        self.setInlineStatus(format_action_status(action, message), is_response_ok(ack))

    def setInlineStatus(self, message, ok=True):
        apply_status(self.statusLabel, message, status_kind_for_ok(ok))

    def updateActionButtons(self):
        selected = self.selectedSession()
        hasSelection = selected is not None
        self.interactButton.setEnabled(hasSelection)
        history_only = hasSelection and not self._canSendCommands(selected)
        self.interactButton.setText("History" if history_only else "Open")
        self.interactButton.setToolTip(
            "View saved commands and responses (read-only)." if history_only
            else "Open an interactive console for the selected session."
        )
        self.stopButton.setEnabled(hasSelection and not self._stop_pending
                                   and selected.available and not _is_truthy(selected.killed)
                                   and selected.state not in {
                                       TeamServerApi_pb2.SESSION_STATE_STOPPING,
                                       TeamServerApi_pb2.SESSION_STATE_STOPPED,
                                   })
        self.copySessionIdButton.setEnabled(hasSelection)

    def selectedSession(self):
        selectedRows = self.listSession.selectionModel().selectedRows() if self.listSession.selectionModel() else []
        if not selectedRows:
            return None

        row = selectedRows[0].row()
        if row < 0 or self.listSession.isRowHidden(row):
            return None
        item = self.listSession.item(row, 0)
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return next(
            (session for session in self.listSessionObject
             if (session.beaconHash, session.listenerHash) == key),
            None,
        )

    def _onHideInactiveToggled(self, hideInactive):
        self.hideInactiveButton.setText("Show inactive" if hideInactive else "Hide inactive")
        self._applyInactiveRowFilter()

    def _applyInactiveRowFilter(self):
        for row, sessionStore in enumerate(self.listSessionObject):
            self.listSession.setRowHidden(
                row,
                self.hideInactiveButton.isChecked() and not self._canSendCommands(sessionStore),
            )
        if self.selectedSession() is None:
            self.listSession.clearSelection()
        self.updateActionButtons()

    def sessionByShortBeaconHash(self, beaconHashPrefix):
        for sessionStore in self.listSessionObject:
            if sessionStore.beaconHash[0:8] == beaconHashPrefix:
                return sessionStore
        return None

    def scriptSnapshot(self):
        snapshots = []
        for sessionStore in self.listSessionObject:
            if not sessionStore.available:
                continue
            state, stateTooltip = resolve_session_state(
                sessionStore.killed,
                sessionStore.lastProofOfLife,
                self.sessionStaleAfterMs,
                serverState=getattr(sessionStore, "state", None),
            )
            snapshots.append(
                {
                    "id": sessionStore.id,
                    "beacon_hash": _to_text(sessionStore.beaconHash),
                    "listener_hash": _to_text(sessionStore.listenerHash),
                    "hostname": _to_text(sessionStore.hostname),
                    "username": _to_text(sessionStore.username),
                    "arch": _to_text(sessionStore.arch),
                    "privilege": _to_text(sessionStore.privilege),
                    "os": _to_text(sessionStore.os),
                    "last_proof_of_life": _to_text(sessionStore.lastProofOfLife),
                    "killed": _is_truthy(sessionStore.killed),
                    "internal_ips": _to_text_list(sessionStore.internalIps),
                    "internal_ips_text": _to_text(sessionStore.internalIps),
                    "process_id": _to_text(sessionStore.processId),
                    "additional_information": _to_text(sessionStore.additionalInformation),
                    "state": state,
                    "state_detail": stateTooltip,
                }
            )
        return snapshots

    def interactWithSelectedSession(self):
        sessionStore = self.selectedSession()
        if sessionStore is None:
            self.setInlineStatus("Select a session first.", False)
            return
        self.interactWithSession.emit(
            sessionStore.beaconHash, sessionStore.listenerHash,
            sessionStore.hostname, sessionStore.username,
            not self._canSendCommands(sessionStore),
        )

    def stopSelectedSession(self):
        sessionStore = self.selectedSession()
        if sessionStore is None:
            self.setInlineStatus("Select a session first.", False)
            return
        if not sessionStore.available:
            self.setInlineStatus("Historical session; stop is unavailable.", False)
            return
        self.stopSession(sessionStore.beaconHash, sessionStore.listenerHash)

    def copySelectedSessionId(self):
        sessionStore = self.selectedSession()
        if sessionStore is None:
            self.setInlineStatus("Select a session first.", False)
            return
        QApplication.clipboard().setText(sessionStore.beaconHash)
        self.setInlineStatus("Beacon ID copied to clipboard.")

    def resizeEvent(self, event):
        super().resizeEvent(event) 
        self.listSession.verticalHeader().setVisible(False)


    def __del__(self):
        self.getSessionsWorker.quit()
        self.thread.quit()
        self.thread.wait()


    def showContextMenu(self, position):
        index = self.listSession.indexAt(position)
        if not index.isValid():
            return

        item = self.listSession.item(index.row(), 0)
        session_key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        sessionStore = next(
            (session for session in self.listSessionObject
             if (session.beaconHash, session.listenerHash) == session_key),
            None,
        )
        if sessionStore is None:
            return
        self._context_session_key = session_key

        menu = create_dark_context_menu(self)
        history_only = not self._canSendCommands(sessionStore)
        interactAction = menu.addAction('View history' if history_only else 'Interact')
        stopAction = menu.addAction(f'Stop {sessionStore.beaconHash[:8]} (PID {sessionStore.processId})')
        interactAction.setEnabled(True)
        stopAction.setEnabled(not self._stop_pending and sessionStore.available
                              and not _is_truthy(sessionStore.killed) and sessionStore.state not in {
            TeamServerApi_pb2.SESSION_STATE_STOPPING,
            TeamServerApi_pb2.SESSION_STATE_STOPPED,
        })
        menu.triggered.connect(lambda action, key=session_key: self.actionClicked(action, key))
        menu.exec(self.listSession.viewport().mapToGlobal(position))


    # catch Interact and Stop menu click
    def actionClicked(self, action, key=None):
        if key is None:
            key = getattr(self, "_context_session_key", None)
        for sessionStore in self.listSessionObject:
            if (sessionStore.beaconHash, sessionStore.listenerHash) != key:
                continue
            if action.text() in {"Interact", "View history"}:
                self.interactWithSession.emit(
                    sessionStore.beaconHash, sessionStore.listenerHash,
                    sessionStore.hostname, sessionStore.username,
                    not self._canSendCommands(sessionStore),
                )
            elif action.text().startswith("Stop ") and sessionStore.available:
                self.stopSession(sessionStore.beaconHash, sessionStore.listenerHash)
            break


    def stopSession(self, beaconHash, listenerHash):
        if self._stop_pending:
            return
        self._stop_pending = True
        self._pending_stop_key = (beaconHash, listenerHash)
        self.setInlineStatus(f"Checking child listeners for beacon {beaconHash[:8]}…")
        self.updateActionButtons()
        QThreadPool.globalInstance().start(
            SessionStopLookupWorker(self.grpcClient, beaconHash, listenerHash, self._stop_lookup_signals)
        )

    def _onStopLookupFinished(self, beaconHash, listenerHash, listeners, error):
        if self._pending_stop_key != (beaconHash, listenerHash):
            return
        sessionStore = next(
            (session for session in self.listSessionObject
             if (session.beaconHash, session.listenerHash) == (beaconHash, listenerHash)),
            None,
        )
        if sessionStore is not None and (
            not sessionStore.available or _is_truthy(sessionStore.killed) or sessionStore.state in {
                TeamServerApi_pb2.SESSION_STATE_STOPPING,
                TeamServerApi_pb2.SESSION_STATE_STOPPED,
            }
        ):
            self._pending_stop_key = None
            self._stop_pending = False
            self.setInlineStatus(f"Session {beaconHash[:8]} is no longer available for stopping.", False)
            self.updateActionButtons()
            return

        childListeners = sorted(
            (listener for listener in listeners
             if getattr(listener, "beacon_hash", "") == beaconHash
             and getattr(listener, "listener_hash", "")),
            key=lambda listener: listener.listener_hash,
        )
        host = sessionStore.hostname if sessionStore is not None else "unknown"
        pid = sessionStore.processId if sessionStore is not None else "unknown"
        message = (
            f"Stop beacon {beaconHash}?\n"
            f"Host: {host} | PID: {pid}\n"
            f"Listener route: {listenerHash}\n\n"
        )
        if childListeners:
            message += f"This beacon hosts {len(childListeners)} child listener(s):\n"
            message += "\n".join(
                f"• {listener.type} {listener.listener_hash[:8]}"
                for listener in childListeners[:5]
            )
            if len(childListeners) > 5:
                message += f"\n• … and {len(childListeners) - 5} more"
            message += "\n\nSessions reached through them may become unavailable."
        elif error:
            logger.warning("Could not check child listeners before stopping beacon %s: %s", beaconHash, error)
            message += "Child listeners could not be checked; their status is unknown."
        else:
            message += "No hosted child listener was reported."

        answer = QMessageBox.question(
            self, "Confirm beacon stop", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._pending_stop_key = None
            self._stop_pending = False
            self.setInlineStatus(f"Stop cancelled for beacon {beaconHash[:8]}.")
            self.updateActionButtons()
            return

        logger.info("StopSession requested for beacon %s on listener %s", beaconHash, listenerHash)
        session = TeamServerApi_pb2.SessionSelector(
            beacon_hash=beaconHash, listener_hash=listenerHash)
        self.setInlineStatus(
            f"Stopping session {beaconHash[:8]} / {listenerHash[:8]}; waiting for TeamServer…"
        )
        QThreadPool.globalInstance().start(SessionStopWorker(self.grpcClient, session, self._stop_signals))

    def _onStopFinished(self, ack, error):
        pending_key = self._pending_stop_key
        self._pending_stop_key = None
        self._stop_pending = False
        if error:
            self.setInlineStatus(
                format_action_status("Stop session", "Server did not confirm the request; refreshing sessions. " + error),
                False,
            )
        elif not is_response_ok(ack):
            self.setStatusMessage(ack, "Request rejected.", action="Stop session")
        else:
            actual_key = (
                getattr(ack, "session_beacon_hash", "") or pending_key[0],
                getattr(ack, "session_listener_hash", "") or pending_key[1],
            )
            logger.info("StopSession accepted for beacon %s on listener %s", *actual_key)
            for sessionStore in self.listSessionObject:
                if (sessionStore.beaconHash, sessionStore.listenerHash) == actual_key:
                    sessionStore.state = TeamServerApi_pb2.SESSION_STATE_STOPPING
            self.setInlineStatus(
                f"Stop session {actual_key[0][:8]} / {actual_key[1][:8]}: "
                + operation_ack_text(ack, "Session stop command queued.")
            )
            if actual_key[1] != pending_key[1]:
                self.setInlineStatus(
                    f"Stop session {actual_key[0][:8]}: queued via current route {actual_key[1][:8]}."
                )
            self.printSessions()
        self.updateActionButtons()
        self.requestRefresh()

    def requestRefresh(self):
        self.getSessionsWorker.request_refresh()

    def _onRefreshFailure(self, _message):
        self._refresh_failed = True
        changed = False
        for item in self.listSessionObject:
            if item.available:
                item.available = False
                last_seen = parse_last_seen(item.lastProofOfLife)
                if last_seen:
                    item.lastProofOfLife = last_seen.isoformat()
                changed = True
        if changed:
            self._saveSessionHistory()
            self.printSessions()
            self.sessionsRefreshed.emit([])
        self.setInlineStatus("Server unavailable; retrying sessions.", False)

    def _emitSessionAction(self, action, item):
        self.sessionScriptSignal.emit(
            action, item.beaconHash, item.listenerHash, item.hostname, item.username,
            item.arch, item.privilege, item.os, item.lastProofOfLife, item.killed,
        )

    @staticmethod
    def _eventFields(item):
        return (
            item.hostname, item.username, item.arch, item.privilege, item.os,
            item.killed, item.internalIps, item.processId, item.additionalInformation,
            getattr(item, "state", None),
        )


    def listSessions(self):
        try:
            fetch = getattr(self.grpcClient, "listSessionHistory", self.grpcClient.listSessions)
            sessions = list(fetch())
        except Exception as exc:
            self._onRefreshFailure(str(exc))
            return
        self._applySessions(sessions)

    def _applySessions(self, sessions):
        auth_generation = getattr(self.grpcClient, "auth_generation", None)
        reauthenticated = (
            self._snapshot_auth_generation is not None
            and auth_generation != self._snapshot_auth_generation
        )
        baseline = not self._has_snapshot or self._refresh_failed or reauthenticated
        self._snapshot_auth_generation = auth_generation
        if self._refresh_failed:
            self.setInlineStatus("Sessions reconnected." if sessions else "Connected; waiting for beacon check-in.")
            self._refresh_failed = False

        selected = self.selectedSession()
        selected_key = (selected.beaconHash, selected.listenerHash) if selected else None
        previous = {(item.beaconHash, item.listenerHash): item for item in self.listSessionObject}
        if not sessions and any(item.available for item in previous.values()):
            self.setInlineStatus("No active sessions on TeamServer; waiting for beacon check-in.")
        current_keys = {(session.beacon_hash, session.listener_hash) for session in sessions}
        history_changed = False
        pending_actions = []
        for key, item in previous.items():
            if key not in current_keys and item.available:
                pending_actions.append(("retire", item))
                item.available = False
                item.archivedAtMs = int(datetime.now().timestamp() * 1000)
                last_seen = parse_last_seen(item.lastProofOfLife)
                if last_seen:
                    item.lastProofOfLife = last_seen.isoformat()
                history_changed = True

        current = []
        for session in sessions:
            key = (session.beacon_hash, session.listener_hash)
            archived = bool(getattr(session, "archived", False))
            last_seen_at_ms = getattr(session, "last_seen_at_ms", 0)
            proof_of_life = (
                datetime.fromtimestamp(last_seen_at_ms / 1000).isoformat()
                if archived and last_seen_at_ms > 0 else session.last_proof_of_life
            )
            item = previous.get(key)
            existing_item = item is not None
            previous_fields = self._eventFields(item) if item is not None else None
            was_available = item.available if item is not None else False
            previous_archived_at = item.archivedAtMs if item is not None else 0
            if item is None:
                item = Session(
                    self.idSession, session.listener_hash, session.beacon_hash,
                    session.hostname, session.username, session.arch, session.privilege,
                    session.os, proof_of_life, session.killed,
                    session.internal_ips, session.process_id, session.additional_information,
                    getattr(session, "state", None), available=not archived,
                    archivedAtMs=getattr(session, "archived_at_ms", 0) if archived else 0,
                )
                self.idSession += 1
                history_changed = True
            else:
                item.hostname = session.hostname
                item.username = session.username
                item.arch = session.arch
                item.privilege = session.privilege
                item.os = session.os
                item.lastProofOfLife = proof_of_life
                item.killed = session.killed
                item.internalIps = session.internal_ips
                item.processId = session.process_id
                item.additionalInformation = session.additional_information
                item.state = getattr(session, "state", None)
                item.available = not archived
                item.archivedAtMs = getattr(session, "archived_at_ms", 0) if archived else 0
                if (item.available != was_available or previous_archived_at != item.archivedAtMs
                        or previous_fields != self._eventFields(item)):
                    history_changed = True
            current.append(item)
            if archived:
                action = "retire" if was_available else None
            elif baseline or (existing_item and not was_available) or (previous_fields is None and session.beacon_hash in self._seen_beacons):
                action = "sync"
            elif previous_fields is None:
                action = "start"
            elif item.state == TeamServerApi_pb2.SESSION_STATE_STOPPED and previous_fields[-1] != item.state:
                action = "stop"
                self.setInlineStatus("Stop session: beacon confirmed termination.")
            elif item.state == TeamServerApi_pb2.SESSION_STATE_STOP_FAILED and previous_fields[-1] != item.state:
                action = "update"
                self.setInlineStatus("Stop session: no final confirmation from beacon; verify whether it exited.", False)
            elif previous_fields != self._eventFields(item):
                action = "update"
            else:
                action = None
            if action is not None:
                pending_actions.append((action, item))
            self._seen_beacons.add(session.beacon_hash)

        current.extend(item for key, item in previous.items() if key not in current_keys)
        self.listSessionObject = current
        self._has_snapshot = True
        for action, item in pending_actions:
            self._emitSessionAction(action, item)
        if history_changed:
            self._saveSessionHistory()
        self.listSession.clearSelection()
        self.printSessions()
        if selected_key is not None:
            for row, item in enumerate(current):
                if (item.beaconHash, item.listenerHash) == selected_key and not self.listSession.isRowHidden(row):
                    self.listSession.selectRow(row)
                    break
        self.sessionsRefreshed.emit([session for session in sessions if not getattr(session, "archived", False)])


    # don't clear the list each time but just when it's necessary
    def printSessions(self):
        self.listSession.setRowCount(len(self.listSessionObject))
        self.listSession.setHorizontalHeaderLabels(["Beacon", "Listener", "Host", "User", "Arch", "Priv", "OS", "PID", "Internal IP", "Last Seen", "State"])
        archHeader = self.listSession.horizontalHeaderItem(4)
        if archHeader is not None:
            archHeader.setToolTip("Architecture du process beacon")
        for index, tooltip in {
            0: "Beacon hash",
            1: "Listener hash",
            6: "Operating system family; full description is available in each cell tooltip",
            8: "Internal IP addresses",
            9: "Relative last proof of life",
            10: "Session state computed from killed flag and last proof of life",
        }.items():
            headerItem = self.listSession.horizontalHeaderItem(index)
            if headerItem is not None:
                headerItem.setToolTip(tooltip)
        for ix, sessionStore in enumerate(self.listSessionObject):

            beaconHash = QTableWidgetItem(sessionStore.beaconHash[0:8])
            beaconHash.setData(
                Qt.ItemDataRole.UserRole,
                (sessionStore.beaconHash, sessionStore.listenerHash),
            )
            self.listSession.setItem(ix, 0, beaconHash)

            listenerHash = QTableWidgetItem(sessionStore.listenerHash[0:8])
            self.listSession.setItem(ix, 1, listenerHash)

            hostname = QTableWidgetItem(sessionStore.hostname)
            self.listSession.setItem(ix, 2, hostname)

            username = QTableWidgetItem(sessionStore.username)
            self.listSession.setItem(ix, 3, username)

            arch = QTableWidgetItem(sessionStore.arch)
            self.listSession.setItem(ix, 4, arch)

            privilege = QTableWidgetItem(sessionStore.privilege)
            if _to_text(sessionStore.privilege).lower() in HIGH_PRIVILEGE_VALUES:
                color_table_item(privilege, HIGH_PRIVILEGE_COLOR)
                privilege.setToolTip("High privilege beacon process.")
            self.listSession.setItem(ix, 5, privilege)

            osLabel = normalize_os_label(sessionStore.os)
            os = QTableWidgetItem(osLabel)
            os.setToolTip(_to_text(sessionStore.os) or "Unknown OS")
            self.listSession.setItem(ix, 6, os)

            processId = QTableWidgetItem(sessionStore.processId)
            self.listSession.setItem(ix, 7, processId)
            
            internalIps = QTableWidgetItem(sessionStore.internalIps)
            internalIps.setToolTip(sessionStore.internalIps)
            self.listSession.setItem(ix, 8, internalIps)

            lastSeenLabel, lastSeenTooltip, _ = humanize_last_seen(sessionStore.lastProofOfLife)
            pol = QTableWidgetItem(lastSeenLabel)
            pol.setToolTip(lastSeenTooltip)
            self.listSession.setItem(ix, 9, pol)

            if not sessionStore.available and sessionStore.state not in HIDDEN_STOP_STATES and not _is_truthy(sessionStore.killed):
                state, stateTooltip = SESSION_STATE_UNAVAILABLE, "No longer listed by TeamServer; saved command history is read-only."
            else:
                state, stateTooltip = resolve_session_state(
                    sessionStore.killed,
                    sessionStore.lastProofOfLife,
                    staleAfterMs=self.sessionStaleAfterMs,
                    serverState=getattr(sessionStore, "state", None),
                )
            if not sessionStore.available and sessionStore.archivedAtMs:
                archived_at = datetime.fromtimestamp(sessionStore.archivedAtMs / 1000)
                stateTooltip += f" Archived: {archived_at.isoformat(sep=' ', timespec='seconds')}."
            stateItem = color_table_item(QTableWidgetItem(state), SESSION_STATE_COLORS[state])
            stateItem.setToolTip(stateTooltip)
            stateItem.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.listSession.setItem(ix, 10, stateItem)
        self._applyInactiveRowFilter()


class GetSessionsWorker(RefreshWorker):
    def __init__(self, grpc_client):
        fetch = getattr(grpc_client, "listSessionHistory", grpc_client.listSessions)
        super().__init__(fetch, env_int("C2_SESSION_REFRESH_MS", 2000, minimum=100))
