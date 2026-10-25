from datetime import datetime, timedelta

from PyQt6.QtCore import QObject, QRunnable, Qt, QThread, QThreadPool, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QHeaderView,
    QAbstractItemView,
    QSizePolicy,
)

from .grpcClient import TeamServerApi_pb2
from .env import env_int
from .grpc_status import is_response_ok, operation_ack_text
from .panel_style import apply_dark_panel_style, create_dark_context_menu
from .refresh_worker import RefreshWorker
from .ui_status import apply_status, format_action_status, status_kind_for_ok

SESSION_STATE_ALIVE = "Alive"
SESSION_STATE_STALE = "Stale"
SESSION_STATE_KILLED = "Killed"
SESSION_STATE_STOPPED = "Stopped"
SESSION_STATE_UNKNOWN = "Unknown"
SESSION_STATE_STOPPING = "Stopping"
SESSION_STATE_STOP_FAILED = "Stop failed"
SESSION_STATE_COLORS = {
    SESSION_STATE_ALIVE: "#0a7f2e",
    SESSION_STATE_STALE: "#a05a00",
    SESSION_STATE_KILLED: "#b00020",
    SESSION_STATE_STOPPED: "#6b7280",
    SESSION_STATE_UNKNOWN: "#6b7280",
    SESSION_STATE_STOPPING: "#a05a00",
    SESSION_STATE_STOP_FAILED: "#b00020",
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
        return SESSION_STATE_STOP_FAILED, "Stop was not confirmed in time; retry is available."
    if serverState == TeamServerApi_pb2.SESSION_STATE_STOPPED:
        return SESSION_STATE_STOPPED, "Beacon confirmed stop; this row will expire."
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

    def __init__(self, id, listenerHash, beaconHash, hostname, username, arch, privilege, os, lastProofOfLife, killed, internalIps, processId, additionalInformation, state=None):
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


class SessionStopSignals(QObject):
    finished = pyqtSignal(object, str)


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

    interactWithSession = pyqtSignal(str, str, str, str)
    sessionScriptSignal = pyqtSignal(str, str, str, str, str, str, str, str, str, bool)
    sessionsRefreshed = pyqtSignal(object)

    idSession = 0
    listSessionObject = []
    COLUMN_WIDTHS = [76, 76, 140, 116, 62, 84, 92, 64, 156, 92, 78]
    STRETCH_COLUMN = 8


    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)

        self.grpcClient = grpcClient
        self.idSession = 0
        self.listSessionObject = []
        self._stop_pending = False
        self._pending_stop_key = None
        self._has_snapshot = False
        self._seen_beacons = set()
        self._snapshot_auth_generation = getattr(grpcClient, "auth_generation", None)
        self._stop_signals = SessionStopSignals()
        self._stop_signals.finished.connect(self._onStopFinished)
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

        self.interactButton = self.createToolbarButton("Open", "Open an interactive console for the selected session.")
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
        self.layout.addLayout(self.headerLayout, 0, 0)

        self.statusLabel = QLabel("")
        self.statusLabel.setMinimumHeight(18)
        self.layout.addWidget(self.statusLabel, 1, 0)

        # List of sessions
        self.listSession = QTableWidget()
        self.listSession.setShowGrid(False)
        self.listSession.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.listSession.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.listSession.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.listSession.setRowCount(0)
        self.listSession.setColumnCount(11)

        self.listSession.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.listSession.customContextMenuRequested.connect(self.showContextMenu)
        self.listSession.itemSelectionChanged.connect(self.updateActionButtons)

        self.listSession.verticalHeader().setVisible(False)
        self.configureTableColumns()
        self.layout.addWidget(self.listSession, 2, 0)

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

    def setStatusMessage(self, ack, successFallback, action="Operation"):
        message = operation_ack_text(ack, successFallback)
        self.setInlineStatus(format_action_status(action, message), is_response_ok(ack))

    def setInlineStatus(self, message, ok=True):
        apply_status(self.statusLabel, message, status_kind_for_ok(ok))

    def updateActionButtons(self):
        selected = self.selectedSession()
        hasSelection = selected is not None
        state = getattr(selected, "state", None) if selected else None
        self.interactButton.setEnabled(hasSelection and state not in {
            TeamServerApi_pb2.SESSION_STATE_STOPPING,
            TeamServerApi_pb2.SESSION_STATE_STOP_FAILED,
            TeamServerApi_pb2.SESSION_STATE_STOPPED,
        })
        self.stopButton.setEnabled(hasSelection and not self._stop_pending and state not in {
            TeamServerApi_pb2.SESSION_STATE_STOPPING,
            TeamServerApi_pb2.SESSION_STATE_STOPPED,
        })
        self.copySessionIdButton.setEnabled(hasSelection)

    def selectedSession(self):
        selectedRows = self.listSession.selectionModel().selectedRows() if self.listSession.selectionModel() else []
        if not selectedRows:
            return None

        row = selectedRows[0].row()
        if row < 0 or row >= len(self.listSessionObject):
            return None
        return self.listSessionObject[row]

    def sessionByShortBeaconHash(self, beaconHashPrefix):
        for sessionStore in self.listSessionObject:
            if sessionStore.beaconHash[0:8] == beaconHashPrefix:
                return sessionStore
        return None

    def scriptSnapshot(self):
        snapshots = []
        for sessionStore in self.listSessionObject:
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
        self.interactWithSession.emit(sessionStore.beaconHash, sessionStore.listenerHash, sessionStore.hostname, sessionStore.username)

    def stopSelectedSession(self):
        sessionStore = self.selectedSession()
        if sessionStore is None:
            self.setInlineStatus("Select a session first.", False)
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

        row = index.row()
        if row >= len(self.listSessionObject):
            return
        sessionStore = self.listSessionObject[row]
        self._context_session_key = (sessionStore.beaconHash, sessionStore.listenerHash)

        menu = create_dark_context_menu(self)
        interactAction = menu.addAction('Interact')
        stopAction = menu.addAction('Stop')
        interactAction.setEnabled(sessionStore.state not in {
            TeamServerApi_pb2.SESSION_STATE_STOPPING,
            TeamServerApi_pb2.SESSION_STATE_STOP_FAILED,
            TeamServerApi_pb2.SESSION_STATE_STOPPED,
        })
        stopAction.setEnabled(not self._stop_pending and sessionStore.state not in {
            TeamServerApi_pb2.SESSION_STATE_STOPPING,
            TeamServerApi_pb2.SESSION_STATE_STOPPED,
        })
        menu.triggered.connect(self.actionClicked)
        menu.exec(self.listSession.viewport().mapToGlobal(position))


    # catch Interact and Stop menu click
    def actionClicked(self, action):
        key = getattr(self, "_context_session_key", None)
        for sessionStore in self.listSessionObject:
            if (sessionStore.beaconHash, sessionStore.listenerHash) != key:
                continue
            if action.text() == "Interact":
                self.interactWithSession.emit(sessionStore.beaconHash, sessionStore.listenerHash, sessionStore.hostname, sessionStore.username)
            elif action.text() == "Stop":
                self.stopSession(sessionStore.beaconHash, sessionStore.listenerHash)
            break


    def stopSession(self, beaconHash, listenerHash):
        if self._stop_pending:
            return
        session = TeamServerApi_pb2.SessionSelector(
            beacon_hash=beaconHash, listener_hash=listenerHash)
        self._stop_pending = True
        self._pending_stop_key = (beaconHash, listenerHash)
        self.setInlineStatus("Stopping session; waiting for TeamServer…")
        self.updateActionButtons()
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
            for sessionStore in self.listSessionObject:
                if (sessionStore.beaconHash, sessionStore.listenerHash) == actual_key:
                    sessionStore.state = TeamServerApi_pb2.SESSION_STATE_STOPPING
            self.setStatusMessage(ack, "Session stop command queued.", action="Stop session")
            if actual_key[1] != pending_key[1]:
                self.setInlineStatus(f"Stop session: queued via current route {actual_key[1][:8]}.")
            self.printSessions()
        self.updateActionButtons()
        self.requestRefresh()

    def requestRefresh(self):
        self.getSessionsWorker.request_refresh()

    def _onRefreshFailure(self, _message):
        self._refresh_failed = True
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
            sessions = list(self.grpcClient.listSessions())
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
        if previous and not sessions:
            self.setInlineStatus("No active sessions on TeamServer; waiting for beacon check-in.")
        current_keys = {(session.beacon_hash, session.listener_hash) for session in sessions}
        for key, item in previous.items():
            if key not in current_keys:
                self._emitSessionAction("retire", item)

        current = []
        for session in sessions:
            key = (session.beacon_hash, session.listener_hash)
            item = previous.get(key)
            previous_fields = self._eventFields(item) if item is not None else None
            if item is None:
                item = Session(
                    self.idSession, session.listener_hash, session.beacon_hash,
                    session.hostname, session.username, session.arch, session.privilege,
                    session.os, session.last_proof_of_life, session.killed,
                    session.internal_ips, session.process_id, session.additional_information,
                    getattr(session, "state", None),
                )
                self.idSession += 1
            else:
                item.hostname = session.hostname
                item.username = session.username
                item.arch = session.arch
                item.privilege = session.privilege
                item.os = session.os
                item.lastProofOfLife = session.last_proof_of_life
                item.killed = session.killed
                item.internalIps = session.internal_ips
                item.processId = session.process_id
                item.additionalInformation = session.additional_information
                item.state = getattr(session, "state", None)
            current.append(item)
            if baseline or (previous_fields is None and session.beacon_hash in self._seen_beacons):
                action = "sync"
            elif previous_fields is None:
                action = "start"
            elif item.state == TeamServerApi_pb2.SESSION_STATE_STOPPED and previous_fields[-1] != item.state:
                action = "stop"
            elif previous_fields != self._eventFields(item):
                action = "update"
            else:
                action = None
            if action is not None:
                self._emitSessionAction(action, item)
            self._seen_beacons.add(session.beacon_hash)

        self.listSessionObject = current
        self._has_snapshot = True
        self.listSession.clearSelection()
        self.printSessions()
        if selected_key is not None:
            for row, item in enumerate(current):
                if (item.beaconHash, item.listenerHash) == selected_key:
                    self.listSession.selectRow(row)
                    break
        self.sessionsRefreshed.emit(sessions)


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

            state, stateTooltip = resolve_session_state(
                sessionStore.killed,
                sessionStore.lastProofOfLife,
                staleAfterMs=self.sessionStaleAfterMs,
                serverState=getattr(sessionStore, "state", None),
            )
            stateItem = color_table_item(QTableWidgetItem(state), SESSION_STATE_COLORS[state])
            stateItem.setToolTip(stateTooltip)
            stateItem.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.listSession.setItem(ix, 10, stateItem)
        self.updateActionButtons()


class GetSessionsWorker(RefreshWorker):
    def __init__(self, grpc_client):
        super().__init__(grpc_client.listSessions, env_int("C2_SESSION_REFRESH_MS", 2000, minimum=100))
