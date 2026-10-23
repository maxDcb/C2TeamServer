"""Task view embedded in Data AI. Network and LLM calls stay off the Qt thread."""

from __future__ import annotations

import json
from threading import Thread

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QPushButton, QTextBrowser, QVBoxLayout, QWidget,
)

from ...console_style import CONSOLE_COLORS, apply_console_output_style
from ...panel_style import apply_dark_panel_style
from .catalog import SKILLS
from .service import C2SkillService, FINISHED_RUN_STATES


class SkillsPanel(QWidget):
    runChanged = pyqtSignal(object)
    sessionsLoaded = pyqtSignal(object)
    operationFinished = pyqtSignal(object)
    operationError = pyqtSignal(str)

    def __init__(self, parent, grpc_client, command_event_hub=None):
        super().__init__(parent)
        self.setObjectName("C2SkillsPanel")
        apply_dark_panel_style(self)
        self.grpc_client = grpc_client
        self.command_event_hub = command_event_hub
        self.available = all(hasattr(grpc_client, name) for name in (
            "submitJob", "getJobExecution", "listSessions", "listCommands", "listModules",
        ))
        self.active_beacon = ""
        self.active_listener = ""
        self._subscriptions = {}
        self._inflight: set[str] = set()
        self._closed = False
        self.service = C2SkillService(grpc_client, on_change=self.runChanged.emit) if self.available else None

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.skillSelector = QComboBox()
        for skill in SKILLS.values():
            self.skillSelector.addItem(f"{skill.title} v{skill.version}", skill.skill_id)
        controls.addWidget(self.skillSelector)
        controls.addWidget(QLabel("Session"))
        self.sessionSelector = QComboBox()
        self.sessionSelector.addItem("Loading sessions...", None)
        controls.addWidget(self.sessionSelector, 1)
        self.refreshSessionsButton = QPushButton("Refresh")
        controls.addWidget(self.refreshSessionsButton)
        self.startButton = QPushButton("Start")
        controls.addWidget(self.startButton)
        layout.addLayout(controls)

        self.planView = QTextBrowser()
        apply_console_output_style(self.planView)
        self.planView.setMaximumHeight(130)
        layout.addWidget(self.planView)
        layout.addWidget(QLabel("Runs"))
        self.runList = QListWidget()
        self.runList.setStyleSheet(f"""
            QListWidget {{
                background-color: {CONSOLE_COLORS['background']};
                color: {CONSOLE_COLORS['text']};
                border: 1px solid {CONSOLE_COLORS['border']};
                selection-background-color: {CONSOLE_COLORS['selection']};
                selection-color: {CONSOLE_COLORS['text']};
            }}
            QListWidget::item {{ padding: 4px 6px; }}
            QListWidget::item:selected {{ background-color: {CONSOLE_COLORS['selection']}; }}
        """)
        layout.addWidget(self.runList, 1)
        self.details = QTextBrowser()
        apply_console_output_style(self.details)
        layout.addWidget(self.details, 3)
        manual = QHBoxLayout()
        self.reasonInput = QLineEdit()
        self.reasonInput.setPlaceholderText("Reason for manual closure")
        manual.addWidget(self.reasonInput, 1)
        self.noResultButton = QPushButton("No result")
        self.failButton = QPushButton("Mark failed")
        manual.addWidget(self.noResultButton)
        manual.addWidget(self.failButton)
        layout.addLayout(manual)

        self.skillSelector.currentIndexChanged.connect(self._show_plan)
        self.sessionSelector.currentIndexChanged.connect(self._session_selected)
        self.refreshSessionsButton.clicked.connect(self._refresh_sessions)
        self.startButton.clicked.connect(self._start)
        self.runList.currentRowChanged.connect(self._show_selected)
        self.noResultButton.clicked.connect(self._confirm_no_result)
        self.failButton.clicked.connect(self._fail)
        self.runChanged.connect(self._on_run_changed)
        self.sessionsLoaded.connect(self._show_sessions)
        self.operationFinished.connect(self._on_finished)
        self.operationError.connect(self._on_error)
        self._show_plan()
        self._refresh()
        self._update_start_button()
        self.refreshSessionsButton.setEnabled(self.available)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        self.timer.start(10000)
        if self.available:
            self._poll()

    def set_active_session(self, beacon_hash: str, listener_hash: str) -> None:
        self.active_beacon = beacon_hash
        self.active_listener = listener_hash
        target = (beacon_hash, listener_hash)
        index = next(
            (i for i in range(self.sessionSelector.count()) if self.sessionSelector.itemData(i) == target),
            -1,
        )
        if index < 0 and all(target):
            self.sessionSelector.addItem(f"{beacon_hash[:8]} · selected", target)
            index = self.sessionSelector.count() - 1
        self.sessionSelector.setCurrentIndex(index if index >= 0 else 0)
        self._update_start_button()

    def _session_selected(self) -> None:
        selected = self.sessionSelector.currentData()
        self.active_beacon, self.active_listener = selected if selected else ("", "")
        self._update_start_button()

    def _update_start_button(self) -> None:
        self.startButton.setEnabled(self.available and bool(self.active_beacon and self.active_listener))

    def _refresh_sessions(self) -> None:
        self._run_async(self._load_sessions, key="sessions")

    def _load_sessions(self) -> None:
        sessions = []
        for session in self.grpc_client.listSessions():
            if getattr(session, "killed", False):
                continue
            beacon = str(session.beacon_hash)
            listener = str(session.listener_hash)
            host = str(getattr(session, "hostname", "") or "").strip()
            user = str(getattr(session, "username", "") or "").strip()
            context = " · ".join(part for part in (host, user) if part)
            label = f"{beacon[:8]} · {context}" if context else beacon[:8]
            sessions.append((label, beacon, listener))
        self.sessionsLoaded.emit(sessions)

    def _show_sessions(self, sessions: list[tuple[str, str, str]]) -> None:
        if self._closed:
            return
        selected = (self.active_beacon, self.active_listener)
        self.sessionSelector.blockSignals(True)
        self.sessionSelector.clear()
        self.sessionSelector.addItem("Select a session" if sessions else "No live sessions", None)
        target_index = 0
        for label, beacon, listener in sessions:
            self.sessionSelector.addItem(label, (beacon, listener))
            index = self.sessionSelector.count() - 1
            self.sessionSelector.setItemData(
                index, f"Beacon: {beacon}\nListener: {listener}", Qt.ItemDataRole.ToolTipRole,
            )
            if (beacon, listener) == selected:
                target_index = index
        if target_index == 0 and len(sessions) == 1:
            target_index = 1
        self.sessionSelector.setCurrentIndex(target_index)
        self.sessionSelector.blockSignals(False)
        self._session_selected()

    def _show_plan(self) -> None:
        skill = SKILLS[self.skillSelector.currentData()]
        lines = [skill.description, "", "Fixed plan:"]
        lines.extend(f"{index}. {step.command_name} — {step.description}" for index, step in enumerate(skill.steps, 1))
        lines.append("Missing modules are loaded first. Uncertain commands are never resent with a new ID.")
        self.planView.setPlainText("\n".join(lines))

    def _run_async(self, action, *args, key: str = "") -> None:
        if self._closed or not self.available or (key and key in self._inflight):
            return
        if key:
            self._inflight.add(key)

        def work():
            try:
                action(*args)
            except Exception as error:
                self.operationError.emit(str(error))
            finally:
                self.operationFinished.emit(key)

        Thread(target=work, daemon=True).start()

    def _start(self) -> None:
        if not self.active_beacon or not self.active_listener:
            self._on_error("Select a session first.")
            return
        self._run_async(
            self.service.start, self.skillSelector.currentData(),
            self.active_beacon, self.active_listener,
            key="start",
        )

    def _selected_id(self) -> str:
        item = self.runList.currentItem()
        return str(item.data(0x0100) or "") if item is not None else ""

    def _confirm_no_result(self) -> None:
        run_id = self._selected_id()
        if run_id:
            self._run_async(self.service.confirm_no_result, run_id, self.reasonInput.text())

    def _fail(self) -> None:
        run_id = self._selected_id()
        if run_id:
            self._run_async(self.service.fail_run, run_id, self.reasonInput.text())

    def _poll(self) -> None:
        if not self.available or self._closed:
            return
        self._refresh_sessions()
        try:
            runs = self.service.list_runs()
        except Exception as error:
            self._on_error(str(error))
            return
        for run in runs:
            if run["status"] not in FINISHED_RUN_STATES:
                self._run_async(self.service.reconcile, run["run_id"], key=f"poll:{run['run_id']}")

    def _watch(self, run: dict) -> None:
        run_id = run["run_id"]
        awaiting_late_result = any(
            step["state"] == "no_result_confirmed"
            and step.get("late_server_state") not in {"succeeded", "failed"}
            for step in run["steps"]
        )
        if run["status"] in FINISHED_RUN_STATES and not awaiting_late_result:
            subscription = self._subscriptions.pop(run_id, None)
            if subscription is not None:
                subscription.close()
            return
        if self.command_event_hub is None or run_id in self._subscriptions:
            return

        def received(event):
            if event.event_id and event.outcome.command_id in job_ids:
                self._run_async(self.service.on_job_event, run_id, event.outcome.command_id, event.event_id)

        job_ids = {step["job_id"] for step in run["steps"]}
        self._subscriptions[run_id] = self.command_event_hub.subscribe(
            run["beacon_hash"], run["listener_hash"], received,
        )

    def _on_run_changed(self, run: dict) -> None:
        if not self._closed:
            self._watch(run)
            self._refresh(run["run_id"])

    def _on_finished(self, key: str) -> None:
        if key:
            self._inflight.discard(key)
        if not self._closed:
            self._refresh()

    def _on_error(self, message: str) -> None:
        self.details.setPlainText(f"Error: {message}")

    def _refresh(self, select_id: str = "") -> None:
        if not self.available:
            self.startButton.setEnabled(False)
            self.details.setPlainText("Job API unavailable.")
            return
        try:
            runs = self.service.list_runs()
        except Exception as error:
            self._on_error(str(error))
            return
        select_id = select_id or self._selected_id()
        self.runList.blockSignals(True)
        self.runList.clear()
        target_row = -1
        for index, run in enumerate(runs):
            self.runList.addItem(f"{run['skill_id']} · {run['beacon_hash'][:8]} · {run['status']} · {run['run_id'][:8]}")
            self.runList.item(index).setData(0x0100, run["run_id"])
            self._watch(run)
            if run["run_id"] == select_id:
                target_row = index
        if target_row < 0 and runs:
            target_row = 0
        self.runList.setCurrentRow(target_row)
        self.runList.blockSignals(False)
        self._show_selected(target_row)

    def _show_selected(self, row: int) -> None:
        if not self.available or row < 0:
            return
        run_id = self._selected_id()
        if not run_id:
            return
        run = self.service.get(run_id)
        lines = [f"Task {run_id}", f"State: {run['status']}", ""]
        for step in run["steps"]:
            lines.append(f"{step['command']} : {step['state']} (job {step['job_id']})")
            if step["error_message"]:
                lines.append(f"  {step['error_message']}")
            if step["manual_reason"]:
                lines.append(f"  Manual closure: {step['manual_reason']}")
            if step.get("late_server_state"):
                lines.append(f"  Late server state: {step['late_server_state']}")
        if run["manual_failure"]:
            lines.append(f"Marked failed: {run['manual_failure']}")
        if run["report"] is not None:
            lines.extend(["", "Report:", json.dumps(run["report"], ensure_ascii=False, indent=2)])
        self.details.setPlainText("\n".join(lines))

    def shutdown(self) -> None:
        self._closed = True
        self.timer.stop()
        for subscription in self._subscriptions.values():
            subscription.close()
        self._subscriptions.clear()
