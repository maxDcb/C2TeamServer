"""Task view embedded in Data AI. Network and LLM calls stay off the Qt thread."""

from __future__ import annotations

from threading import Thread

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextBrowser, QToolTip, QVBoxLayout, QWidget,
)

from ...console_style import CONSOLE_COLORS, apply_console_output_style
from ...panel_style import apply_dark_panel_style
from .catalog import SKILLS, AgenticSkillDefinition
from .service import C2SkillService, FINISHED_RUN_STATES, WAITING_STATES


ANY_SESSION = ("*", "*")


def skill_help(skill) -> str:
    if isinstance(skill, AgenticSkillDefinition):
        return (
            f"{skill.description}\n\nAgent skill: the assistant follows SKILL.md and may call "
            f"{', '.join(skill.allowed_tools)}. The selected session is fixed by the operator."
        )
    steps = "\n".join(
        f"{index}. {step.command_name} — {step.description}"
        for index, step in enumerate(skill.steps, 1)
    )
    return (
        f"{skill.description}\n\nFixed sequence:\n{steps}\n\n"
        "Missing modules are loaded first. Uncertain commands are never resent with a new ID."
    )


def format_run_details(run: dict, *, show_evidence: bool = False) -> str:
    lines = [f"Task {run['run_id'][:8]} · {run['status']}"]
    report = run.get("report")
    if report:
        if report.get("outcome") == "partial":
            lines.extend(["", "This report is partial."])
        if report.get("verified_identity"):
            lines.extend(["", f"Observed account: {report['verified_identity']}"])
        lines.extend(["", str(report.get("summary", ""))])
        findings = [str(item.get("finding", "")) for item in report.get("observations", [])]
        if findings:
            lines.extend(["", "What I found", ""])
            lines.extend(f"{finding}\n" for finding in findings)
        limitations = [str(item) for item in report.get("limitations", [])]
        if limitations:
            lines.extend(["What remains uncertain", ""])
            lines.extend(f"{limitation}\n" for limitation in limitations)
    elif run.get("manual_failure"):
        lines.extend(["", f"Stopped by the operator: {run['manual_failure']}"])
    else:
        active = next((step for step in run["steps"] if step["state"] not in {
            "succeeded", "already_loaded", "failed", "no_result_confirmed", "skipped",
        }), None)
        if active:
            lines.extend(["", f"Waiting for {active['command']}."])

    if show_evidence:
        lines.extend(["", "Execution details", ""])
        evidence = {
            item["step_id"]: item for item in (report or {}).get("evidence", [])
        }
        findings_by_job = {
            item["job_id"]: item["finding"] for item in (report or {}).get("observations", [])
        }
        for step in run["steps"]:
            state = "already available" if step["state"] == "already_loaded" else step["state"]
            lines.append(f"{step['command']} · {state}")
            lines.append(f"  Job: {step['job_id']}")
            if step.get("job_state") and step["job_state"] != step["state"]:
                lines.append(f"  Server job state: {step['job_state']}")
            if step.get("error_message"):
                lines.append(f"  Server response: {step['error_message']}")
            if step.get("manual_reason"):
                lines.append(f"  Manual closure: {step['manual_reason']}")
            if step.get("late_server_state"):
                lines.append(f"  Late server state: {step['late_server_state']}")
            if step["job_id"] in findings_by_job:
                lines.append(f"  Finding: {findings_by_job[step['job_id']]}")
            proof = evidence.get(step["step_id"], {})
            if proof.get("output_sha256"):
                lines.append(f"  Output: {proof['output_size']} bytes · SHA-256 {proof['output_sha256']}")
            if proof.get("output_preview") and step.get("purpose", "command") == "command":
                lines.append(f"  Output:\n{proof['output_preview']}")
            lines.append("")
    return "\n".join(lines).strip()


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
        self._displayed_run_id = ""
        self.service = C2SkillService(grpc_client, on_change=self.runChanged.emit) if self.available else None

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.skillSelector = QComboBox()
        for skill in SKILLS.values():
            kind = "Agent" if isinstance(skill, AgenticSkillDefinition) else "Fixed"
            self.skillSelector.addItem(f"{kind} · {skill.title} v{skill.version}", skill.skill_id)
            self.skillSelector.setItemData(
                self.skillSelector.count() - 1, skill_help(skill), Qt.ItemDataRole.ToolTipRole,
            )
        controls.addWidget(self.skillSelector, 1)
        self.skillHelpButton = QPushButton("?")
        self.skillHelpButton.setAccessibleName("Task help")
        self.skillHelpButton.setFixedWidth(28)
        controls.addWidget(self.skillHelpButton)
        controls.addWidget(QLabel("Session"))
        self.sessionSelector = QComboBox()
        self.sessionSelector.addItem("Loading sessions...", None)
        controls.addWidget(self.sessionSelector, 1)
        self.refreshSessionsButton = QPushButton("Refresh")
        controls.addWidget(self.refreshSessionsButton)
        self.startButton = QPushButton("Start")
        controls.addWidget(self.startButton)
        layout.addLayout(controls)

        runs = QHBoxLayout()
        runs.addWidget(QLabel("Runs"))
        self.runSelector = QComboBox()
        self.runSelector.addItem("No runs yet", None)
        self.runSelector.setEnabled(False)
        runs.addWidget(self.runSelector, 1)
        layout.addLayout(runs)
        self.showEvidence = QCheckBox("Show execution details")
        self.showEvidence.setStyleSheet(f"QCheckBox {{ color: {CONSOLE_COLORS['text']}; spacing: 6px; }}")
        layout.addWidget(self.showEvidence)
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
        self.skillHelpButton.clicked.connect(self._show_skill_help)
        self.sessionSelector.currentIndexChanged.connect(self._session_selected)
        self.refreshSessionsButton.clicked.connect(self._refresh_sessions)
        self.startButton.clicked.connect(self._start)
        self.runSelector.currentIndexChanged.connect(self._show_selected)
        self.showEvidence.toggled.connect(lambda _checked: self._show_selected(self.runSelector.currentIndex()))
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
        self.active_beacon, self.active_listener = (
            selected if selected and selected != ANY_SESSION else ("", "")
        )
        self._update_start_button()

    def _update_start_button(self) -> None:
        skill = SKILLS[self.skillSelector.currentData()]
        session_selected = bool(self.active_beacon and self.active_listener)
        any_selected = self.sessionSelector.currentData() == ANY_SESSION and skill.supports_any_session
        self.startButton.setEnabled(self.available and (session_selected or any_selected))

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
        selected = self.sessionSelector.currentData()
        if selected != ANY_SESSION:
            selected = (self.active_beacon, self.active_listener)
        skill = SKILLS[self.skillSelector.currentData()]
        self.sessionSelector.blockSignals(True)
        self.sessionSelector.clear()
        self.sessionSelector.addItem("Select a session" if sessions else "No live sessions", None)
        self.sessionSelector.addItem("Any session · multi-session skills", ANY_SESSION)
        any_index = self.sessionSelector.count() - 1
        self.sessionSelector.setItemData(
            any_index, "Available when a multi-session skill supports this scope.",
            Qt.ItemDataRole.ToolTipRole,
        )
        self.sessionSelector.model().item(any_index).setEnabled(skill.supports_any_session)
        target_index = any_index if selected == ANY_SESSION and skill.supports_any_session else 0
        for label, beacon, listener in sessions:
            self.sessionSelector.addItem(label, (beacon, listener))
            index = self.sessionSelector.count() - 1
            self.sessionSelector.setItemData(
                index, f"Beacon: {beacon}\nListener: {listener}", Qt.ItemDataRole.ToolTipRole,
            )
            if (beacon, listener) == selected:
                target_index = index
        if target_index == 0 and len(sessions) == 1:
            target_index = 2
        self.sessionSelector.setCurrentIndex(target_index)
        self.sessionSelector.blockSignals(False)
        self._session_selected()

    def _show_plan(self) -> None:
        skill = SKILLS[self.skillSelector.currentData()]
        help_text = skill_help(skill)
        self.skillHelpButton.setToolTip(help_text)
        self.skillSelector.setToolTip(help_text)
        any_index = self.sessionSelector.findData(ANY_SESSION)
        if any_index >= 0:
            self.sessionSelector.model().item(any_index).setEnabled(skill.supports_any_session)
            if not skill.supports_any_session and self.sessionSelector.currentData() == ANY_SESSION:
                self.sessionSelector.setCurrentIndex(0)
        self._update_start_button()

    def _show_skill_help(self) -> None:
        QToolTip.showText(
            self.skillHelpButton.mapToGlobal(self.skillHelpButton.rect().bottomLeft()),
            self.skillHelpButton.toolTip(), self.skillHelpButton,
        )

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
        skill = SKILLS[self.skillSelector.currentData()]
        any_selected = self.sessionSelector.currentData() == ANY_SESSION and skill.supports_any_session
        if not any_selected and (not self.active_beacon or not self.active_listener):
            self._on_error("Select a session first.")
            return
        self._run_async(
            self.service.start, skill.skill_id,
            "*" if any_selected else self.active_beacon,
            "*" if any_selected else self.active_listener,
            key="start",
        )

    def _selected_id(self) -> str:
        return str(self.runSelector.currentData() or "")

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
            selected_id = self._selected_id()
            if self.runSelector.findData(run["run_id"]) < 0:
                selected_id = run["run_id"]
            self._refresh(selected_id)

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
        self.runSelector.blockSignals(True)
        self.runSelector.clear()
        target_index = -1
        if not runs:
            self.runSelector.addItem("No runs yet", None)
        for index, run in enumerate(runs):
            run_skill = SKILLS.get(run["skill_id"])
            agentic = run.get("mode") == "agentic_identity" or isinstance(run_skill, AgenticSkillDefinition)
            kind = "Agent" if agentic else "Fixed" if run_skill is not None else "Task"
            self.runSelector.addItem(
                f"{kind} · {run['skill_id']} · {run['beacon_hash'][:8]} · "
                f"{run['status']} · {run['run_id'][:8]}",
                run["run_id"],
            )
            self._watch(run)
            if run["run_id"] == select_id:
                target_index = index
        if target_index < 0 and runs:
            target_index = 0
        elif not runs:
            target_index = 0
        self.runSelector.setCurrentIndex(target_index)
        self.runSelector.setEnabled(bool(runs))
        self.runSelector.blockSignals(False)
        self._show_selected(target_index)

    def _show_selected(self, row: int) -> None:
        self.noResultButton.setEnabled(False)
        self.failButton.setEnabled(False)
        if not self.available or row < 0:
            self._displayed_run_id = ""
            self.details.clear()
            return
        run_id = self._selected_id()
        if not run_id:
            self._displayed_run_id = ""
            self.details.clear()
            return
        run = self.service.get(run_id)
        self.noResultButton.setEnabled(
            run["status"] == "running" and any(step["state"] in WAITING_STATES for step in run["steps"])
        )
        self.failButton.setEnabled(run["status"] not in FINISHED_RUN_STATES)
        content = format_run_details(run, show_evidence=self.showEvidence.isChecked())
        if self._displayed_run_id == run_id and self.details.toPlainText() == content:
            return
        scroll = self.details.verticalScrollBar()
        same_run = self._displayed_run_id == run_id
        old_position = scroll.value()
        was_at_bottom = same_run and old_position >= scroll.maximum() - 2
        self.details.setPlainText(content)
        self._displayed_run_id = run_id
        if same_run:
            scroll.setValue(scroll.maximum() if was_at_bottom else min(old_position, scroll.maximum()))

    def shutdown(self) -> None:
        self._closed = True
        self.timer.stop()
        for subscription in self._subscriptions.values():
            subscription.close()
        self._subscriptions.clear()
