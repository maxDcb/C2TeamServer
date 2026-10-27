from __future__ import annotations

from types import SimpleNamespace
from dataclasses import replace

from C2Client.assistant_agent.skills.catalog import SKILLS
from C2Client.assistant_agent.skills.panel import SkillsPanel, format_run_details


def session(beacon: str, listener: str, *, killed: bool = False):
    return SimpleNamespace(
        beacon_hash=beacon, listener_hash=listener,
        hostname=f"host-{beacon}", username="operator", killed=killed,
    )


class FakeGrpc:
    def __init__(self, sessions):
        self.sessions = sessions

    def listSessions(self):
        return list(self.sessions)

    def submitJob(self):
        pass

    def getJobExecution(self):
        pass

    def listCommands(self):
        pass

    def listModules(self):
        pass


class FakeService:
    def __init__(self, grpc_client, on_change):
        self.calls = []
        self.runs = []

    def list_runs(self):
        return self.runs

    def get(self, run_id):
        return next(run for run in self.runs if run["run_id"] == run_id)

    def start(self, skill_id, beacon_hash, listener_hash, additional_context):
        self.calls.append((skill_id, beacon_hash, listener_hash, additional_context))


def make_panel(qtbot, monkeypatch, sessions):
    monkeypatch.setattr("C2Client.assistant_agent.skills.panel.C2SkillService", FakeService)
    grpc_client = FakeGrpc(sessions)
    panel = SkillsPanel(None, grpc_client)
    qtbot.addWidget(panel)
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    return panel, grpc_client


def test_task_auto_selects_only_live_session_and_starts_without_console(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])

    assert panel.sessionSelector.currentData() == ("beacon-1", "listener-1")
    assert panel.startButton.isEnabled()
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("identify-user", "beacon-1", "listener-1", "")]
    panel.shutdown()


def test_agentic_skill_appears_and_uses_selected_session(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])
    skill_index = panel.skillSelector.findData("identify-user")
    assert skill_index >= 0
    panel.skillSelector.setCurrentIndex(skill_index)
    assert "Skill ·" in panel.skillSelector.currentText()
    assert "SKILL.md" in panel.skillHelpButton.toolTip()
    assert "whoami" in panel.skillHelpButton.toolTip()
    panel.contextInput.setPlainText("Focus on account identity.")
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("identify-user", "beacon-1", "listener-1", "Focus on account identity.")]
    panel.shutdown()


def test_recon_skill_appears_with_multiple_capabilities(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])
    skill_index = panel.skillSelector.findData("recon-host")
    assert skill_index >= 0
    panel.skillSelector.setCurrentIndex(skill_index)
    assert "Skill ·" in panel.skillSelector.currentText()
    assert "recon.host" in panel.skillHelpButton.toolTip()
    assert "listC2Listeners" in panel.skillHelpButton.toolTip()
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("recon-host", "beacon-1", "listener-1", "") ]
    panel.shutdown()


def test_recon_network_appears_with_narrow_capabilities(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])
    skill_index = panel.skillSelector.findData("recon-network")
    assert skill_index >= 0
    panel.skillSelector.setCurrentIndex(skill_index)
    help_text = panel.skillHelpButton.toolTip()
    assert "recon.network" in help_text
    assert "netstat" in help_text
    assert "listC2Listeners" in help_text
    assert "screenShot" not in help_text
    panel.shutdown()


def test_teamserver_skill_starts_without_beacon_session(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [])
    panel.skillSelector.setCurrentIndex(panel.skillSelector.findData("teamserver-inspect"))
    assert panel.sessionSelector.currentData() == ("*", "*")
    assert "TeamServer" in panel.sessionSelector.currentText()
    assert panel.startButton.isEnabled()
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("teamserver-inspect", "*", "*", "")]
    panel.shutdown()


def test_task_selects_from_multiple_sessions_and_preserves_choice(qtbot, monkeypatch):
    panel, grpc_client = make_panel(qtbot, monkeypatch, [
        session("beacon-1", "listener-1"),
        session("beacon-2", "listener-2"),
        session("beacon-3", "listener-3", killed=True),
    ])

    assert panel.sessionSelector.count() == 4
    assert not panel.startButton.isEnabled()
    panel.sessionSelector.setCurrentIndex(3)
    assert (panel.active_beacon, panel.active_listener) == ("beacon-2", "listener-2")
    assert panel.startButton.isEnabled()
    grpc_client.sessions = list(reversed(grpc_client.sessions))
    panel.refreshSessionsButton.click()
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    assert panel.sessionSelector.currentData() == ("beacon-2", "listener-2")
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("identify-user", "beacon-2", "listener-2", "")]
    panel.shutdown()


def test_any_session_is_visible_but_unavailable_for_single_session_skills(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [
        session("beacon-1", "listener-1"), session("beacon-2", "listener-2"),
    ])
    assert panel.sessionSelector.itemData(1) == ("*", "*")
    assert not panel.sessionSelector.model().item(1).isEnabled()
    panel.sessionSelector.setCurrentIndex(1)
    assert not panel.startButton.isEnabled()
    panel.shutdown()


def test_any_session_is_available_to_a_multi_session_skill(qtbot, monkeypatch):
    monkeypatch.setitem(SKILLS, "multi-test", replace(
        SKILLS["identify-user"], skill_id="multi-test", title="Multi test", supports_any_session=True,
    ))
    panel, grpc_client = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])
    panel.skillSelector.setCurrentIndex(panel.skillSelector.findData("multi-test"))
    assert panel.sessionSelector.model().item(1).isEnabled()
    panel.sessionSelector.setCurrentIndex(1)
    assert panel.startButton.isEnabled()

    grpc_client.sessions.append(session("beacon-2", "listener-2"))
    panel.refreshSessionsButton.click()
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    assert panel.sessionSelector.currentData() == ("*", "*")
    panel.startButton.click()
    qtbot.waitUntil(lambda: len(panel.service.calls) == 1)
    assert panel.service.calls == [("multi-test", "*", "*", "") ]
    panel.shutdown()


def test_task_clears_stopped_session_and_accepts_console_selection(qtbot, monkeypatch):
    panel, grpc_client = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])

    panel.set_active_session("beacon-1", "listener-1")
    assert panel.sessionSelector.currentData() == ("beacon-1", "listener-1")
    grpc_client.sessions = [session("beacon-1", "listener-1", killed=True)]
    panel.refreshSessionsButton.click()
    qtbot.waitUntil(lambda: "sessions" not in panel._inflight)
    assert panel.sessionSelector.currentData() is None
    assert not panel.startButton.isEnabled()
    panel.shutdown()


def test_report_reads_as_prose_with_optional_execution_details(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])
    run = {
        "run_id": "run-12345678", "status": "completed", "skill_id": "identify-user",
        "beacon_hash": "beacon-1", "manual_failure": "",
        "steps": [{
            "step_id": "load-identity", "command": "loadModule whoami",
            "state": "already_loaded", "job_state": "failed", "job_id": "load-job",
            "purpose": "module_load", "error_message": "Error: Module already loaded",
            "manual_reason": "",
        }, {
            "step_id": "identity", "command": "whoami", "state": "succeeded",
            "job_state": "succeeded", "job_id": "identity-job", "purpose": "command",
            "error_message": "", "manual_reason": "",
        }],
        "report": {
            "outcome": "complete", "summary": "The beacon ran as operator.",
            "observations": [{"job_id": "identity-job", "finding": "The account is operator."}],
            "limitations": [],
            "evidence": [{"step_id": "identity", "output_preview": "operator"}],
        },
    }
    panel.service.runs = [run]
    panel._refresh()

    visible = panel.details.toPlainText()
    assert "The beacon ran as operator." in visible
    assert "The account is operator." in visible
    assert "The account is operator. (source: identity-job)" in visible
    assert "load-job" not in visible
    assert '"evidence"' not in visible

    panel.showEvidence.setChecked(True)
    technical = panel.details.toPlainText()
    assert "load-job" in technical
    assert "Server job state: failed" in technical
    assert "Output:\noperator" in technical
    assert format_run_details(run) == visible
    panel.shutdown()


def test_report_shows_warnings_without_hiding_findings():
    run = {
        "run_id": "run-1", "status": "completed", "steps": [],
        "report": {
            "outcome": "complete", "analysis_status": "available", "summary": "Network observed.",
            "observations": [{"source_id": "job-1; terminal-1", "finding": "Port comparison."}],
            "limitations": [], "validation_warnings": ["Finding 1 has an unusual source_id."],
            "raw_output": '{"summary":"Network observed.","extra":"retained"}',
            "evidence": [],
        },
    }
    visible = format_run_details(run)
    assert "Port comparison. (source: job-1; terminal-1)" in visible
    assert "Report warnings" in visible
    assert "partial" not in visible
    assert "Original model response" in format_run_details(run, show_evidence=True)


def test_run_dropdown_preserves_selection_and_report_scroll(qtbot, monkeypatch):
    panel, _ = make_panel(qtbot, monkeypatch, [session("beacon-1", "listener-1")])
    panel.resize(680, 330)
    panel.show()

    def completed_run(run_id, summary):
        return {
            "run_id": run_id, "status": "completed", "skill_id": "identify-user",
            "beacon_hash": "beacon-1", "listener_hash": "listener-1", "steps": [],
            "report": {"outcome": "complete", "summary": summary,
                       "observations": [], "limitations": [], "evidence": []},
        }

    first = completed_run("run-1", "\n".join(f"Line {index}" for index in range(120)))
    second = completed_run("run-2", "Another report")
    panel.service.runs = [first, second]
    panel._refresh()
    assert panel.runSelector.count() == 2
    assert panel.runSelector.itemText(0).startswith("Skill ·")
    panel.runSelector.setCurrentIndex(1)
    assert "Another report" in panel.details.toPlainText()
    panel._on_run_changed(first)
    assert panel.runSelector.currentData() == "run-2"
    panel.runSelector.setCurrentIndex(0)

    scroll = panel.details.verticalScrollBar()
    qtbot.waitUntil(lambda: scroll.maximum() > 10)
    position = scroll.maximum() // 2
    scroll.setValue(position)
    first["report"]["summary"] += "\nOne more line"
    panel._refresh()
    assert panel.runSelector.currentData() == "run-1"
    assert scroll.value() == position

    scroll.setValue(scroll.maximum())
    first["report"]["summary"] += "\nLatest result"
    panel._refresh()
    assert scroll.value() == scroll.maximum()

    third = completed_run("run-3", "New run")
    panel.service.runs.insert(0, third)
    panel._on_run_changed(third)
    assert panel.runSelector.currentData() == "run-3"
    panel.shutdown()
