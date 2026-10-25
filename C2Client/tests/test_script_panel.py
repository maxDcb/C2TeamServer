from PyQt6.QtCore import Qt
from C2Client.ScriptPanel import Script, HookDefinition
import pytest
import json
import time
from threading import Event
from types import SimpleNamespace


@pytest.fixture(autouse=True)
def isolated_hook_files(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_HOOK_STATE_PATH", str(tmp_path / "hook-state.json"))
    monkeypatch.setenv("C2_HOOK_AUDIT_PATH", str(tmp_path / "hook-audit.jsonl"))


class RaisingScript:
    __name__ = "RaisingScript"

    @staticmethod
    def OnStart(grpc_client, context):
        raise RuntimeError("boom")


class ConsoleContextScript:
    calls = []
    DESCRIPTION = "Console hook test file."
    HOOK_DESCRIPTIONS = {
        "OnConsoleSend": "Receives the unified console send context.",
    }

    @staticmethod
    def OnConsoleSend(grpc_client, context):
        ConsoleContextScript.calls.append((grpc_client, context))
        return "console send ok"


class OnStartScript:
    calls = 0
    contexts = []

    @staticmethod
    def OnStart(grpc_client, context):
        OnStartScript.calls += 1
        OnStartScript.contexts.append(context)
        return "start ok"


class ManualStartScript:
    calls = []

    @staticmethod
    def ManualStart(grpc_client, context):
        ManualStartScript.calls.append((grpc_client, context))
        return "manual ok"


class OldManualStartScript:
    calls = 0

    @staticmethod
    def ManualStart(grpc_client):
        OldManualStartScript.calls += 1
        return "legacy manual ok"


def test_script_hook_error_is_visible_without_stdout(qtbot, monkeypatch, capsys):
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [RaisingScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)

    capsys.readouterr()
    script_panel.mainScriptMethod("start", "", "", "")
    qtbot.waitUntil(lambda: script_panel.scriptStates["RaisingScript"]["errors"] == 1)
    captured = capsys.readouterr()

    output = script_panel.editorOutput.toPlainText()
    assert captured.out == ""
    assert "Script error:" in output
    assert "RaisingScript.OnStart: boom" in output
    assert script_panel.scriptStates["RaisingScript"]["activations"] == 1
    assert script_panel.scriptStates["RaisingScript"]["errors"] == 1


def test_script_panel_lists_hooks_and_import_errors(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [ConsoleContextScript])
    monkeypatch.setattr(
        "C2Client.ScriptPanel.FailedScripts",
        ["C2Client.Scripts.badScript: import boom"],
    )

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)

    assert "#0b1117" in script_panel.styleSheet()
    assert "#263241" in script_panel.styleSheet()
    assert script_panel.automationTable.rowCount() == 2
    assert script_panel.scriptStates["ConsoleContextScript"]["hooks"] == ["OnConsoleSend"]
    assert script_panel.scriptStates["C2Client.Scripts.badScript"]["errors"] == 1
    row = script_panel.tableItemsByScript["ConsoleContextScript"]
    assert "Console hook test file." in script_panel.automationTable.item(row, 1).toolTip()
    assert "Receives the unified console send context." in script_panel.automationTable.item(row, 2).toolTip()


def test_script_console_uses_role_badges_without_default_marker(qtbot, monkeypatch):
    OnStartScript.calls = 0
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [OnStartScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)
    script_panel.mainScriptMethod("start", "", "", "")
    qtbot.waitUntil(lambda: "[script] OnStart" in script_panel.editorOutput.toPlainText())

    output = script_panel.editorOutput.toPlainText()
    assert "[system] Available hooks:" in output
    assert "[script] OnStart" in output
    assert "[+]" not in output
    assert output.endswith("\n\n")


def test_console_hook_receives_unified_context(qtbot, monkeypatch):
    ConsoleContextScript.calls = []
    grpc_client = object()
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [ConsoleContextScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, grpc_client)
    qtbot.addWidget(script_panel)
    script_panel.setClientStateProvider(
        lambda: {
            "sessions": [
                {
                    "beacon_hash": "beacon",
                    "listener_hash": "listener",
                    "hostname": "host",
                }
            ],
            "listeners": [
                {
                    "listener_hash": "listener",
                    "type": "https",
                    "host": "0.0.0.0",
                    "port": 8443,
                }
            ],
        }
    )

    script_panel.consoleScriptMethod(
        "send",
        "beacon",
        "listener",
        "Host host - Username user",
        "whoami",
        "",
        "cmd-1",
    )
    qtbot.waitUntil(lambda: len(ConsoleContextScript.calls) == 1)

    assert len(ConsoleContextScript.calls) == 1
    context = ConsoleContextScript.calls[0][1]
    assert ConsoleContextScript.calls[0][0]._client is grpc_client
    assert context["hook"] == "OnConsoleSend"
    assert context["trigger"] == "send"
    assert context["object_type"] == "session"
    assert context["object_id"] == "beacon"
    assert context["object"]["hostname"] == "host"
    assert context["event"]["command"] == "whoami"
    assert context["event"]["command_id"] == "cmd-1"
    assert script_panel.lastHookContexts["OnConsoleSend"]["event"]["command"] == "whoami"


def test_disabled_script_does_not_run_automatically(qtbot, monkeypatch):
    ConsoleContextScript.calls = []
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [ConsoleContextScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)

    row = script_panel.tableItemsByScript["ConsoleContextScript"]
    script_panel.automationTable.item(row, 0).setCheckState(Qt.CheckState.Unchecked)

    script_panel.consoleScriptMethod(
        "send",
        "beacon",
        "listener",
        "context",
        "whoami",
        "",
        "cmd-1",
    )

    assert ConsoleContextScript.calls == []
    assert script_panel.scriptStates["ConsoleContextScript"]["enabled"] is False
    assert script_panel.scriptStates["ConsoleContextScript"]["activations"] == 0


def test_manual_run_replays_last_hook_context(qtbot, monkeypatch):
    ConsoleContextScript.calls = []
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [ConsoleContextScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)
    script_panel.setClientStateProvider(lambda: {"sessions": [{
        "beacon_hash": "beacon", "listener_hash": "listener",
    }], "listeners": []})

    script_panel.consoleScriptMethod(
        "send",
        "beacon",
        "listener",
        "context",
        "whoami",
        "",
        "cmd-1",
    )
    qtbot.waitUntil(lambda: len(ConsoleContextScript.calls) == 1)
    row = script_panel.tableItemsByScript["ConsoleContextScript"]
    script_panel.automationTable.setCurrentCell(row, 1)
    script_panel.updateManualHookSelector()

    script_panel.runSelectedHook()
    qtbot.waitUntil(lambda: len(ConsoleContextScript.calls) == 2)

    assert len(ConsoleContextScript.calls) == 2
    assert ConsoleContextScript.calls[1][1]["event"]["command"] == "whoami"
    assert script_panel.scriptStates["ConsoleContextScript"]["activations"] == 2


def test_manual_replay_rejects_retired_route(qtbot, monkeypatch):
    ConsoleContextScript.calls = []
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [ConsoleContextScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])
    routes = [{"beacon_hash": "beacon", "listener_hash": "listener"}]
    panel = Script(None, object())
    qtbot.addWidget(panel)
    panel.setClientStateProvider(lambda: {"sessions": routes, "listeners": []})
    panel.consoleScriptMethod("send", "beacon", "listener", "", "whoami", "", "cmd-1")
    qtbot.waitUntil(lambda: len(ConsoleContextScript.calls) == 1)
    routes.clear()
    panel.automationTable.setCurrentCell(panel.tableItemsByScript["ConsoleContextScript"], 1)
    panel.runSelectedHook()
    assert len(ConsoleContextScript.calls) == 1
    assert "no longer available" in panel.editorOutput.toPlainText()


def test_onstart_trigger_subtlety_is_available_in_hook_tooltip(qtbot, monkeypatch):
    OnStartScript.calls = 0
    OnStartScript.contexts = []
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [OnStartScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)

    row = script_panel.tableItemsByScript["OnStartScript"]
    assert "connected/reconnected" in script_panel.automationTable.item(row, 2).toolTip()

    script_panel.mainScriptMethod("start", "", "", "")
    qtbot.waitUntil(lambda: OnStartScript.calls == 1)

    assert OnStartScript.calls == 1
    assert OnStartScript.contexts[0]["hook"] == "OnStart"
    assert OnStartScript.contexts[0]["trigger"] == "start"
    assert "Trigger:" not in script_panel.editorOutput.toPlainText()


def test_manual_start_hook_runs_without_captured_context(qtbot, monkeypatch):
    ManualStartScript.calls = []
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [ManualStartScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)
    script_panel.setClientStateProvider(
        lambda: {
            "sessions": [
                {
                    "beacon_hash": "beacon",
                    "listener_hash": "listener",
                    "hostname": "host1",
                }
            ],
            "listeners": [
                {
                    "listener_hash": "listener",
                    "type": "https",
                    "host": "0.0.0.0",
                    "port": 8443,
                }
            ],
        }
    )

    row = script_panel.tableItemsByScript["ManualStartScript"]
    script_panel.automationTable.setCurrentCell(row, 1)
    script_panel.updateManualHookSelector()

    assert script_panel.manualHookSelector.currentData() == "ManualStart"

    script_panel.runSelectedHook()
    qtbot.waitUntil(lambda: len(ManualStartScript.calls) == 1)
    qtbot.waitUntil(lambda: "manual ok" in script_panel.editorOutput.toPlainText())

    assert len(ManualStartScript.calls) == 1
    assert ManualStartScript.calls[0][1]["sessions"][0]["beacon_hash"] == "beacon"
    assert ManualStartScript.calls[0][1]["listeners"][0]["port"] == 8443
    assert script_panel.scriptStates["ManualStartScript"]["activations"] == 1
    assert "manual ok" in script_panel.editorOutput.toPlainText()


def test_old_hook_signature_is_not_supported(qtbot, monkeypatch):
    OldManualStartScript.calls = 0
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [OldManualStartScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)
    script_panel.setClientStateProvider(lambda: {"sessions": [{"beacon_hash": "beacon"}], "listeners": []})

    row = script_panel.tableItemsByScript["OldManualStartScript"]
    script_panel.automationTable.setCurrentCell(row, 1)
    script_panel.updateManualHookSelector()
    script_panel.runSelectedHook()
    qtbot.waitUntil(lambda: script_panel.scriptStates["OldManualStartScript"]["errors"] == 1)

    assert OldManualStartScript.calls == 0
    assert script_panel.scriptStates["OldManualStartScript"]["activations"] == 1
    assert script_panel.scriptStates["OldManualStartScript"]["errors"] == 1


def test_slow_hook_does_not_block_gui(qtbot, monkeypatch):
    started, release = Event(), Event()

    class SlowScript:
        @staticmethod
        def OnStart(_client, _context):
            started.set()
            release.wait(2)
            return "finished"

    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [SlowScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])
    panel = Script(None, object())
    qtbot.addWidget(panel)
    try:
        start = time.monotonic()
        panel.mainScriptMethod("start", "", "", "")
        assert time.monotonic() - start < 0.2
        qtbot.waitUntil(started.is_set)
        panel.printInTerminal("UI responsive:", "yes")
        assert "UI responsive:" in panel.editorOutput.toPlainText()
    finally:
        release.set()
    qtbot.waitUntil(lambda: "finished" in panel.editorOutput.toPlainText())


def test_timed_out_hook_reports_unknown_once(qtbot, monkeypatch):
    from C2Client import hook_runtime
    monkeypatch.setattr(hook_runtime, "HOOK_TIMEOUT_SECONDS", 0.05)
    started, release = Event(), Event()

    class TimedScript:
        @staticmethod
        def OnStart(_client, _context):
            started.set()
            release.wait(1)
            return "late result"

    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [TimedScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])
    panel = Script(None, object())
    qtbot.addWidget(panel)
    try:
        panel.mainScriptMethod("start", "", "", "")
        qtbot.waitUntil(started.is_set)
        qtbot.waitUntil(lambda: panel.scriptStates["TimedScript"]["errors"] == 1)
    finally:
        release.set()
    qtbot.wait(50)
    assert panel.scriptStates["TimedScript"]["errors"] == 1
    assert "late result" not in panel.editorOutput.toPlainText()
    records = [json.loads(line) for line in panel.hookAudit.path.read_text().splitlines()]
    assert [record["status"] for record in records if record["event"] == "finished"] == ["timeout_unknown"]


def test_hook_activation_persists_and_package_scripts_start_disabled(qtbot, monkeypatch):
    class PackageScript:
        @staticmethod
        def OnStart(_client, _context):
            return "enabled"

    name = "C2Client.Scripts.PackageScript"
    imports = []
    def import_script(module_name):
        imports.append(module_name)
        return PackageScript
    monkeypatch.setattr("C2Client.ScriptPanel.importlib.import_module", import_script)
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [
        HookDefinition(name, ["OnStart"], "test", {}),
    ])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])
    first = Script(None, object())
    qtbot.addWidget(first)
    assert first.scriptStates[name]["enabled"] is False
    assert imports == []
    row = first.tableItemsByScript[name]
    first.automationTable.item(row, 0).setCheckState(Qt.CheckState.Checked)
    assert imports == []
    second = Script(None, object())
    qtbot.addWidget(second)
    assert second.scriptStates[name]["enabled"] is True
    assert imports == []
    first.mainScriptMethod("start", "", "", "")
    qtbot.waitUntil(lambda: imports == [name])


def test_hook_context_selects_route_and_audit_records_rpc(qtbot, monkeypatch):
    class AuditedScript:
        @staticmethod
        def OnSessionStart(client, context):
            client.addListener(SimpleNamespace(type="https"))
            return context["object"]["listener_hash"]

    class FakeClient:
        username = "operator-one"

        def addListener(self, _listener):
            return SimpleNamespace(status=0)

    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [AuditedScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])
    panel = Script(None, FakeClient())
    qtbot.addWidget(panel)
    panel.setClientStateProvider(lambda: {"sessions": [
        {"beacon_hash": "beacon", "listener_hash": "old"},
        {"beacon_hash": "beacon", "listener_hash": "new"},
    ], "listeners": []})
    panel.sessionScriptMethod("start", "beacon", "new", "host", "user", "x64", "user", "Linux", "0", False)
    qtbot.waitUntil(lambda: "[script] OnSessionStart" in panel.editorOutput.toPlainText())
    assert panel.lastHookContexts["OnSessionStart"]["object"]["listener_hash"] == "new"
    records = [json.loads(line) for line in panel.hookAudit.path.read_text().splitlines()]
    assert any(record.get("method") == "addListener" and record["operator"] == "operator-one"
               for record in records)
