from PyQt6.QtCore import Qt
from C2Client.ScriptPanel import Script


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

    output = script_panel.editorOutput.toPlainText()
    assert "[system] Loaded hooks:" in output
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

    assert len(ConsoleContextScript.calls) == 1
    context = ConsoleContextScript.calls[0][1]
    assert ConsoleContextScript.calls[0][0] is grpc_client
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

    script_panel.consoleScriptMethod(
        "send",
        "beacon",
        "listener",
        "context",
        "whoami",
        "",
        "cmd-1",
    )
    row = script_panel.tableItemsByScript["ConsoleContextScript"]
    script_panel.automationTable.setCurrentCell(row, 1)
    script_panel.updateManualHookSelector()

    script_panel.runSelectedHook()

    assert len(ConsoleContextScript.calls) == 2
    assert ConsoleContextScript.calls[1][1]["event"]["command"] == "whoami"
    assert script_panel.scriptStates["ConsoleContextScript"]["activations"] == 2


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

    assert OldManualStartScript.calls == 0
    assert script_panel.scriptStates["OldManualStartScript"]["activations"] == 1
    assert script_panel.scriptStates["OldManualStartScript"]["errors"] == 1
