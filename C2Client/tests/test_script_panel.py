from PyQt6.QtCore import Qt
from C2Client.ScriptPanel import Script


class RaisingScript:
    __name__ = "RaisingScript"

    @staticmethod
    def OnStart(grpc_client):
        raise RuntimeError("boom")


class ConsoleContextScript:
    calls = []

    @staticmethod
    def OnConsoleSend(grpc_client, beacon_hash, listener_hash, context, command, result, command_id):
        ConsoleContextScript.calls.append(
            (grpc_client, beacon_hash, listener_hash, context, command, result, command_id)
        )
        return "console send ok"


class LegacyConsoleScript:
    calls = 0

    @staticmethod
    def OnConsoleSend(grpc_client):
        LegacyConsoleScript.calls += 1
        return "legacy send ok"


class OnStartScript:
    calls = 0

    @staticmethod
    def OnStart(grpc_client):
        OnStartScript.calls += 1
        return "start ok"


class ManualStartScript:
    calls = []

    @staticmethod
    def ManualStart(grpc_client, context):
        ManualStartScript.calls.append((grpc_client, context))
        return "manual ok"


class LegacyManualStartScript:
    calls = 0

    @staticmethod
    def ManualStart(grpc_client):
        LegacyManualStartScript.calls += 1
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

    assert script_panel.automationTable.rowCount() == 2
    assert script_panel.scriptStates["ConsoleContextScript"]["hooks"] == ["OnConsoleSend"]
    assert script_panel.scriptStates["C2Client.Scripts.badScript"]["errors"] == 1


def test_console_hook_receives_context_and_legacy_signature_still_works(qtbot, monkeypatch):
    ConsoleContextScript.calls = []
    LegacyConsoleScript.calls = 0
    grpc_client = object()
    monkeypatch.setattr(
        "C2Client.ScriptPanel.LoadedScripts",
        [ConsoleContextScript, LegacyConsoleScript],
    )
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, grpc_client)
    qtbot.addWidget(script_panel)

    script_panel.consoleScriptMethod(
        "send",
        "beacon",
        "listener",
        "Host host - Username user",
        "whoami",
        "",
        "cmd-1",
    )

    assert ConsoleContextScript.calls == [
        (grpc_client, "beacon", "listener", "Host host - Username user", "whoami", "", "cmd-1")
    ]
    assert LegacyConsoleScript.calls == 1
    assert script_panel.lastHookContexts["OnConsoleSend"]["args"][3] == "whoami"


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
    assert ConsoleContextScript.calls[1][4] == "whoami"
    assert script_panel.scriptStates["ConsoleContextScript"]["activations"] == 2


def test_onstart_trigger_subtlety_is_available_in_hook_tooltip(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [OnStartScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)

    row = script_panel.tableItemsByScript["OnStartScript"]
    assert "connected/reconnected" in script_panel.automationTable.item(row, 2).toolTip()

    script_panel.mainScriptMethod("start", "", "", "")

    assert OnStartScript.calls == 1
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


def test_legacy_manual_start_hook_still_runs_without_context_arg(qtbot, monkeypatch):
    LegacyManualStartScript.calls = 0
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [LegacyManualStartScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    script_panel = Script(None, object())
    qtbot.addWidget(script_panel)
    script_panel.setClientStateProvider(lambda: {"sessions": [{"beacon_hash": "beacon"}], "listeners": []})

    row = script_panel.tableItemsByScript["LegacyManualStartScript"]
    script_panel.automationTable.setCurrentCell(row, 1)
    script_panel.updateManualHookSelector()
    script_panel.runSelectedHook()

    assert LegacyManualStartScript.calls == 1
    assert script_panel.scriptStates["LegacyManualStartScript"]["activations"] == 1
