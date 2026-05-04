from PyQt6.QtWidgets import QWidget

from C2Client.ScriptPanel import Script


class RaisingScript:
    __name__ = "RaisingScript"

    @staticmethod
    def OnStart(grpc_client):
        raise RuntimeError("boom")


def test_script_hook_error_is_visible_without_stdout(qtbot, monkeypatch, capsys):
    monkeypatch.setattr("C2Client.ScriptPanel.LoadedScripts", [RaisingScript])
    monkeypatch.setattr("C2Client.ScriptPanel.FailedScripts", [])

    parent = QWidget()
    script_panel = Script(parent, object())
    qtbot.addWidget(script_panel)

    capsys.readouterr()
    script_panel.mainScriptMethod("start", "", "", "")
    captured = capsys.readouterr()

    output = script_panel.editorOutput.toPlainText()
    assert captured.out == ""
    assert "Script error:" in output
    assert "RaisingScript.OnStart: boom" in output
