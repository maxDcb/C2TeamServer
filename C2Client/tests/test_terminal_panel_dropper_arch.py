from types import SimpleNamespace

from PyQt6.QtWidgets import QWidget

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

import C2Client.TerminalPanel as terminal_panel


class FakeGrpc:
    def __init__(self):
        self.commands = []

    def listArtifacts(self, query=None):
        return iter([
            SimpleNamespace(
                artifact_id="artifact-1234567890",
                name="hosted/dropper.exe",
                display_name="dropper.exe",
                category="upload",
            ),
            SimpleNamespace(
                artifact_id="hosted-1234567890",
                name="hosted/dropper.exe",
                display_name="dropper.exe",
                category="hosted",
            ),
        ])

    def listListeners(self):
        return iter([
            SimpleNamespace(listener_hash="listener-primary"),
        ])

    def listSessions(self):
        return iter([
            SimpleNamespace(beacon_hash="beacon-active"),
        ])

    def executeTerminalCommand(self, command):
        self.commands.append(command.command)
        if command.command.startswith(terminal_panel.GrpcInfoListenerInstruction):
            return SimpleNamespace(result="http\n127.0.0.1\n8080\n/uploads/\n", data=b"")
        if command.command.startswith(terminal_panel.GrpcGetBeaconBinaryInstruction):
            return SimpleNamespace(result="ok", data=b"beacon")
        if command.command.startswith(terminal_panel.GrpcHostArtifactInstruction):
            return SimpleNamespace(result="hosted.bin", data=b"")
        if command.command.startswith(terminal_panel.GrpcPutIntoUploadDirInstruction):
            return SimpleNamespace(result="ok", data=b"")
        return SimpleNamespace(result="Error: unexpected command", data=b"")


class FakeKoGrpc:
    def executeTerminalCommand(self, command):
        return SimpleNamespace(
            status=terminal_panel.TeamServerApi_pb2.KO,
            result="raw failure",
            message="Reload failed.",
            data=b"",
        )


class FakeDropperModule:
    @staticmethod
    def getTargetOsExploration():
        return "windows"

    @staticmethod
    def generatePayloadsExploration(binary, binaryArgs, rawShellCode, url, aditionalArgs):
        return [], [], "generated"


FakeDropperModule.__name__ = "FakeDropper"


def _completion_children(entries, text):
    return next(entry[1] for entry in entries if entry[0] == text)


def test_extract_dropper_target_arch_accepts_aliases_and_removes_flag():
    target_arch, remaining = terminal_panel.extractDropperTargetArch(
        ["--arch", "aarch64", "--other", "value"],
        "amd64",
    )

    assert target_arch == "arm64"
    assert remaining == ["--other", "value"]


def test_dropper_arch_help_and_file_names_are_arch_specific():
    assert "dropper config beaconArch x86|x64|arm64" in terminal_panel.DropperArchitectureHelp
    assert terminal_panel.makeBeaconFilePath("windows", "arm64") == "./Beacon-arm64.exe"
    assert terminal_panel.makeBeaconFilePath("linux", "x64") == "./Beacon-linux"


def test_dropper_worker_requests_selected_windows_arch(tmp_path, monkeypatch, qtbot, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(terminal_panel, "DropperModules", [FakeDropperModule])
    donut_calls = []

    def fake_create_donut_shellcode(beacon_file_path, beacon_arg, target_arch, output_path=terminal_panel.DonutShellcodeFileName):
        donut_calls.append((beacon_file_path, beacon_arg, target_arch, output_path))
        (tmp_path / output_path).write_bytes(b"shellcode")
        return ""

    monkeypatch.setattr(terminal_panel, "createDonutShellcode", fake_create_donut_shellcode)

    grpc = FakeGrpc()
    worker = terminal_panel.DropperWorker(
        grpc,
        "dropper FakeDropper dl beacon --arch arm64",
        "fakedropper",
        "dl",
        "beacon",
        "",
        terminal_panel.ShellcodeGeneratorDonut,
        "arm64",
    )

    results = []
    worker.finished.connect(lambda command, result: results.append((command, result)))
    capsys.readouterr()
    worker.run()
    captured = capsys.readouterr()

    assert captured.out == ""
    assert "getBeaconBinary beacon windows arm64" in grpc.commands
    assert donut_calls[0][0] == "./Beacon-arm64.exe"
    assert donut_calls[0][2] == "arm64"
    assert (tmp_path / "Beacon-arm64.exe").read_bytes() == b"beacon"
    assert results == [("dropper FakeDropper dl beacon --arch arm64", "generated")]


def test_terminal_command_error_message_uses_status_message(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeKoGrpc())
    qtbot.addWidget(terminal)

    terminal.runReloadModules("reloadModules", ["reloadModules"])

    assert "Reload failed." in terminal.editorOutput.toPlainText()
    assert "raw failure" not in terminal.editorOutput.toPlainText()


def test_terminal_host_uses_artifact_reference(qtbot):
    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(terminal)

    terminal.runHost("host artifact-123 listener-pri", ["host", "artifact-123", "listener-pri"])

    assert "infoListener listener-pri" in grpc.commands
    assert "hostArtifact listener-pri artifact-123" in grpc.commands
    output = terminal.editorOutput.toPlainText()
    assert "http://127.0.0.1:8080/uploads/hosted.bin" in output
    assert not any(command.startswith(terminal_panel.GrpcPutIntoUploadDirInstruction) for command in grpc.commands)


def test_terminal_host_accepts_selected_artifact_label_token(qtbot):
    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(terminal)

    terminal.runHost(
        "host dropper.exe(artifact-123) listener-pri",
        ["host", "dropper.exe(artifact-123)", "listener-pri"],
    )

    assert "hostArtifact listener-pri artifact-123" in grpc.commands


def test_terminal_shows_welcome_message(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(terminal)

    output = terminal.editorOutput.toPlainText()
    lines = output.splitlines()
    assert "[system] Terminal" in lines[0]
    assert lines[1].startswith("Local TeamServer terminal.")
    assert lines[2] == ""
    assert "[+]" not in output
    assert "Local TeamServer terminal." in output
    assert "Type help to list available commands" in output


def test_terminal_uses_dark_panel_toolbar(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(terminal)

    assert "#0b1117" in terminal.styleSheet()
    assert terminal.layout.spacing() == 6
    assert terminal.searchInput.placeholderText() == "Search output"
    assert terminal.commandEditor.placeholderText() == "Terminal command"
    assert terminal.clearOutputButton.text() == "Clear"
    assert terminal.exportLogButton.text() == "Export"


def test_terminal_user_commands_use_user_badge(qtbot, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(terminal)

    terminal.commandEditor.setText("help")
    terminal.runCommand()

    output = terminal.editorOutput.toPlainText()
    assert "[user] help" in output
    assert output.endswith("\n\n")
    assert "[+]" not in output


def test_terminal_help_lists_lowercase_commands_with_descriptions(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(terminal)

    terminal.runHelp("help")

    output = terminal.editorOutput.toPlainText()
    assert "Available terminal commands:" in output
    assert "Use help <command> for command-specific details." in output
    assert "host - Host a TeamServer artifact through an HTTP/HTTPS listener." in output
    assert "dropper - Generate and host a beacon dropper." in output
    assert "Host\n" not in output
    assert "Socks\n" not in output


def test_terminal_specific_help_matches_command_spec_style(qtbot, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(terminal)

    terminal.commandEditor.setText("help host")
    terminal.runCommand()

    output = terminal.editorOutput.toPlainText()
    assert "host\nHost a TeamServer artifact" in output
    assert "Usage: host <artifact_id|name> <listener_hash> [hosted_filename]" in output
    assert "Kind: terminal" in output
    assert "Target: teamserver" in output
    assert "Arguments:" in output
    assert "Examples:" in output


def test_terminal_unknown_help_is_explicit(qtbot, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(terminal)

    terminal.commandEditor.setText("help doesNotExist")
    terminal.runCommand()

    assert "No terminal help available for doesNotExist." in terminal.editorOutput.toPlainText()


def test_create_donut_shellcode_reports_subprocess_crash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    class Completed:
        returncode = -11
        stderr = ""
        stdout = ""

    monkeypatch.setattr(terminal_panel.subprocess, "run", lambda *args, **kwargs: Completed())

    error = terminal_panel.createDonutShellcode("./Beacon-arm64.exe", "127.0.0.1 443 https", "arm64")

    assert error == "Donut shellcode generation crashed with signal 11."


def test_terminal_completer_uses_artifacts_listeners_sessions_and_dropper_modules(monkeypatch):
    monkeypatch.setattr(terminal_panel, "DropperModules", [FakeDropperModule])
    monkeypatch.setattr(terminal_panel, "ShellCodeModules", [])

    completions = terminal_panel.build_terminal_completer_data(FakeGrpc())

    help_children = _completion_children(completions, terminal_panel.HelpInstruction)
    assert (terminal_panel.HostInstruction, []) in help_children
    assert (terminal_panel.SocksInstruction, []) in help_children

    host_children = _completion_children(completions, terminal_panel.HostInstruction)
    host_labels = [entry[0] for entry in host_children]
    assert host_labels == ["dropper.exe (artifact-123)"]
    assert "dropper.exe" not in host_labels
    assert "artifact-1234567890" not in host_labels
    assert "artifact-123" not in host_labels
    artifact_children = _completion_children(host_children, "dropper.exe (artifact-123)")
    assert ("listener-primary", []) not in artifact_children
    listener_children = _completion_children(artifact_children, "listener")
    assert ("<hosted_filename>", []) in listener_children

    dropper_children = _completion_children(completions, terminal_panel.DropperInstruction)
    module_children = _completion_children(dropper_children, "FakeDropper")
    assert ("listener-primary", []) not in module_children
    download_listener_children = _completion_children(module_children, "listener")
    beacon_listener_children = _completion_children(download_listener_children, "listener")
    arch_children = _completion_children(beacon_listener_children, "--arch")
    assert ("arm64", []) in arch_children

    config_children = _completion_children(dropper_children, terminal_panel.DropperConfigSubInstruction)
    generator_children = _completion_children(config_children, terminal_panel.DropperConfigShellcodeGeneratorDisplay)
    assert (terminal_panel.ShellcodeGeneratorDonut, []) in generator_children

    socks_children = _completion_children(completions, terminal_panel.SocksInstruction)
    socks_bind_children = _completion_children(socks_children, "bind")
    assert ("beacon-active", []) in socks_bind_children


def test_terminal_host_completer_displays_artifact_label_but_inserts_safe_token(qtbot):
    completions = terminal_panel.build_terminal_completer_data(FakeGrpc())
    completer = terminal_panel.CodeCompleter(completions)
    qtbot.addWidget(completer.popup())

    host_item = next(
        completer.model().item(row)
        for row in range(completer.model().rowCount())
        if completer.model().item(row).text() == terminal_panel.HostInstruction
    )
    artifact_item = host_item.child(0)

    assert artifact_item.text() == "dropper.exe (artifact-123)"
    assert artifact_item.data(terminal_panel.CodeCompleter.MatchRole) == "dropper.exe(artifact-123)"
    assert artifact_item.data(terminal_panel.CodeCompleter.ConcatenationRole) == "host dropper.exe(artifact-123)"


def test_terminal_command_editor_tab_cycles_without_static_completer_reset(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    editor = terminal_panel.CommandEditor(grpcClient=FakeGrpc())
    qtbot.addWidget(editor)

    editor.nextCompletion()
    assert editor.codeCompleter.popup().isVisible()
    assert editor.codeCompleter.currentRow() == 0

    editor.nextCompletion()
    assert editor.codeCompleter.currentRow() == 1

    editor.nextCompletion()
    assert editor.codeCompleter.currentRow() == 2


def test_terminal_command_editor_opens_completer_while_typing(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    editor = terminal_panel.CommandEditor(grpcClient=FakeGrpc())
    qtbot.addWidget(editor)
    editor.show()
    editor.setFocus()

    qtbot.keyClicks(editor, "h")
    qtbot.wait(10)

    assert editor.completionPrefix() == "h"
    assert editor.codeCompleter.popup().isVisible()
    assert editor.codeCompleter.currentRow() == 0

    editor.setText("host")
    editor.setCursorPosition(4)
    assert editor.showCompletionPopup()
    assert editor.completionPrefix() == "host"
    assert editor.codeCompleter.completionPrefix() == "host "
    assert editor.codeCompleter.currentCompletion() == "host dropper.exe(artifact-123)"
