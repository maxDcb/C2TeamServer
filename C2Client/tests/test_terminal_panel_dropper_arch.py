from types import SimpleNamespace
from threading import Event
import json

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

import C2Client.TerminalPanel as terminal_panel


class FakeGrpc:
    def __init__(self):
        self.requests = []
        self.operations = []

    def hostArtifact(self, request):
        self.operations.append(request)
        return SimpleNamespace(job_id=request.job_id, state="succeeded",
                               output_inline=b"http://127.0.0.1:8080/uploads/hosted.bin",
                               error_message="")

    def reloadModules(self, request):
        self.operations.append(request)
        return SimpleNamespace(job_id=request.job_id, state="succeeded",
                               output_inline=b"Reloaded 2 TeamServer module(s).",
                               error_message="")

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

    def getListenerInfo(self, request):
        self.requests.append(request)
        return SimpleNamespace(status=grpc_client_module.TeamServerApi_pb2.OK,
                               type="http", address="127.0.0.1", port="8080",
                               download_uri="/uploads/", message="")

    def getBeaconBinary(self, request):
        self.requests.append(request)
        return SimpleNamespace(status=grpc_client_module.TeamServerApi_pb2.OK,
                               data=b"beacon", message="")

    def uploadListenerFile(self, request):
        self.requests.append(request)
        return SimpleNamespace(status=grpc_client_module.TeamServerApi_pb2.OK, message="ok")

    def installTool(self, request):
        self.requests.append(request)
        return SimpleNamespace(status=grpc_client_module.TeamServerApi_pb2.OK, message="ok")

    def installToolBundle(self, request):
        self.requests.append(request)
        return SimpleNamespace(status=grpc_client_module.TeamServerApi_pb2.OK,
                               message="Batcave bundle installed (2 tools).")


class FakeKoGrpc:
    def reloadModules(self, request):
        return SimpleNamespace(job_id=request.job_id, state="failed",
                               output_inline=b"raw failure", error_message="Reload failed.")


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
    assert any(getattr(request, "listener_hash", "") == "beacon" and
               getattr(request, "target_arch", "") == "arm64" for request in grpc.requests)
    assert donut_calls[0][0] == "./Beacon-arm64.exe"
    assert donut_calls[0][2] == "arm64"
    assert (tmp_path / "Beacon-arm64.exe").read_bytes() == b"beacon"
    assert results == [("dropper FakeDropper dl beacon --arch arm64", "generated")]


def test_terminal_command_error_message_uses_status_message(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeKoGrpc())
    qtbot.addWidget(parent)

    terminal.runReloadModules("reloadModules", ["reloadModules"])

    assert "Reload failed." in terminal.editorOutput.toPlainText()
    assert "raw failure" not in terminal.editorOutput.toPlainText()


def test_terminal_command_keeps_ui_responsive_and_reports_disconnect(qtbot, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    started = Event()
    release = Event()

    class DisconnectedGrpc(FakeGrpc):
        def reloadModules(self, request):
            started.set()
            release.wait(2)
            raise RuntimeError("server unavailable")

    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, DisconnectedGrpc())
    qtbot.addWidget(parent)
    terminal.commandEditor.setText("reloadModules")
    try:
        terminal.runCommand()
        assert started.wait(1)
        assert terminal._terminalWorker is not None
        terminal.runHelp("help")  # GUI work remains possible while the RPC waits.
        assert "Available terminal commands:" in terminal.editorOutput.toPlainText()
    finally:
        release.set()
    qtbot.waitUntil(lambda: terminal._terminalWorker is None, timeout=3000)
    assert "server unavailable" in terminal.editorOutput.toPlainText()


def test_terminal_initial_completion_does_not_wait_for_server(qtbot):
    started = Event()
    release = Event()

    class SlowCompletionGrpc(FakeGrpc):
        def listListeners(self):
            started.set()
            release.wait(2)
            return iter([])

    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, SlowCompletionGrpc())
    qtbot.addWidget(parent)
    assert not started.is_set()
    try:
        parent.show()
        terminal.show()
        qtbot.waitUntil(started.is_set, timeout=1000)
        terminal.runHelp("help")
        assert "Available terminal commands:" in terminal.editorOutput.toPlainText()
    finally:
        release.set()
    qtbot.waitUntil(lambda: terminal._completionWorker is None, timeout=3000)


def test_terminal_can_close_while_rpc_is_in_flight(qtbot, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    started = Event()
    release = Event()

    class SlowGrpc(FakeGrpc):
        def reloadModules(self, request):
            started.set()
            release.wait(2)
            raise RuntimeError("server unavailable")

    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, SlowGrpc())
    qtbot.addWidget(parent)
    baseline = len(terminal_panel._activeWorkerThreads)
    terminal.commandEditor.setText("reloadModules")
    try:
        terminal.runCommand()
        assert started.wait(1)
        parent.close()
        parent.deleteLater()
    finally:
        release.set()
    qtbot.waitUntil(lambda: len(terminal_panel._activeWorkerThreads) == baseline, timeout=3000)


def test_dropper_worker_always_emits_one_result_on_bad_response_or_exception():
    class MalformedGrpc:
        def getListenerInfo(self, request):
            return SimpleNamespace(status=grpc_client_module.TeamServerApi_pb2.OK,
                                   type="http", address="", port="", download_uri="", message="")

    class FailedGrpc:
        def getListenerInfo(self, request):
            raise RuntimeError("server unavailable")

    for grpc in (MalformedGrpc(), FailedGrpc()):
        worker = terminal_panel.DropperWorker(
            grpc, "dropper test", "test", "download", "beacon", "",
            terminal_panel.ShellcodeGeneratorDonut,
        )
        results = []
        worker.finished.connect(lambda command, result: results.append((command, result)))
        worker.run()
        assert len(results) == 1
        assert results[0][0] == "dropper test"
        assert results[0][1].startswith("Error:")


def test_terminal_host_uses_artifact_reference(qtbot):
    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(parent)

    terminal.runHost("host artifact-123 listener-pri", ["host", "artifact-123", "listener-pri"])

    assert [(request.listener_hash, request.artifact_reference) for request in grpc.operations] == [
        ("listener-pri", "artifact-123")]
    output = terminal.editorOutput.toPlainText()
    assert "http://127.0.0.1:8080/uploads/hosted.bin" in output
    assert not any(request.DESCRIPTOR.name == "ListenerFileRequest" for request in grpc.requests)


def test_terminal_host_accepts_selected_artifact_label_token(qtbot):
    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(parent)

    terminal.runHost(
        "host dropper.exe(artifact-123) listener-pri",
        ["host", "dropper.exe(artifact-123)", "listener-pri"],
    )

    assert grpc.operations[0].artifact_reference == "artifact-123"


def test_terminal_command_parser_and_host_preserve_quoted_argument(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(terminal_panel, "HistoryFileName", str(tmp_path / "history"))
    monkeypatch.setattr(terminal_panel, "logsDir", str(tmp_path))
    assert terminal_panel.splitTerminalCommand("host 'artifact with spaces' listener") == [
        "host", "artifact with spaces", "listener",
    ]
    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(parent)
    terminal.commandEditor.setText("host 'artifact with spaces' listener")
    terminal.runCommand()
    qtbot.waitUntil(lambda: terminal._terminalWorker is None, timeout=3000)
    assert grpc.operations[0].artifact_reference == "artifact with spaces"


def test_dropper_worker_preserves_quoted_additional_argument():
    worker = terminal_panel.DropperWorker(
        FakeGrpc(), "dropper module dl beacon 'value with spaces'", "module", "dl", "beacon",
        "'value with spaces' --flag", terminal_panel.ShellcodeGeneratorDonut,
    )
    assert worker.additionalArgs == ["value with spaces", "--flag"]


def test_terminal_history_and_audit_redact_sensitive_values(qtbot, tmp_path, monkeypatch):
    history_path = tmp_path / "history"
    history_path.write_text("help --token old-secret\n")
    monkeypatch.setattr(terminal_panel, "HistoryFileName", str(history_path))
    monkeypatch.setattr(terminal_panel, "logsDir", str(tmp_path))
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(parent)
    assert "old-secret" not in history_path.read_text()
    terminal.commandEditor.setText("help --token super-secret")
    terminal.runCommand()
    history = history_path.read_text()
    audit = (tmp_path / terminal_panel.AuditFileName).read_text()
    assert "super-secret" not in history + audit + terminal.editorOutput.toPlainText()
    assert "[REDACTED]" in history
    assert json.loads(audit.splitlines()[-1])["command"] == history.splitlines()[-1]
    assert "secret-value" not in terminal_panel.redactTerminalResult("token=secret-value Bearer secret-value")
    assert terminal_panel.redactTerminalResult("Rejected super-secret", "help --token super-secret") == "Rejected [REDACTED]"


def test_terminal_tab_refresh_stays_async_when_server_is_slow(qtbot):
    started = Event()
    release = Event()

    class SlowCompletionGrpc(FakeGrpc):
        def listListeners(self):
            started.set()
            release.wait(2)
            return iter([])

    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, SlowCompletionGrpc())
    qtbot.addWidget(parent)
    terminal.commandEditor.setText("host")
    try:
        terminal.commandEditor.nextCompletion()
        qtbot.waitUntil(started.is_set, timeout=1000)
        terminal.runHelp("help")
        assert "Available terminal commands:" in terminal.editorOutput.toPlainText()
    finally:
        release.set()
    qtbot.waitUntil(lambda: terminal._completionWorker is None, timeout=3000)


def test_batcave_bundle_is_sent_as_one_request(qtbot, tmp_path, monkeypatch):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"A\x00B")
    second.write_bytes(b"SECOND")
    monkeypatch.setattr(terminal_panel.batcave, "downloadBatBundle", lambda name: [str(first), str(second)])

    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(parent)
    terminal.runBatcave("batcave bundleInstall demo", ["batcave", "bundleInstall", "demo"])

    assert len(grpc.requests) == 1
    assert [(file.filename, file.data) for file in grpc.requests[0].files] == [
        ("first.bin", b"A\x00B"), ("second.bin", b"SECOND")]
    assert "Batcave bundle installed" in terminal.editorOutput.toPlainText()


def test_batcave_empty_bundle_never_uploads(qtbot, monkeypatch):
    monkeypatch.setattr(terminal_panel.batcave, "downloadBatBundle", lambda name: [])
    parent = QWidget()
    grpc = FakeGrpc()
    terminal = terminal_panel.Terminal(parent, grpc)
    qtbot.addWidget(parent)

    terminal.runBatcave("batcave bundleInstall missing", ["batcave", "bundleInstall", "missing"])

    assert grpc.requests == []
    assert "bundle not found or empty" in terminal.editorOutput.toPlainText()


def test_terminal_shows_welcome_message(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(parent)

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
    qtbot.addWidget(parent)

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
    qtbot.addWidget(parent)

    terminal.commandEditor.setText("help")
    terminal.runCommand()

    output = terminal.editorOutput.toPlainText()
    assert "[user] help" in output
    assert output.endswith("\n\n")
    assert "[+]" not in output


def test_terminal_help_lists_lowercase_commands_with_descriptions(qtbot):
    parent = QWidget()
    terminal = terminal_panel.Terminal(parent, FakeGrpc())
    qtbot.addWidget(parent)

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
    qtbot.addWidget(parent)

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
    qtbot.addWidget(parent)

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
    assert all(entry[0] != "credentialVault" for entry in help_children)

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


def test_terminal_host_completer_displays_artifact_label_but_inserts_safe_token():
    completions = terminal_panel.build_terminal_completer_data(FakeGrpc())
    options = terminal_panel.completion_options(completions, "host", descend_exact=True)
    hash_options = terminal_panel.completion_options(completions, "host artifact-123")

    assert options[0].label == "dropper.exe (artifact-123)"
    assert options[0].insert_text == "dropper.exe(artifact-123)"
    assert options[0].full_text == "host dropper.exe(artifact-123)"
    assert hash_options[0].label == "dropper.exe (artifact-123)"


def test_terminal_completer_does_not_offer_exact_leaf_commands():
    completions = terminal_panel.build_terminal_completer_data(FakeGrpc())

    assert terminal_panel.completion_options(completions, "socks start") == []
    assert terminal_panel.completion_options(completions, "reloadModules") == []


def test_terminal_completer_only_descends_exact_matches_on_explicit_completion():
    completions = [("ls", [("/tmp", [])]), ("cd", [("/tmp", [])])]

    assert terminal_panel.completion_options(completions, "ls") == []
    assert terminal_panel.completion_options(completions, "ls ")[0].full_text == "ls /tmp"
    assert terminal_panel.completion_options(completions, "ls", descend_exact=True)[0].full_text == "ls /tmp"


def test_terminal_command_editor_tab_cycles_without_static_completer_reset(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    editor = terminal_panel.CommandEditor(grpcClient=FakeGrpc())
    qtbot.addWidget(editor)
    editor.show()
    editor.setFocus()

    assert editor._refreshOnFocus is False

    editor.nextCompletion()
    assert editor.dropdown.isVisible()
    assert editor.dropdown.currentRow() == 0

    editor.nextCompletion()
    assert editor.dropdown.currentRow() == 1

    editor.nextCompletion()
    assert editor.dropdown.currentRow() == 2

    editor.previousCompletion()
    assert editor.dropdown.currentRow() == 1

    editor.hideCompletionPopup()
    qtbot.keyClick(editor.lineEdit, Qt.Key.Key_Backtab)
    assert editor.dropdown.isVisible()
    assert editor.dropdown.currentRow() == editor.dropdown.count() - 1


def test_terminal_command_editor_opens_completer_while_typing(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    editor = terminal_panel.CommandEditor(grpcClient=FakeGrpc())
    qtbot.addWidget(editor)
    editor.show()
    editor.setFocus()

    qtbot.keyClicks(editor.lineEdit, "h")
    qtbot.wait(10)

    assert editor.completionPrefix() == "h"
    assert editor.dropdown.isVisible()
    assert editor.dropdown.currentRow() == 0
    assert editor.dropdown.item(0).text() == "help"

    editor.setText("host")
    editor.setCursorPosition(4)
    assert editor.showCompletionPopup(descendExact=True)
    assert editor.completionPrefix() == "host"
    assert editor.dropdown.item(0).text() == "dropper.exe (artifact-123)"
    assert editor.currentCompletion().full_text == "host dropper.exe(artifact-123)"
