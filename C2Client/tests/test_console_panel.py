import os
from types import SimpleNamespace

from PyQt6.QtWidgets import QWidget

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client.ConsolePanel import CommandEditor, Console, ConsolesTab, build_completer_data, command_specs_to_completer_data
from C2Client.grpcClient import TeamServerApi_pb2


class StubGrpc:
    def __init__(self):
        self.reject_commands = False
        self.responses = []
        self.sent_commands = []
        self.modules = []
        self.list_modules_requests = []

    def getCommandHelp(self, command):
        return SimpleNamespace(status=TeamServerApi_pb2.OK, command=command.command, help="help", message="")

    def sendSessionCommand(self, command):
        self.sent_commands.append(command)
        if self.reject_commands:
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="Session not found.", command_id=command.command_id)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="", command_id=command.command_id)

    def streamSessionCommandResults(self, session):
        return self.responses

    def listCommands(self, query=None):
        return iter([])

    def listSessions(self):
        return iter([])

    def listListeners(self):
        return iter([])

    def listModules(self, session):
        self.list_modules_requests.append(session)
        return iter(self.modules)


class DummyPanel(QWidget):
    def __init__(self, parent=None, *_args, **_kwargs):
        super().__init__(parent)


def test_command_history_and_logging(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    parent = QWidget()
    console = Console(parent, StubGrpc(), 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.commandEditor.setText('help')
    console.runCommand()

    history_file = tmp_path / '.cmdHistory'
    assert history_file.read_text() == 'help\n'

    log_file = tmp_path / 'host_user_beacon.log'
    assert 'send: "help"' in log_file.read_text()


def test_command_ack_error_is_displayed_without_pending_emit(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    grpc.reject_commands = True
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    emitted = []
    console.consoleScriptSignal.connect(lambda *args: emitted.append(args))

    console.commandEditor.setText('whoami')
    console.runCommand()

    assert emitted == []
    output = console.editorOutput.toPlainText()
    assert "Session not found." in output
    assert "[error]" in output
    assert "[<<]" not in output
    command_id = grpc.sent_commands[0].command_id
    assert console.commandStatusById[command_id]["status"] == "error"
    assert 'rejected: "whoami"' in (tmp_path / 'host_user_beacon.log').read_text()


def test_list_module_command_uses_list_modules_without_queueing(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    grpc.modules = [
        SimpleNamespace(name="pwd", state="loaded"),
        SimpleNamespace(name="shell", state="loading", load_count=7, command_id="cmd-1"),
    ]
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)
    grpc.list_modules_requests.clear()

    console.commandEditor.setText('listModule')
    console.runCommand()

    assert grpc.sent_commands == []
    assert len(grpc.list_modules_requests) == 1
    assert grpc.list_modules_requests[0].beacon_hash == "beacon"
    assert grpc.list_modules_requests[0].listener_hash == "listener"
    output = console.editorOutput.toPlainText()
    assert "pwd" in output
    assert "loaded" in output
    assert "shell" in output
    assert "loading" in output
    assert "count" not in output
    assert "cmd-1" not in output


def test_command_result_error_uses_message_for_display(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    grpc.responses = [
        SimpleNamespace(
            status=TeamServerApi_pb2.KO,
            session=SimpleNamespace(listener_hash="listener"),
            command="whoami",
            instruction="",
            command_id="cmd-1",
            output=b"raw failure",
            message="Command failed.",
        )
    ]
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    emitted = []
    console.consoleScriptSignal.connect(lambda *args: emitted.append(args))

    console.displayResponse()

    assert "Command failed." in console.editorOutput.toPlainText()
    assert "raw failure" not in console.editorOutput.toPlainText()
    assert console.commandStatusById["cmd-1"]["status"] == "error"
    assert emitted[0][-2] == "Command failed."


def test_console_tracks_command_status_and_resend(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.commandEditor.setText('whoami')
    console.runCommand()

    first_command_id = grpc.sent_commands[0].command_id
    assert console.lastCommandLine == 'whoami'
    assert console.commandStatusById[first_command_id]["status"] == "queued"
    output = console.editorOutput.toPlainText()
    assert "[queued]" in output
    assert "[>>]" not in output

    console.resendLastCommand()

    assert len(grpc.sent_commands) == 2
    assert grpc.sent_commands[1].command == 'whoami'

    grpc.responses = [
        SimpleNamespace(
            status=TeamServerApi_pb2.OK,
            session=SimpleNamespace(listener_hash="listener"),
            command="whoami",
            instruction="",
            command_id=first_command_id,
            output=b"user",
            message="",
        )
    ]

    console.displayResponse()

    assert console.commandStatusById[first_command_id]["status"] == "done"
    output = console.editorOutput.toPlainText()
    assert "[done]" in output
    assert "[<<]" not in output
    assert output.index("[done]") < output.index("user")


def test_console_search_clear_and_export_controls(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    parent = QWidget()
    console = Console(parent, StubGrpc(), 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.printInTerminal("whoami", "", "")
    console.printInTerminal("", "whoami", "needle output")

    console.searchInput.setText("needle")
    assert console.findNextSearchMatch() is True
    assert console.consoleNoticeLabel.text() in {"Match found.", "Search wrapped."}

    export_path = console.exportConsoleOutput()
    assert os.path.exists(export_path)
    with open(export_path, encoding="utf-8") as exportFile:
        assert "needle output" in exportFile.read()

    console.clearConsoleOutput()
    assert console.editorOutput.toPlainText() == ""


def test_console_replays_structured_log_on_reopen(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('C2Client.ConsolePanel.logsDir', str(tmp_path))
    monkeypatch.setattr('C2Client.ConsolePanel.QThread.start', lambda self: None)

    grpc = StubGrpc()
    parent = QWidget()
    console = Console(parent, grpc, 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(console)

    console.commandEditor.setText('whoami')
    console.runCommand()
    command_id = grpc.sent_commands[0].command_id
    grpc.responses = [
        SimpleNamespace(
            status=TeamServerApi_pb2.OK,
            session=SimpleNamespace(listener_hash="listener"),
            command="whoami",
            instruction="",
            command_id=command_id,
            output=b"user",
            message="",
        )
    ]
    console.displayResponse()

    log_text = (tmp_path / 'host_user_beacon.log').read_text()
    assert '[console]' in log_text

    reopened = Console(parent, StubGrpc(), 'beacon', 'listener', 'host', 'user')
    qtbot.addWidget(reopened)

    output = reopened.editorOutput.toPlainText()
    assert "[queued]" in output
    assert "[done]" in output
    assert "[>>]" not in output
    assert "whoami" in output
    assert "user" in output
    assert reopened.commandStatusById[command_id]["status"] == "done"
    assert command_id in reopened.renderedResponseIds


def test_consoles_tab_uses_dark_flush_pages(qtbot, monkeypatch):
    monkeypatch.setattr('C2Client.ConsolePanel.Terminal', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Script', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Artifacts', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Commands', DummyPanel)
    monkeypatch.setattr('C2Client.ConsolePanel.Assistant', DummyPanel)

    parent = QWidget()
    consoles = ConsolesTab(parent, StubGrpc())
    qtbot.addWidget(consoles)

    assert consoles.objectName() == "C2ConsolesTab"
    assert consoles.tabs.objectName() == "C2ConsoleTabs"
    assert consoles.tabs.tabText(1) == "Hooks"
    assert consoles.tabs.tabText(2) == "Artifacts"
    assert consoles.tabs.tabText(3) == "Commands"
    assert consoles.tabs.tabText(4) == "Data AI"
    assert "#0b1117" in consoles.styleSheet()
    assert "#070b10" in consoles.styleSheet()
    assert consoles.layout.contentsMargins().left() == 0
    assert consoles.layout.spacing() == 0

    protected_count = consoles.tabs.count()
    consoles.closeTab(2)
    assert consoles.tabs.count() == protected_count

    for index in range(consoles.tabs.count()):
        page = consoles.tabs.widget(index)
        assert page.objectName() == "C2ConsolePage"
        assert page.layout().contentsMargins().left() == 0
        assert page.layout().contentsMargins().top() == 0
        assert page.layout().spacing() == 0


def _completion_children(entries, text):
    return next(children for entry_text, children in entries if entry_text == text)


def test_command_specs_seed_console_completer_from_manifest_examples():
    sleep_spec = SimpleNamespace(
        name="sleep",
        kind="common",
        examples=["sleep 0.5"],
        args=[
            SimpleNamespace(name="seconds", type="number", values=[]),
        ],
    )
    custom_spec = SimpleNamespace(
        name="custom",
        kind="module",
        examples=["custom --flag"],
        args=[],
    )

    server_data = command_specs_to_completer_data([sleep_spec, custom_spec])

    assert ("custom", [("--flag", [])]) in server_data
    sleep_entry = _completion_children(server_data, "sleep")
    assert ("0.5", []) in sleep_entry


def test_contextual_completer_uses_artifacts_listeners_and_module_specs():
    class FakeGrpc:
        def listCommands(self, query=None):
            return iter([
                SimpleNamespace(
                    name="help",
                    kind="common",
                    examples=["help loadModule"],
                    args=[],
                ),
                SimpleNamespace(
                    name="listener",
                    kind="common",
                    examples=["listener start tcp 10.2.4.8 4444", "listener stop <listener_hash>"],
                    args=[
                        SimpleNamespace(name="action", values=["start", "stop"]),
                        SimpleNamespace(name="type_or_hash", values=["tcp", "smb"]),
                    ],
                ),
                SimpleNamespace(
                    name="loadModule",
                    kind="common",
                    examples=["loadModule pwd"],
                    args=[
                        SimpleNamespace(
                            name="module",
                            values=[],
                            artifact_filter=SimpleNamespace(
                                category="module",
                                target="beacon",
                                scope="",
                                platform="session.platform",
                                arch="session.arch",
                                runtime="native",
                            ),
                        )
                    ],
                ),
                SimpleNamespace(name="unloadModule", kind="common", examples=[], args=[]),
                SimpleNamespace(name="pwd", kind="module", examples=["pwd"], args=[]),
            ])

        def listSessions(self):
            return iter([
                SimpleNamespace(
                    beacon_hash="beacon-1",
                    listener_hash="listener-1",
                    os="Linux ubuntu",
                    arch="x64",
                )
            ])

        def listListeners(self):
            return iter([SimpleNamespace(listener_hash="listener-hash")])

        def listModules(self, session):
            assert session.beacon_hash == "beacon-1"
            assert session.listener_hash == "listener-1"
            return iter([SimpleNamespace(name="pwd", state="loaded")])

        def listArtifacts(self, query):
            assert query.category == "module"
            assert query.target == "beacon"
            assert query.platform == "linux"
            assert query.arch == "x64"
            assert query.runtime == "native"
            return iter([
                SimpleNamespace(name="libPrintWorkingDirectory.so", display_name="libPrintWorkingDirectory.so"),
                SimpleNamespace(name="libListDirectory.so", display_name="libListDirectory.so"),
            ])

    completions = build_completer_data(FakeGrpc(), beaconHash="beacon-1", listenerHash="listener-1")

    listener_children = _completion_children(completions, "listener")
    listener_stop_children = _completion_children(listener_children, "stop")
    assert ("listener-hash", []) in listener_stop_children

    load_module_children = _completion_children(completions, "loadModule")
    assert ("pwd", []) not in load_module_children
    assert ("printWorkingDirectory", []) not in load_module_children
    assert ("ls", []) in load_module_children

    unload_module_children = _completion_children(completions, "unloadModule")
    assert ("pwd", []) in unload_module_children
    assert ("ls", []) not in unload_module_children

    help_children = _completion_children(completions, "help")
    assert ("loadModule", []) in help_children
    assert ("pwd", []) in help_children


def test_command_editor_up_arrow_history_still_returns_last_command(tmp_path, qtbot, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cmdHistory").write_text("first\nsecond\n")

    editor = CommandEditor(grpcClient=StubGrpc())
    qtbot.addWidget(editor)

    editor.historyUp()

    assert editor.text() == "second"


def test_command_editor_tab_cycles_completion_rows_without_reset(tmp_path, qtbot, monkeypatch):
    class CompletionGrpc(StubGrpc):
        def listCommands(self, query=None):
            return iter([
                SimpleNamespace(name="alpha", kind="module", examples=["alpha"], args=[]),
                SimpleNamespace(name="beta", kind="module", examples=["beta"], args=[]),
            ])

    monkeypatch.chdir(tmp_path)
    editor = CommandEditor(grpcClient=CompletionGrpc())
    qtbot.addWidget(editor)

    assert editor.codeCompleter.setCurrentRow(0) is True
    editor.nextCompletion()
    assert editor.codeCompleter.currentRow() == 1

    editor.nextCompletion()
    assert editor.codeCompleter.currentRow() == 0
