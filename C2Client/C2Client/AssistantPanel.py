import os

from threading import Thread, Lock, Semaphore

from PyQt6.QtCore import Qt, QEvent, pyqtSignal
from PyQt6.QtGui import QShortcut
from PyQt6.QtWidgets import (
    QTextBrowser,
    QVBoxLayout,
    QWidget,
    QTextEdit
)
import markdown

from .assistant_agent import C2AssistantAgent
from .assistant_agent.domain.command_outcome import CommandOutcome
from .command_event_hub import CommandEventHub, CommandResultEvent
from .console_style import (
    apply_console_output_style,
    append_console_block,
    append_console_spacing,
    move_editor_to_end,
)
from .autocomplete import CompletionInput

ASSISTANT_COMPLETIONS = [
    ("/help", []),
    ("/status", []),
    ("/stop", []),
    ("/cancel", []),
    ("/reset", []),
]

ASSISTANT_HEADER_ROLES = {
    "system": ("[system]", "system", False),
    "user": ("[user]", "user", False),
    "analysis": ("[assistant]", "assistant", False),
}


#
# Assistant tab implementation
#
class Assistant(QWidget):
    tabPressed = pyqtSignal()
    responseReady = pyqtSignal(object)
    responseError = pyqtSignal(str)
    workerFinished = pyqtSignal()
    logFileName=""
    sem = Semaphore()

    def __init__(self, parent, grpcClient, *, command_event_hub: CommandEventHub | None = None):
        super().__init__(parent) 
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.agent = C2AssistantAgent(grpcClient)
        self.command_event_hub = command_event_hub
        self._result_subscriptions = {}

        # self.logFileName=LogFileName

        self.editorOutput = QTextBrowser()
        apply_console_output_style(self.editorOutput)
        self.editorOutput.setReadOnly(True)
        # Force word wrapping
        self.editorOutput.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.editorOutput.setLineWrapColumnOrWidth(0)
        self.layout.addWidget(self.editorOutput, 8)

        self.commandEditor = CommandEditor()
        self.commandEditor.setPlaceholderText("Ask assistant or /help")
        self.layout.addWidget(self.commandEditor, 0)
        self.commandEditor.returnPressed.connect(self.runCommand)

        self.responseReady.connect(self._process_assistant_response)
        self.responseError.connect(self._handle_assistant_error)
        self.workerFinished.connect(self._drain_deferred_resume)

        # Track pending tool execution state
        self.awaiting_tool_result = False
        self.pending_tool_context = None
        self.pending_tool_id = None
        self._stopped_command_keys = set()
        self._deferred_resume = None

        self._response_thread = None
        self._response_lock = Lock()

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            self.printInTerminal("System", "OPENAI_API_KEY is not set, functionality deactivated.")
        else:
            self.printInTerminal(
                "System",
                "Assistant ready. Open a session console from the Sessions tab to provide session context and command output to the assistant. Use /help to list local assistant commands.",
            )

    def sessionAssistantMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        self.agent.domain_hooks.record_session_event(
            action=action,
            beacon_hash=beaconHash,
            listener_hash=listenerHash,
            hostname=hostname,
            username=username,
            arch=arch,
            privilege=privilege,
            os_name=os,
            killed=killed,
        )
        return


    def setActiveSession(self, beaconHash, listenerHash):
        self.watchSession(beaconHash, listenerHash)
        self.agent.domain_hooks.record_active_session(
            beacon_hash=beaconHash,
            listener_hash=listenerHash,
        )

    def watchSession(self, beacon_hash, listener_hash):
        if self.command_event_hub is None or not beacon_hash or not listener_hash:
            return
        key = (listener_hash, beacon_hash)
        if key not in self._result_subscriptions:
            self._result_subscriptions[key] = self.command_event_hub.subscribe(
                beacon_hash, listener_hash, self.receiveCommandEvent,
            )

    def closeResultSubscriptions(self):
        for subscription in self._result_subscriptions.values():
            subscription.close()
        self._result_subscriptions.clear()

    def closeEvent(self, event):
        self.closeResultSubscriptions()
        super().closeEvent(event)

    def receiveCommandEvent(self, event: CommandResultEvent):
        outcome = event.outcome
        if not self._matches_pending_command(outcome.command_id, outcome.beacon_hash, outcome.listener_hash):
            self.agent.domain_hooks.record_console_observation(
                beacon_hash=outcome.beacon_hash,
                listener_hash=outcome.listener_hash,
                command=outcome.command_line,
                output=event.display_output,
            )
        self.receiveCommandOutcome(outcome)
                    
    
    def listenerAssistantMethod(self, action, hash, str3, str4):
        return


    def consoleAssistantMethod(self, action, beaconHash, listenerHash, context, cmd, result, commandId=""):
        if action == "send":
            self.agent.domain_hooks.record_active_session(
                beacon_hash=beaconHash,
                listener_hash=listenerHash,
            )
            return

        if action != "receive":
            return

        self.agent.domain_hooks.record_active_session(
            beacon_hash=beaconHash,
            listener_hash=listenerHash,
        )

        command_text = cmd or ""
        if isinstance(command_text, bytes):
            command_text = command_text.decode("latin1", errors="ignore")
        command_text = command_text.strip()

        output_text = result or ""
        if isinstance(output_text, bytes):
            output_text = output_text.decode("latin1", errors="ignore")
        output_text = output_text.replace(chr(0), "")
        if self._matches_pending_command(commandId, beaconHash, listenerHash):
            return

        combined = command_text
        if output_text:
            combined = f"{command_text}\n{output_text}" if command_text else output_text
        if combined.strip():
            self.agent.domain_hooks.record_console_observation(
                beacon_hash=beaconHash,
                listener_hash=listenerHash,
                command=command_text,
                output=output_text,
            )

    def _matches_pending_command(self, command_id, beacon_hash, listener_hash):
        pending = self.pending_tool_context or {}
        return bool(
            self.awaiting_tool_result
            and self.pending_tool_id
            and command_id
            and pending.get("command_id") == command_id
            and pending.get("beacon_hash") == beacon_hash
            and pending.get("listener_hash") == listener_hash
        )

    def receiveCommandOutcome(self, outcome: CommandOutcome):
        key = (outcome.command_id, outcome.beacon_hash, outcome.listener_hash)
        if key in self._stopped_command_keys:
            return
        if not self._matches_pending_command(outcome.command_id, outcome.beacon_hash, outcome.listener_hash):
            return

        pending_id = self.pending_tool_id
        if outcome.ok:
            notice = f"Received result for command `{outcome.command_id}`. Resuming assistant."
        else:
            notice = f"Command `{outcome.command_id}` failed: {outcome.error_message or 'TeamServer reported an error'}. Resuming assistant."
        self.printInTerminal("Analysis:", notice)
        self._clear_pending_tool_state()
        self._deferred_resume = (pending_id, outcome.tool_content(), outcome.ok)
        self._drain_deferred_resume()

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)


    def printInTerminal(self, header="", message="", detail="", rich_message=False):
        self.sem.acquire()
        try:
            has_entry = bool(header or message or detail)
            marker, tone, show_label = self._console_role_for_header(header)
            append_console_block(
                self.editorOutput,
                header,
                message,
                marker=marker,
                tone=tone,
                rich_message=rich_message,
                show_label=show_label,
            )
            if detail:
                append_console_block(
                    self.editorOutput,
                    "",
                    detail,
                    tone=tone,
                    rich_message=rich_message,
                )
            if has_entry:
                append_console_spacing(self.editorOutput)

            self.setCursorEditorAtEnd()
        finally:
            self.sem.release()

    def _console_role_for_header(self, header):
        normalized = str(header or "").strip().rstrip(":").lower()
        if normalized in ASSISTANT_HEADER_ROLES:
            return ASSISTANT_HEADER_ROLES[normalized]
        return "[assistant]", "assistant", True


    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "")
            return

        local_command = commandLine.strip().lower()
        if local_command == "/help":
            self._show_local_help()
            return

        if local_command == "/status":
            self._show_pending_status()
            return

        if local_command in {"/stop", "/cancel", "/reset"}:
            if not self.awaiting_tool_result:
                self.printInTerminal("Analysis:", "No pending assistant wait to stop.")
                return

            try:
                stopped = self.agent.stop_pending_tool_wait(pending_id=self.pending_tool_id)
            except Exception as exc:
                self.printInTerminal("Analysis:", f"Could not stop the assistant wait: {exc}")
                return
            if not stopped:
                self.printInTerminal("Analysis:", "The assistant wait changed; it was not stopped. Check /status.")
                return
            pending = self.pending_tool_context or {}
            command_id = pending.get("command_id")
            if command_id:
                self._stopped_command_keys.add((
                    command_id, pending.get("beacon_hash"), pending.get("listener_hash"),
                ))
            self._clear_pending_tool_state()
            self.printInTerminal(
                "Analysis:",
                "Stopped waiting in this assistant conversation. The remote command was not cancelled or marked failed.",
            )
            return

        if local_command.startswith("/"):
            self.printInTerminal("Analysis:", f"Unknown local assistant command `{commandLine.strip()}`.")
            self._show_local_help()
            return

        if self.awaiting_tool_result or self._deferred_resume is not None:
            self.printInTerminal("Analysis:", "Waiting for previous command output before continuing.")
            return

        with self._response_lock:
            if self._response_thread and self._response_thread.is_alive():
                self.printInTerminal("Analysis:", "Assistant is still processing the previous request.")
                return

        # Reset state for a new round of tool calls triggered by operator input
        self._clear_pending_tool_state()

        self.printInTerminal("User:", commandLine)
        self._start_agent_turn(commandLine)

        self.setCursorEditorAtEnd()


    def _show_local_help(self):
        self.printInTerminal(
            "Assistant commands:",
            "\n".join(
                [
                    "/help - Show AssistantPanel local commands.",
                    "/status - Show the current assistant pending command state.",
                    "/stop - Stop this assistant wait; the remote command continues.",
                    "/cancel and /reset - Aliases for /stop.",
                    "Accepted commands have no automatic assistant wait timeout.",
                ]
            ),
        )


    def _show_pending_status(self):
        self.printInTerminal("Analysis:", self._format_pending_status())


    def _format_pending_status(self, prefix=None):
        if not self.awaiting_tool_result:
            with self._response_lock:
                busy = self._response_thread is not None and self._response_thread.is_alive()
            if busy:
                return "Assistant is processing a request. No beacon command result is pending yet."
            return "No pending beacon command result."

        context = self.pending_tool_context or {}
        command = context.get("command_line") or "unknown command"
        command_id = context.get("command_id") or "unknown"
        beacon_hash = context.get("beacon_hash") or "unknown"
        command_id_short = self._short_id(command_id)
        beacon_hash_short = self._short_id(beacon_hash)
        status = prefix or "Waiting for beacon command result."

        return f"{status} Command `{command}` on beacon `{beacon_hash_short}` (cmd `{command_id_short}`, no automatic timeout)."

    def _short_id(self, value):
        text = str(value or "unknown")
        return text[:8] if len(text) > 8 else text


    def _start_agent_turn(self, user_input):
        with self._response_lock:
            if self._response_thread and self._response_thread.is_alive():
                return
            self._response_thread = Thread(
                target=self._agent_turn_worker,
                args=(user_input,),
                daemon=True,
            )
            self._response_thread.start()


    def _start_agent_resume(self, pending_id, tool_output, ok):
        with self._response_lock:
            if self._response_thread and self._response_thread.is_alive():
                self.printInTerminal("Analysis:", "Assistant is still processing the previous request.")
                return
            self._response_thread = Thread(
                target=self._agent_resume_worker,
                args=(pending_id, tool_output, ok),
                daemon=True,
            )
            self._response_thread.start()

    def _drain_deferred_resume(self):
        if self._deferred_resume is None:
            return
        with self._response_lock:
            if self._response_thread and self._response_thread.is_alive():
                return
        pending_id, tool_output, ok = self._deferred_resume
        self._deferred_resume = None
        self._start_agent_resume(pending_id, tool_output, ok)


    def _agent_turn_worker(self, user_input):
        try:
            result = self.agent.run_user_turn(user_input)
            self.responseReady.emit(result)
        except Exception as e:
            self.responseError.emit(f"An unexpected error occurred: {e}")
        finally:
            with self._response_lock:
                self._response_thread = None
            self.workerFinished.emit()


    def _agent_resume_worker(self, pending_id, tool_output, ok):
        try:
            result = self.agent.resume_pending_tool(
                pending_id=pending_id,
                tool_content=tool_output,
                ok=ok,
            )
            self.responseReady.emit(result)
        except Exception as e:
            self.responseError.emit(f"An unexpected error occurred: {e}")
        finally:
            with self._response_lock:
                self._response_thread = None
            self.workerFinished.emit()

    def _process_assistant_response(self, message):
        assistant_reply = getattr(message, "content", "") or ""
        if assistant_reply:
            self.printInTerminal(
                "Analysis:",
                markdown.markdown(assistant_reply, extensions=["fenced_code", "tables"]),
                rich_message=True,
            )

        if getattr(message, "is_pending", False):
            metadata = getattr(message, "metadata", {}) or {}
            arguments = getattr(message, "tool_arguments", {}) or {}
            self.awaiting_tool_result = True
            self.pending_tool_id = getattr(message, "pending_id", None)
            self.pending_tool_context = {
                "command_id": metadata.get("command_id") or arguments.get("command_id"),
                "beacon_hash": metadata.get("beacon_hash") or arguments.get("beacon_hash"),
                "listener_hash": metadata.get("listener_hash") or arguments.get("listener_hash"),
                "command_line": metadata.get("command_line") or arguments.get("command_line"),
            }
            self.printInTerminal("Analysis:", self._format_pending_status("Waiting for beacon command result."))
            pending = self.pending_tool_context
            self.watchSession(pending.get("beacon_hash"), pending.get("listener_hash"))
            if self.command_event_hub is not None:
                recent = self.command_event_hub.recent_event(
                    pending.get("beacon_hash"), pending.get("listener_hash"), pending.get("command_id"),
                )
                if recent is not None:
                    self.receiveCommandEvent(recent)

    def _clear_pending_tool_state(self):
        self.awaiting_tool_result = False
        self.pending_tool_context = None
        self.pending_tool_id = None

    def _handle_assistant_error(self, error_message):
        if error_message:
            self.printInTerminal("Analysis:", error_message)


    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        move_editor_to_end(self.editorOutput)


class CommandEditor(CompletionInput):
    cmdHistory = []
    idx = 0

    def __init__(self, parent=None):
        super().__init__(parent, completion_data=ASSISTANT_COMPLETIONS)

        QShortcut(Qt.Key.Key_Up, self.lineEdit, self.historyUp)
        QShortcut(Qt.Key.Key_Down, self.lineEdit, self.historyDown)

    def historyUp(self):
        if self.idx < len(self.cmdHistory) and self.idx >= 0:
            cmd = self.cmdHistory[self.idx % len(self.cmdHistory)]
            self.idx = max(self.idx - 1, 0)
            self.setText(cmd.strip())

    def historyDown(self):
        if self.idx < len(self.cmdHistory) and self.idx >= 0:
            self.idx = min(self.idx + 1, len(self.cmdHistory) - 1)
            cmd = self.cmdHistory[self.idx % len(self.cmdHistory)]
            self.setText(cmd.strip())

    def setCmdHistory(self):
        with open(".termHistory", encoding="utf-8") as cmdHistoryFile:
            self.cmdHistory = cmdHistoryFile.readlines()
            self.idx = len(self.cmdHistory) - 1

    def clearLine(self):
        self.clear()
