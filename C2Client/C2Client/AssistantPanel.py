import os

from threading import Thread, Lock, Semaphore

from PyQt6.QtCore import Qt, QEvent, QTimer, pyqtSignal
from PyQt6.QtGui import QShortcut
from PyQt6.QtWidgets import (
    QLineEdit,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
    QTextEdit
)
import markdown

from .assistant_agent import C2AssistantAgent
from .console_style import (
    apply_console_output_style,
    append_console_block,
    append_console_spacing,
    move_editor_to_end,
)
from .env import env_int

DEFAULT_PENDING_TOOL_TIMEOUT_MS = 2 * 60 * 1000

ASSISTANT_HEADER_ROLES = {
    "system": ("[system]", "system", False),
    "user": ("[user]", "user", False),
    "analysis": ("[assistant]", "assistant", False),
}


def _load_pending_tool_timeout_ms():
    return env_int(
        "C2_ASSISTANT_PENDING_TIMEOUT_MS",
        DEFAULT_PENDING_TOOL_TIMEOUT_MS,
        minimum=0,
    )


#
# Assistant tab implementation
#
class Assistant(QWidget):
    tabPressed = pyqtSignal()
    responseReady = pyqtSignal(object)
    responseError = pyqtSignal(str)
    logFileName=""
    sem = Semaphore()

    def __init__(self, parent, grpcClient):
        super().__init__(parent) 
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.agent = C2AssistantAgent(grpcClient)

        # self.logFileName=LogFileName

        self.editorOutput = QTextBrowser()
        apply_console_output_style(self.editorOutput)
        self.editorOutput.setReadOnly(True)
        # Force word wrapping
        self.editorOutput.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.editorOutput.setLineWrapColumnOrWidth(0)
        self.layout.addWidget(self.editorOutput, 8)

        self.commandEditor = CommandEditor()
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)

        self.responseReady.connect(self._process_assistant_response)
        self.responseError.connect(self._handle_assistant_error)

        # Track pending tool execution state
        self.awaiting_tool_result = False
        self.pending_tool_context = None
        self.pending_tool_id = None
        self.pending_tool_timeout_ms = _load_pending_tool_timeout_ms()
        self.pending_tool_timer = QTimer(self)
        self.pending_tool_timer.setSingleShot(True)
        self.pending_tool_timer.timeout.connect(self._handle_pending_tool_timeout)

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
        )
        return
                    
    
    def listenerAssistantMethod(self, action, hash, str3, str4):
        return


    def consoleAssistantMethod(self, action, beaconHash, listenerHash, context, cmd, result, commandId=""):
        if action != "receive":
            return

        command_text = cmd or ""
        if isinstance(command_text, bytes):
            command_text = command_text.decode("latin1", errors="ignore")
        command_text = command_text.strip()

        output_text = result or ""
        if isinstance(output_text, bytes):
            output_text = output_text.decode("latin1", errors="ignore")
        output_text = output_text.replace(chr(0), "")
        display_output = output_text if output_text else "[no output]"

        awaiting_result = False
        if self.awaiting_tool_result:
            if self.pending_tool_context:
                pending_command_id = self.pending_tool_context.get("command_id")
                awaiting_result = (
                    (not pending_command_id or pending_command_id == commandId)
                    and self.pending_tool_context.get("beacon_hash") == beaconHash
                    and self.pending_tool_context.get("listener_hash") == listenerHash
                )
            else:
                awaiting_result = True

        if awaiting_result:
            pending_id = self.pending_tool_id
            tool_output = self._format_tool_result_for_resume(
                beacon_hash=beaconHash,
                listener_hash=listenerHash,
                command_id=commandId,
                command=command_text,
                output=display_output,
            )
            self.printInTerminal("Analysis:", f"Received result for command `{commandId or command_text}`. Resuming assistant.")
            self._clear_pending_tool_state()

            if pending_id:
                self._start_agent_resume(pending_id, tool_output)
        else:
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


    def _format_tool_result_for_resume(self, *, beacon_hash, listener_hash, command_id, command, output):
        return "\n".join(
            [
                "Command result received from TeamServer.",
                f"command_id: {command_id or 'unknown'}",
                f"beacon_hash: {beacon_hash or 'unknown'}",
                f"listener_hash: {listener_hash or 'unknown'}",
                f"command: {command or 'unknown'}",
                "output:",
                output or "[no output]",
            ]
        )

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

        if local_command in {"/cancel", "/reset"}:
            if not self.awaiting_tool_result:
                self.printInTerminal("Analysis:", "No pending command wait to cancel.")
                return

            self._clear_pending_tool_state()
            self.printInTerminal("Analysis:", "Pending command wait cancelled.")
            return

        if local_command.startswith("/"):
            self.printInTerminal("Analysis:", f"Unknown local assistant command `{commandLine.strip()}`.")
            self._show_local_help()
            return

        if self.awaiting_tool_result:
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
        timeout_seconds = self.pending_tool_timeout_ms // 1000
        timeout_line = (
            f"Pending command timeout: {timeout_seconds}s."
            if self.pending_tool_timeout_ms > 0
            else "Pending command timeout: disabled."
        )
        self.printInTerminal(
            "Assistant commands:",
            "\n".join(
                [
                    "/help - Show AssistantPanel local commands.",
                    "/status - Show the current assistant pending command state.",
                    "/cancel - Cancel the current pending beacon result wait.",
                    "/reset - Alias for /cancel.",
                    timeout_line,
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

        if self.pending_tool_timeout_ms > 0:
            timeout = f", timeout {self.pending_tool_timeout_ms // 1000}s"
        else:
            timeout = ", timeout disabled"

        return f"{status} Command `{command}` on beacon `{beacon_hash_short}` (cmd `{command_id_short}`{timeout})."

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


    def _start_agent_resume(self, pending_id, tool_output):
        with self._response_lock:
            if self._response_thread and self._response_thread.is_alive():
                self.printInTerminal("Analysis:", "Assistant is still processing the previous request.")
                return
            self._response_thread = Thread(
                target=self._agent_resume_worker,
                args=(pending_id, tool_output),
                daemon=True,
            )
            self._response_thread.start()


    def _agent_turn_worker(self, user_input):
        try:
            result = self.agent.run_user_turn(user_input)
            self.responseReady.emit(result)
        except Exception as e:
            self.responseError.emit(f"An unexpected error occurred: {e}")
        finally:
            with self._response_lock:
                self._response_thread = None


    def _agent_resume_worker(self, pending_id, tool_output):
        try:
            result = self.agent.resume_pending_tool(
                pending_id=pending_id,
                tool_content=tool_output,
                ok=True,
            )
            self.responseReady.emit(result)
        except Exception as e:
            self.responseError.emit(f"An unexpected error occurred: {e}")
        finally:
            with self._response_lock:
                self._response_thread = None

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
            self._start_pending_tool_timer()
            self.printInTerminal("Analysis:", self._format_pending_status("Waiting for beacon command result."))
        else:
            self._stop_pending_tool_timer()

    def _start_pending_tool_timer(self):
        if self.pending_tool_timeout_ms > 0:
            self.pending_tool_timer.start(self.pending_tool_timeout_ms)

    def _stop_pending_tool_timer(self):
        if self.pending_tool_timer.isActive():
            self.pending_tool_timer.stop()

    def _clear_pending_tool_state(self):
        self.awaiting_tool_result = False
        self.pending_tool_context = None
        self.pending_tool_id = None
        self._stop_pending_tool_timer()

    def _handle_pending_tool_timeout(self):
        if not self.awaiting_tool_result:
            return

        context = self.pending_tool_context or {}
        command = context.get("command_line") or context.get("command_id") or "command"
        command_id = context.get("command_id")
        beacon_hash = context.get("beacon_hash")
        target = f" on beacon {beacon_hash[:8]}" if beacon_hash else ""
        command_id_text = f" Command ID: {command_id}." if command_id else ""

        self._clear_pending_tool_state()
        self.printInTerminal(
            "Analysis:",
            f"Timed out waiting for result of `{command}`{target}.{command_id_text} The assistant is ready for a new request.",
        )

    def _handle_assistant_error(self, error_message):
        if error_message:
            self.printInTerminal("Analysis:", error_message)


    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        move_editor_to_end(self.editorOutput)


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()
    cmdHistory = []
    idx = 0

    def __init__(self, parent=None):
        super().__init__(parent)

        QShortcut(Qt.Key.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key.Key_Down, self, self.historyDown)

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def historyUp(self):
        if(self.idx<len(self.cmdHistory) and self.idx>=0):
            cmd = self.cmdHistory[self.idx%len(self.cmdHistory)]
            self.idx=max(self.idx-1,0)
            self.setText(cmd.strip())

    def historyDown(self):
        if(self.idx<len(self.cmdHistory) and self.idx>=0):
            self.idx=min(self.idx+1,len(self.cmdHistory)-1)
            cmd = self.cmdHistory[self.idx%len(self.cmdHistory)]
            self.setText(cmd.strip())

    def setCmdHistory(self):
        cmdHistoryFile = open('.termHistory')
        self.cmdHistory = cmdHistoryFile.readlines()
        self.idx=len(self.cmdHistory)-1
        cmdHistoryFile.close()

    def clearLine(self):
        self.clear()
