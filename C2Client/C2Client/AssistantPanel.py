import os
from datetime import datetime

from threading import Thread, Lock, Semaphore

from PyQt6.QtCore import Qt, QEvent, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QShortcut
from PyQt6.QtWidgets import (
    QLineEdit,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
    QTextEdit
)
import markdown

from .assistant_agent import C2AssistantAgent


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
        self.editorOutput.setFont(QFont("JetBrainsMono Nerd Font")) 
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

        self._response_thread = None
        self._response_lock = Lock()

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            self.printInTerminal("System", "OPENAI_API_KEY is not set, functionality deactivated.")
        else:
            self.printInTerminal("System", "To let the assistant interact with sessions, select one or multiples sessions in the Sessions tab and interact with it, otherwise the assistant will not be feed the responses.")

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


    def consoleAssistantMethod(self, action, beaconHash, listenerHash, context, cmd, result):
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
                awaiting_result = (
                    self.pending_tool_context.get("beacon_hash") == beaconHash
                    and self.pending_tool_context.get("listener_hash") == listenerHash
                )
            else:
                awaiting_result = True

        if awaiting_result:
            pending_id = self.pending_tool_id
            self.awaiting_tool_result = False
            self.pending_tool_context = None
            self.pending_tool_id = None

            if pending_id:
                self._start_agent_resume(pending_id, display_output)
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

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)


    def printInTerminal(self, header="", message="", detail=""):
        now = datetime.now()
        formater = (
            '<p style="white-space:pre-wrap; word-wrap:break-word;">'
            '<span style="color:blue;">['+now.strftime("%Y:%m:%d %H:%M:%S").rstrip()+']</span>'
            '<span style="color:red;"> [+] </span>'
            '<span style="color:red;">{}</span>'
            '</p>'
        )

        self.sem.acquire()
        try:
            if header:
                self.editorOutput.append(formater.format(header))
            for text in (message, detail):
                if text:
                    self.editorOutput.append(text)

            self.setCursorEditorAtEnd()
        finally:
            self.sem.release()


    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "")
            return

        if self.awaiting_tool_result:
            self.printInTerminal("Analysis:", "Waiting for previous command output before continuing.")
            return

        with self._response_lock:
            if self._response_thread and self._response_thread.is_alive():
                self.printInTerminal("Analysis:", "Assistant is still processing the previous request.")
                return

        # Reset state for a new round of tool calls triggered by operator input
        self.awaiting_tool_result = False
        self.pending_tool_context = None
        self.pending_tool_id = None

        self.printInTerminal("User:", commandLine)
        self._start_agent_turn(commandLine)

        self.setCursorEditorAtEnd()


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
            self.printInTerminal("Analysis:", markdown.markdown(assistant_reply, extensions=["fenced_code", "tables"]))

        if getattr(message, "is_pending", False):
            metadata = getattr(message, "metadata", {}) or {}
            arguments = getattr(message, "tool_arguments", {}) or {}
            self.awaiting_tool_result = True
            self.pending_tool_id = getattr(message, "pending_id", None)
            self.pending_tool_context = {
                "beacon_hash": metadata.get("beacon_hash") or arguments.get("beacon_hash"),
                "listener_hash": metadata.get("listener_hash") or arguments.get("listener_hash"),
            }

    def _handle_assistant_error(self, error_message):
        if error_message:
            self.printInTerminal("Analysis:", error_message)


    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        cursor = self.editorOutput.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.editorOutput.setTextCursor(cursor)


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
