import sys
import os
import logging
import importlib
from datetime import datetime

from threading import Thread, Lock, Semaphore

from PyQt6.QtCore import Qt, QEvent, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QStandardItem, QStandardItemModel, QShortcut
from PyQt6.QtWidgets import (
    QCompleter,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from .grpcClient import TeamServerApi_pb2

import openai
from openai import OpenAI

import json


#
# Assistant tab implementation
#
class Assistant(QWidget):
    tabPressed = pyqtSignal()
    logFileName=""
    sem = Semaphore()

    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.grpcClient = grpcClient

        # self.logFileName=LogFileName

        self.editorOutput = QPlainTextEdit()
        self.editorOutput.setFont(QFont("JetBrainsMono Nerd Font")) 
        self.editorOutput.setReadOnly(True)
        self.layout.addWidget(self.editorOutput, 8)

        self.commandEditor = CommandEditor()
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)

        system_prompt = {
            "role": "system",
            "content": (
                """You are a Red Team Operator Assistant embedded in the "Exploration" C2 framework. 
You operate in offensive security engagements and support operators by reasoning over command output from enumeration before getting a foothold and compromised machines and suggesting the next best actions. 
You also point out security gaps that could be leveraged. You understand operational security (OPSEC), red teaming tactics, post-exploitation phases, and tradecraft.

## Context:
- Exploration C2 framework run on a kali machine
- You will be fed output from commands previously ran.
- All tools available on a kali machine can use used

## Instructions:
- Suggest only what makes tactical sense based on the output provided.
- Prioritize stealth and minimal footprint.
- Chain commands where appropriate to complete an objective (e.g., escalate, pivot, loot).
- When unclear, ask the operator for additional context instead of assuming."""
)
        }

        # Initialize message history with the system prompt
        self.messages = [system_prompt]

        # Maximum number of messages to retain
        self.MAX_MESSAGES = 20

        # Track pending tool execution state
        self.awaiting_tool_result = False
        self.pending_tool_name = None
        self.pending_tool_context = None
        self.tool_call_count = 0
        self.max_function_calls = 5

        self._openai_client = None


    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)


    def sessionAssistantMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        if action == "start":
            # print("sessionAssistantMethod", action, beaconHash)
            self.messages.append({"role": "user", "content": "New session stared: beaconHash={}, listenerHash={}, hostname={}, username={}, privilege={}, os={}.".format(beaconHash, listenerHash, hostname, username, privilege, os) })
        elif action == "stop":
            toto = 1
        elif action == "update":
            toto = 1
                    
    
    def listenerAssistantMethod(self, action, hash, str3, str4):
        # print("listenerAssistantMethod", action, hash)
        if action == "start":
            toto = 1
        elif action == "stop":
            toto = 1


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

        # print(f"consoleAssistantMethod: action={action}, beaconHash={beaconHash}, listenerHash={listenerHash}, cmd={command_text}, result={display_output}")
        # print("pending_tool_context:", self.pending_tool_context)
        # print("awaiting_tool_result:", self.awaiting_tool_result)

        awaiting_result = False
        if self.awaiting_tool_result:
            if self.pending_tool_context:
                awaiting_result = (
                    self.pending_tool_context.get("beacon_hash") == beaconHash
                    and self.pending_tool_context.get("listener_hash") == listenerHash
                )
            else:
                awaiting_result = True

        # print("awaiting_result:", awaiting_result)

        if awaiting_result:
            header = command_text or "[assistant command]"
            self.printInTerminal("Command:", header, display_output)

            function_name = self.pending_tool_name or "unknown"
            self.messages.append({"role": "function", "name": function_name, "content": display_output})
            self._trim_message_history()

            self.awaiting_tool_result = False
            self.pending_tool_name = None
            self.pending_tool_context = None
            self.tool_call_count += 1

            try:
                self._request_assistant_response()
            except openai.APIConnectionError as e:
                print(f"Server connection error: {e.__cause__}")
            except openai.RateLimitError as e:
                print(f"OpenAI RATE LIMIT error {e.status_code}: {e.response}")
            except openai.APIStatusError as e:
                print(f"OpenAI STATUS error {e.status_code}: {e.response}")
            except openai.BadRequestError as e:
                print(f"OpenAI BAD REQUEST error {e.status_code}: {e.response}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        else:
            combined = command_text
            if output_text:
                combined = f"{command_text}\n{output_text}" if command_text else output_text

            if combined.strip():
                self.messages.append({"role": "user", "content": combined})
                self._trim_message_history()

            header = command_text or "[command]"
            # self.printInTerminal("Command:", header, display_output)
            

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)


    def printInTerminal(self, header="", message="", detail=""):
        now = datetime.now()
        formater = '<p style="white-space:pre">'+'<span style="color:blue;">['+now.strftime("%Y:%m:%d %H:%M:%S").rstrip()+']</span>'+'<span style="color:red;"> [+] </span>'+'<span style="color:red;">{}</span>'+'</p>'

        self.sem.acquire()
        try:
            if header:
                self.editorOutput.appendHtml(formater.format(header))
                self.editorOutput.insertPlainText("\n")
            for text in (message, detail):
                if text:
                    self.editorOutput.insertPlainText(text)
                    self.editorOutput.insertPlainText("\n")
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

        client = self._get_openai_client()
        if client is None:
            self.printInTerminal("OPENAI_API_KEY is not set, functionality deactivated.", "")
            return

        # Reset state for a new round of tool calls triggered by operator input
        self.awaiting_tool_result = False
        self.pending_tool_name = None
        self.pending_tool_context = None
        self.tool_call_count = 0

        # Add user command to the conversation history
        self.messages.append({"role": "user", "content": commandLine})
        self._trim_message_history()

        try:
            self.printInTerminal("User:", commandLine)
            self._request_assistant_response()
        except openai.APIConnectionError as e:
            print(f"Server connection error: {e.__cause__}")
        except openai.RateLimitError as e:
            print(f"OpenAI RATE LIMIT error {e.status_code}: {e.response}")
        except openai.APIStatusError as e:
            print(f"OpenAI STATUS error {e.status_code}: {e.response}")
        except openai.BadRequestError as e:
            print(f"OpenAI BAD REQUEST error {e.status_code}: {e.response}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        self.setCursorEditorAtEnd()


    def _get_openai_client(self):
        if self._openai_client is not None:
            return self._openai_client

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None

        self._openai_client = OpenAI(api_key=api_key)
        return self._openai_client


    def _function_specs(self):
        function_spec_ls = {
            "name": "ls",
            "description": "List the contents of a specified directory on a specific beacon.",
            "parameters": {
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the beacon to execute the command on"
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the listener at which the beacon is connected"
                    },
                    "path": {
                        "type": "string",
                        "description": "The path of the directory to list. If omitted, uses the current working directory.",
                        "default": "."
                    }
                },
                "required": ["beacon_hash", "listener_hash", "path"]
            }
        }

        function_spec_cd = {
            "name": "cd",
            "description": "Change the working directory for subsequent module execution or file operations on a specific beacon.",
            "parameters": {
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the beacon to execute the command on"
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the listener at which the beacon is connected"
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to change to (e.g., '../modules', '/tmp').",
                    }
                },
                "required": ["beacon_hash", "listener_hash", "path"]
            }
        }

        function_spec_cat = {
            "name": "cat",
            "description": "Read and return the contents of a specified file on disk on a specific beacon.",
            "parameters": {
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the beacon to execute the command on"
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the listener at which the beacon is connected"
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the file (e.g., './modules/shellcode.bin', '/etc/hosts')."
                    }
                },
                "required": ["beacon_hash", "listener_hash", "path"]
            }
        }

        function_spec_pwd = {
            "name": "pwd",
            "description": "Return the current working directory path on a specific beacon.",
            "parameters": {
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the beacon to execute the command on"
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the listener at which the beacon is connected"
                    }
                },
                "required": ["beacon_hash", "listener_hash"]
            }
        }

        function_spec_tree = {
            "name": "tree",
            "description": "Recursively display the directory structure of a specified path on a specific beacon in a tree-like format.",
            "parameters": {
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the beacon to execute the command on"
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the listener at which the beacon is connected"
                    },
                    "path": {
                        "type": "string",
                        "description": "The root directory path to start the tree traversal. If omitted, uses the current working directory.",
                        "default": "."
                    }
                },
                "required": ["beacon_hash", "listener_hash", "path"]
            }
        }

        function_spec_loadmodule = {
            "name": "loadModule",
            "description": "Loads a module DLL into the beacon's memory, extending its capabilities. Perform this call when Module not loaded error is returned.",
            "parameters": {
                "type": "object",
                "properties": {
                    "beacon_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the beacon to execute the command on"
                    },
                    "listener_hash": {
                        "type": "string",
                        "description": "The unique hash identifying the listener at which the beacon is connected"
                    },
                    "module_to_load": {
                        "type": "string",
                        "description": "the module to loaad: ls, cd, cat, pwd, tree"
                    }
                },
                "required": ["beacon_hash", "listener_hash", "module_to_load"]
            }
        }

        return [
            function_spec_loadmodule,
            function_spec_ls,
            function_spec_cd,
            function_spec_cat,
            function_spec_pwd,
            function_spec_tree,
        ]


    def _request_assistant_response(self):
        if self.awaiting_tool_result:
            return

        client = self._get_openai_client()
        if client is None:
            return

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=self.messages,
            functions=self._function_specs(),
            function_call="auto",
            temperature=0.05,
        )

        message = response.choices[0].message
        function_call = getattr(message, "function_call", None)

        if function_call and function_call.name:
            if self.tool_call_count >= self.max_function_calls:
                warning = "Maximum number of tool calls reached without final response."
                self.printInTerminal("Analysis:", warning)
                self.messages.append({"role": "user", "content": warning})
                self._trim_message_history()
                return

            self._handle_function_call(message)
            return

        assistant_reply = message.content
        if assistant_reply:
            self.printInTerminal("Analysis:", assistant_reply)
            self.messages.append({"role": "assistant", "content": assistant_reply})
            self._trim_message_history()


    def _handle_function_call(self, message):
        function_call = message.function_call
        name = function_call.name
        raw_arguments = function_call.arguments or "{}"

        self.messages.append({
            "role": message.role,
            "content": message.content,
            "function_call": {
                "name": name,
                "arguments": raw_arguments,
            },
        })
        self._trim_message_history()

        self.pending_tool_context = None

        try:
            args = json.loads(raw_arguments)
        except json.JSONDecodeError as decode_error:
            error_message = f"Error decoding arguments for `{name}`: {decode_error}"
            self.printInTerminal("Analysis:", error_message)
            self.messages.append({"role": "function", "name": name, "content": error_message})
            self._trim_message_history()
            self.tool_call_count += 1
            return

        step_index = self.tool_call_count + 1
        step_info = f"Step {step_index}: calling `{name}` with arguments: {args}"
        self.printInTerminal("Analysis:", step_info)

        try:
            self.executeCmd(name, args)
        except Exception as tool_error:
            tool_error_message = f"Error executing `{name}`: {tool_error}"
            self.printInTerminal("Analysis:", tool_error_message)
            self.messages.append({"role": "function", "name": name, "content": tool_error_message})
            self._trim_message_history()
            self.tool_call_count += 1
            return

        self.awaiting_tool_result = True
        self.pending_tool_name = name
        self.pending_tool_context = {
            "beacon_hash": args.get("beacon_hash"),
            "listener_hash": args.get("listener_hash"),
        }


    def executeCmd(self, cmd, args):
        supported_commands = {"loadModule", "ls", "tree", "cd", "cat", "pwd"}
        if cmd not in supported_commands:
            raise ValueError(f"Unsupported command type: {cmd}")

        required_keys = ["beacon_hash", "listener_hash"]
        if cmd == "module_to_load":
            required_keys.append("module_to_load")
        elif cmd == "ls" or cmd == "cd" or cmd == "cat" or cmd == "tree":
            required_keys.append("path")

        missing = [key for key in required_keys if key not in args]
        if missing:
            raise KeyError(f"Missing required argument(s) for `{cmd}`: {', '.join(missing)}")

        beacon_hash = args["beacon_hash"]
        listener_hash = args["listener_hash"]

        if cmd == "pwd":
            command_line = "pwd"
        elif cmd == "loadModule":
            module_to_load = args["module_to_load"]
            command_line = f"{cmd} {module_to_load}"
        elif cmd == "ls" or cmd == "cd" or cmd == "cat" or cmd == "tree":
            path = args["path"]
            command_line = f"{cmd} {path}"

        command = TeamServerApi_pb2.Command(
            beaconHash=beacon_hash,
            listenerHash=listener_hash,
            cmd=command_line,
        )
        self.grpcClient.sendCmdToSession(command)

        return command_line


    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        cursor = self.editorOutput.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.editorOutput.setTextCursor(cursor)


    def _trim_message_history(self):
        if len(self.messages) > self.MAX_MESSAGES * 2 + 1:
            system_prompt = self.messages[0]
            recent_messages = self.messages[-(self.MAX_MESSAGES * 2):]
            self.messages = [system_prompt] + recent_messages


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()
    cmdHistory = []
    idx = 0

    def __init__(self, parent=None):
        super().__init__(parent)

        QShortcut(Qt.Key.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key.Key_Down, self, self.historyDown)

        # self.codeCompleter = CodeCompleter(completerData, self)
        # # needed to clear the completer after activation
        # self.codeCompleter.activated.connect(self.onActivated)
        # self.setCompleter(self.codeCompleter)
        # self.tabPressed.connect(self.nextCompletion)

    def nextCompletion(self):
        index = self.codeCompleter.currentIndex()
        self.codeCompleter.popup().setCurrentIndex(index)
        start = self.codeCompleter.currentRow()
        if not self.codeCompleter.setCurrentRow(start + 1):
            self.codeCompleter.setCurrentRow(0)

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

    def onActivated(self):
        QTimer.singleShot(0, self.clear)


class CodeCompleter(QCompleter):
    ConcatenationRole = Qt.ItemDataRole.UserRole + 1

    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.createModel(data)

    def splitPath(self, path):
        return path.split(' ')

    def pathFromIndex(self, ix):
        return ix.data(CodeCompleter.ConcatenationRole)

    def createModel(self, data):
        def addItems(parent, elements, t=""):
            for text, children in elements:
                item = QStandardItem(text)
                data = t + " " + text if t else text
                item.setData(data, CodeCompleter.ConcatenationRole)
                parent.appendRow(item)
                if children:
                    addItems(item, children, data)
        model = QStandardItemModel(self)
        addItems(model, data)
        self.setModel(model)
