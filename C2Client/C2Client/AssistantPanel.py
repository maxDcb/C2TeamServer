import sys
import os
import logging
import importlib
from datetime import datetime

from threading import Thread, Lock, Semaphore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *

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
        self.editorOutput.setFont(QFont("Courier"));
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


    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)


    def sessionAssistantMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        if action == "start":
            print("sessionAssistantMethod", action, beaconHash)
            self.messages.append({"role": "user", "content": "New session stared: beaconHash={}, listenerHash={}, hostname={}, username={}, privilege={}, os={}.".format(beaconHash, listenerHash, hostname, username, privilege, os) })
        elif action == "stop":
            toto = 1
        elif action == "update":
            toto = 1
                    
    
    def listenerAssistantMethod(self, action, hash, str3, str4):
        print("listenerAssistantMethod", action, hash)
        if action == "start":
            toto = 1
        elif action == "stop":
            toto = 1


    def consoleAssistantMethod(self, action, beaconHash, listenerHash, context, cmd, result):
        if action == "receive":
            print("consoleAssistantMethod", "-Context:\n" + context + "\n\n-Command sent:\n" + cmd + "\n\n-Response:\n" + result)
            self.messages.append({"role": "user", "content": cmd + "\n" + result})
        elif action == "send":
            toto = 1


    def event(self, event):
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)


    def printInTerminal(self, cmd, result):
        now = datetime.now()
        formater = '<p style="white-space:pre">'+'<span style="color:blue;">['+now.strftime("%Y:%m:%d %H:%M:%S").rstrip()+']</span>'+'<span style="color:red;"> [+] </span>'+'<span style="color:red;">{}</span>'+'</p>'

        self.sem.acquire()
        if cmd:
            self.editorOutput.appendHtml(formater.format(cmd))
            self.editorOutput.insertPlainText("\n")
        if result:
            self.editorOutput.insertPlainText(result)
            self.editorOutput.insertPlainText("\n")
        self.sem.release()


    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "")

        else:

            function_spec_assemblyExec = {
                "name": "assemblyExec",
                "description": "Execute a red team tool on a specific beacon using assembly execution",
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
                        "tool": {
                            "type": "string",
                            "description": "The tool to use (e.g., Rubeus)"
                        },
                        "arguments": {
                            "type": "string",
                            "description": "Command line arguments to pass to the tool (e.g., '/dump')"
                        }
                    },
                    "required": ["beacon_hash", "listener_hash", "tool"]
                }
            }

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
                            "description": "Absolute or relative path to change to (e.g., '../modules', '/tmp')."
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
                    }
                },
                    "required": ["beacon_hash", "listener_hash"]
            }


            api_key = os.environ.get("OPENAI_API_KEY")
            
            if api_key:
                client = OpenAI(
                    # This is the default and can be omitted
                    api_key=api_key,
                )

                # Add user command output
                self.messages.append({"role": "user", "content": commandLine})

                if len(self.messages) > self.MAX_MESSAGES * 2 + 1:
                    # Always keep the first message (system prompt)
                    system_prompt = self.messages[0]
                    recent_messages = self.messages[-(self.MAX_MESSAGES * 2):]
                    self.messages = [system_prompt] + recent_messages

                try:
                    # Call OpenAI API
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        # model="gpt-3.5-turbo-1106", # test
                        messages=self.messages,
                        functions=[function_spec_ls, function_spec_cd, function_spec_cat, function_spec_pwd],
                        function_call="auto",
                        temperature=0.05
                    )

                    self.printInTerminal("User:", commandLine)

                    message = response.choices[0].message
                    print(message)

                    function_call = message.function_call
                    if function_call:
                        name = function_call.name
                        args = json.loads(function_call.arguments)
                        print(f"Model wants to call `{name}` with arguments: {args}")

                        self.printInTerminal("Analysis:", f"Model wants to call `{name}` with arguments: {args}")

                        self.executeCmd(name, args)


                    assistant_reply = message.content
                    if assistant_reply:
                        self.printInTerminal("Analysis:", assistant_reply)

                        # Add assistant's response to conversation
                        self.messages.append({"role": "assistant", "content": assistant_reply})

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
                self.printInTerminal("OPENAI_API_KEY is not set, functionality deactivated.", "")
                

        self.setCursorEditorAtEnd()


    def executeCmd(self, cmd, args):
        
        if cmd == "ls":
            beacon_hash = args["beacon_hash"]
            listener_hash = args["listener_hash"]
            path = args["path"]
            commandLine = "ls " + path
            command = TeamServerApi_pb2.Command(beaconHash=beacon_hash, listenerHash=listener_hash, cmd=commandLine)
            result = self.grpcClient.sendCmdToSession(command)
            if result.message:
                self.printInTerminal("", commandLine, result.message.decode(encoding="latin1", errors="ignore"))

        elif cmd == "cd":
            beacon_hash = args["beacon_hash"]
            listener_hash = args["listener_hash"]
            path = args["path"]
            commandLine = "cd " + path
            command = TeamServerApi_pb2.Command(beaconHash=beacon_hash, listenerHash=listener_hash, cmd=commandLine)
            result = self.grpcClient.sendCmdToSession(command)
            if result.message:
                self.printInTerminal("", commandLine, result.message.decode(encoding="latin1", errors="ignore"))

        elif cmd == "cat":
            beacon_hash = args["beacon_hash"]
            listener_hash = args["listener_hash"]
            path = args["path"]
            commandLine = "cat " + path
            command = TeamServerApi_pb2.Command(beaconHash=beacon_hash, listenerHash=listener_hash, cmd=commandLine)
            result = self.grpcClient.sendCmdToSession(command)
            if result.message:
                self.printInTerminal("", commandLine, result.message.decode(encoding="latin1", errors="ignore"))

        elif cmd == "pwd":
            beacon_hash = args["beacon_hash"]
            listener_hash = args["listener_hash"]
            commandLine = "pwd"
            command = TeamServerApi_pb2.Command(beaconHash=beacon_hash, listenerHash=listener_hash, cmd=commandLine)
            result = self.grpcClient.sendCmdToSession(command)
            if result.message:
                self.printInTerminal("", commandLine, result.message.decode(encoding="latin1", errors="ignore"))

        else:
            raise ValueError("Unsupported command type")
        
        return
    

    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        cursor = self.editorOutput.textCursor()
        cursor.movePosition(QTextCursor.End,)
        self.editorOutput.setTextCursor(cursor)


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()
    cmdHistory = []
    idx = 0

    def __init__(self, parent=None):
        super().__init__(parent)

        QShortcut(Qt.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key_Down, self, self.historyDown)

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
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
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
    ConcatenationRole = Qt.UserRole + 1

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
