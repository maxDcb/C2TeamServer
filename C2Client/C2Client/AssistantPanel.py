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

        # System prompt defined once
        system_prompt = {
            "role": "system",
            "content": (
                "You are a professional cybersecurity red teamer. Your role is to examine output from security tools and command output comming from Linux or Windows systems "
                "You detect anomalies, potential security threats, misconfigurations, unusual behavior and important information. "
                "You guide the operator by explaining your reasoning and, if applicable, suggest further investigation steps. "
                "Be concise, technical, and focused, you give as much as possible how an attacker could gain advantage of any vulnerability. Do not assume anything beyond the provided output."
            )
        }

        # Initialize message history with the system prompt
        self.messages = [system_prompt]

        # Maximum number of messages to retain
        self.MAX_MESSAGES = 10


    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)


    def sessionAssistantMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        if action == "start":
            toto = 1
        elif action == "stop":
            toto = 1
        elif action == "update":
            toto = 1
                    
    
    def listenerAssistantMethod(self, action, hash, str3, str4):
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

            api_key = os.environ.get("OPENAI_API_KEY")
            
            if api_key:
                client = OpenAI(
                    # This is the default and can be omitted
                    api_key=api_key,
                )

                # Add user command output
                self.messages.append({"role": "user", "content": commandLine})

                # Prune messages to keep only the last 10 (including system, user, and assistant messages)
                if len(self.messages) > self.MAX_MESSAGES * 2 + 1:  # (10 user + 10 assistant + 1 system)
                    self.messages = self.messages[-(MAX_MESSAGES * 2 + 1):]

                try:
                    # Call OpenAI API
                    response = client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=self.messages,
                        temperature=0.3
                    )

                    assistant_reply = response.choices[0].message.content

                    self.printInTerminal("Analysis:", assistant_reply)

                    # Add assistant's response to conversation
                    self.messages.append({"role": "assistant", "content": assistant_reply})
                except openai.APIConnectionError as e:
                    print("Server connection error: {e.__cause__}") 
                    
                except openai.RateLimitError as e:
                    print(f"OpenAI RATE LIMIT error {e.status_code}: (e.response)")
                    
                except openai.APIStatusError as e:
                    print(f"OpenAI STATUS error {e.status_code}: (e.response)")
                    
                except openai.BadRequestError as e:
                    print(f"OpenAI BAD REQUEST error {e.status_code}: (e.response)")
                    
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")
            
            else:
                self.printInTerminal("OPENAI_API_KEY is not set, functionality deactivated.", "")
                

        self.setCursorEditorAtEnd()


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
