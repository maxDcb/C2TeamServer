import sys
import os
import time
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *


class Terminal(QWidget):
    tabPressed = pyqtSignal()
    logFileName=""

    def __init__(self, parent, ip, port, devMode):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        self.grpcClient = GrpcClient(ip, port, devMode)

        self.logFileName="Terminal.log"

        self.editorOutput = QPlainTextEdit()
        self.editorOutput.setFont(QFont("Courier"));
        self.editorOutput.setReadOnly(True)
        self.layout.addWidget(self.editorOutput, 8)

        self.commandEditor = CommandEditor()
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)


    def __del__(self):
        self.thread.quit()
        self.thread.wait()

    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)

    def event(self, event):
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            line = '\n';
            self.editorOutput.insertPlainText(line)
        else:
            cmdHistoryFile = open('.termHistory', 'a')
            cmdHistoryFile.write(commandLine)
            cmdHistoryFile.write('\n')
            cmdHistoryFile.close()

            logFile = open("./logs/"+self.logFileName, 'a')
            logFile.write('[+] send: \"' + commandLine + '\"')
            logFile.write('\n')
            logFile.close()

            self.commandEditor.setCmdHistory()
            instructions = commandLine.split()

            #TODO integrat generation of shellcode and stuff 

            if instructions[0]=="help":
                helpText = "TODO"
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + "help" + '</p>'
                self.editorOutput.appendHtml(line)
                line = '\n' + helpText  + '\n';
                self.editorOutput.insertPlainText(line)

            else:
                
                line = '<p style=\"color:orange;white-space:pre\">[+] send: \"' + commandLine + '\"</p>'
                self.editorOutput.appendHtml(line)
                line = '\n';
                self.editorOutput.insertPlainText(line)

                termCommand = TeamServerApi_pb2.TermCommand(cmd=commandLine)
                resultTermCommand = self.grpcClient.sendTermCmd(termCommand)
                if resultTermCommand.result:
                    line = resultTermCommand.result + '\n'

                self.editorOutput.insertPlainText(line)

        self.setCursorEditorAtEnd()

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

        if(os.path.isfile('.termHistory')):
            cmdHistoryFile = open('.termHistory')
            self.cmdHistory = cmdHistoryFile.readlines()
            self.idx=len(self.cmdHistory)-1
            cmdHistoryFile.close()

        QShortcut(Qt.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key_Down, self, self.historyDown)

        self.codeCompleter = CodeCompleter(completerData, self)
        # needed to clear the completer after activation
        self.codeCompleter.activated.connect(self.onActivated)
        self.setCompleter(self.codeCompleter)
        self.tabPressed.connect(self.nextCompletion)

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


completerData = [
    ('help',[]),
    ('shellcode',[
            ('127.0.0.1 8443 https',[]),
             ]),
]


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