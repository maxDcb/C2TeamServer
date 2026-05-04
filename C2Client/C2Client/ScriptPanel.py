import sys
import os
import logging
import importlib
from pathlib import Path
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

logger = logging.getLogger(__name__)


#
# scripts
#
try:
    import pkg_resources
    scriptsDir = pkg_resources.resource_filename('C2Client', 'Scripts')
except ImportError:
    # Fallback: relative to this file (…/C2Client/Scripts)
    scriptsDir = os.path.join(os.path.dirname(__file__), 'Scripts')

scripts_path = Path(scriptsDir).resolve()
scripts_path.mkdir(parents=True, exist_ok=True)

# Ensure it's a real package
(scripts_path / "__init__.py").touch(exist_ok=True)

# Ensure the project root (parent of C2Client) is on sys.path so
# `C2Client.Scripts` is importable as a package
# e.g. /path/to/project_root/C2Client/Scripts
project_root = scripts_path.parent.parent  # .../project_root
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

package_name = "C2Client.Scripts"

# ----------------------------
# Load all scripts as modules
# ----------------------------
LoadedScripts = []
FailedScripts = []
for entry in scripts_path.iterdir():
    if entry.suffix == ".py" and entry.name != "__init__.py":
        modname = f"{package_name}.{entry.stem}"
        try:
            m = importlib.import_module(modname)
            LoadedScripts.append(m)
            logger.debug("Imported script module %s", modname)
        except Exception as exc:
            FailedScripts.append(f"{modname}: {exc}")
            logger.warning(
                "Failed to import script module %s: %s",
                modname,
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )


#
# Script tab implementation
#
class Script(QWidget):
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

        output = ""
        for script in LoadedScripts:
            output += script.__name__ + "\n"
        self.printInTerminal("Loaded Scripts:", output)
        if FailedScripts:
            self.printInTerminal("Script load errors:", "\n".join(FailedScripts))


    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)


    def sessionScriptMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        hooks = {
            "start": "OnSessionStart",
            "stop": "OnSessionStop",
            "update": "OnSessionUpdate",
        }
        hookName = hooks.get(action)
        if not hookName:
            return

        for script in LoadedScripts:
            self.runScriptHook(
                script,
                hookName,
                hookName,
                beaconHash,
                listenerHash,
                hostname,
                username,
                arch,
                privilege,
                os,
                lastProofOfLife,
                killed,
            )

    
    def listenerScriptMethod(self, action, hash, str3, str4):
        hooks = {
            "start": "OnListenerStart",
            "stop": "OnListenerStop",
        }
        hookName = hooks.get(action)
        if not hookName:
            return

        for script in LoadedScripts:
            self.runScriptHook(script, hookName, hookName)


    def consoleScriptMethod(self, action, beaconHash, listenerHash, context, cmd, result, commandId=""):
        hooks = {
            "receive": "OnConsoleReceive",
            "send": "OnConsoleSend",
        }
        hookName = hooks.get(action)
        if not hookName:
            return

        for script in LoadedScripts:
            self.runScriptHook(script, hookName, hookName)

    def mainScriptMethod(self, action, str2, str3, str4):
        hooks = {
            "start": "OnStart",
            "stop": "OnStop",
        }
        hookName = hooks.get(action)
        if not hookName:
            return

        for script in LoadedScripts:
            self.runScriptHook(script, hookName, hookName)

    def runScriptHook(self, script, hookName, displayName, *args):
        scriptName = getattr(script, "__name__", script.__class__.__name__)
        hook = getattr(script, hookName, None)
        if hook is None:
            return

        try:
            output = hook(self.grpcClient, *args)
        except Exception as exc:
            logger.warning(
                "Script hook %s.%s failed: %s",
                scriptName,
                hookName,
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            self.printInTerminal("Script error:", f"{scriptName}.{hookName}: {exc}")
            return

        if output:
            self.printInTerminal(displayName, output)


    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
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
            toto=1
            

        self.setCursorEditorAtEnd()


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
