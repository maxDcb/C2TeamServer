import sys
import os
import logging
import importlib
import inspect
from pathlib import Path
from datetime import datetime

from threading import Thread, Lock, Semaphore

from PyQt6.QtCore import Qt, QEvent, QTimer, pyqtSignal
from PyQt6.QtGui import QStandardItem, QStandardItemModel, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCompleter,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .console_style import (
    apply_console_output_style,
    append_console_block,
    append_console_spacing,
    move_editor_to_end,
)
from .panel_style import apply_dark_panel_style

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

HOOK_ORDER = [
    "ManualStart",
    "OnStart",
    "OnStop",
    "OnListenerStart",
    "OnListenerStop",
    "OnSessionStart",
    "OnSessionUpdate",
    "OnSessionStop",
    "OnConsoleSend",
    "OnConsoleReceive",
]

HOOK_TRIGGER_NOTES = {
    "ManualStart": "Manual-only hook launched from the Script panel.",
    "OnStart": "Client window connected/reconnected to the TeamServer.",
    "OnStop": "Client window is closing; this depends on Qt widget teardown.",
    "OnListenerStart": "Listener table saw a listener start event.",
    "OnListenerStop": "Listener table saw a listener stop event.",
    "OnSessionStart": "Session table saw a new beacon.",
    "OnSessionUpdate": "Session table saw updated beacon data; this can repeat often during refresh.",
    "OnSessionStop": "Session table saw a killed/stopped beacon.",
    "OnConsoleSend": "Operator sent a command from a beacon console.",
    "OnConsoleReceive": "Beacon console received command output.",
}

MAIN_HOOKS = {
    "start": "OnStart",
    "stop": "OnStop",
}
LISTENER_HOOKS = {
    "start": "OnListenerStart",
    "stop": "OnListenerStop",
}
SESSION_HOOKS = {
    "start": "OnSessionStart",
    "stop": "OnSessionStop",
    "update": "OnSessionUpdate",
}
CONSOLE_HOOKS = {
    "send": "OnConsoleSend",
    "receive": "OnConsoleReceive",
}

MANUAL_HOOKS_WITHOUT_CONTEXT = {
    "ManualStart",
    "OnStart",
    "OnStop",
    "OnListenerStart",
    "OnListenerStop",
}

SCRIPT_NAME_ROLE = Qt.ItemDataRole.UserRole

COL_ENABLED = 0
COL_SCRIPT = 1
COL_HOOKS = 2
COL_LAST_RUN = 3
COL_ACTIVATIONS = 4
COL_ERRORS = 5

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
        apply_dark_panel_style(self)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.grpcClient = grpcClient
        self.scriptStates = {}
        self.tableItemsByScript = {}
        self.lastHookContexts = {}
        self.clientStateProvider = self.emptyClientState
        self._tableUpdating = False

        # self.logFileName=LogFileName

        self.automationTable = QTableWidget()
        self.automationTable.setColumnCount(6)
        self.automationTable.setHorizontalHeaderLabels(
            ["Active", "Script", "Hooks", "Last run", "Runs", "Errors"]
        )
        self.automationTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.automationTable.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.automationTable.setAlternatingRowColors(True)
        self.automationTable.verticalHeader().setVisible(False)
        self.automationTable.horizontalHeader().setSectionResizeMode(COL_ENABLED, QHeaderView.ResizeMode.ResizeToContents)
        self.automationTable.horizontalHeader().setSectionResizeMode(COL_SCRIPT, QHeaderView.ResizeMode.ResizeToContents)
        self.automationTable.horizontalHeader().setSectionResizeMode(COL_HOOKS, QHeaderView.ResizeMode.Stretch)
        self.automationTable.horizontalHeader().setSectionResizeMode(COL_LAST_RUN, QHeaderView.ResizeMode.ResizeToContents)
        self.automationTable.horizontalHeader().setSectionResizeMode(COL_ACTIVATIONS, QHeaderView.ResizeMode.ResizeToContents)
        self.automationTable.horizontalHeader().setSectionResizeMode(COL_ERRORS, QHeaderView.ResizeMode.ResizeToContents)
        self.automationTable.itemChanged.connect(self.onAutomationItemChanged)
        self.automationTable.itemSelectionChanged.connect(self.updateManualHookSelector)
        self.layout.addWidget(self.automationTable, 4)

        manualLayout = QHBoxLayout()
        self.manualHookSelector = QComboBox()
        self.manualHookSelector.setMinimumWidth(220)
        self.runHookButton = QPushButton("Run Hook")
        self.runHookButton.clicked.connect(self.runSelectedHook)
        manualLayout.addWidget(QLabel("Manual action:"))
        manualLayout.addWidget(self.manualHookSelector, 1)
        manualLayout.addWidget(self.runHookButton)
        self.layout.addLayout(manualLayout)

        self.editorOutput = QTextBrowser()
        apply_console_output_style(self.editorOutput)
        self.editorOutput.setReadOnly(True)
        self.layout.addWidget(self.editorOutput, 5)

        self.commandEditor = CommandEditor()
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)

        self.buildAutomationStates()
        self.refreshAutomationTable()
        self.printLoadedAutomationSummary()


    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)


    def sessionScriptMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        hookName = SESSION_HOOKS.get(action)
        if not hookName:
            return

        self.dispatchHook(
            hookName,
            HOOK_TRIGGER_NOTES[hookName],
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
        hookName = LISTENER_HOOKS.get(action)
        if not hookName:
            return

        self.dispatchHook(hookName, HOOK_TRIGGER_NOTES[hookName], hash, str3, str4)


    def consoleScriptMethod(self, action, beaconHash, listenerHash, context, cmd, result, commandId=""):
        hookName = CONSOLE_HOOKS.get(action)
        if not hookName:
            return

        self.dispatchHook(
            hookName,
            HOOK_TRIGGER_NOTES[hookName],
            beaconHash,
            listenerHash,
            context,
            cmd,
            result,
            commandId,
        )

    def mainScriptMethod(self, action, str2, str3, str4):
        hookName = MAIN_HOOKS.get(action)
        if not hookName:
            return

        self.dispatchHook(hookName, HOOK_TRIGGER_NOTES[hookName])

    def setClientStateProvider(self, provider):
        self.clientStateProvider = provider or self.emptyClientState

    def emptyClientState(self):
        return {"sessions": [], "listeners": []}

    def clientStateSnapshot(self):
        try:
            snapshot = self.clientStateProvider()
        except Exception as exc:
            logger.warning(
                "Failed to build script client state snapshot: %s",
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            self.printInTerminal("Manual context error:", str(exc))
            return {"sessions": [], "listeners": [], "error": str(exc)}

        if not isinstance(snapshot, dict):
            return {"sessions": [], "listeners": []}

        return {
            "sessions": self.copySnapshotItems(snapshot.get("sessions", [])),
            "listeners": self.copySnapshotItems(snapshot.get("listeners", [])),
        }

    def copySnapshotItems(self, items):
        copied = []
        for item in items or []:
            if isinstance(item, dict):
                copied.append(dict(item))
        return copied

    def buildAutomationStates(self):
        self.scriptStates = {}
        for script in LoadedScripts:
            scriptName = self.scriptName(script)
            hooks = self.scriptHooks(script)
            self.scriptStates[scriptName] = {
                "script": script,
                "enabled": True,
                "hooks": hooks,
                "last_run": "Never",
                "activations": 0,
                "errors": 0,
                "last_error": "",
                "load_error": "",
            }

        for failure in FailedScripts:
            scriptName, error = self.parseFailedScript(failure)
            self.scriptStates[scriptName] = {
                "script": None,
                "enabled": False,
                "hooks": [],
                "last_run": "Never",
                "activations": 0,
                "errors": 1,
                "last_error": error,
                "load_error": error,
            }

    def refreshAutomationTable(self):
        self._tableUpdating = True
        self.tableItemsByScript = {}
        scriptNames = sorted(self.scriptStates)
        self.automationTable.setRowCount(len(scriptNames))

        for row, scriptName in enumerate(scriptNames):
            state = self.scriptStates[scriptName]
            enabledItem = QTableWidgetItem()
            enabledItem.setData(SCRIPT_NAME_ROLE, scriptName)
            enabledItem.setFlags(
                (enabledItem.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                & ~Qt.ItemFlag.ItemIsEditable
            )
            if state["script"] is None:
                enabledItem.setFlags(enabledItem.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            enabledItem.setCheckState(
                Qt.CheckState.Checked if state["enabled"] else Qt.CheckState.Unchecked
            )
            self.automationTable.setItem(row, COL_ENABLED, enabledItem)
            self.setTableItem(row, COL_SCRIPT, self.displayScriptName(scriptName), scriptName)
            self.setTableItem(row, COL_HOOKS, ", ".join(state["hooks"]) or "-", scriptName)
            self.setTableItem(row, COL_LAST_RUN, state["last_run"], scriptName)
            self.setTableItem(row, COL_ACTIVATIONS, str(state["activations"]), scriptName)
            self.setTableItem(row, COL_ERRORS, str(state["errors"]), scriptName)
            self.updateAutomationRowTooltip(row, scriptName)
            self.tableItemsByScript[scriptName] = row

        if scriptNames and self.automationTable.currentRow() < 0:
            self.automationTable.setCurrentCell(0, COL_SCRIPT)

        self._tableUpdating = False
        self.updateManualHookSelector()

    def setTableItem(self, row, column, text, scriptName):
        item = QTableWidgetItem(text)
        item.setData(SCRIPT_NAME_ROLE, scriptName)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.automationTable.setItem(row, column, item)

    def updateAutomationRow(self, scriptName):
        row = self.tableItemsByScript.get(scriptName)
        if row is None:
            return

        state = self.scriptStates[scriptName]
        self._tableUpdating = True
        enabledItem = self.automationTable.item(row, COL_ENABLED)
        if enabledItem is not None:
            enabledItem.setCheckState(
                Qt.CheckState.Checked if state["enabled"] else Qt.CheckState.Unchecked
            )
        self.automationTable.item(row, COL_LAST_RUN).setText(state["last_run"])
        self.automationTable.item(row, COL_ACTIVATIONS).setText(str(state["activations"]))
        self.automationTable.item(row, COL_ERRORS).setText(str(state["errors"]))
        self.updateAutomationRowTooltip(row, scriptName)
        self._tableUpdating = False

    def updateAutomationRowTooltip(self, row, scriptName):
        state = self.scriptStates[scriptName]
        hookNotes = []
        for hookName in state["hooks"]:
            hookNotes.append(f"{hookName}: {HOOK_TRIGGER_NOTES.get(hookName, 'Custom hook.')}")
        tooltip = "\n".join(hookNotes) or state["last_error"] or "No hook detected."
        if state["last_error"]:
            tooltip += "\nLast error: " + state["last_error"]
        for column in range(self.automationTable.columnCount()):
            item = self.automationTable.item(row, column)
            if item is not None:
                item.setToolTip(tooltip)

    def onAutomationItemChanged(self, item):
        if self._tableUpdating or item.column() != COL_ENABLED:
            return

        scriptName = item.data(SCRIPT_NAME_ROLE)
        state = self.scriptStates.get(scriptName)
        if not state or state["script"] is None:
            return

        enabled = item.checkState() == Qt.CheckState.Checked
        state["enabled"] = enabled
        self.updateAutomationRow(scriptName)
        self.updateManualHookSelector()

    def updateManualHookSelector(self):
        scriptName = self.selectedScriptName()
        state = self.scriptStates.get(scriptName)
        self.manualHookSelector.clear()

        if not state or state["script"] is None or not state["hooks"]:
            self.runHookButton.setEnabled(False)
            return

        for hookName in state["hooks"]:
            self.manualHookSelector.addItem(hookName, hookName)
            index = self.manualHookSelector.count() - 1
            self.manualHookSelector.setItemData(
                index,
                HOOK_TRIGGER_NOTES.get(hookName, ""),
                Qt.ItemDataRole.ToolTipRole,
            )
        self.runHookButton.setEnabled(True)

    def selectedScriptName(self):
        row = self.automationTable.currentRow()
        if row < 0:
            return ""
        item = self.automationTable.item(row, COL_SCRIPT)
        if item is None:
            return ""
        return item.data(SCRIPT_NAME_ROLE) or ""

    def scriptName(self, script):
        return getattr(script, "__name__", script.__class__.__name__)

    def displayScriptName(self, scriptName):
        return scriptName.split(".")[-1]

    def scriptHooks(self, script):
        hooks = []
        for hookName in HOOK_ORDER:
            if callable(getattr(script, hookName, None)):
                hooks.append(hookName)
        return hooks

    def parseFailedScript(self, failure):
        scriptName, separator, error = str(failure).partition(":")
        return scriptName.strip() or "unknown", error.strip() if separator else str(failure)

    def printLoadedAutomationSummary(self):
        loaded = []
        for scriptName, state in sorted(self.scriptStates.items()):
            if state["script"] is None:
                continue
            loaded.append(f"{self.displayScriptName(scriptName)}: {', '.join(state['hooks']) or 'no hooks'}")
        self.printInTerminal("Loaded automations:", "\n".join(loaded) or "No script loaded.")

        failed = []
        for scriptName, state in sorted(self.scriptStates.items()):
            if state["script"] is None:
                failed.append(f"{scriptName}: {state['last_error']}")
        if failed:
            self.printInTerminal("Script load errors:", "\n".join(failed))

    def dispatchHook(self, hookName, triggerDescription, *args):
        self.lastHookContexts[hookName] = {
            "args": args,
            "trigger": triggerDescription,
            "updated_at": datetime.now(),
        }

        for state in self.scriptStates.values():
            script = state["script"]
            if script is not None:
                self.runScriptHook(script, hookName, hookName, *args)

    def runScriptHook(self, script, hookName, displayName, *args):
        scriptName = getattr(script, "__name__", script.__class__.__name__)
        hook = getattr(script, hookName, None)
        if hook is None:
            return False

        state = self.scriptStates.get(scriptName)
        if state is None:
            state = {
                "script": script,
                "enabled": True,
                "hooks": self.scriptHooks(script),
                "last_run": "Never",
                "activations": 0,
                "errors": 0,
                "last_error": "",
                "load_error": "",
            }
            self.scriptStates[scriptName] = state
            self.refreshAutomationTable()

        if not state["enabled"]:
            self.updateAutomationRow(scriptName)
            return False

        state["activations"] += 1
        state["last_run"] = datetime.now().strftime("%H:%M:%S")
        self.updateAutomationRow(scriptName)

        try:
            output = self.invokeScriptHook(hook, *args)
        except Exception as exc:
            state["errors"] += 1
            state["last_error"] = f"{hookName}: {exc}"
            self.updateAutomationRow(scriptName)
            logger.warning(
                "Script hook %s.%s failed: %s",
                scriptName,
                hookName,
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            self.printInTerminal("Script error:", f"{scriptName}.{hookName}: {exc}")
            return False

        state["last_error"] = ""
        self.updateAutomationRow(scriptName)
        if output:
            self.printInTerminal(displayName, output)
        return True

    def invokeScriptHook(self, hook, *args):
        fullArgs = (self.grpcClient, *args)
        try:
            signature = inspect.signature(hook)
        except (TypeError, ValueError):
            return hook(*fullArgs)

        parameters = list(signature.parameters.values())
        if any(param.kind == inspect.Parameter.VAR_POSITIONAL for param in parameters):
            return hook(*fullArgs)

        positional = [
            param for param in parameters
            if param.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        return hook(*fullArgs[:len(positional)])

    def runSelectedHook(self):
        scriptName = self.selectedScriptName()
        state = self.scriptStates.get(scriptName)
        hookName = self.manualHookSelector.currentData()
        if not state or state["script"] is None or not hookName:
            self.printInTerminal("Manual run blocked:", "Select a loaded script and hook first.")
            return

        if not state["enabled"]:
            self.printInTerminal("Manual run blocked:", f"{self.displayScriptName(scriptName)} is disabled.")
            return

        context = self.lastHookContexts.get(hookName)
        if hookName == "ManualStart":
            args = (self.clientStateSnapshot(),)
        elif context is None and hookName not in MANUAL_HOOKS_WITHOUT_CONTEXT:
            self.printInTerminal(
                "Manual run blocked:",
                f"{hookName} needs a captured trigger context. Trigger it once from the UI first.",
            )
            return
        else:
            args = context["args"] if context is not None else ()
        self.printInTerminal("Manual run:", f"{self.displayScriptName(scriptName)}.{hookName}")
        self.runScriptHook(state["script"], hookName, hookName, *args)


    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)


    def printInTerminal(self, cmd, result):
        self.sem.acquire()
        try:
            marker, tone = self._console_role_for_header(cmd)
            has_entry = bool(cmd or result)
            append_console_block(
                self.editorOutput,
                cmd,
                result,
                marker=marker,
                tone=tone,
            )
            if has_entry:
                append_console_spacing(self.editorOutput)
        finally:
            self.sem.release()

    def _console_role_for_header(self, header):
        normalized = str(header or "").strip().rstrip(":").lower()
        if normalized in {
            "loaded automations",
            "automation command",
            "manual context error",
            "manual run blocked",
        }:
            return "[system]", "system"
        if normalized in {"script load errors", "script error"}:
            return "[error]", "error"
        if normalized == "manual run":
            return "[user]", "user"
        return "[script]", "script"


    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "")

        else:
            self.printInTerminal(
                "Automation command:",
                "Use the table to enable scripts and run hooks manually.",
            )
            

        self.setCursorEditorAtEnd()


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
