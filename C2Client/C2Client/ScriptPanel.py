import sys
import os
import logging
import importlib
from pathlib import Path
from datetime import datetime

from threading import Semaphore

from PyQt6.QtCore import Qt, QEvent, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
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
    "ManualStart": "Manual-only hook launched from the Hooks panel.",
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
# Hooks tab implementation
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
            ["Active", "Hook file", "Hooks", "Last run", "Runs", "Errors"]
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
        manualLayout.addWidget(QLabel("Manual hook:"))
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


    def sessionScriptMethod(self, action, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
        hookName = SESSION_HOOKS.get(action)
        if not hookName:
            return

        event = {
            "beacon_hash": beaconHash,
            "listener_hash": listenerHash,
            "hostname": hostname,
            "username": username,
            "arch": arch,
            "privilege": privilege,
            "os": os,
            "last_proof_of_life": lastProofOfLife,
            "killed": killed,
        }
        context = self.buildHookContext(
            hookName,
            action,
            objectType="session",
            objectId=beaconHash,
            event=event,
        )
        self.dispatchHook(hookName, context)

    
    def listenerScriptMethod(self, action, hash, str3, str4):
        hookName = LISTENER_HOOKS.get(action)
        if not hookName:
            return

        event = {
            "listener_hash": hash,
            "type": str3,
            "host": str4,
        }
        context = self.buildHookContext(
            hookName,
            action,
            objectType="listener",
            objectId=hash,
            event=event,
        )
        self.dispatchHook(hookName, context)


    def consoleScriptMethod(self, action, beaconHash, listenerHash, context, cmd, result, commandId=""):
        hookName = CONSOLE_HOOKS.get(action)
        if not hookName:
            return

        event = {
            "beacon_hash": beaconHash,
            "listener_hash": listenerHash,
            "console_context": context,
            "command": cmd,
            "result": result,
            "command_id": commandId,
        }
        hookContext = self.buildHookContext(
            hookName,
            action,
            objectType="session",
            objectId=beaconHash,
            event=event,
        )
        self.dispatchHook(hookName, hookContext)

    def mainScriptMethod(self, action, str2, str3, str4):
        hookName = MAIN_HOOKS.get(action)
        if not hookName:
            return

        context = self.buildHookContext(
            hookName,
            action,
            event={"action": action},
        )
        self.dispatchHook(hookName, context)

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

    def buildHookContext(self, hookName, trigger, *, objectType="", objectId="", event=None):
        snapshot = self.clientStateSnapshot()
        event = dict(event or {})
        objectType = str(objectType or "")
        objectId = str(objectId or "")
        resolvedObject = self.resolveSnapshotObject(snapshot, objectType, objectId)

        context = {
            "hook": hookName,
            "trigger": trigger,
            "trigger_description": HOOK_TRIGGER_NOTES.get(hookName, ""),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "object_type": objectType,
            "object_id": objectId,
            "object": resolvedObject,
            "sessions": snapshot.get("sessions", []),
            "listeners": snapshot.get("listeners", []),
            "event": event,
        }
        if "error" in snapshot:
            context["snapshot_error"] = snapshot["error"]
        return context

    def resolveSnapshotObject(self, snapshot, objectType, objectId):
        if not objectType or not objectId:
            return None

        if objectType == "session":
            collection = snapshot.get("sessions", [])
            keys = ("beacon_hash", "id")
        elif objectType == "listener":
            collection = snapshot.get("listeners", [])
            keys = ("listener_hash", "id")
        else:
            return None

        objectId = str(objectId)
        for item in collection:
            for key in keys:
                if str(item.get(key, "")) == objectId:
                    return dict(item)
        return None

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
                "description": self.scriptDescription(script),
                "hook_descriptions": self.scriptHookDescriptions(script),
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
                "description": "",
                "hook_descriptions": {},
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
        if state.get("description"):
            hookNotes.append(state["description"])
        for hookName in state["hooks"]:
            hookNotes.append(f"{hookName}: {self.hookDescription(state, hookName)}")
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
                self.hookDescription(state, hookName),
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

    def scriptDescription(self, script):
        description = getattr(script, "DESCRIPTION", "") or getattr(script, "__doc__", "")
        return str(description or "").strip()

    def scriptHookDescriptions(self, script):
        descriptions = getattr(script, "HOOK_DESCRIPTIONS", {}) or {}
        if not isinstance(descriptions, dict):
            return {}
        return {
            str(hookName): str(description).strip()
            for hookName, description in descriptions.items()
            if str(description).strip()
        }

    def hookDescription(self, state, hookName):
        return (
            state.get("hook_descriptions", {}).get(hookName)
            or HOOK_TRIGGER_NOTES.get(hookName, "Custom hook.")
        )

    def parseFailedScript(self, failure):
        scriptName, separator, error = str(failure).partition(":")
        return scriptName.strip() or "unknown", error.strip() if separator else str(failure)

    def printLoadedAutomationSummary(self):
        loaded = []
        for scriptName, state in sorted(self.scriptStates.items()):
            if state["script"] is None:
                continue
            loaded.append(f"{self.displayScriptName(scriptName)}: {', '.join(state['hooks']) or 'no hooks'}")
        self.printInTerminal("Loaded hooks:", "\n".join(loaded) or "No hook file loaded.")

        failed = []
        for scriptName, state in sorted(self.scriptStates.items()):
            if state["script"] is None:
                failed.append(f"{scriptName}: {state['last_error']}")
        if failed:
            self.printInTerminal("Hook load errors:", "\n".join(failed))

    def dispatchHook(self, hookName, context):
        self.lastHookContexts[hookName] = context

        for state in self.scriptStates.values():
            script = state["script"]
            if script is not None:
                self.runScriptHook(script, hookName, hookName, context)

    def runScriptHook(self, script, hookName, displayName, context):
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
                "description": self.scriptDescription(script),
                "hook_descriptions": self.scriptHookDescriptions(script),
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
            output = self.invokeScriptHook(hook, context)
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

    def invokeScriptHook(self, hook, context):
        return hook(self.grpcClient, context)

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

        if hookName == "ManualStart":
            context = self.buildHookContext(hookName, "manual", event={"action": "manual"})
        else:
            context = self.lastHookContexts.get(hookName)

        if context is None:
            self.printInTerminal(
                "Manual run blocked:",
                f"{hookName} needs a captured trigger context. Trigger it once from the UI first.",
            )
            return
        self.printInTerminal("Manual run:", f"{self.displayScriptName(scriptName)}.{hookName}")
        self.runScriptHook(state["script"], hookName, hookName, context)


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
            "loaded hooks",
            "hook command",
            "manual context error",
            "manual run blocked",
        }:
            return "[system]", "system"
        if normalized in {"hook load errors", "script error"}:
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
                "Hook command:",
                "Use the table to enable hook files and run hooks manually.",
            )
            

        self.setCursorEditorAtEnd()


    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        move_editor_to_end(self.editorOutput)


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def clearLine(self):
        self.clear()
