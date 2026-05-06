import sys
import os
import json
import logging
import re
import subprocess
from datetime import datetime
from typing import Any
from PyQt6.QtCore import Qt, QEvent, QThread, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QStandardItem, QStandardItemModel, QShortcut, QTextCursor, QTextDocument
from PyQt6.QtWidgets import (
    QCompleter,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .grpcClient import TeamServerApi_pb2
from .console_style import (
    CONSOLE_COLORS,
    apply_console_output_style,
    append_console_block,
    append_console_spacing,
    move_editor_to_end,
)
from .env import env_path
from .grpc_status import is_response_ok, terminal_response_text
from .panel_style import apply_dark_panel_style
from .TerminalModules.Batcave import batcave
from .TerminalModules.Credentials import credentials

from git import Repo 

logger = logging.getLogger(__name__)


#
# Dropper modules
#
configuredDropperModulesDir = env_path("C2_DROPPER_MODULES_DIR")
configuredDropperModulesPath = env_path("C2_DROPPER_MODULES_CONF")
try:
    import pkg_resources
    defaultDropperModulesDir = pkg_resources.resource_filename(
        'C2Client',  
        'DropperModules' 
    )
    defaultDropperModulesPath = pkg_resources.resource_filename(
        'C2Client',  
        'DropperModules.conf'  
    )

except ImportError:
    defaultDropperModulesDir = os.path.join(os.path.dirname(__file__), 'DropperModules')
    defaultDropperModulesPath = os.path.join(os.path.dirname(__file__), 'DropperModules.conf')

dropperModulesDir = str(configuredDropperModulesDir) if configuredDropperModulesDir else defaultDropperModulesDir
DropperModulesPath = str(configuredDropperModulesPath) if configuredDropperModulesPath else defaultDropperModulesPath

if not os.path.exists(dropperModulesDir):
    os.makedirs(dropperModulesDir)

with open(DropperModulesPath, "r") as file:
    repositories = file.readlines()

DropperModules = []
for repo in repositories:
    repo = repo.strip()
    repoName = repo.split('/')[-1].replace('.git', '')
    repoPath = os.path.join(dropperModulesDir, repoName)

    if not os.path.exists(repoPath):
        logger.info("Cloning %s in %s.", repoName, repoPath)
        try:
            Repo.clone_from(repo, repoPath)
        except Exception as exc:
            logger.warning(
                "Failed to clone %s: %s",
                repoName,
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
    else:
        logger.debug("Repository %s already exists in %s.", repoName, dropperModulesDir)

for moduleName in os.listdir(dropperModulesDir):
    modulePath = os.path.join(dropperModulesDir, moduleName)
    
    if os.path.isdir(modulePath):
        if os.path.exists(modulePath):
            sys.path.insert(1, modulePath)
            try:
                # Dynamically import the module
                importedModule = __import__(moduleName)
                DropperModules.append(importedModule)
                logger.debug("Imported dropper module %s", moduleName)
            except ImportError as exc:
                logger.warning(
                    "Failed to import dropper module %s: %s",
                    moduleName,
                    exc,
                    exc_info=logger.isEnabledFor(logging.DEBUG),
                )

configuredShellCodeModulesDir = env_path("C2_SHELLCODE_MODULES_DIR")
configuredShellCodeModulesPath = env_path("C2_SHELLCODE_MODULES_CONF")
try:
    import pkg_resources
    defaultShellCodeModulesDir = pkg_resources.resource_filename(
        'C2Client',  
        'ShellCodeModules' 
    )
    defaultShellCodeModulesPath = pkg_resources.resource_filename(
        'C2Client',  
        'ShellCodeModules.conf'  
    )

except ImportError:
    defaultShellCodeModulesDir = os.path.join(os.path.dirname(__file__), 'ShellCodeModules')
    defaultShellCodeModulesPath = os.path.join(os.path.dirname(__file__), 'ShellCodeModules.conf')

shellCodeModulesDir = str(configuredShellCodeModulesDir) if configuredShellCodeModulesDir else defaultShellCodeModulesDir
ShellCodeModulesPath = str(configuredShellCodeModulesPath) if configuredShellCodeModulesPath else defaultShellCodeModulesPath

if not os.path.exists(shellCodeModulesDir):
    os.makedirs(shellCodeModulesDir)

with open(ShellCodeModulesPath, "r") as file:
    repositories = file.readlines()

ShellCodeModules = []
for repo in repositories:
    repo = repo.strip()
    repoName = repo.split('/')[-1].replace('.git', '')
    repoPath = os.path.join(shellCodeModulesDir, repoName)

    if not os.path.exists(repoPath):
        logger.info("Cloning %s in %s.", repoName, repoPath)
        try:
            Repo.clone_from(repo, repoPath)
        except Exception as exc:
            logger.warning(
                "Failed to clone %s: %s",
                repoName,
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
    else:
        logger.debug("Repository %s already exists in %s.", repoName, shellCodeModulesDir)

for moduleName in os.listdir(shellCodeModulesDir):
    modulePath = os.path.join(shellCodeModulesDir, moduleName)
    
    if os.path.isdir(modulePath):
        if os.path.exists(modulePath):
            sys.path.insert(1, modulePath)
            try:
                # Dynamically import the module
                importedModule = __import__(moduleName)
                ShellCodeModules.append(importedModule)
                logger.debug("Imported shellcode module %s", moduleName)
            except ImportError as exc:
                logger.warning(
                    "Failed to import shellcode module %s: %s",
                    moduleName,
                    exc,
                    exc_info=logger.isEnabledFor(logging.DEBUG),
                )


#
# Log
#
configuredLogsDir = env_path("C2_LOG_DIR")
if configuredLogsDir:
    logsDir = str(configuredLogsDir)
else:
    try:
        import pkg_resources
        logsDir = pkg_resources.resource_filename(
            'C2Client',
            'logs'
        )

    except ImportError:
        logsDir = os.path.join(os.path.dirname(__file__), 'logs')

if not os.path.exists(logsDir):
    os.makedirs(logsDir)


#
# Constant
#
LogFileName = "Terminal.log"
HistoryFileName = ".termHistory"

HttpType = "http"
HttpsType = "https"

GrpcGetBeaconBinaryInstruction = "getBeaconBinary"
GrpcHostArtifactInstruction = "hostArtifact"
GrpcPutIntoUploadDirInstruction = "putIntoUploadDir"
GrpcInfoListenerInstruction = "infoListener"
GrpcBatcaveUploadToolInstruction = "batcaveUpload"
GrpcSocksInstruction = "socks"
GrpcReloadModulesInstruction = "reloadModules";

BeaconFileWindowsPattern = "Beacon-{}.exe"
BeaconFileLinuxGenerated = "Beacon-linux"

ErrorInstruction = "Error"


def isTerminalResponseError(response):
    return not is_response_ok(response) or ErrorInstruction in terminal_response_text(response)

HelpInstruction = "Help"

SocksInstruction = "Socks"
SocksHelp = """Socks:
Socks start
Socks bind beaconHash
Socks unbind
Socks stop"""

BatcaveInstruction = "Batcave"
BatcaveHelp = """Batcave:
Install the given module locally or on the team server:
exemple:
- Batcave Install rubeus
- Batcave BundleInstall recon
- Batcave Search rec"""

DropperInstruction = "Dropper"
DropperConfigSubInstruction = "Config"
DropperConfigShellcodeGeneratorDisplay = "ShellcodeGenerator"
DropperConfigShellcodeGeneratorKey = DropperConfigShellcodeGeneratorDisplay.lower()
DropperConfigBeaconArchDisplay = "BeaconArch"
DropperConfigBeaconArchKey = DropperConfigBeaconArchDisplay.lower()
ShellcodeGeneratorDonut = "Donut"
DefaultWindowsArch = "x64"
SupportedWindowsArchs = ("x86", "x64", "arm64")
DropperAvailableHeader = "- Available dropper:\n"
DropperArchitectureHelp = (
    "\nArchitecture:\n"
    "  Dropper Config BeaconArch x86|x64|arm64\n"
    "  Dropper <module> <listenerDownload> <listenerBeacon> --arch x86|x64|arm64\n"
)
DropperThreadRunningMessage = "Dropper thread already running"
DropperConfigHeader = "- Dropper Config:"
DropperConfigShellcodeGeneratorLine = f"  {DropperConfigShellcodeGeneratorDisplay}: {{}}"
DropperConfigShellcodeGeneratorAvailableLine = "    Available: {}"
DropperConfigBeaconArchLine = f"  {DropperConfigBeaconArchDisplay}: {{}}"
DropperConfigBeaconArchAvailableLine = "    Available: {}"
DropperConfigUnknownOptionError = "Error: Unknown dropper config option."
DropperConfigUnknownValueError = "Error: Unknown shellcode generator."
DropperConfigUnknownArchError = "Error: Unknown beacon architecture."
DropperConfigUpdatedMessage = "Shellcode generator set to {}."
DropperConfigBeaconArchUpdatedMessage = "Beacon architecture set to {}."
DropperArchFlagPattern = re.compile(r"^--(?:beacon-)?arch=(.+)$", re.IGNORECASE)
DonutShellcodeGeneratorMessage = "Donut Shellcode generator"
DonutShellcodeFileName = "loader.bin"
ModuleShellcodeFileName = "finalShellcode.bin"

DropperModuleGetHelpFunction = "getHelpExploration"
DropperModuleGeneratePayloadFunction = "generatePayloadsExploration"

HostInstruction = "Host"
HostHelp="""Host:
Host a TeamServer artifact so it can be downloaded by a web request from an HTTP/HTTPS listener:
exemple:
- Host artifactId hostListenerHash
- Host artifactId hostListenerHash hostedName.exe"""

CredentialStoreInstruction = "CredentialStore"
CredentialStoreHelp = """CredentialStore:
Handle the credential store:
exemple:
- CredentialStore get
- CredentialStore set domain username credential
- CredentialStore search something"""

GetSubInstruction = "get"
SetSubInstruction = "set"
SearchSubInstruction = "search"

ReloadModulesInstruction = "ReloadModules";
ReloadModulesHelp = """ReloadModules:
Command the TeamServer to reload the modules libraries located in TeamServerModulesDirectoryPath.
Can be used to add a new functionality without restarting the TeamServer.
"""


def getHelpMsg():
    helpText  = HostInstruction+"\n"
    helpText += DropperInstruction+"\n"
    helpText += BatcaveInstruction+"\n"
    helpText += CredentialStoreInstruction+"\n"
    helpText += SocksInstruction+"\n"
    helpText += ReloadModulesInstruction
    return helpText


def normalizeWindowsArch(arch):
    normalized = (arch or "").lower()
    if normalized in ("amd64", "x86_64"):
        return "x64"
    if normalized in ("i386", "i686"):
        return "x86"
    if normalized == "aarch64":
        return "arm64"
    if normalized in SupportedWindowsArchs:
        return normalized
    return ""


def donutArchValue(arch):
    # Python donut follows Donut's C constants for x86/x64. Some packaged
    # versions may reject ARM64 even though the teamserver-side Donut supports it.
    if arch == "x86":
        return 1
    if arch == "x64":
        return 2
    if arch == "arm64":
        return 4
    return 2


def makeBeaconFilePath(targetOs, targetArch):
    if (targetOs or "").lower() == "windows":
        return "./" + BeaconFileWindowsPattern.format(targetArch)
    return "./" + BeaconFileLinuxGenerated


def createDonutShellcode(beaconFilePath, beaconArg, targetArch, outputPath=DonutShellcodeFileName):
    outputPath = os.path.abspath(outputPath)
    if os.path.exists(outputPath):
        os.remove(outputPath)

    code = r"""
import os
import sys
import donut

result = donut.create(file=sys.argv[1], params=sys.argv[2], arch=int(sys.argv[3]))
output_path = sys.argv[4]
if isinstance(result, bytes) and result:
    with open(output_path, "wb") as output:
        output.write(result)
elif isinstance(result, bytearray) and result:
    with open(output_path, "wb") as output:
        output.write(bytes(result))
elif not os.path.isfile(output_path):
    raise RuntimeError("donut.create did not return shellcode and did not create the output file")
"""

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            beaconFilePath,
            beaconArg,
            str(donutArchValue(targetArch)),
            outputPath,
        ],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
    )

    if completed.returncode < 0:
        return f"Donut shellcode generation crashed with signal {-completed.returncode}."
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}"
        return "Donut shellcode generation failed: " + detail
    if not os.path.isfile(outputPath) or os.path.getsize(outputPath) == 0:
        return "Donut shellcode generation failed: output shellcode is missing or empty."
    return ""


def extractDropperTargetArch(arguments, defaultArch=DefaultWindowsArch):
    targetArch = normalizeWindowsArch(defaultArch) or DefaultWindowsArch
    remainingArgs = []
    skipNext = False

    for index, argument in enumerate(arguments):
        if skipNext:
            skipNext = False
            continue

        archMatch = DropperArchFlagPattern.match(argument)
        if archMatch:
            normalized = normalizeWindowsArch(archMatch.group(1))
            if not normalized:
                return "", arguments
            targetArch = normalized
            continue

        if argument.lower() in ("--arch", "--beacon-arch"):
            if index + 1 >= len(arguments):
                return "", arguments
            normalized = normalizeWindowsArch(arguments[index + 1])
            if not normalized:
                return "", arguments
            targetArch = normalized
            skipNext = True
            continue

        remainingArgs.append(argument)

    return targetArch, remainingArgs

def _add_completion_path(entries: list[tuple[str, list]], parts: list[str]) -> None:
    if not parts:
        return
    head = str(parts[0]).strip()
    if not head:
        return
    for index, (text, children) in enumerate(entries):
        if text == head:
            if len(parts) > 1:
                _add_completion_path(children, parts[1:])
            entries[index] = (text, children)
            return
    children: list[tuple[str, list]] = []
    entries.append((head, children))
    if len(parts) > 1:
        _add_completion_path(children, parts[1:])


def _merge_completion_entries(destination: list[tuple[str, list]], source: list[tuple[str, list]]) -> None:
    for text, children in source:
        _add_completion_path(destination, [text])
        destination_entry = next(entry for entry in destination if entry[0] == text)
        if children:
            _merge_completion_entries(destination_entry[1], children)


def _field(value: Any, name: str, default: Any = "") -> Any:
    return getattr(value, name, default)


def _safe_completion_token(value: Any) -> str:
    text = str(value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return ""
    return text


def _artifact_completion_values(artifact: Any) -> list[str]:
    values = []
    artifact_id = _safe_completion_token(_field(artifact, "artifact_id"))
    if artifact_id:
        values.append(artifact_id)
        if len(artifact_id) > 12:
            values.append(artifact_id[:12])
    for field_name in ("name", "display_name"):
        token = _safe_completion_token(_field(artifact, field_name))
        if token:
            values.append(token)
    return list(dict.fromkeys(values))


def _listener_completion_values(listener: Any) -> list[str]:
    listener_hash = _safe_completion_token(_field(listener, "listener_hash"))
    if not listener_hash:
        return []
    values = [listener_hash]
    if len(listener_hash) > 8:
        values.append(listener_hash[:8])
    return list(dict.fromkeys(values))


def _session_completion_values(session: Any) -> list[str]:
    beacon_hash = _safe_completion_token(_field(session, "beacon_hash"))
    if not beacon_hash:
        return []
    values = [beacon_hash]
    if len(beacon_hash) > 8:
        values.append(beacon_hash[:8])
    return list(dict.fromkeys(values))


def _module_completion_name(module: Any) -> str:
    return _safe_completion_token(getattr(module, "__name__", ""))


def _artifact_entries(artifacts: list[Any], children: list[tuple[str, list]]) -> list[tuple[str, list]]:
    entries: list[tuple[str, list]] = []
    for artifact in artifacts:
        for value in _artifact_completion_values(artifact):
            _add_completion_path(entries, [value])
            artifact_entry = next(entry for entry in entries if entry[0] == value)
            _merge_completion_entries(artifact_entry[1], children)
    if not entries:
        entries.append(("<artifact_id|name>", children.copy()))
    return entries


def _listener_entries(listeners: list[Any], children: list[tuple[str, list]] | None = None) -> list[tuple[str, list]]:
    entries: list[tuple[str, list]] = []
    for listener in listeners:
        for value in _listener_completion_values(listener):
            _add_completion_path(entries, [value])
            if children:
                listener_entry = next(entry for entry in entries if entry[0] == value)
                _merge_completion_entries(listener_entry[1], children)
    if not entries:
        entries.append(("<listener_hash>", children.copy() if children else []))
    return entries


def _session_entries(sessions: list[Any]) -> list[tuple[str, list]]:
    entries: list[tuple[str, list]] = []
    for session in sessions:
        for value in _session_completion_values(session):
            _add_completion_path(entries, [value])
    if not entries:
        entries.append(("<beacon_hash>", []))
    return entries


def build_terminal_completer_data(grpcClient: Any = None) -> list[tuple[str, list]]:
    listeners: list[Any] = []
    artifacts: list[Any] = []
    sessions: list[Any] = []
    if grpcClient is not None:
        try:
            listeners = list(grpcClient.listListeners())
        except Exception as exc:
            logger.debug("Terminal autocomplete could not load listeners: %s", exc)
        try:
            artifacts = list(grpcClient.listArtifacts())
        except Exception as exc:
            logger.debug("Terminal autocomplete could not load artifacts: %s", exc)
        try:
            sessions = list(grpcClient.listSessions())
        except Exception as exc:
            logger.debug("Terminal autocomplete could not load sessions: %s", exc)

    terminal_commands = [
        HostInstruction,
        DropperInstruction,
        BatcaveInstruction,
        CredentialStoreInstruction,
        SocksInstruction,
        ReloadModulesInstruction,
    ]
    listener_with_optional_filename = _listener_entries(listeners, [("<hosted_filename>", [])])
    listener_then_listener = _listener_entries(listeners, _listener_entries(listeners, [("--arch", [(arch, []) for arch in SupportedWindowsArchs])]))
    dropper_module_entries: list[tuple[str, list]] = []
    for module in DropperModules:
        module_name = _module_completion_name(module)
        if module_name:
            _add_completion_path(dropper_module_entries, [module_name])
            module_entry = next(entry for entry in dropper_module_entries if entry[0] == module_name)
            _merge_completion_entries(module_entry[1], listener_then_listener)

    shellcode_generator_entries = [(ShellcodeGeneratorDonut, [])]
    for module in ShellCodeModules:
        module_name = _module_completion_name(module)
        if module_name and module_name != ShellcodeGeneratorDonut:
            shellcode_generator_entries.append((module_name, []))

    dropper_children = [
        (
            DropperConfigSubInstruction,
            [
                (DropperConfigShellcodeGeneratorDisplay, shellcode_generator_entries),
                (DropperConfigBeaconArchDisplay, [(arch, []) for arch in SupportedWindowsArchs]),
            ],
        ),
        *dropper_module_entries,
    ]
    if not dropper_module_entries:
        dropper_children.append(("<dropper_module>", listener_then_listener))

    return [
        (HelpInstruction, [(command, []) for command in terminal_commands]),
        (HostInstruction, _artifact_entries(artifacts, listener_with_optional_filename)),
        (DropperInstruction, dropper_children),
        (BatcaveInstruction, [("Install", []), ("BundleInstall", []), ("Search", [])]),
        (CredentialStoreInstruction, [(GetSubInstruction, []), (SetSubInstruction, []), (SearchSubInstruction, [])]),
        (SocksInstruction, [("start", []), ("stop", []), ("unbind", []), ("bind", _session_entries(sessions))]),
        (ReloadModulesInstruction, []),
    ]

InfoProcessing = "Processing..." 
ErrorCmdUnknow = "Error: Command Unknown"
ErrorFileNotFound = "Error: File doesn't exist."
ErrorListener = "Error: Download listener must be of type http or https."
TerminalWelcomeMessage = (
    "Local TeamServer terminal. Type Help to list available commands, "
    "or Help <command> for command-specific details."
)


#
# Terminal tab implementation
#
class Terminal(QWidget):
    tabPressed = pyqtSignal()

    def __init__(self, parent, grpcClient):
        super().__init__(parent)
        apply_dark_panel_style(self)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(6)

        self.grpcClient = grpcClient
        self.dropperConfig = {
            DropperConfigShellcodeGeneratorKey: ShellcodeGeneratorDonut,
            DropperConfigBeaconArchKey: DefaultWindowsArch,
        }

        self.logFileName = LogFileName
        self.dropperWorker = None
        self.thread = None

        self.searchInput = QLineEdit()
        self.searchInput.setPlaceholderText("Search output")
        self.searchInput.setFixedHeight(26)
        self.searchInput.returnPressed.connect(self.findNextSearchMatch)
        self.findPreviousButton = QPushButton("Prev")
        self.findPreviousButton.setFixedHeight(26)
        self.findPreviousButton.clicked.connect(lambda _checked=False: self.findNextSearchMatch(backward=True))
        self.findNextButton = QPushButton("Next")
        self.findNextButton.setFixedHeight(26)
        self.findNextButton.clicked.connect(lambda _checked=False: self.findNextSearchMatch())
        self.clearOutputButton = QPushButton("Clear")
        self.clearOutputButton.setFixedHeight(26)
        self.clearOutputButton.clicked.connect(self.clearTerminalOutput)
        self.exportLogButton = QPushButton("Export")
        self.exportLogButton.setFixedHeight(26)
        self.exportLogButton.clicked.connect(self.exportTerminalOutput)
        self.terminalNoticeLabel = QLabel("")
        self.terminalNoticeLabel.setMinimumWidth(180)
        self.terminalNoticeLabel.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        toolbarLayout = QHBoxLayout()
        toolbarLayout.setSpacing(6)
        toolbarLayout.addWidget(self.searchInput, 3)
        toolbarLayout.addWidget(self.findPreviousButton)
        toolbarLayout.addWidget(self.findNextButton)
        toolbarLayout.addWidget(self.clearOutputButton)
        toolbarLayout.addWidget(self.exportLogButton)
        toolbarLayout.addWidget(self.terminalNoticeLabel, 2)
        self.layout.addLayout(toolbarLayout)

        self.editorOutput = QTextBrowser()
        apply_console_output_style(self.editorOutput)
        self.editorOutput.setReadOnly(True)
        self.editorOutput.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.editorOutput.setLineWrapColumnOrWidth(0)
        self.layout.addWidget(self.editorOutput, 8)

        self.commandEditor = CommandEditor(grpcClient=self.grpcClient)
        self.commandEditor.setPlaceholderText("Terminal command")
        self.commandEditor.setMinimumHeight(28)
        self.layout.addWidget(self.commandEditor, 0)
        self.commandEditor.returnPressed.connect(self.runCommand)
        self.printInTerminal("Terminal", TerminalWelcomeMessage, role="system")


    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)


    def printInTerminal(self, cmd, result, role="user"):
        normalized_role = role if role in {"system", "user"} else "user"
        has_entry = bool(cmd or result)
        append_console_block(
            self.editorOutput,
            cmd,
            result,
            marker=f"[{normalized_role}]",
            tone=normalized_role,
        )
        if has_entry:
            append_console_spacing(self.editorOutput)
        self.setCursorEditorAtEnd()


    def setTerminalNotice(self, message, is_error=False):
        self.terminalNoticeLabel.setText(message)
        color = CONSOLE_COLORS["error"] if is_error else CONSOLE_COLORS["muted"]
        self.terminalNoticeLabel.setStyleSheet(f"color: {color};")


    def findNextSearchMatch(self, backward=False):
        search_text = self.searchInput.text().strip()
        if search_text == "":
            self.setTerminalNotice("Search term required.", True)
            return False

        original_cursor = self.editorOutput.textCursor()
        flags = QTextDocument.FindFlag.FindBackward if backward else QTextDocument.FindFlag(0)
        if self.editorOutput.find(search_text, flags):
            self.setTerminalNotice("Match found.")
            return True

        cursor = self.editorOutput.textCursor()
        if backward:
            cursor.movePosition(QTextCursor.MoveOperation.End)
        else:
            cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editorOutput.setTextCursor(cursor)

        if self.editorOutput.find(search_text, flags):
            self.setTerminalNotice("Search wrapped.")
            return True

        self.editorOutput.setTextCursor(original_cursor)
        self.setTerminalNotice("No match.", True)
        return False


    def clearTerminalOutput(self):
        self.editorOutput.clear()
        self.setTerminalNotice("Output cleared.")


    def exportTerminalOutput(self):
        os.makedirs(logsDir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base_name = os.path.splitext(self.logFileName)[0]
        output_path = os.path.join(logsDir, f"{base_name}_terminal_{timestamp}.log")
        with open(output_path, "w", encoding="utf-8") as exportFile:
            exportFile.write(self.editorOutput.toPlainText().rstrip())
            exportFile.write("\n")
        self.setTerminalNotice("Exported " + os.path.basename(output_path))
        return output_path
        

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "")

        else:
            cmdHistoryFile = open(HistoryFileName, 'a')
            cmdHistoryFile.write(commandLine)
            cmdHistoryFile.write('\n')
            cmdHistoryFile.close()

            logFile = open(logsDir+"/"+self.logFileName, 'a')
            logFile.write('[+] send: \"' + commandLine + '\"')
            logFile.write('\n')
            logFile.close()

            self.commandEditor.setCmdHistory()
            instructions = commandLine.split()
            if len(instructions) < 1:
                return;

            if instructions[0].lower()==HelpInstruction.lower():
                if len(instructions) == 1:
                    self.runHelp()
                elif len(instructions) >=2:
                    if instructions[1].lower() == BatcaveInstruction.lower():
                        self.printInTerminal(commandLine, BatcaveHelp)
                    elif instructions[1].lower() == HostInstruction.lower():
                        self.printInTerminal(commandLine, HostHelp)
                    elif instructions[1].lower() == CredentialStoreInstruction.lower():
                        self.printInTerminal(commandLine, CredentialStoreHelp)
                    elif instructions[1].lower() == ReloadModulesInstruction.lower():
                        self.printInTerminal(commandLine, ReloadModulesHelp)
                    elif instructions[1].lower() == DropperInstruction.lower():
                        availableModules = DropperAvailableHeader
                        for module in DropperModules:
                            availableModules += "  " + module.__name__ + "\n"
                        availableModules += DropperArchitectureHelp
                        availableModules += "\n" + self._format_shellcode_generator_summary()
                        self.printInTerminal(commandLine, availableModules)
                        return
                    elif instructions[1].lower() ==  SocksInstruction.lower():
                        self.printInTerminal(commandLine, SocksHelp)
                    else:
                        self.runHelp()
            elif instructions[0].lower()==BatcaveInstruction.lower():
                self.runBatcave(commandLine, instructions)
            elif instructions[0].lower()==HostInstruction.lower():
                self.runHost(commandLine, instructions)
            elif instructions[0].lower()==CredentialStoreInstruction.lower():
                self.runCredentialStore(commandLine, instructions)
            elif instructions[0].lower()==DropperInstruction.lower():
                self.runDropper(commandLine, instructions)
            elif instructions[0].lower()==SocksInstruction.lower():
                self.runSocks(commandLine, instructions)
            elif instructions[0].lower()==ReloadModulesInstruction.lower():
                self.runReloadModules(commandLine, instructions)
            else:
                self.printInTerminal(commandLine, ErrorCmdUnknow)

        self.setCursorEditorAtEnd()


    def runHelp(self):
        self.printInTerminal(HelpInstruction, getHelpMsg())


    def runReloadModules(self, commandLine, instructions):
        commandTeamServer = GrpcReloadModulesInstruction
        termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
        resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

        result = terminal_response_text(resultTermCommand)
        self.printInTerminal(commandLine, result)
        return   
        

    def runSocks(self, commandLine, instructions):
        if len(instructions) < 2:
            self.printInTerminal(commandLine, SocksHelp)
            return;

        cmd = instructions[1].lower()

        if cmd == "start" or cmd == "stop" or cmd == "unbind":

            commandTeamServer = GrpcSocksInstruction + " " + cmd
            termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
            resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

            result = terminal_response_text(resultTermCommand)
            self.printInTerminal(commandLine, result)
            return   
            
        elif cmd == "bind":

            if len(instructions) < 3:
                self.printInTerminal(commandLine, SocksHelp)
                return;

            beaconHash = instructions[2]

            commandTeamServer = GrpcSocksInstruction + " " + cmd + " " + beaconHash
            termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
            resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

            result = terminal_response_text(resultTermCommand)
            self.printInTerminal(commandLine, result)
        
        else:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return;

        return

    #
    # Batcave
    # 
    def runBatcave(self, commandLine, instructions):
        if len(instructions) < 3:
            self.printInTerminal(commandLine, BatcaveHelp)
            return;

        cmd = instructions[1].lower()
        batgadget = instructions[2]

        if cmd == "Install".lower():
            filePath = batcave.downloadBatGadget(batgadget)
            try:
                filename = os.path.basename(filePath)
                with open(filePath, mode='rb') as fileDesc:
                    payload = fileDesc.read()
            except IOError:
                self.printInTerminal(commandLine, ErrorFileNotFound)
                return  

            commandTeamServer = GrpcBatcaveUploadToolInstruction + " " + filename
            termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer, data=payload)
            resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

            result = terminal_response_text(resultTermCommand)
            if isTerminalResponseError(resultTermCommand):
                self.printInTerminal(commandLine, result)
                return   

            self.printInTerminal(commandLine, f"Added {filename} to TeamServer Tools.")
            return    

        elif cmd == "BundleInstall".lower():

            filePathList = batcave.downloadBatBundle(batgadget)
            line = ""
            for filePath in filePathList:
                try:
                    filename = os.path.basename(filePath)
                    with open(filePath, mode='rb') as fileDesc:
                        payload = fileDesc.read()
                except IOError:
                    self.printInTerminal(commandLine, ErrorFileNotFound)
                    return  

                commandTeamServer = GrpcBatcaveUploadToolInstruction + " " + filename
                termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer, data=payload)
                resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

                result = terminal_response_text(resultTermCommand)
                if isTerminalResponseError(resultTermCommand):
                    self.printInTerminal(commandLine, result)
                    return  

                line += f"Added {filename} to TeamServer Tools.\n"
            line += f"BatBundle {batgadget} successfully installed!"
            self.printInTerminal(commandLine, line)

        elif cmd == "Search".lower():
            result = batcave.searchTheBatcave(batgadget)
            self.printInTerminal(commandLine, result)
            return    

        else:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return     

    #
    # CredentialStore
    # 
    def runCredentialStore(self, commandLine, instructions):
        if len(instructions) < 2:
            self.printInTerminal(commandLine, CredentialStoreHelp)
            return;

        cmd = instructions[1].lower()

        if cmd == GetSubInstruction.lower():
            try:
                currentcredentials = json.loads(credentials.getCredentials(self.grpcClient, TeamServerApi_pb2))
            except (RuntimeError, json.JSONDecodeError) as exc:
                self.printInTerminal(commandLine, str(exc))
                return

            toPrint = ""
            for cred in currentcredentials:
                toPrint+=json.dumps(cred)
                toPrint+="\n"
            self.printInTerminal(commandLine, toPrint)
            
            return    

        elif cmd == SetSubInstruction.lower():
            if len(instructions) < 5:
                self.printInTerminal(commandLine, CredentialStoreHelp)
                return
            
            domain = instructions[2]
            username = instructions[3]
            credential = instructions[4]

            cred = {}
            cred["domain"] = domain
            cred["username"] = username
            cred["manual"] = credential
            try:
                result = credentials.addCredentials(self.grpcClient, TeamServerApi_pb2, json.dumps(cred))
            except (RuntimeError, json.JSONDecodeError) as exc:
                self.printInTerminal(commandLine, str(exc))
                return
            if result:
                self.printInTerminal(commandLine, result)
            return

        elif cmd == SearchSubInstruction.lower():
            if len(instructions) < 3:
                self.printInTerminal(commandLine, CredentialStoreHelp)
                return
            
            searchPatern = instructions[2]

            try:
                currentcredentials = json.loads(credentials.getCredentials(self.grpcClient, TeamServerApi_pb2))
            except (RuntimeError, json.JSONDecodeError) as exc:
                self.printInTerminal(commandLine, str(exc))
                return

            toPrint = ""
            for cred in currentcredentials:
                for key, value in cred.items():
                    if searchPatern in value:
                        toPrint+=json.dumps(cred)
                        toPrint+="\n"
            self.printInTerminal(commandLine, toPrint)
            return    

        else:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return    

    #
    # Host
    # 
    def runHost(self, commandLine, instructions):
        if len(instructions) < 3:
            self.printInTerminal(commandLine, HostHelp)
            return;

        artifactReference = instructions[1]
        hostListenerHash = instructions[2]
        hostedFilename = instructions[3] if len(instructions) >= 4 else ""

        commandTeamServer = GrpcInfoListenerInstruction+" "+hostListenerHash
        termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
        resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

        result = terminal_response_text(resultTermCommand)
        if isTerminalResponseError(resultTermCommand):
            self.printInTerminal(commandLine, result)
            return        

        results = result.split("\n")
        if len(results)<4:
            return

        schemeDownload = results[0]
        ipDownload = results[1]
        portDownload = results[2]
        downloadPath = results[3]
        if not downloadPath:
            self.printInTerminal(commandLine, ErrorListener)
            return

        if downloadPath[0]=="/":
            downloadPath = downloadPath[1:]

        commandTeamServer = GrpcHostArtifactInstruction+" "+hostListenerHash+" "+artifactReference
        if hostedFilename:
            commandTeamServer += " " + hostedFilename
        termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
        resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

        result = terminal_response_text(resultTermCommand)
        if isTerminalResponseError(resultTermCommand):
            self.printInTerminal(commandLine, result)
            return  

        hostedFilename = result.strip()
        if not hostedFilename:
            self.printInTerminal(commandLine, "Error: hosted artifact filename missing.")
            return

        hostedUrl =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + hostedFilename
        self.printInTerminal(commandLine, hostedUrl)


    def _handle_dropper_config(self, commandLine, instructions):
        if len(instructions) == 2:
            self.printInTerminal(commandLine, self._format_shellcode_generator_summary())
            return

        configKey = instructions[2].lower()
        if configKey not in (DropperConfigShellcodeGeneratorKey, DropperConfigBeaconArchKey):
            self.printInTerminal(commandLine, DropperConfigUnknownOptionError)
            return

        if len(instructions) == 3:
            self.printInTerminal(commandLine, self._format_dropper_config_summary(configKey=configKey, include_header=False))
            return

        requestedGenerator = instructions[3].lower()
        if configKey == DropperConfigBeaconArchKey:
            normalizedArch = normalizeWindowsArch(requestedGenerator)
            if not normalizedArch:
                self.printInTerminal(commandLine, DropperConfigUnknownArchError)
                return

            self.dropperConfig[DropperConfigBeaconArchKey] = normalizedArch
            self.printInTerminal(commandLine, DropperConfigBeaconArchUpdatedMessage.format(normalizedArch))
            return

        availableGenerators = self._get_available_shellcode_generators()
        selectedGenerator = None
        for generator in availableGenerators:
            if generator.lower() == requestedGenerator:
                selectedGenerator = generator
                break

        if not selectedGenerator:
            self.printInTerminal(commandLine, DropperConfigUnknownValueError)
            return

        self.dropperConfig[DropperConfigShellcodeGeneratorKey] = selectedGenerator
        self.printInTerminal(commandLine, DropperConfigUpdatedMessage.format(selectedGenerator))

    def _format_shellcode_generator_summary(self, include_header=True):
        return self._format_dropper_config_summary(include_header=include_header)

    def _format_dropper_config_summary(self, configKey=None, include_header=True):
        currentGenerator = self.dropperConfig.get(
            DropperConfigShellcodeGeneratorKey,
            ShellcodeGeneratorDonut,
        )
        availableGenerators = ", ".join(self._get_available_shellcode_generators())
        currentArch = self.dropperConfig.get(DropperConfigBeaconArchKey, DefaultWindowsArch)
        availableArchs = ", ".join(SupportedWindowsArchs)

        lines = []
        if include_header:
            lines.append(DropperConfigHeader)
        if configKey in (None, DropperConfigShellcodeGeneratorKey):
            generatorLine = DropperConfigShellcodeGeneratorLine.format(currentGenerator)
            availableLine = DropperConfigShellcodeGeneratorAvailableLine.format(availableGenerators)
            if not include_header:
                generatorLine = generatorLine.strip()
                availableLine = availableLine.strip()
            lines.append(generatorLine)
            lines.append(availableLine)
        if configKey in (None, DropperConfigBeaconArchKey):
            archLine = DropperConfigBeaconArchLine.format(currentArch)
            availableLine = DropperConfigBeaconArchAvailableLine.format(availableArchs)
            if not include_header:
                archLine = archLine.strip()
                availableLine = availableLine.strip()
            lines.append(archLine)
            lines.append(availableLine)
        return "\n".join(lines)

    def _get_available_shellcode_generators(self):
        generators = [ShellcodeGeneratorDonut]
        for module in ShellCodeModules:
            moduleName = module.__name__
            if moduleName not in generators:
                generators.append(moduleName)
        return generators


    #
    # runDropper
    #
    def runDropper(self, commandLine, instructions):
        if len(instructions) < 2:
            availableModules = DropperAvailableHeader
            for module in DropperModules:
                availableModules += "  " + module.__name__ + "\n"
            availableModules += DropperArchitectureHelp
            availableModules += "\n" + self._format_shellcode_generator_summary()
            self.printInTerminal(commandLine, availableModules)
            return

        subCommand = instructions[1].lower()

        if subCommand == DropperConfigSubInstruction.lower():
            self._handle_dropper_config(commandLine, instructions)
            return

        moduleName = subCommand

        moduleFound = False
        for module in DropperModules:

            if moduleName == module.__name__.lower():
                moduleFound = True

                if len(instructions) < 4:
                    helpText = ""
                    getHelp = getattr(module, DropperModuleGetHelpFunction)
                    helpText += getHelp()
                    helpText += DropperArchitectureHelp
                    self.printInTerminal(commandLine, helpText)
                    return;
            
                listenerDownload = instructions[2]
                listenerBeacon = instructions[3]
                targetArch, remainingArgs = extractDropperTargetArch(
                    instructions[4:],
                    self.dropperConfig.get(DropperConfigBeaconArchKey, DefaultWindowsArch),
                )
                if not targetArch:
                    self.printInTerminal(commandLine, DropperConfigUnknownArchError)
                    return
                additionalArgss = " ".join(remainingArgs)

                if self.dropperWorker:
                    self.printInTerminal(commandLine, DropperThreadRunningMessage)
                else:
                    self.thread = QThread()
                    shellcodeGenerator = self.dropperConfig.get(
                        DropperConfigShellcodeGeneratorKey,
                        ShellcodeGeneratorDonut,
                    )
                    self.dropperWorker = DropperWorker(
                        self.grpcClient,
                        commandLine,
                        moduleName,
                        listenerDownload,
                        listenerBeacon,
                        additionalArgss,
                        shellcodeGenerator,
                        targetArch,
                    )
                    self.dropperWorker.moveToThread(self.thread)
                    self.thread.started.connect(self.dropperWorker.run)
                    self.dropperWorker.finished.connect(self.printDropperResult)
                    self.thread.start()

                    self.printInTerminal(commandLine, InfoProcessing)
    
        if moduleFound == False:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return;

    def printDropperResult(self, cmd, result):
        self.printInTerminal(cmd, result)
        self.dropperWorker = None
        self.thread.quit()
        self.thread.wait()


    # setCursorEditorAtEnd
    def setCursorEditorAtEnd(self):
        move_editor_to_end(self.editorOutput)


class DropperWorker(QObject):
    finished = pyqtSignal(str, str)

    def __init__(
        self,
        grpcClient,
        commandLine,
        moduleName,
        listenerDownload,
        listenerBeacon,
        additionalArgs,
        shellcodeGenerator,
        targetArch=DefaultWindowsArch,
    ):
        super().__init__()
        self.grpcClient = grpcClient
        self.commandLine = commandLine
        self.moduleName = moduleName
        self.listenerDownload = listenerDownload
        self.listenerBeacon = listenerBeacon
        self.additionalArgs = additionalArgs
        self.shellcodeGenerator = shellcodeGenerator or ShellcodeGeneratorDonut
        self.targetArch = normalizeWindowsArch(targetArch) or DefaultWindowsArch

    def run(self):

        commandTeamServer = GrpcInfoListenerInstruction+" "+self.listenerDownload
        termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
        resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

        logger.debug("DropperWorker GenerateAndHostGeneric start")

        result = terminal_response_text(resultTermCommand)
        if isTerminalResponseError(resultTermCommand):
            self.finished.emit(self.commandLine, result)
            return        

        results = result.split("\n")
        if len(results)<4:
            return

        schemeDownload = results[0].lower()
        ipDownload = results[1]
        portDownload = results[2]
        downloadPath = results[3]
        if not downloadPath:
            self.printInTerminal(self.commandLine, ErrorListener)
            return

        if downloadPath[0]=="/":
            downloadPath = downloadPath[1:]

        if  self.listenerBeacon != self.listenerDownload:
            commandTeamServer = GrpcInfoListenerInstruction+" "+self.listenerBeacon
            termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
            resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)    

            result = terminal_response_text(resultTermCommand)
            if isTerminalResponseError(resultTermCommand):
                self.finished.emit(self.commandLine, result)
                return   

            results = result.split("\n")
            if len(results)<4:
                return

            scheme = results[0]
            ip = results[1]
            port = results[2]
        else:
            scheme=schemeDownload
            ip=ipDownload
            port=portDownload

        targetOs = "windows"
        for module in DropperModules:
            if self.moduleName == module.__name__.lower():
                logger.debug("DropperWorker GenerateAndHostGeneric check OS for module: %s", self.moduleName)
                try:
                    getTargetOs = getattr(module, "getTargetOsExploration")
                    logger.debug("Dropper module %s target OS hook: %s", self.moduleName, getTargetOs)
                    targetOs = getTargetOs().lower()
                    logger.debug("Dropper module %s target OS: %s", self.moduleName, targetOs)
                except AttributeError:
                    targetOs = "windows"

        commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+self.listenerBeacon+" "+targetOs
        if targetOs == "windows":
            commandTeamServer += " " + self.targetArch
        termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer)
        resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

        result = terminal_response_text(resultTermCommand)
        if isTerminalResponseError(resultTermCommand):
            self.finished.emit(self.commandLine, result)
            return   

        beaconFilePath = makeBeaconFilePath(targetOs, self.targetArch)
        with open(beaconFilePath, "wb") as beaconFile:
            beaconFile.write(resultTermCommand.data)

        beaconArg = ip+" "+port
        if scheme==HttpType or scheme==HttpsType:
            beaconArg = beaconArg+" "+scheme

        urlDownload =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath

        logger.debug("DropperWorker GenerateAndHostGeneric urlDownload: %s", urlDownload)

        # Generate the payload
        droppersPath = []
        shellcodesPath = []
        cmdToRun = ""
        for module in DropperModules:
            if self.moduleName == module.__name__.lower():
                logger.debug("GenerateAndHostGeneric DropperModule: %s", self.moduleName)

                shellcodeGenerator = self.shellcodeGenerator
                shellcodeGeneratorLower = shellcodeGenerator.lower()
                rawshellcode = ""

                # Check shellcode generator
                if shellcodeGeneratorLower == ShellcodeGeneratorDonut.lower():
                    logger.debug(DonutShellcodeGeneratorMessage)
                    donutError = createDonutShellcode(beaconFilePath, beaconArg, self.targetArch)
                    if donutError:
                        self.finished.emit(self.commandLine, "Error: " + donutError)
                        return
                    beaconArg = ""
                    beaconFilePath = ""
                    rawshellcode = DonutShellcodeFileName

                else:
                    for ShellCodeModule in ShellCodeModules:
                        logger.debug("ShellCodeModule: %s", ShellCodeModule)

                        if shellcodeGeneratorLower == ShellCodeModule.__name__.lower():
                            logger.debug("GenerateAndHostGeneric ShellCodeModule: %s", ShellCodeModule.__name__)

                            genShellcode = getattr(ShellCodeModule, "buildLoaderShellcode")
                            genShellcode(beaconFilePath, "", beaconArg, 3)

                            beaconArg = ""
                            beaconFilePath = ""
                            rawshellcode = ModuleShellcodeFileName

                genPayload = getattr(module, DropperModuleGeneratePayloadFunction)
                droppersPath, shellcodesPath, cmdToRun = genPayload(beaconFilePath, beaconArg, rawshellcode, urlDownload, self.additionalArgs.split(" "))

        # Upload the file and get the path
        for dropperPath in droppersPath:
            try:
                with open(dropperPath, mode='rb') as fileDesc:
                    payload = fileDesc.read()
            except IOError:
                self.printInTerminal(self.commandLine, ErrorFileNotFound)
                return  

            filename = os.path.basename(dropperPath)
            commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+self.listenerDownload+" "+filename
            termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer, data=payload)
            resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

            result = terminal_response_text(resultTermCommand)
            if isTerminalResponseError(resultTermCommand):
                self.finished.emit(self.commandLine, result)
                return  
            
        for shellcodePath in shellcodesPath:
            try:
                with open(shellcodePath, mode='rb') as fileDesc:
                    payload = fileDesc.read()
            except IOError:
                self.printInTerminal(self.commandLine, ErrorFileNotFound)
                return  

            filename = os.path.basename(shellcodePath)
            commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+self.listenerDownload+" "+filename
            termCommand = TeamServerApi_pb2.TerminalCommandRequest(command=commandTeamServer, data=payload)
            resultTermCommand = self.grpcClient.executeTerminalCommand(termCommand)

            result = terminal_response_text(resultTermCommand)
            if isTerminalResponseError(resultTermCommand):
                self.finished.emit(self.commandLine, result)
                return  
                
        result = cmdToRun 
        self.finished.emit(self.commandLine, result)
        return


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()

    def __init__(self, parent=None, grpcClient=None):
        super().__init__(parent)

        self.grpcClient = grpcClient
        self.cmdHistory = []
        self.idx = 0
        self.completionData = []

        if(os.path.isfile(HistoryFileName)):
            cmdHistoryFile = open(HistoryFileName)
            self.cmdHistory = cmdHistoryFile.readlines()
            self.idx=len(self.cmdHistory)-1
            cmdHistoryFile.close()

        QShortcut(Qt.Key.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key.Key_Down, self, self.historyDown)

        self.completionData = build_terminal_completer_data(self.grpcClient)
        self.codeCompleter = CodeCompleter(self.completionData, self)
        # needed to clear the completer after activation
        self.codeCompleter.activated.connect(self.onActivated)
        self.setCompleter(self.codeCompleter)
        self.tabPressed.connect(self.nextCompletion)

    def refreshCompleter(self, force=False):
        completionData = build_terminal_completer_data(self.grpcClient)
        if force or completionData != self.completionData:
            self.completionData = completionData
            self.codeCompleter.updateData(completionData)

    def nextCompletion(self):
        self.refreshCompleter()
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
        cmdHistoryFile = open(HistoryFileName)
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
        self.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.createModel(data)

    def updateData(self, data):
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
