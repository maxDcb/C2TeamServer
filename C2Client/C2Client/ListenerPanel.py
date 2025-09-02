import time
import logging

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QHeaderView,
    QAbstractItemView,
)

from .grpcClient import TeamServerApi_pb2


#
# Constant
#
ListenerTabTitle = "Listeners"
AddListenerWindowTitle = "Add Listener"

TypeLabel = "Type"
IpLabel = "IP"
PortLabel = "Port"
DomainLabel = "Domain"
ProjectLabel = "Project"
TokenLabel = "Token"

HttpType = "http"
HttpsType = "https"
TcpType = "tcp"
GithubType = "github"
DnsType = "dns"
SmbType = "smb"


#
# Listener tab implementation
#
class Listener():

    def __init__(self, id, hash, type, host, port, nbSession):
        self.id = id
        self.listenerHash = hash
        self.type = type
        self.host = host
        self.port = port
        self.nbSession = nbSession


class Listeners(QWidget):

    listenerScriptSignal = pyqtSignal(str, str, str, str)

    idListener = 0
    listListenerObject = []


    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)

        self.grpcClient = grpcClient
                
        self.createListenerWindow = None

        widget = QWidget(self)
        self.layout = QGridLayout(widget)

        self.label = QLabel(ListenerTabTitle)
        self.layout.addWidget(self.label)

        # List of sessions
        self.listListener = QTableWidget()
        self.listListener.setShowGrid(False)
        self.listListener.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        self.listListener.setRowCount(0)
        self.listListener.setColumnCount(4)

        # self.listListener.cellPressed.connect(self.listListenerClicked)
        self.listListener.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.listListener.customContextMenuRequested.connect(self.showContextMenu)

        self.listListener.verticalHeader().setVisible(False)
        header = self.listListener.horizontalHeader()      
        for i in range(header.count()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.listListener)

        # Thread to get listeners every second
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getListenerWorker = GetListenerWorker()
        self.getListenerWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getListenerWorker.run)
        self.getListenerWorker.checkin.connect(self.getListeners)
        self.thread.start()

        self.setLayout(self.layout)


    def __del__(self):
        self.getListenerWorker.quit()
        self.thread.quit()
        self.thread.wait()


    def showContextMenu(self, position):
        index = self.listListener.indexAt(position)
        if not index.isValid():
            menu = QMenu()
            menu.addAction('Add')
            menu.triggered.connect(self.actionClicked)
            menu.exec(self.listListener.viewport().mapToGlobal(position))
        else:
            row = index.row()
            self.item = str(self.listListener.item(row, 0).data(0))

            menu = QMenu()
            menu.addAction('Stop')
            menu.triggered.connect(self.actionClicked)
            menu.exec(self.listListener.viewport().mapToGlobal(position))


    # catch stopListener menu click
    def actionClicked(self, action):
        if action.text() == "Add":
            self.listenerForm()
        elif action.text() == "Stop":         
            hash = self.item
            for listenerStore in self.listListenerObject:
                if listenerStore.listenerHash[0:8] == hash:
                    self.stopListener(listenerStore.listenerHash)


    # form for adding a listener
    def listenerForm(self):
        if self.createListenerWindow is None:
            self.createListenerWindow = CreateListner()
            self.createListenerWindow.procDone.connect(self.addListener)
        self.createListenerWindow.show()


    # send message for adding a listener
    def addListener(self, message):
        if message[0]=="github":
            listener = TeamServerApi_pb2.Listener(
            type=message[0],
            project=message[1],
            token=message[2])
        elif message[0]=="dns":
            listener = TeamServerApi_pb2.Listener(
            type=message[0],
            domain=message[1],
            port=int(message[2]))
        else:
            listener = TeamServerApi_pb2.Listener(
            type=message[0],
            ip=message[1],
            port=int(message[2]))
        self.grpcClient.addListener(listener)


    # send message for stoping a listener
    def stopListener(self, listenerHash):
        listener = TeamServerApi_pb2.Listener(
        listenerHash=listenerHash)
        self.grpcClient.stopListener(listener)


    # query the server to get the list of listeners
    def getListeners(self):
        responses = self.grpcClient.getListeners()

        listeners = list()
        for response in responses:
            listeners.append(response)

        # delete listener
        for ix, listenerStore in enumerate(self.listListenerObject):
            runing=False
            for listener in listeners:
                if listener.listenerHash == listenerStore.listenerHash:
                    runing=True
            # delete
            if not runing:
                del self.listListenerObject[ix]
                
        for listener in listeners:
            inStore=False
            # if listener is already on our list
            for ix, listenerStore in enumerate(self.listListenerObject):
                # maj
                if listener.listenerHash == listenerStore.listenerHash:
                    inStore=True
                    listenerStore.nbSession=listener.numberOfSession
            # add
            # if listener is not yet already on our list
            if not inStore:

                self.listenerScriptSignal.emit("start", "", "", "")

                if listener.type == GithubType:
                    self.listListenerObject.append(Listener(self.idListener, listener.listenerHash, listener.type, listener.project, listener.token[0:10], listener.numberOfSession))
                elif listener.type == DnsType:
                    self.listListenerObject.append(Listener(self.idListener, listener.listenerHash, listener.type, listener.domain, listener.port, listener.numberOfSession))
                elif listener.type == SmbType:
                    self.listListenerObject.append(Listener(self.idListener, listener.listenerHash, listener.type, listener.ip, listener.domain, listener.numberOfSession))
                else:
                    self.listListenerObject.append(Listener(self.idListener, listener.listenerHash, listener.type, listener.ip, listener.port, listener.numberOfSession))
                self.idListener = self.idListener+1

        self.printListeners()


    def printListeners(self):
        self.listListener.setRowCount(len(self.listListenerObject))
        self.listListener.setHorizontalHeaderLabels(["Listener ID", "Type", "Host", "Port"])
        for ix, listenerStore in enumerate(self.listListenerObject):

            listenerHash = QTableWidgetItem(listenerStore.listenerHash[0:8])
            self.listListener.setItem(ix, 0, listenerHash)

            type = QTableWidgetItem(listenerStore.type)
            self.listListener.setItem(ix, 1, type)

            host = QTableWidgetItem(listenerStore.host)
            self.listListener.setItem(ix, 2, host)

            port = QTableWidgetItem(str(listenerStore.port))
            self.listListener.setItem(ix, 3, port)


class CreateListner(QWidget):

    procDone = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        
        layout = QFormLayout()
        self.labelType = QLabel(TypeLabel)
        self.qcombo = QComboBox(self)
        self.qcombo.addItems([HttpType , HttpsType, TcpType, GithubType, DnsType])
        self.qcombo.setCurrentIndex(1)
        self.qcombo.currentTextChanged.connect(self.changeLabels)
        self.type = self.qcombo
        layout.addRow(self.labelType, self.type)

        self.labelIP = QLabel(IpLabel)
        self.param1 = QLineEdit()
        self.param1.setText("0.0.0.0")
        layout.addRow(self.labelIP, self.param1)

        self.labelPort = QLabel(PortLabel)
        self.param2 = QLineEdit()
        self.param2.setText("8443")
        layout.addRow(self.labelPort, self.param2)

        self.buttonOk = QPushButton('&OK', clicked=self.checkAndSend)
        layout.addRow(self.buttonOk)

        self.setLayout(layout)
        self.setWindowTitle(AddListenerWindowTitle)


    def changeLabels(self):
        if self.qcombo.currentText() == HttpType:
            self.labelIP.setText(IpLabel)
            self.labelPort.setText(PortLabel)
        elif self.qcombo.currentText() == HttpsType:
            self.labelIP.setText(IpLabel)
            self.labelPort.setText(PortLabel)
        elif self.qcombo.currentText() == TcpType:
            self.labelIP.setText(IpLabel)
            self.labelPort.setText(PortLabel)
        elif self.qcombo.currentText() == GithubType:
            self.labelIP.setText(ProjectLabel)
            self.labelPort.setText(TokenLabel)
        elif self.qcombo.currentText() == DnsType:
            self.labelIP.setText(DomainLabel)
            self.labelPort.setText(PortLabel)


    def checkAndSend(self):
        type = self.type.currentText()
        param1 = self.param1.text()
        param2 = self.param2.text()

        result = [type, param1, param2]

        self.procDone.emit(result)
        self.close()


class GetListenerWorker(QObject):
    checkin = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.exit = False

    def __del__(self):
        self.exit=True

    def run(self):
        try: 
            while self.exit==False:
                if self.receivers(self.checkin) > 0:
                    self.checkin.emit()
                time.sleep(2)
        except Exception as e:
            pass

    def quit(self):
        self.exit=True
