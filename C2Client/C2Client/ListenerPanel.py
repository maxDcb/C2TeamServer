import time
import logging

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QHeaderView,
    QAbstractItemView,
    QSizePolicy,
)

from .grpcClient import TeamServerApi_pb2
from .env import env_int
from .grpc_status import is_response_ok, operation_ack_text
from .ui_status import apply_status, format_action_status, status_kind_for_ok

logger = logging.getLogger(__name__)


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
    COLUMN_WIDTHS = [76, 70, 160, 72]
    STRETCH_COLUMN = 2


    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)

        self.grpcClient = grpcClient
        self.idListener = 0
        self.listListenerObject = []
                
        self.createListenerWindow = None

        widget = QWidget(self)
        self.layout = QGridLayout(widget)
        self.layout.setContentsMargins(4, 4, 4, 4)
        self.layout.setHorizontalSpacing(6)
        self.layout.setVerticalSpacing(4)
        self.layout.setColumnStretch(0, 1)
        self.layout.setRowStretch(2, 1)

        self.label = QLabel(ListenerTabTitle)
        self.headerLayout = QHBoxLayout()
        self.headerLayout.setSpacing(4)
        self.headerLayout.addWidget(self.label)
        self.headerLayout.addStretch(1)

        self.addListenerButton = self.createToolbarButton("Add", "Create a new primary listener.")
        self.addListenerButton.clicked.connect(self.listenerForm)
        self.headerLayout.addWidget(self.addListenerButton)

        self.stopListenerButton = self.createToolbarButton("Stop", "Stop the selected listener.")
        self.stopListenerButton.clicked.connect(self.stopSelectedListener)
        self.headerLayout.addWidget(self.stopListenerButton)

        self.copyListenerIdButton = self.createToolbarButton("Copy", "Copy the selected listener hash.")
        self.copyListenerIdButton.clicked.connect(self.copySelectedListenerId)
        self.headerLayout.addWidget(self.copyListenerIdButton)

        self.refreshButton = self.createToolbarButton("Refresh", "Refresh listeners now.", width=70)
        self.refreshButton.clicked.connect(self.listListeners)
        self.headerLayout.addWidget(self.refreshButton)
        self.layout.addLayout(self.headerLayout, 0, 0)

        self.statusLabel = QLabel("")
        self.statusLabel.setMinimumHeight(18)
        self.layout.addWidget(self.statusLabel, 1, 0)

        # List of sessions
        self.listListener = QTableWidget()
        self.listListener.setShowGrid(False)
        self.listListener.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.listListener.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.listListener.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.listListener.setRowCount(0)
        self.listListener.setColumnCount(4)

        # self.listListener.cellPressed.connect(self.listListenerClicked)
        self.listListener.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.listListener.customContextMenuRequested.connect(self.showContextMenu)
        self.listListener.itemSelectionChanged.connect(self.updateActionButtons)

        self.listListener.verticalHeader().setVisible(False)
        self.configureTableColumns()
        self.layout.addWidget(self.listListener, 2, 0)

        # Thread to get listeners every second
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getListenerWorker = GetListenerWorker()
        self.getListenerWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getListenerWorker.run)
        self.getListenerWorker.checkin.connect(self.listListeners)
        self.thread.start()

        self.setLayout(self.layout)
        self.updateActionButtons()

    def createToolbarButton(self, text, tooltip, width=58):
        button = QPushButton(text)
        button.setToolTip(tooltip)
        button.setFixedHeight(26)
        button.setMinimumWidth(width)
        button.setMaximumWidth(width)
        return button

    def configureTableColumns(self):
        header = self.listListener.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(44)
        for index, width in enumerate(self.COLUMN_WIDTHS):
            if index == self.STRETCH_COLUMN:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
                self.listListener.setColumnWidth(index, width)

    def setStatusMessage(self, ack, successFallback, action="Operation"):
        message = operation_ack_text(ack, successFallback)
        self.setInlineStatus(format_action_status(action, message), is_response_ok(ack))

    def setInlineStatus(self, message, ok=True):
        apply_status(self.statusLabel, message, status_kind_for_ok(ok))

    def updateActionButtons(self):
        hasSelection = self.selectedListener() is not None
        self.stopListenerButton.setEnabled(hasSelection)
        self.copyListenerIdButton.setEnabled(hasSelection)

    def selectedListener(self):
        selectedRows = self.listListener.selectionModel().selectedRows() if self.listListener.selectionModel() else []
        if not selectedRows:
            return None

        row = selectedRows[0].row()
        if row < 0 or row >= len(self.listListenerObject):
            return None
        return self.listListenerObject[row]

    def stopSelectedListener(self):
        listenerStore = self.selectedListener()
        if listenerStore is None:
            self.setInlineStatus("Select a listener first.", False)
            return
        self.stopListener(listenerStore.listenerHash)

    def copySelectedListenerId(self):
        listenerStore = self.selectedListener()
        if listenerStore is None:
            self.setInlineStatus("Select a listener first.", False)
            return
        QApplication.clipboard().setText(listenerStore.listenerHash)
        self.setInlineStatus("Listener ID copied to clipboard.")

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
        ack = self.grpcClient.addListener(listener)
        self.setStatusMessage(ack, "Listener command accepted.", action="Add listener")


    # send message for stoping a listener
    def stopListener(self, listenerHash):
        listener = TeamServerApi_pb2.ListenerSelector(
        listener_hash=listenerHash)
        ack = self.grpcClient.stopListener(listener)
        self.setStatusMessage(ack, "Listener stop command accepted.", action="Stop listener")


    # query the server to get the list of listeners
    def listListeners(self):
        responses = self.grpcClient.listListeners()

        listeners = list()
        for response in responses:
            listeners.append(response)

        # delete listener
        for ix, listenerStore in enumerate(self.listListenerObject):
            runing=False
            for listener in listeners:
                if listener.listener_hash == listenerStore.listenerHash:
                    runing=True
            # delete
            if not runing:
                del self.listListenerObject[ix]
                
        for listener in listeners:
            inStore=False
            # if listener is already on our list
            for ix, listenerStore in enumerate(self.listListenerObject):
                # maj
                if listener.listener_hash == listenerStore.listenerHash:
                    inStore=True
                    listenerStore.nbSession=listener.session_count
            # add
            # if listener is not yet already on our list
            if not inStore:

                self.listenerScriptSignal.emit("start", "", "", "")

                if listener.type == GithubType:
                    self.listListenerObject.append(Listener(self.idListener, listener.listener_hash, listener.type, listener.project, listener.token[0:10], listener.session_count))
                elif listener.type == DnsType:
                    self.listListenerObject.append(Listener(self.idListener, listener.listener_hash, listener.type, listener.domain, listener.port, listener.session_count))
                elif listener.type == SmbType:
                    self.listListenerObject.append(Listener(self.idListener, listener.listener_hash, listener.type, listener.ip, listener.domain, listener.session_count))
                else:
                    self.listListenerObject.append(Listener(self.idListener, listener.listener_hash, listener.type, listener.ip, listener.port, listener.session_count))
                self.idListener = self.idListener+1

        self.printListeners()


    def printListeners(self):
        self.listListener.setRowCount(len(self.listListenerObject))
        self.listListener.setHorizontalHeaderLabels(["ID", "Type", "Host", "Port"])
        for index, tooltip in {
            0: "Listener hash",
            2: "Bind IP, domain, project, or pivot host",
        }.items():
            headerItem = self.listListener.horizontalHeaderItem(index)
            if headerItem is not None:
                headerItem.setToolTip(tooltip)
        for ix, listenerStore in enumerate(self.listListenerObject):

            listenerHash = QTableWidgetItem(listenerStore.listenerHash[0:8])
            self.listListener.setItem(ix, 0, listenerHash)

            type = QTableWidgetItem(listenerStore.type)
            self.listListener.setItem(ix, 1, type)

            host = QTableWidgetItem(listenerStore.host)
            host.setToolTip(listenerStore.host)
            self.listListener.setItem(ix, 2, host)

            port = QTableWidgetItem(str(listenerStore.port))
            self.listListener.setItem(ix, 3, port)
        self.updateActionButtons()


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
        self.refreshIntervalSeconds = env_int("C2_LISTENER_REFRESH_MS", 2000, minimum=100) / 1000

    def __del__(self):
        self.exit=True

    def run(self):
        try: 
            while self.exit==False:
                if self.receivers(self.checkin) > 0:
                    self.checkin.emit()
                time.sleep(self.refreshIntervalSeconds)
        except Exception:
            logger.exception("Listener refresh worker stopped unexpectedly")

    def quit(self):
        self.exit=True
