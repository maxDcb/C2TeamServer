import time
import logging
import re
from ipaddress import ip_address

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QIntValidator
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
from .panel_style import apply_dark_panel_style
from .ui_status import apply_error, apply_status, clear_status, format_action_status, status_kind_for_ok

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

DOMAIN_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
GITHUB_PROJECT_PART_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
PORT_FIELD_TYPES = {HttpType, HttpsType, TcpType, DnsType}
PRIMARY_LISTENER_TYPES = [HttpType, HttpsType, TcpType, GithubType, DnsType]
AUTO_FIELD_VALUES = {"0.0.0.0", "8443", "8080", "4444", "53"}
LISTENER_FORM_CONFIG = {
    HttpType: {
        "param1_label": IpLabel,
        "param2_label": PortLabel,
        "param1_placeholder": "0.0.0.0 or ::",
        "param2_placeholder": "1-65535",
        "default_param1": "0.0.0.0",
        "default_param2": "8080",
        "help": "HTTP listener bound on a local interface.",
        "secret": False,
    },
    HttpsType: {
        "param1_label": IpLabel,
        "param2_label": PortLabel,
        "param1_placeholder": "0.0.0.0 or ::",
        "param2_placeholder": "1-65535",
        "default_param1": "0.0.0.0",
        "default_param2": "8443",
        "help": "HTTPS listener bound on a local interface.",
        "secret": False,
    },
    TcpType: {
        "param1_label": IpLabel,
        "param2_label": PortLabel,
        "param1_placeholder": "0.0.0.0 or ::",
        "param2_placeholder": "1-65535",
        "default_param1": "0.0.0.0",
        "default_param2": "4444",
        "help": "Raw TCP listener bound on a local interface.",
        "secret": False,
    },
    GithubType: {
        "param1_label": ProjectLabel,
        "param2_label": TokenLabel,
        "param1_placeholder": "project or owner/repo",
        "param2_placeholder": "GitHub token",
        "default_param1": "",
        "default_param2": "",
        "help": "GitHub listener using a simple project name or owner/repo.",
        "secret": True,
    },
    DnsType: {
        "param1_label": DomainLabel,
        "param2_label": PortLabel,
        "param1_placeholder": "example.com",
        "param2_placeholder": "1-65535",
        "default_param1": "",
        "default_param2": "53",
        "help": "DNS listener for a controlled domain.",
        "secret": False,
    },
}


def _text(value):
    return str(value or "").strip()


def _validate_port(port):
    portText = _text(port)
    if not portText.isdigit():
        return False, "Port must be a number between 1 and 65535."

    parsedPort = int(portText)
    if parsedPort < 1 or parsedPort > 65535:
        return False, "Port must be a number between 1 and 65535."
    return True, ""


def _is_valid_domain(domain):
    domainText = _text(domain).rstrip(".")
    if not domainText or len(domainText) > 253:
        return False
    if "://" in domainText or "/" in domainText or ":" in domainText:
        return False
    return all(DOMAIN_LABEL_PATTERN.match(label) for label in domainText.split("."))


def _is_valid_github_project(project):
    projectParts = _text(project).split("/")
    if len(projectParts) > 2:
        return False
    return all(GITHUB_PROJECT_PART_PATTERN.match(part) for part in projectParts)


def validate_listener_fields(listenerType, param1, param2):
    listenerType = _text(listenerType).lower()
    param1 = _text(param1)
    param2 = _text(param2)

    if listenerType in {HttpType, HttpsType, TcpType}:
        if not param1:
            return False, "IP is required."
        try:
            ip_address(param1)
        except ValueError:
            return False, "IP must be a valid IPv4 or IPv6 address."
        return _validate_port(param2)

    if listenerType == DnsType:
        if not _is_valid_domain(param1):
            return False, "Domain must be a valid DNS name."
        return _validate_port(param2)

    if listenerType == GithubType:
        if not param1:
            return False, "GitHub project is required."
        if not _is_valid_github_project(param1):
            return False, "GitHub project must use a simple name or owner/repo."
        if not param2:
            return False, "GitHub token is required."
        return True, ""

    return False, "Unknown listener type."


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
        apply_dark_panel_style(self)
                
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

    def scriptSnapshot(self):
        snapshots = []
        for listenerStore in self.listListenerObject:
            snapshots.append(
                {
                    "id": listenerStore.id,
                    "listener_hash": _text(listenerStore.listenerHash),
                    "type": _text(listenerStore.type),
                    "host": _text(listenerStore.host),
                    "port": listenerStore.port,
                    "session_count": listenerStore.nbSession,
                }
            )
        return snapshots

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
        listenerType = _text(message[0]) if len(message) > 0 else ""
        param1 = _text(message[1]) if len(message) > 1 else ""
        param2 = _text(message[2]) if len(message) > 2 else ""
        valid, error = validate_listener_fields(listenerType, param1, param2)
        if not valid:
            self.setInlineStatus(format_action_status("Add listener", error), False)
            return

        if listenerType=="github":
            listener = TeamServerApi_pb2.Listener(
            type=listenerType,
            project=param1,
            token=param2)
        elif listenerType=="dns":
            listener = TeamServerApi_pb2.Listener(
            type=listenerType,
            domain=param1,
            port=int(param2))
        else:
            listener = TeamServerApi_pb2.Listener(
            type=listenerType,
            ip=param1,
            port=int(param2))
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
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setHorizontalSpacing(10)
        layout.setVerticalSpacing(8)
        self.labelType = QLabel(TypeLabel)
        self.qcombo = QComboBox(self)
        self.qcombo.addItems(PRIMARY_LISTENER_TYPES)
        self.qcombo.setCurrentIndex(1)
        self.qcombo.currentTextChanged.connect(self.changeLabels)
        self.type = self.qcombo
        layout.addRow(self.labelType, self.type)

        self.helpLabel = QLabel("")
        self.helpLabel.setWordWrap(True)
        layout.addRow(self.helpLabel)

        self.labelIP = QLabel(IpLabel)
        self.param1 = QLineEdit()
        self.param1.setClearButtonEnabled(True)
        layout.addRow(self.labelIP, self.param1)

        self.labelPort = QLabel(PortLabel)
        self.param2 = QLineEdit()
        self.param2.setClearButtonEnabled(True)
        self.portValidator = QIntValidator(1, 65535, self)
        layout.addRow(self.labelPort, self.param2)

        self.errorLabel = QLabel("")
        self.errorLabel.setMinimumHeight(18)
        self.errorLabel.setWordWrap(True)
        self.errorLabel.setVisible(False)
        layout.addRow(self.errorLabel)

        self.buttonLayout = QHBoxLayout()
        self.buttonLayout.addStretch(1)
        self.cancelButton = QPushButton("Cancel", clicked=self.close)
        self.buttonOk = QPushButton("Add", clicked=self.checkAndSend)
        self.buttonOk.setDefault(True)
        self.buttonLayout.addWidget(self.cancelButton)
        self.buttonLayout.addWidget(self.buttonOk)
        layout.addRow(self.buttonLayout)

        self.setLayout(layout)
        self.setWindowTitle(AddListenerWindowTitle)
        self.setMinimumWidth(360)
        self.param1.textChanged.connect(self.updateFormState)
        self.param2.textChanged.connect(self.updateFormState)
        self.param1.returnPressed.connect(self.checkAndSend)
        self.param2.returnPressed.connect(self.checkAndSend)
        self.changeLabels()


    def changeLabels(self):
        self.clearValidationError()
        listenerType = self.qcombo.currentText()
        config = LISTENER_FORM_CONFIG[listenerType]

        self.labelIP.setText(config["param1_label"])
        self.labelPort.setText(config["param2_label"])
        self.helpLabel.setText(config["help"])
        self.param1.setPlaceholderText(config["param1_placeholder"])
        self.param2.setPlaceholderText(config["param2_placeholder"])
        self.param1.setToolTip(config["param1_placeholder"])
        self.param2.setToolTip(config["param2_placeholder"])

        if listenerType in PORT_FIELD_TYPES:
            self.param2.setValidator(self.portValidator)
            self.param2.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.param2.setValidator(None)
            self.param2.setEchoMode(
                QLineEdit.EchoMode.Password if config["secret"] else QLineEdit.EchoMode.Normal
            )

        self.applyParam1Default(listenerType, config["default_param1"])
        self.applyParam2Default(listenerType, config["default_param2"])
        self.updateFormState()

    def applyParam1Default(self, listenerType, defaultValue):
        current = self.param1.text().strip()
        shouldReset = not current or current in AUTO_FIELD_VALUES

        if listenerType in {HttpType, HttpsType, TcpType}:
            shouldReset = shouldReset or not self.looksLikeIp(current)
        elif listenerType == DnsType:
            shouldReset = shouldReset or self.looksLikeIp(current) or "/" in current or ":" in current
        elif listenerType == GithubType:
            shouldReset = shouldReset or self.looksLikeIp(current) or "://" in current

        if shouldReset:
            self.param1.setText(defaultValue)

    def applyParam2Default(self, listenerType, defaultValue):
        current = self.param2.text().strip()
        if listenerType in PORT_FIELD_TYPES:
            shouldReset = not current or current in AUTO_FIELD_VALUES or not current.isdigit()
        else:
            shouldReset = current in AUTO_FIELD_VALUES or current.isdigit()

        if shouldReset:
            self.param2.setText(defaultValue)

    def looksLikeIp(self, value):
        candidate = _text(value)
        if candidate and candidate not in AUTO_FIELD_VALUES:
            try:
                ip_address(candidate)
                return True
            except ValueError:
                return False
        return False

    def clearValidationError(self):
        clear_status(self.errorLabel, "")
        self.errorLabel.setVisible(False)

    def showValidationError(self, message):
        apply_error(self.errorLabel, message)
        self.errorLabel.setVisible(True)

    def updateFormState(self):
        self.clearValidationError()
        valid, _ = validate_listener_fields(
            self.type.currentText(),
            self.param1.text(),
            self.param2.text(),
        )
        self.buttonOk.setEnabled(valid)

    def checkAndSend(self):
        type = self.type.currentText().strip()
        param1 = self.param1.text().strip()
        param2 = self.param2.text().strip()

        valid, error = validate_listener_fields(type, param1, param2)
        if not valid:
            self.showValidationError(error)
            return

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
