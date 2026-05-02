import time
import logging

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QGridLayout,
    QLabel,
    QMenu,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QHeaderView,
    QAbstractItemView,
)

from .grpcClient import TeamServerApi_pb2
      

#
# Session
#
class Session():

    def __init__(self, id, listenerHash, beaconHash, hostname, username, arch, privilege, os, lastProofOfLife, killed, internalIps, processId, additionalInformation):
        self.id = id
        self.listenerHash = listenerHash
        self.beaconHash = beaconHash
        self.hostname = hostname
        self.username = username
        self.arch = arch
        self.privilege = privilege
        self.os = os
        self.lastProofOfLife = lastProofOfLife
        self.killed = killed
        self.internalIps = internalIps
        self.processId = processId
        self.additionalInformation = additionalInformation


class Sessions(QWidget):

    interactWithSession = pyqtSignal(str, str, str, str)
    sessionScriptSignal = pyqtSignal(str, str, str, str, str, str, str, str, str, bool)

    idSession = 0
    listSessionObject = []


    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)

        self.grpcClient = grpcClient

        widget = QWidget(self)
        self.layout = QGridLayout(widget)

        self.label = QLabel('Sessions')
        self.layout.addWidget(self.label)

        # List of sessions
        self.listSession = QTableWidget()
        self.listSession.setShowGrid(False)
        self.listSession.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.listSession.setRowCount(0)
        self.listSession.setColumnCount(11)

        self.listSession.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.listSession.customContextMenuRequested.connect(self.showContextMenu)

        self.listSession.verticalHeader().setVisible(False)
        header = self.listSession.horizontalHeader()      
        for i in range(header.count()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)     
        QTimer.singleShot(100, self.switch_to_interactive)
        self.layout.addWidget(self.listSession)

        # Thread to fetch sessions every second
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getSessionsWorker = GetSessionsWorker()
        self.getSessionsWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getSessionsWorker.run)
        self.getSessionsWorker.checkin.connect(self.listSessions)
        self.thread.start()

        self.setLayout(self.layout)


    def resizeEvent(self, event):
        super().resizeEvent(event) 
        self.listSession.verticalHeader().setVisible(False)
        header = self.listSession.horizontalHeader()      
        for i in range(header.count()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        QTimer.singleShot(100, self.switch_to_interactive)


    def switch_to_interactive(self):
        header = self.listSession.horizontalHeader()   
        for i in range(header.count()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)

    def __del__(self):
        self.getSessionsWorker.quit()
        self.thread.quit()
        self.thread.wait()


    def showContextMenu(self, position):
        index = self.listSession.indexAt(position)
        if not index.isValid():
            return

        row = index.row()
        self.item = str(self.listSession.item(row, 0).data(0))

        menu = QMenu()
        menu.addAction('Interact')
        menu.addAction('Stop')
        menu.addAction('Delete')
        menu.triggered.connect(self.actionClicked)
        menu.exec(self.listSession.viewport().mapToGlobal(position))


    # catch Interact and Stop menu click
    def  actionClicked(self, action):
        hash = self.item
        for ix, sessionStore in enumerate(self.listSessionObject):
            if sessionStore.beaconHash[0:8] == hash:
                if action.text() == "Interact":
                    self.interactWithSession.emit(sessionStore.beaconHash, sessionStore.listenerHash, sessionStore.hostname, sessionStore.username)
                elif action.text() == "Stop":
                    self.stopSession(sessionStore.beaconHash, sessionStore.listenerHash)
                elif action.text() == "Delete":
                    self.listSessionObject.pop(ix)
            self.printSessions()


    def stopSession(self, beaconHash, listenerHash):
        session = TeamServerApi_pb2.SessionSelector(
            beacon_hash=beaconHash, listener_hash=listenerHash)
        self.grpcClient.stopSession(session)
        self.listSessions()


    def listSessions(self):
        responses = self.grpcClient.listSessions()

        sessions = list()
        for response in responses:
            sessions.append(response)

        # check for idl sessions
        for ix, item in enumerate(self.listSessionObject):
            runing=False
            for session in sessions:
                if session.beacon_hash == item.beaconHash:
                    runing=True
            # set idl
            if not runing:
                self.listSessionObject[ix].lastProofOfLife="-1"

        for session in sessions:
            inStore=False
            for sessionStore in self.listSessionObject:
                #maj
                if session.listener_hash == sessionStore.listenerHash and session.beacon_hash == sessionStore.beaconHash:
                    self.sessionScriptSignal.emit("update", session.beacon_hash, session.listener_hash, session.hostname, session.username, session.arch, session.privilege, session.os, session.last_proof_of_life, session.killed)
                    inStore=True
                    sessionStore.lastProofOfLife=session.last_proof_of_life
                    sessionStore.listenerHash=session.listener_hash
                    if session.hostname:
                        sessionStore.hostname=session.hostname
                    if session.username:
                        sessionStore.username=session.username
                    if session.arch:
                        sessionStore.arch=session.arch
                    if session.privilege:
                        sessionStore.privilege=session.privilege
                    if session.os:
                        sessionStore.os=session.os
                    if session.last_proof_of_life:
                        sessionStore.lastProofOfLife=session.last_proof_of_life
                    if session.killed:
                        sessionStore.killed=session.killed
                    if session.internal_ips:
                        sessionStore.internalIps=session.internal_ips
                    if session.process_id:
                        sessionStore.processId=session.process_id
                    if session.additional_information:
                        sessionStore.additionalInformation=session.additional_information
            # add
            if not inStore:
                self.sessionScriptSignal.emit("start", session.beacon_hash, session.listener_hash, session.hostname, session.username, session.arch, session.privilege, session.os, session.last_proof_of_life, session.killed)

                # print(session)

                self.listSessionObject.append(
                    Session(
                        self.idSession,
                        session.listener_hash, session.beacon_hash, 
                        session.hostname, session.username, session.arch,
                        session.privilege, session.os, session.last_proof_of_life,
                        session.killed, session.internal_ips, session.process_id, session.additional_information
                        )
                    )
                self.idSession = self.idSession+1

        self.printSessions()


    # don't clear the list each time but just when it's necessary
    def printSessions(self):
        self.listSession.setRowCount(len(self.listSessionObject))
        self.listSession.setHorizontalHeaderLabels(["Beacon ID", "Listener ID", "Host", "User", "Beacon Arch", "Privilege", "Operating System", "Process ID", "Internal IP", "ProofOfLife", "Killed"])
        archHeader = self.listSession.horizontalHeaderItem(4)
        if archHeader is not None:
            archHeader.setToolTip("Architecture du process beacon")
        for ix, sessionStore in enumerate(self.listSessionObject):

            beaconHash = QTableWidgetItem(sessionStore.beaconHash[0:8])
            self.listSession.setItem(ix, 0, beaconHash)

            listenerHash = QTableWidgetItem(sessionStore.listenerHash[0:8])
            self.listSession.setItem(ix, 1, listenerHash)

            hostname = QTableWidgetItem(sessionStore.hostname)
            self.listSession.setItem(ix, 2, hostname)

            username = QTableWidgetItem(sessionStore.username)
            self.listSession.setItem(ix, 3, username)

            arch = QTableWidgetItem(sessionStore.arch)
            self.listSession.setItem(ix, 4, arch)

            privilege = QTableWidgetItem(sessionStore.privilege)
            self.listSession.setItem(ix, 5, privilege)

            os = QTableWidgetItem(sessionStore.os)
            self.listSession.setItem(ix, 6, os)

            processId = QTableWidgetItem(sessionStore.processId)
            self.listSession.setItem(ix, 7, processId)
            
            internalIps = QTableWidgetItem(sessionStore.internalIps)
            self.listSession.setItem(ix, 8, internalIps)

            pol = QTableWidgetItem(sessionStore.lastProofOfLife.split(".", 1)[0])
            self.listSession.setItem(ix, 9, pol)

            killed = QTableWidgetItem(str(sessionStore.killed))
            self.listSession.setItem(ix, 10, killed)


class GetSessionsWorker(QObject):
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
