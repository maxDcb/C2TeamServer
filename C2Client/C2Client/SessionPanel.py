import time
import logging

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *
      

#
# Sessions
#
class Session():

    def __init__(self, id, listenerHash, beaconHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
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
        self.listSession.setSelectionBehavior(QTableView.SelectRows)
        self.listSession.setRowCount(0)
        self.listSession.setColumnCount(10)
        self.listSession.cellPressed.connect(self.listSessionClicked)
        self.listSession.verticalHeader().setVisible(False)
        header = self.listSession.horizontalHeader()      
        for i in range(10): 
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(9, QHeaderView.ResizeToContents)
        self.layout.addWidget(self.listSession)

        # Thread to get sessions every second
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getSessionsWorker = GetSessionsWorker()
        self.getSessionsWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getSessionsWorker.run)
        self.getSessionsWorker.checkin.connect(self.getSessions)
        self.thread.start()

        self.setLayout(self.layout)

    def __del__(self):
        self.getSessionsWorker.quit()
        self.thread.quit()
        self.thread.wait()

    # interact with session list
    def listSessionClicked(self, row, column):
        self.item = str(self.listSession.item(row, 0).data(0))
        menu = QMenu()
        menu.addAction('Interact')
        menu.addAction('Stop')
        menu.addAction('Delete')
        menu.triggered.connect(self.actionClicked)
        menu.exec_(QCursor.pos())

    # catch Interact and Stop menu click
    # TODO add remove ?
    def  actionClicked(self, action):
        if action.text() == "Interact":
            id = self.item
            for sessionStore in self.listSessionObject:
                if sessionStore.id == int(id):
                    self.interactWithSession.emit(sessionStore.beaconHash, sessionStore.listenerHash, sessionStore.hostname, sessionStore.username)
        elif action.text() == "Stop":
            id = self.item
            for sessionStore in self.listSessionObject:
                if sessionStore.id == int(id):
                    self.stopSession(sessionStore.beaconHash, sessionStore.listenerHash)
        elif action.text() == "Delete":
            id = self.item
            for ix, sessionStore in enumerate(self.listSessionObject):
                if sessionStore.id == int(id):
                    self.listSessionObject.pop(ix)
            self.printSessions()

    def stopSession(self, beaconHash, listenerHash):
        session = TeamServerApi_pb2.Session(
            beaconHash=beaconHash, listenerHash=listenerHash)
        self.grpcClient.stopSession(session)
        self.getSessions()

    def getSessions(self):
        responses = self.grpcClient.getSessions()

        sessions = list()
        for response in responses:
            sessions.append(response)

        # check for idl sessions
        for ix, item in enumerate(self.listSessionObject):
            runing=False
            for session in sessions:
                if session.beaconHash == item.beaconHash:
                    runing=True
            # set idl
            if not runing:
                self.listSessionObject[ix].lastProofOfLife="-1"

        for session in sessions:
            inStore=False
            for sessionStore in self.listSessionObject:
                #maj
                if session.listenerHash == sessionStore.listenerHash and session.beaconHash == sessionStore.beaconHash:
                #if session.beaconHash == sessionStore.beaconHash:
                    self.sessionScriptSignal.emit("update", session.beaconHash, session.listenerHash, session.hostname, session.username, session.arch, session.privilege, session.os, session.lastProofOfLife, session.killed)
                    inStore=True
                    sessionStore.lastProofOfLife=session.lastProofOfLife
                    sessionStore.listenerHash=session.listenerHash
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
                    if session.lastProofOfLife:
                        sessionStore.lastProofOfLife=session.lastProofOfLife
                    if session.killed:
                        sessionStore.killed=session.killed
            # add
            if not inStore:
                self.sessionScriptSignal.emit("start", session.beaconHash, session.listenerHash, session.hostname, session.username, session.arch, session.privilege, session.os, session.lastProofOfLife, session.killed)

                self.listSessionObject.append(Session(self.idSession,
                session.listenerHash, session.beaconHash, 
                session.hostname, session.username, session.arch,
                session.privilege, session.os, session.lastProofOfLife,
                session.killed))
                self.idSession = self.idSession+1

        self.printSessions()

    # don't clear the list each time but just when it's necessary
    def printSessions(self):
        self.listSession.setRowCount(len(self.listSessionObject))
        self.listSession.setHorizontalHeaderLabels(["ID", "Beacon ID", "Listener ID", "Host", "User", "Arch", "Priv", "OS", "POL","Killed"])
        for ix, sessionStore in enumerate(self.listSessionObject):
            id = QTableWidgetItem(str(sessionStore.id))
            self.listSession.setItem(ix, 0, id)
            beaconHash = QTableWidgetItem(sessionStore.beaconHash[0:8])
            self.listSession.setItem(ix, 1, beaconHash)
            listenerHash = QTableWidgetItem(sessionStore.listenerHash[0:8])
            self.listSession.setItem(ix, 2, listenerHash)
            hostname = QTableWidgetItem(sessionStore.hostname)
            self.listSession.setItem(ix, 3, hostname)
            username = QTableWidgetItem(sessionStore.username)
            self.listSession.setItem(ix, 4, username)
            arch = QTableWidgetItem(sessionStore.arch)
            self.listSession.setItem(ix, 5, arch)
            privilege = QTableWidgetItem(sessionStore.privilege)
            self.listSession.setItem(ix, 6, privilege)
            os = QTableWidgetItem(sessionStore.os)
            self.listSession.setItem(ix, 7, os)
            pol = QTableWidgetItem(sessionStore.lastProofOfLife.split(".", 1)[0])
            self.listSession.setItem(ix, 8, pol)
            killed = QTableWidgetItem(str(sessionStore.killed))
            self.listSession.setItem(ix, 9, killed)


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

