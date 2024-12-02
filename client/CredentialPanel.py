import json
import sys
import os
import time
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtGui import QPixmap, QTransform

from grpcClient import *

sys.path.insert(1, './Credentials')
import credentials

class CredentialsTab(QWidget):
    listNodeItem = []

    def __init__(self, parent, ip, port, devMode):
        super(QWidget, self).__init__(parent)
        
        width = self.frameGeometry().width()
        height = self.frameGeometry().height()

        self.ip = ip
        self.port = port
        self.grpcClient = GrpcClient(ip, port, devMode)

        self.scene = QGraphicsScene()

        self.refreshButton = QPushButton("Refresh")
        self.refreshButton.clicked.connect(lambda: self.updateCredentialTab(self.grpcClient))


        self.view = QTableWidget()
        self.view.setColumnCount(3)
        self.view.setHorizontalHeaderLabels(["Domain", "Username", "Credential"])

        self.vbox = QVBoxLayout()
        self.vbox.setContentsMargins(0, 0, 0, 0)
        self.vbox.addWidget(self.refreshButton)
        self.vbox.addWidget(self.view)

        self.setLayout(self.vbox)


        self.updateCredentialTab(self.grpcClient)
        

    # Update the graphe every X sec with information from the team server
    def updateCredentialTab(self, grpcClient: GrpcClient):
        currentcredentials = json.loads(credentials.getCredentials(grpcClient, TeamServerApi_pb2))

        self.view.setRowCount(0)

        for i in range(len(currentcredentials)):
            domain = currentcredentials[i]["domain"]
            user = currentcredentials[i]["username"]
            ntlm = currentcredentials[i]["ntlm"]

            self.view.insertRow(i)

            domainItem = QTableWidgetItem(domain)
            userItem = QTableWidgetItem(user)
            ntlmItem = QTableWidgetItem(ntlm)

            domainItem.setFlags(domainItem.flags() & ~Qt.ItemIsEditable)
            userItem.setFlags(userItem.flags() & ~Qt.ItemIsEditable)
            ntlmItem.setFlags(ntlmItem.flags() & ~Qt.ItemIsEditable)

            self.view.setItem(i, 0, domainItem)
            self.view.setItem(i, 1, userItem)
            self.view.setItem(i, 2, ntlmItem)

            self.view.resizeColumnsToContents()

        return
