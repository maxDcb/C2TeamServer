import sys
import os
import time
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class CreatePayload(QWidget):

    procDone = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        
        layout = QFormLayout()

        self.labelMethode = QLabel("Methode")
        self.qcomboMethode = QComboBox(self)
        self.qcomboMethode.addItems(["exe" , "dll" , "powershell" ])
        self.qcomboMethode.currentTextChanged.connect(self.changeLabels)
        self.methode = self.qcomboMethode
        layout.addRow(self.labelMethode, self.methode)

        self.labelType = QLabel("Type")
        self.qcombo = QComboBox(self)
        self.qcombo.addItems(["http" , "https" , "tcp" , "github" , "dns"])
        self.qcombo.currentTextChanged.connect(self.changeLabels)
        self.type = self.qcombo
        layout.addRow(self.labelType, self.type)

        self.labelIP = QLabel("IP")
        self.param1 = QLineEdit()
        layout.addRow(self.labelIP, self.param1)

        self.labelPort = QLabel("Port")
        self.param2 = QLineEdit()
        layout.addRow(self.labelPort, self.param2)

        self.buttonOk = QPushButton('&Generate', clicked=self.generate)
        layout.addRow(self.buttonOk)

        self.setLayout(layout)
        self.setWindowTitle("Add Listener")


    def changeLabels(self):
        if self.qcombo.currentText() == "http":
            self.labelIP.setText("IP")
            self.labelPort.setText("Port")
        elif self.qcombo.currentText() == "https":
            self.labelIP.setText("IP")
            self.labelPort.setText("Port")
        elif self.qcombo.currentText() == "tcp":
            self.labelIP.setText("IP")
            self.labelPort.setText("Port")
        elif self.qcombo.currentText() == "github":
            self.labelIP.setText("Project")
            self.labelPort.setText("Token")
        elif self.qcombo.currentText() == "dns":
            self.labelIP.setText("Domain")
            self.labelPort.setText("Port")


    def generate(self):
        type = self.type.currentText()
        param1 = self.param1.text()
        param2 = self.param2.text()

        print(type, param1, param2)

        # self.procDone.emit(result)
        # self.close()