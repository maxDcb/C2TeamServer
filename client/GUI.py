import sys
import signal
import argparse
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *
from ListenerPanel import *
from SessionPanel import *
from ConsolePanel import *
from PayloadPanel import *

import qdarktheme


signal.signal(signal.SIGINT, signal.SIG_DFL)

class App(QMainWindow):

    def __init__(self, ip, port, devMode):
        super().__init__()

        self.ip = ip
        self.port = port

        self.createPayloadWindow = None
        
        self.title = 'Exploration C2'
        self.left = 0
        self.top = 0
        self.width = 1000
        self.height = 1000
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.m_w11 = QWidget()
        self.m_w12 = QWidget()
        self.m_w21 = QWidget()

        config_button = QPushButton("Payload")
        config_button.clicked.connect(self.payloadForm)

        lay = QGridLayout(central_widget)
        lay.setRowStretch(1, 3)
        lay.setRowStretch(2, 7)
        # TODO complet PayloadPanel
        # row: int, column: int, rowSpan: int, columnSpan: int, alignment
        #lay.addWidget(config_button, 0, 0, 1, 1)
        lay.addWidget(self.m_w11, 1, 0, 1, 1)
        lay.addWidget(self.m_w12, 1, 1, 1, 1)
        lay.addWidget(self.m_w21, 2, 0, 1, 2)

        lay = QVBoxLayout(self.m_w11)
        sessionsWidget = Sessions(self, ip, port, devMode)
        lay.addWidget(sessionsWidget)

        lay = QVBoxLayout(self.m_w12)
        listenersWidget = Listeners(self, ip, port, devMode)
        lay.addWidget(listenersWidget)

        lay = QVBoxLayout(self.m_w21)
        consoleWidget = ConsolesTab(self, ip, port, devMode)
        lay.addWidget(consoleWidget)

        sessionsWidget.interactWithSession.connect(consoleWidget.addConsole)
        
        self.show()

    def __del__(self):
        print("Exit")

    def payloadForm(self):
        if self.createPayloadWindow is None:
            self.createPayloadWindow = CreatePayload()
        self.createPayloadWindow.show()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='TeamServer IP and port.')
    parser.add_argument('--ip', default='127.0.0.1', help='IP address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=50051, help='Port number (default: 50051)')
    parser.add_argument('--dev', action='store_true', help='Enable developer mode to disable the SSL hostname check.')

    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setStyleSheet(qdarktheme.load_stylesheet())

    ex = App(args.ip, args.port, args.dev)
    sys.exit(app.exec_())