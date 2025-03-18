import sys
import os
import signal
import argparse
import logging

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from grpcClient import *
from ListenerPanel import *
from SessionPanel import *
from ConsolePanel import *
from GraphPanel import *

import qdarktheme

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

signal.signal(signal.SIGINT, signal.SIG_DFL)


class App(QMainWindow):

    def __init__(self, ip, port, devMode):
        super().__init__()

        self.ip = ip
        self.port = port
        self.devMode = devMode

        try:
            self.grpcClient = GrpcClient(self.ip, self.port, self.devMode)
        except ValueError as e:
            raise e

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

        config_button = QPushButton("Payload")
        config_button.clicked.connect(self.payloadForm)

        self.mainLayout = QGridLayout(central_widget)
        self.mainLayout.setContentsMargins(0, 0, 0, 0)
        self.mainLayout.setRowStretch(1, 3)
        self.mainLayout.setRowStretch(2, 7)

        self.topLayout()
        self.botLayout()

        self.sessionsWidget.sessionScriptSignal.connect(self.consoleWidget.script.sessionScriptMethod)
        self.listenersWidget.listenerScriptSignal.connect(self.consoleWidget.script.listenerScriptMethod)

        self.sessionsWidget.interactWithSession.connect(self.consoleWidget.addConsole)

        self.consoleWidget.script.mainScriptMethod("start", "", "", "")
        
        self.show()


    def topLayout(self):

        self.topWidget = QTabWidget()

        self.m_main = QWidget()

        self.m_main.layout = QHBoxLayout(self.m_main)
        self.m_main.layout.setContentsMargins(0, 0, 0, 0)
        self.sessionsWidget = Sessions(self, self.grpcClient)
        self.m_main.layout.addWidget(self.sessionsWidget)
        self.listenersWidget = Listeners(self, self.grpcClient)
        self.m_main.layout.addWidget( self.listenersWidget)

        self.topWidget.addTab(self.m_main, "Main")

        self.graphWidget = Graph(self, self.grpcClient)
        self.topWidget.addTab(self.graphWidget, "Graph")

        self.mainLayout.addWidget(self.topWidget, 1, 1, 1, 1)


    def botLayout(self):

        self.consoleWidget = ConsolesTab(self, self.grpcClient)
        self.mainLayout.addWidget(self.consoleWidget, 2, 0, 1, 2)


    def __del__(self):
        if hasattr(self, 'consoleWidget'):
            self.consoleWidget.script.mainScriptMethod("stop", "", "", "")


    def payloadForm(self):
        if self.createPayloadWindow is None:
            self.createPayloadWindow = CreatePayload()
        self.createPayloadWindow.show()


def main():
    parser = argparse.ArgumentParser(description='TeamServer IP and port.')
    parser.add_argument('--ip', default='127.0.0.1', help='IP address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=50051, help='Port number (default: 50051)')
    parser.add_argument('--dev', action='store_true', help='Enable developer mode to disable the SSL hostname check.')

    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setStyleSheet(qdarktheme.load_stylesheet())

    try:
        ex = App(args.ip, args.port, args.dev)
    except ValueError as e:
        sys.exit(1)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()