import sys
import signal
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from grpcClient import *
from ListenerPanel import *
from SessionPanel import *
from ConsolePanel import *

import qdarktheme


signal.signal(signal.SIGINT, signal.SIG_DFL)

class App(QMainWindow):

    def __init__(self, ip, port):
        super().__init__()

        self.ip = ip
        self.port = port
        
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

        lay = QGridLayout(central_widget)
        lay.setRowStretch(0, 3)
        lay.setRowStretch(1, 7)
        lay.addWidget(self.m_w11, 0, 0, 1, 1)
        lay.addWidget(self.m_w12, 0, 1, 1, 1)
        lay.addWidget(self.m_w21, 1, 0, 1, 2)

        lay = QVBoxLayout(self.m_w11)
        sessionsWidget = Sessions(self, ip, port)
        lay.addWidget(sessionsWidget)

        lay = QVBoxLayout(self.m_w12)
        listenersWidget = Listeners(self, ip, port)
        lay.addWidget(listenersWidget)

        lay = QVBoxLayout(self.m_w21)
        consoleWidget = ConsolesTab(self, ip, port)
        lay.addWidget(consoleWidget)

        sessionsWidget.interactWithSession.connect(consoleWidget.addConsole)
        
        self.show()

    def __del__(self):
        print("Exit")


if __name__ == '__main__':

    ip = "localhost"
    port = 50051

    app = QApplication(sys.argv)
    app.setStyleSheet(qdarktheme.load_stylesheet())

    ex = App(ip, port)
    sys.exit(app.exec_())