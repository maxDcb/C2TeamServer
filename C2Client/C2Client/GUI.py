import argparse
import logging
import signal
import sys
from typing import Optional

from PyQt5.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QWidget,
)

from .grpcClient import GrpcClient
from .ListenerPanel import Listeners
from .SessionPanel import Sessions
from .ConsolePanel import ConsolesTab
from .GraphPanel import Graph

import qdarktheme

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

signal.signal(signal.SIGINT, signal.SIG_DFL)


class App(QMainWindow):
    """Main application window for the C2 client."""

    def __init__(self, ip: str, port: int, devMode: bool) -> None:
        super().__init__()

        self.ip = ip
        self.port = port
        self.devMode = devMode

        try:
            self.grpcClient = GrpcClient(self.ip, self.port, self.devMode)
        except ValueError as e:
            raise e

        self.createPayloadWindow: Optional[QWidget] = None
        
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
        self.sessionsWidget.sessionScriptSignal.connect(self.consoleWidget.assistant.sessionAssistantMethod)
        self.listenersWidget.listenerScriptSignal.connect(self.consoleWidget.script.listenerScriptMethod)

        self.sessionsWidget.interactWithSession.connect(self.consoleWidget.addConsole)

        self.consoleWidget.script.mainScriptMethod("start", "", "", "")
        
        self.show()


    def topLayout(self) -> None:
        """Initialise the upper part of the main window."""

        self.topWidget = QTabWidget()

        self.m_main = QWidget()

        self.m_main.layout = QHBoxLayout(self.m_main)
        self.m_main.layout.setContentsMargins(0, 0, 0, 0)

        self.sessionsWidget = Sessions(self, self.grpcClient)
        self.listenersWidget = Listeners(self, self.grpcClient)

        # Adjust the stretch factors: sessions gets more space, listeners gets less
        self.m_main.layout.addWidget(self.sessionsWidget, 2)  # 66% width
        self.m_main.layout.addWidget(self.listenersWidget, 1)  # 33% width

        self.topWidget.addTab(self.m_main, "Main")

        self.graphWidget = Graph(self, self.grpcClient)
        self.topWidget.addTab(self.graphWidget, "Graph")

        self.mainLayout.addWidget(self.topWidget, 1, 1, 1, 1)


    def botLayout(self) -> None:
        """Initialise the bottom console area."""

        self.consoleWidget = ConsolesTab(self, self.grpcClient)
        self.mainLayout.addWidget(self.consoleWidget, 2, 0, 1, 2)


    def __del__(self) -> None:
        """Ensure scripts are stopped when the window is destroyed."""
        if hasattr(self, 'consoleWidget'):
            self.consoleWidget.script.mainScriptMethod("stop", "", "", "")


    def payloadForm(self) -> None:
        """Display the payload creation window."""
        if self.createPayloadWindow is None:
            try:
                from .ScriptPanel import CreatePayload  # type: ignore
            except Exception:
                CreatePayload = QWidget  # fallback to simple widget
            self.createPayloadWindow = CreatePayload()
        self.createPayloadWindow.show()


def main() -> None:
    """Entry point used by the project script."""

    parser = argparse.ArgumentParser(description='TeamServer IP and port.')
    parser.add_argument('--ip', default='127.0.0.1', help='IP address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=50051, help='Port number (default: 50051)')
    parser.add_argument('--dev', action='store_true', help='Enable developer mode to disable the SSL hostname check.')

    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setStyleSheet(qdarktheme.load_stylesheet())

    try:
        App(args.ip, args.port, args.dev)
    except ValueError:
        sys.exit(1)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
