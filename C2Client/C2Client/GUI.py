import argparse
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Optional, Tuple

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .grpcClient import GrpcClient
from .ListenerPanel import Listeners
from .SessionPanel import Sessions
from .ConsolePanel import ConsolesTab
from .GraphPanel import Graph
from .env import env_bool, env_int, env_value, load_c2_env
from .ui_status import (
    DEFAULT_LAST_ERROR_TEXT,
    DEFAULT_LAST_RPC_TEXT,
    StatusKind,
    apply_error,
    apply_status,
    clear_status,
    compact_message,
    format_last_error,
    format_last_rpc,
)

import qdarktheme

def configureLogging() -> None:
    level_name = env_value("C2_LOG_LEVEL", "WARNING").strip().upper()
    level = getattr(logging, level_name, logging.WARNING)
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger().setLevel(level)
    for noisy_logger in ("openai", "httpx", "httpcore"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


configureLogging()

signal.signal(signal.SIGINT, signal.SIG_DFL)


class RpcStatusEvents(QObject):
    """Bridge gRPC worker-thread status callbacks back to the Qt UI thread."""

    rpcStatus = pyqtSignal(str, bool, str)


class CredentialDialog(QDialog):
    """Prompt for credentials when environment variables are absent."""

    def __init__(self, parent: Optional[QWidget] = None, default_username: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setModal(True)

        layout = QVBoxLayout(self)
        description = QLabel("Login:")
        description.setWordWrap(True)
        layout.addWidget(description)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Username")
        if default_username:
            self.username_input.setText(default_username)
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.error_label = QLabel()
        apply_error(self.error_label, "Username and password are required.")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._handle_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _handle_accept(self) -> None:
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username or not password:
            self.error_label.setVisible(True)
            return
        self.accept()

    def credentials(self) -> Tuple[str, str]:
        return self.username_input.text().strip(), self.password_input.text()


class App(QMainWindow):
    """Main application window for the C2 client."""

    def __init__(self, ip: str, port: int, devMode: bool, credentials: Optional[Tuple[str, str]] = None) -> None:
        super().__init__()

        self.ip = ip
        self.port = port
        self.devMode = devMode

        username: Optional[str] = None
        password: Optional[str] = None
        if credentials:
            username, password = credentials

        try:
            self.grpcClient = GrpcClient(
                self.ip,
                self.port,
                self.devMode,
                username=username,
                password=password,
            )
        except ValueError as e:
            raise e

        self.createPayloadWindow: Optional[QWidget] = None
        self.operatorUsername = username or getattr(self.grpcClient, "username", "") or "unknown"
        self._lastRpcError = ""
        
        self.title = 'Exploration C2'
        self.left = 0
        self.top = 0
        self.width = 1000
        self.height = 1000
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        self.rpcStatusEvents = RpcStatusEvents(self)
        self.rpcStatusEvents.rpcStatus.connect(self.updateRpcStatus)
        if hasattr(self.grpcClient, "set_status_callback"):
            self.grpcClient.set_status_callback(self.rpcStatusEvents.rpcStatus.emit)
        self.setupStatusBar()
        
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

        if hasattr(self.consoleWidget.script, "setClientStateProvider"):
            self.consoleWidget.script.setClientStateProvider(
                lambda: {
                    "sessions": self.sessionsWidget.scriptSnapshot(),
                    "listeners": self.listenersWidget.scriptSnapshot(),
                }
            )

        self.consoleWidget.script.mainScriptMethod("start", "", "", "")

    def setupStatusBar(self) -> None:
        """Initialise the persistent connection and RPC status widgets."""

        self.connectionStatusLabel = QLabel(self)
        self.rpcStatusLabel = QLabel(DEFAULT_LAST_RPC_TEXT, self)
        self.errorStatusLabel = QLabel(DEFAULT_LAST_ERROR_TEXT, self)

        for label in (self.connectionStatusLabel, self.rpcStatusLabel, self.errorStatusLabel):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        status_bar = self.statusBar()
        status_bar.setSizeGripEnabled(False)
        status_bar.addWidget(self.connectionStatusLabel, 5)
        status_bar.addPermanentWidget(self.rpcStatusLabel, 2)
        status_bar.addPermanentWidget(self.errorStatusLabel, 4)

        self.setConnectionStatus(True)

    def setConnectionStatus(self, connected: bool) -> None:
        state = "Connected" if connected else "RPC error"
        endpoint = getattr(self.grpcClient, "endpoint", f"{self.ip}:{self.port}")
        client_id = getattr(self.grpcClient, "client_id", "")
        client_id_text = f" | client {client_id[:8]}" if client_id else ""
        cert_path = getattr(self.grpcClient, "ca_cert_path", "")
        cert_name = os.path.basename(cert_path) if cert_path else "unknown cert"
        tls_mode = "dev TLS" if self.devMode else "TLS"
        apply_status(
            self.connectionStatusLabel,
            f"{state} | {endpoint} | user {self.operatorUsername} | {tls_mode} | cert {cert_name}{client_id_text}",
            StatusKind.SUCCESS if connected else StatusKind.ERROR,
        )

    def updateRpcStatus(self, operation: str, ok: bool, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.setConnectionStatus(ok)
        self.rpcStatusLabel.setText(format_last_rpc(operation, timestamp))

        if not ok:
            self._lastRpcError = format_last_error(operation, message)
            apply_error(self.errorStatusLabel, f"Last error: {self._lastRpcError}")
        elif not self._lastRpcError:
            clear_status(self.errorStatusLabel, DEFAULT_LAST_ERROR_TEXT)

    @staticmethod
    def compactStatusMessage(message: str, limit: int = 160) -> str:
        return compact_message(message, limit=limit)

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


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI parser using environment-backed defaults."""

    default_ip = env_value("C2_IP", "127.0.0.1")
    default_port = env_int("C2_PORT", 50051, minimum=1, maximum=65535)
    default_dev_mode = env_bool("C2_DEV_MODE", False)

    parser = argparse.ArgumentParser(description='TeamServer IP and port.')
    parser.add_argument('--ip', default=default_ip, help=f'IP address (default: {default_ip})')
    parser.add_argument('--port', type=int, default=default_port, help=f'Port number (default: {default_port})')
    parser.add_argument(
        '--dev',
        action=argparse.BooleanOptionalAction,
        default=default_dev_mode,
        help='Enable developer mode to disable the SSL hostname check.',
    )
    return parser


def parse_client_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse client arguments after loading `.env` values."""

    load_c2_env()
    return build_arg_parser().parse_args(argv)


def main() -> None:
    """Entry point used by the project script."""

    args = parse_client_args()

    app = QApplication(sys.argv)
    theme = env_value("C2_UI_THEME", "dark").strip().lower()
    if theme in {"dark", "light"}:
        app.setStyleSheet(qdarktheme.load_stylesheet(theme))
    elif theme not in {"native", "none"}:
        app.setStyleSheet(qdarktheme.load_stylesheet())

    username = os.getenv("C2_USERNAME")
    password = os.getenv("C2_PASSWORD")

    credentials: Optional[Tuple[str, str]] = None
    if username and password:
        credentials = (username, password)
    else:
        dialog = CredentialDialog(default_username=username or "")
        if dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(1)
        credentials = dialog.credentials()

    try:
        window = App(args.ip, args.port, args.dev, credentials)
        window.show()
        sys.exit(app.exec())
    except ValueError:
        sys.exit(1)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
