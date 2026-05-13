from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .console_style import apply_console_output_style
from .grpcClient import TeamServerApi_pb2
from .grpc_status import is_response_ok, operation_ack_text, response_message
from .panel_style import apply_dark_panel_style
from .ui_status import StatusKind, apply_status, compact_message


CredentialVaultTabTitle = "Vault"

ALL_FILTER = "All"
TYPE_FILTERS = [ALL_FILTER, "password", "ntlm_hash", "token", "ssh_key", "custom"]
ENTRY_TYPES = ["password", "ntlm_hash", "token", "ssh_key", "custom"]

COL_TITLE = 0
COL_USERNAME = 1
COL_TYPE = 2
COL_SECRET = 3
COL_NOTES = 4
COL_MODIFIED = 5

SECRET_NAME_BY_TYPE = {
    "password": "password",
    "ntlm_hash": "ntlm",
    "token": "token",
    "ssh_key": "private_key",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _field(value: Any, name: str, default: Any = "") -> Any:
    return getattr(value, name, default)


def _list_field(value: Any, name: str) -> list[Any]:
    field = _field(value, name, [])
    try:
        return list(field)
    except TypeError:
        return []


def _first_text(values: list[Any]) -> str:
    for value in values:
        text = _text(value)
        if text:
            return text
    return ""


def secret_name_for_type(credential_type: str, existing_secret_name: str = "") -> str:
    normalized_type = _text(credential_type).lower()
    if existing_secret_name and normalized_type == "custom":
        return existing_secret_name
    return SECRET_NAME_BY_TYPE.get(normalized_type, existing_secret_name or "secret")


def first_secret_value(secrets: list[Any]) -> tuple[str, str]:
    for secret in secrets:
        name = _text(_field(secret, "name"))
        value = str(_field(secret, "value", ""))
        if name:
            return name, value
    return "", ""


class CredentialEntryDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        *,
        title: str,
        credential: Any | None = None,
        secret_name: str = "",
        secret_value: str = "",
        require_secret: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumSize(680, 480)
        self.resize(740, 520)
        self.secretName = secret_name
        self.requireSecret = require_secret
        apply_dark_panel_style(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        form = QFormLayout()
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(6)

        self.titleInput = QLineEdit(self)
        self.titleInput.setPlaceholderText("Title")
        self.usernameInput = QLineEdit(self)
        self.usernameInput.setPlaceholderText("Username or DOMAIN\\username")
        self.typeInput = QComboBox(self)
        self.typeInput.addItems(ENTRY_TYPES)
        self.typeInput.setEditable(True)
        self.secretInput = QLineEdit(self)
        self.secretInput.setPlaceholderText("Secret value")
        self.secretInput.setEchoMode(QLineEdit.EchoMode.Password)
        self.showSecretCheck = QCheckBox("Show", self)
        self.showSecretCheck.stateChanged.connect(self.toggleSecretVisibility)
        secretRow = QHBoxLayout()
        secretRow.setSpacing(6)
        secretRow.addWidget(self.secretInput, 1)
        secretRow.addWidget(self.showSecretCheck)

        self.notesInput = QTextEdit(self)
        self.notesInput.setPlaceholderText("Notes / description")
        self.notesInput.setMinimumHeight(150)
        apply_console_output_style(self.notesInput)

        form.addRow("Title", self.titleInput)
        form.addRow("Username", self.usernameInput)
        form.addRow("Type", self.typeInput)
        form.addRow("Secret", secretRow)
        form.addRow("Notes", self.notesInput)
        layout.addLayout(form)

        self.statusLabel = QLabel("", self)
        layout.addWidget(self.statusLabel)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if credential is not None:
            self.titleInput.setText(_text(_field(credential, "display_name")))
            self.usernameInput.setText(_text(_field(credential, "username")))
            self.typeInput.setEditText(_text(_field(credential, "type")) or "password")
            self.notesInput.setPlainText(_text(_field(credential, "description")))
        else:
            self.typeInput.setEditText("password")

        if secret_value:
            self.secretInput.setText(secret_value)
        elif not require_secret:
            self.secretInput.setPlaceholderText("Leave empty to keep current secret")

    def toggleSecretVisibility(self) -> None:
        self.secretInput.setEchoMode(
            QLineEdit.EchoMode.Normal
            if self.showSecretCheck.isChecked()
            else QLineEdit.EchoMode.Password
        )

    def values(self) -> dict[str, str]:
        return {
            "title": self.titleInput.text().strip(),
            "username": self.usernameInput.text().strip(),
            "type": self.typeInput.currentText().strip(),
            "secret_name": self.secretName,
            "secret": self.secretInput.text(),
            "description": self.notesInput.toPlainText().strip(),
        }

    def accept(self) -> None:
        values = self.values()
        if not values["title"]:
            apply_status(self.statusLabel, "Title is required.", StatusKind.ERROR)
            return
        if not values["type"]:
            apply_status(self.statusLabel, "Type is required.", StatusKind.ERROR)
            return
        if self.requireSecret and not values["secret"]:
            apply_status(self.statusLabel, "Secret value is required.", StatusKind.ERROR)
            return
        super().accept()


class CredentialVault(QWidget):
    COLUMN_WIDTHS = [240, 180, 104, 90, 360, 150]
    STRETCH_COLUMN = COL_NOTES

    def __init__(self, parent: QWidget | None, grpcClient: Any) -> None:
        super().__init__(parent)
        self.grpcClient = grpcClient
        self.credentials: list[Any] = []
        self.selectedCredentialId = ""
        self.detailSecretRevealed = False
        apply_dark_panel_style(self)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.typeFilter = self.createFilter(TYPE_FILTERS, "Filter by credential type.")
        self.usernameFilter = self.createLineEdit("Username", "Filter by username.")
        self.searchInput = self.createLineEdit("Search title / notes", "Filter by title, username, notes, or id.")
        self.refreshButton = self.createToolbarButton("Refresh", "Refresh credential vault.", width=72)
        self.refreshButton.clicked.connect(self.refreshCredentials)
        self.newButton = self.createToolbarButton("New", "Create a credential entry.", width=64)
        self.newButton.clicked.connect(self.addCredential)
        self.editButton = self.createToolbarButton("Edit", "Edit selected credential entry.", width=64)
        self.editButton.clicked.connect(self.editSelectedCredential)
        self.deleteButton = self.createToolbarButton("Delete", "Delete selected credential.", width=72)
        self.deleteButton.clicked.connect(self.deleteSelectedCredential)

        toolbar.addWidget(QLabel("Type"))
        toolbar.addWidget(self.typeFilter)
        toolbar.addWidget(self.usernameFilter)
        toolbar.addWidget(self.searchInput, 1)
        toolbar.addWidget(self.refreshButton)
        toolbar.addWidget(self.newButton)
        toolbar.addWidget(self.editButton)
        toolbar.addWidget(self.deleteButton)
        self.layout.addLayout(toolbar)

        self.statusLabel = QLabel("")
        self.statusLabel.setMinimumHeight(18)
        self.layout.addWidget(self.statusLabel)

        self.credentialTable = QTableWidget(self)
        self.credentialTable.setObjectName("C2CredentialVaultTable")
        self.credentialTable.setShowGrid(False)
        self.credentialTable.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.credentialTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.credentialTable.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.credentialTable.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.credentialTable.setRowCount(0)
        self.credentialTable.setColumnCount(len(self.COLUMN_WIDTHS))
        self.credentialTable.verticalHeader().setVisible(False)
        self.credentialTable.itemSelectionChanged.connect(self.onSelectionChanged)
        self.credentialTable.itemDoubleClicked.connect(lambda _item: self.editSelectedCredential())
        self.configureTableColumns()
        self.layout.addWidget(self.credentialTable, 1)

        self.detailsFrame = QFrame(self)
        self.detailsFrame.setObjectName("C2CredentialVaultDetails")
        self.detailsFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.detailsFrame.setStyleSheet(
            """
            QFrame#C2CredentialVaultDetails {
                background-color: #101820;
                border: 1px solid #263443;
                border-radius: 4px;
            }
            """
        )
        detailsLayout = QGridLayout(self.detailsFrame)
        detailsLayout.setContentsMargins(10, 8, 10, 8)
        detailsLayout.setHorizontalSpacing(10)
        detailsLayout.setVerticalSpacing(4)
        self.detailTitleLabel = QLabel("-", self.detailsFrame)
        self.detailUsernameLabel = QLabel("-", self.detailsFrame)
        self.detailTypeLabel = QLabel("-", self.detailsFrame)
        self.detailModifiedLabel = QLabel("-", self.detailsFrame)
        self.detailNotesLabel = QLabel("-", self.detailsFrame)
        self.detailNotesLabel.setWordWrap(True)
        self.detailIdLabel = QLineEdit("-", self.detailsFrame)
        self.detailIdLabel.setReadOnly(True)
        self.detailIdLabel.setToolTip("Selected credential id. Select and copy it for --vault if needed.")
        self.detailSecretLabel = QLineEdit("••••••••", self.detailsFrame)
        self.detailSecretLabel.setReadOnly(True)
        self.detailSecretLabel.setToolTip("Selected credential secret. Reveal to inspect, select, or copy it.")
        self.detailRevealButton = self.createToolbarButton("Reveal", "Reveal selected credential secret.", width=72)
        self.detailRevealButton.clicked.connect(self.revealDetailSecret)

        detailsLayout.addWidget(QLabel("Title"), 0, 0)
        detailsLayout.addWidget(self.detailTitleLabel, 0, 1)
        detailsLayout.addWidget(QLabel("Username"), 0, 2)
        detailsLayout.addWidget(self.detailUsernameLabel, 0, 3)
        detailsLayout.addWidget(QLabel("Type"), 1, 0)
        detailsLayout.addWidget(self.detailTypeLabel, 1, 1)
        detailsLayout.addWidget(QLabel("Modified"), 1, 2)
        detailsLayout.addWidget(self.detailModifiedLabel, 1, 3)
        detailsLayout.addWidget(QLabel("Secret"), 2, 0)
        secretLayout = QHBoxLayout()
        secretLayout.setContentsMargins(0, 0, 0, 0)
        secretLayout.setSpacing(6)
        secretLayout.addWidget(self.detailSecretLabel, 1)
        secretLayout.addWidget(self.detailRevealButton)
        detailsLayout.addLayout(secretLayout, 2, 1, 1, 3)
        detailsLayout.addWidget(QLabel("ID"), 3, 0)
        detailsLayout.addWidget(self.detailIdLabel, 3, 1, 1, 3)
        detailsLayout.addWidget(QLabel("Notes"), 4, 0)
        detailsLayout.addWidget(self.detailNotesLabel, 4, 1, 1, 3)
        self.layout.addWidget(self.detailsFrame)

        self.connectFilterSignals()
        self.updateActionButtons()
        self.refreshCredentials()

    def createFilter(self, values: list[str], tooltip: str) -> QComboBox:
        combo = QComboBox(self)
        combo.addItems(values)
        combo.setToolTip(tooltip)
        combo.setMinimumWidth(112)
        return combo

    def createLineEdit(self, placeholder: str, tooltip: str) -> QLineEdit:
        line_edit = QLineEdit(self)
        line_edit.setPlaceholderText(placeholder)
        line_edit.setToolTip(tooltip)
        return line_edit

    def createToolbarButton(self, text: str, tooltip: str, width: int = 58) -> QPushButton:
        button = QPushButton(text, self)
        button.setToolTip(tooltip)
        button.setFixedHeight(26)
        button.setMinimumWidth(width)
        button.setMaximumWidth(width)
        return button

    def configureTableColumns(self) -> None:
        header = self.credentialTable.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(54)
        for index, width in enumerate(self.COLUMN_WIDTHS):
            if index == self.STRETCH_COLUMN:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
                self.credentialTable.setColumnWidth(index, width)

    def connectFilterSignals(self) -> None:
        self.typeFilter.currentTextChanged.connect(lambda _value: self.refreshCredentials())
        self.usernameFilter.returnPressed.connect(self.refreshCredentials)
        self.searchInput.returnPressed.connect(self.refreshCredentials)

    def buildQuery(self) -> Any:
        query = TeamServerApi_pb2.CredentialQuery()
        credential_type = self.typeFilter.currentText().strip()
        if credential_type and credential_type != ALL_FILTER:
            query.type = credential_type
        if self.usernameFilter.text().strip():
            query.username = self.usernameFilter.text().strip()
        if self.searchInput.text().strip():
            query.name_contains = self.searchInput.text().strip()
        return query

    def refreshCredentials(self) -> None:
        try:
            self.credentials = list(self.grpcClient.listCredentials(self.buildQuery()))
        except Exception as exc:
            self.credentials = []
            self.printCredentials()
            apply_status(
                self.statusLabel,
                f"Vault: {compact_message(exc, limit=120)}",
                StatusKind.ERROR,
            )
            return

        self.printCredentials()
        apply_status(
            self.statusLabel,
            f"Vault: {len(self.credentials)} item(s)",
            StatusKind.SUCCESS,
        )

    def printCredentials(self) -> None:
        preferred_credential_id = self.selectedCredentialId
        self.selectedCredentialId = ""
        self.updateDetails(None)
        self.credentialTable.setRowCount(len(self.credentials))
        self.credentialTable.setHorizontalHeaderLabels(
            ["Title", "Username", "Type", "Secret", "Notes", "Modified"]
        )

        for row, credential in enumerate(self.credentials):
            credential_id = _text(_field(credential, "credential_id"))
            secret_fields = _list_field(credential, "secret_fields")
            has_secret = bool(_first_text(secret_fields))
            values = [
                _text(_field(credential, "display_name")),
                _text(_field(credential, "username")),
                _text(_field(credential, "type")),
                "••••••••" if has_secret else "",
                _text(_field(credential, "description")),
                _text(_field(credential, "updated_at")),
            ]
            tooltip = "\n".join(
                value
                for value in [
                    f"id: {credential_id}" if credential_id else "",
                    f"secret: {_first_text(secret_fields)}" if has_secret else "",
                ]
                if value
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                item.setData(Qt.ItemDataRole.UserRole, row)
                if tooltip:
                    item.setToolTip(tooltip)
                self.credentialTable.setItem(row, column, item)

        self.restoreSelection(preferred_credential_id)
        self.updateActionButtons()

    def restoreSelection(self, preferred_credential_id: str = "") -> None:
        if not self.credentials:
            self.credentialTable.clearSelection()
            self.selectedCredentialId = ""
            self.updateDetails(None)
            return

        row_to_select = -1
        if preferred_credential_id:
            for row, credential in enumerate(self.credentials):
                if _text(_field(credential, "credential_id")) == preferred_credential_id:
                    row_to_select = row
                    break
        if row_to_select < 0 and len(self.credentials) == 1:
            row_to_select = 0
        if row_to_select < 0:
            self.credentialTable.clearSelection()
            self.selectedCredentialId = ""
            self.updateDetails(None)
            return

        self.credentialTable.selectRow(row_to_select)
        credential = self.credentials[row_to_select]
        self.selectedCredentialId = _text(_field(credential, "credential_id"))
        self.updateDetails(credential)

    def selectedCredential(self) -> Any | None:
        selected_rows = self.credentialTable.selectionModel().selectedRows() if self.credentialTable.selectionModel() else []
        if not selected_rows:
            if not self.selectedCredentialId:
                return None
            for credential in self.credentials:
                if _text(_field(credential, "credential_id")) == self.selectedCredentialId:
                    return credential
            return None
        row = selected_rows[0].row()
        if row < 0 or row >= len(self.credentials):
            return None
        return self.credentials[row]

    def onSelectionChanged(self) -> None:
        credential = self.selectedCredential()
        self.selectedCredentialId = _text(_field(credential, "credential_id")) if credential is not None else ""
        self.updateDetails(credential)
        self.updateActionButtons()

    def updateDetails(self, credential: Any | None = None) -> None:
        self.detailSecretRevealed = False
        self.detailTitleLabel.setText(_text(_field(credential, "display_name")) or "-")
        self.detailUsernameLabel.setText(_text(_field(credential, "username")) or "-")
        self.detailTypeLabel.setText(_text(_field(credential, "type")) or "-")
        self.detailModifiedLabel.setText(_text(_field(credential, "updated_at")) or "-")
        self.detailNotesLabel.setText(_text(_field(credential, "description")) or "-")
        self.detailIdLabel.setText(_text(_field(credential, "credential_id")) or "-")
        self.detailIdLabel.setCursorPosition(0)
        self.detailSecretLabel.setText("••••••••" if credential is not None and _first_text(_list_field(credential, "secret_fields")) else "-")
        self.detailSecretLabel.setCursorPosition(0)
        self.detailRevealButton.setText("Reveal")
        self.detailRevealButton.setToolTip("Reveal selected credential secret.")

    def buildRequestFromValues(self, values: dict[str, str], *, credential_id: str = "", replace_secret: bool = False) -> Any:
        request = TeamServerApi_pb2.CredentialUpsertRequest()
        if credential_id:
            request.credential_id = credential_id
        request.display_name = values["title"]
        request.type = values["type"]
        request.username = values["username"]
        request.description = values["description"]
        if values["secret"]:
            secret = request.secrets.add()
            secret.name = secret_name_for_type(values["type"], values.get("secret_name", ""))
            secret.value = values["secret"]
            request.replace_secrets = True
        else:
            request.replace_secrets = replace_secret
        return request

    def runEntryDialog(
        self,
        *,
        title: str,
        credential: Any | None = None,
        secret_name: str = "",
        secret_value: str = "",
        require_secret: bool = False,
    ) -> dict[str, str] | None:
        dialog = CredentialEntryDialog(
            self,
            title=title,
            credential=credential,
            secret_name=secret_name,
            secret_value=secret_value,
            require_secret=require_secret,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.values()

    def addCredential(self) -> None:
        values = self.runEntryDialog(title="New Credential", require_secret=True)
        if values is None:
            return
        try:
            ack = self.grpcClient.addCredential(self.buildRequestFromValues(values))
        except Exception as exc:
            apply_status(self.statusLabel, f"Add credential: {compact_message(exc, limit=120)}", StatusKind.ERROR)
            return
        self.handleMutationAck(ack, "Credential stored.")

    def editSelectedCredential(self) -> None:
        credential = self.selectedCredential()
        if credential is None:
            apply_status(self.statusLabel, "Edit credential: select a credential first.", StatusKind.WARNING)
            return
        try:
            detail = self.grpcClient.getCredential(self.selectedCredentialId, reveal_secret=True)
        except Exception as exc:
            apply_status(self.statusLabel, f"Edit credential: {compact_message(exc, limit=120)}", StatusKind.ERROR)
            return
        if not is_response_ok(detail):
            apply_status(self.statusLabel, response_message(detail, "Credential reveal failed."), StatusKind.ERROR)
            return
        secret_name, secret_value = first_secret_value(list(detail.secrets))
        values = self.runEntryDialog(
            title="Edit Credential",
            credential=detail.summary,
            secret_name=secret_name,
            secret_value=secret_value,
        )
        if values is None:
            return
        self.updateCredential(values)

    def updateCredential(self, values: dict[str, str]) -> None:
        if not self.selectedCredentialId:
            apply_status(self.statusLabel, "Update credential: select a credential first.", StatusKind.WARNING)
            return
        try:
            request = self.buildRequestFromValues(values, credential_id=self.selectedCredentialId)
            ack = self.grpcClient.updateCredential(request)
        except Exception as exc:
            apply_status(self.statusLabel, f"Update credential: {compact_message(exc, limit=120)}", StatusKind.ERROR)
            return
        self.handleMutationAck(ack, "Credential updated.")

    def revealDetailSecret(self) -> None:
        credential = self.selectedCredential()
        if credential is None or not self.selectedCredentialId:
            apply_status(self.statusLabel, "Reveal credential: select a credential first.", StatusKind.WARNING)
            return
        if self.detailSecretRevealed:
            self.detailSecretRevealed = False
            self.detailSecretLabel.setText("••••••••" if _first_text(_list_field(credential, "secret_fields")) else "-")
            self.detailSecretLabel.setCursorPosition(0)
            self.detailRevealButton.setText("Reveal")
            self.detailRevealButton.setToolTip("Reveal selected credential secret.")
            apply_status(self.statusLabel, "Credential secret hidden.", StatusKind.SUCCESS)
            return
        try:
            detail = self.grpcClient.getCredential(self.selectedCredentialId, reveal_secret=True)
        except Exception as exc:
            apply_status(self.statusLabel, f"Reveal credential: {compact_message(exc, limit=120)}", StatusKind.ERROR)
            return
        if not is_response_ok(detail):
            apply_status(self.statusLabel, response_message(detail, "Credential reveal failed."), StatusKind.ERROR)
            return

        _secret_name, secret_value = first_secret_value(list(detail.secrets))
        self.detailSecretRevealed = bool(secret_value)
        self.detailSecretLabel.setText(secret_value or "-")
        self.detailSecretLabel.setCursorPosition(0)
        if self.detailSecretRevealed:
            self.detailRevealButton.setText("Hide")
            self.detailRevealButton.setToolTip("Hide selected credential secret.")
            apply_status(self.statusLabel, "Credential secret revealed in details.", StatusKind.WARNING)
        else:
            self.detailRevealButton.setText("Reveal")
            self.detailRevealButton.setToolTip("Reveal selected credential secret.")
            apply_status(self.statusLabel, "Credential has no secret value to reveal.", StatusKind.WARNING)

    def deleteSelectedCredential(self) -> None:
        credential = self.selectedCredential()
        if credential is None or not self.selectedCredentialId:
            apply_status(self.statusLabel, "Delete credential: select a credential first.", StatusKind.WARNING)
            return
        title = _text(_field(credential, "display_name")) or self.selectedCredentialId[:12]
        answer = QMessageBox.question(
            self,
            "Delete credential",
            f"Delete credential '{title}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            ack = self.grpcClient.deleteCredential(self.selectedCredentialId)
        except Exception as exc:
            apply_status(self.statusLabel, f"Delete credential: {compact_message(exc, limit=120)}", StatusKind.ERROR)
            return
        self.handleMutationAck(ack, "Credential deleted.")

    def handleMutationAck(self, ack: Any, success_fallback: str) -> None:
        if is_response_ok(ack):
            apply_status(self.statusLabel, operation_ack_text(ack, success_fallback), StatusKind.SUCCESS)
            self.refreshCredentials()
        else:
            apply_status(self.statusLabel, operation_ack_text(ack), StatusKind.ERROR)

    def updateActionButtons(self) -> None:
        has_selection = bool(self.selectedCredentialId)
        self.editButton.setEnabled(has_selection)
        self.detailRevealButton.setEnabled(has_selection)
        self.deleteButton.setEnabled(has_selection)
