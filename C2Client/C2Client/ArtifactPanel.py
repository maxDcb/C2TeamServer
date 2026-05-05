from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .grpcClient import TeamServerApi_pb2
from .panel_style import apply_dark_panel_style
from .ui_status import StatusKind, apply_status, compact_message


ArtifactTabTitle = "Artifacts"

ALL_FILTER = "All"
CATEGORY_FILTERS = [ALL_FILTER, "module", "beacon", "tool", "script", "payload"]
SCOPE_FILTERS = [ALL_FILTER, "generated", "beacon", "implant", "teamserver", "server", "operator", "any"]
TARGET_FILTERS = [ALL_FILTER, "teamserver", "beacon", "listener", "operator", "any"]
PLATFORM_FILTERS = [ALL_FILTER, "windows", "linux", "server", "any"]
ARCH_FILTERS = [ALL_FILTER, "x64", "x86", "arm64", "any"]
RUNTIME_FILTERS = [ALL_FILTER, "native", "python", "dotnet", "powershell", "bof", "shellcode", "text", "archive", "any"]

COL_CATEGORY = 0
COL_SCOPE = 1
COL_TARGET = 2
COL_NAME = 3
COL_PLATFORM = 4
COL_ARCH = 5
COL_RUNTIME = 6
COL_FORMAT = 7
COL_SIZE = 8
COL_SHA256 = 9
COL_SOURCE = 10


def _text(value: Any) -> str:
    return str(value or "").strip()


def _field(artifact: Any, name: str, default: Any = "") -> Any:
    return getattr(artifact, name, default)


def _short_hash(value: Any, length: int = 12) -> str:
    text = _text(value)
    if len(text) <= length:
        return text
    return text[:length]


def format_size(size: Any) -> str:
    try:
        value = int(size)
    except (TypeError, ValueError):
        return "0 B"

    if value < 0:
        value = 0

    units = ["B", "KB", "MB", "GB"]
    size_float = float(value)
    unit_index = 0
    while size_float >= 1024 and unit_index < len(units) - 1:
        size_float /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size_float)} B"
    return f"{size_float:.1f} {units[unit_index]}"


class Artifacts(QWidget):
    COLUMN_WIDTHS = [82, 92, 92, 220, 86, 66, 92, 70, 86, 112, 88]
    STRETCH_COLUMN = COL_NAME

    def __init__(self, parent: QWidget | None, grpcClient: Any) -> None:
        super().__init__(parent)
        self.grpcClient = grpcClient
        self.artifacts: list[Any] = []
        apply_dark_panel_style(self)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self.categoryFilter = self.createFilter(CATEGORY_FILTERS, "Filter by artifact category.")
        self.scopeFilter = self.createFilter(SCOPE_FILTERS, "Filter by artifact scope.")
        self.targetFilter = self.createFilter(TARGET_FILTERS, "Filter by execution or ownership target.")
        self.platformFilter = self.createFilter(PLATFORM_FILTERS, "Filter by target platform.")
        self.archFilter = self.createFilter(ARCH_FILTERS, "Filter by target architecture.")
        self.runtimeFilter = self.createFilter(RUNTIME_FILTERS, "Filter by runtime or file family.")
        self.searchInput = QLineEdit(self)
        self.searchInput.setPlaceholderText("Name contains")
        self.searchInput.setToolTip("Filter artifacts by name.")
        self.searchInput.returnPressed.connect(self.refreshArtifacts)

        self.generatedButton = self.createToolbarButton("Generated", "Show generated shellcode artifacts.", width=84)
        self.generatedButton.clicked.connect(self.showGeneratedShellcodes)
        self.refreshButton = self.createToolbarButton("Refresh", "Refresh artifact catalog.", width=72)
        self.refreshButton.clicked.connect(self.refreshArtifacts)
        self.copyIdButton = self.createToolbarButton("Copy ID", "Copy selected artifact id.", width=72)
        self.copyIdButton.clicked.connect(self.copySelectedArtifactId)
        self.deleteButton = self.createToolbarButton("Delete", "Delete selected generated artifact.", width=72)
        self.deleteButton.clicked.connect(self.deleteSelectedGeneratedArtifact)

        toolbar.addWidget(QLabel("Category"))
        toolbar.addWidget(self.categoryFilter)
        toolbar.addWidget(QLabel("Scope"))
        toolbar.addWidget(self.scopeFilter)
        toolbar.addWidget(QLabel("Target"))
        toolbar.addWidget(self.targetFilter)
        toolbar.addWidget(QLabel("Platform"))
        toolbar.addWidget(self.platformFilter)
        toolbar.addWidget(QLabel("Arch"))
        toolbar.addWidget(self.archFilter)
        toolbar.addWidget(QLabel("Runtime"))
        toolbar.addWidget(self.runtimeFilter)
        toolbar.addWidget(self.searchInput, 1)
        toolbar.addWidget(self.generatedButton)
        toolbar.addWidget(self.refreshButton)
        toolbar.addWidget(self.copyIdButton)
        toolbar.addWidget(self.deleteButton)
        self.layout.addLayout(toolbar)

        self.statusLabel = QLabel("")
        self.statusLabel.setMinimumHeight(18)
        self.layout.addWidget(self.statusLabel)

        self.artifactTable = QTableWidget(self)
        self.artifactTable.setObjectName("C2ArtifactTable")
        self.artifactTable.setShowGrid(False)
        self.artifactTable.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.artifactTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.artifactTable.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.artifactTable.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.artifactTable.setRowCount(0)
        self.artifactTable.setColumnCount(11)
        self.artifactTable.verticalHeader().setVisible(False)
        self.artifactTable.itemSelectionChanged.connect(self.updateActionButtons)
        self.configureTableColumns()
        self.layout.addWidget(self.artifactTable, 1)

        self.updateActionButtons()
        self.refreshArtifacts()

    def createFilter(self, values: list[str], tooltip: str) -> QComboBox:
        combo = QComboBox(self)
        combo.addItems(values)
        combo.setToolTip(tooltip)
        combo.setMinimumWidth(96)
        return combo

    def createToolbarButton(self, text: str, tooltip: str, width: int = 58) -> QPushButton:
        button = QPushButton(text, self)
        button.setToolTip(tooltip)
        button.setFixedHeight(26)
        button.setMinimumWidth(width)
        button.setMaximumWidth(width)
        return button

    def configureTableColumns(self) -> None:
        header = self.artifactTable.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(48)
        for index, width in enumerate(self.COLUMN_WIDTHS):
            if index == self.STRETCH_COLUMN:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
                self.artifactTable.setColumnWidth(index, width)

    def buildQuery(self) -> Any:
        query = TeamServerApi_pb2.ArtifactQuery()

        category = self.categoryFilter.currentText()
        if category != ALL_FILTER:
            query.category = category

        scope = self.scopeFilter.currentText()
        if scope != ALL_FILTER:
            query.scope = scope

        platform = self.platformFilter.currentText()
        if platform != ALL_FILTER:
            query.platform = platform

        arch = self.archFilter.currentText()
        if arch != ALL_FILTER:
            query.arch = arch

        target = self.targetFilter.currentText()
        if target != ALL_FILTER:
            query.target = target

        runtime = self.runtimeFilter.currentText()
        if runtime != ALL_FILTER:
            query.runtime = runtime

        name_contains = self.searchInput.text().strip()
        if name_contains:
            query.name_contains = name_contains

        return query

    def showGeneratedShellcodes(self) -> None:
        self.categoryFilter.setCurrentText("payload")
        self.scopeFilter.setCurrentText("generated")
        self.targetFilter.setCurrentText(ALL_FILTER)
        self.platformFilter.setCurrentText(ALL_FILTER)
        self.archFilter.setCurrentText(ALL_FILTER)
        self.runtimeFilter.setCurrentText("shellcode")
        self.searchInput.clear()
        self.refreshArtifacts()

    def refreshArtifacts(self) -> None:
        try:
            self.artifacts = list(self.grpcClient.listArtifacts(self.buildQuery()))
        except Exception as exc:
            self.artifacts = []
            self.printArtifacts()
            apply_status(
                self.statusLabel,
                f"Artifacts: {compact_message(exc, limit=120)}",
                StatusKind.ERROR,
            )
            return

        self.printArtifacts()
        apply_status(
            self.statusLabel,
            f"Artifacts: {len(self.artifacts)} item(s)",
            StatusKind.SUCCESS,
        )

    def printArtifacts(self) -> None:
        self.artifactTable.setRowCount(len(self.artifacts))
        self.artifactTable.setHorizontalHeaderLabels(
            ["Category", "Scope", "Target", "Name", "Platform", "Arch", "Runtime", "Format", "Size", "SHA256", "Source"]
        )

        for row, artifact in enumerate(self.artifacts):
            artifact_id = _text(_field(artifact, "artifact_id"))
            full_hash = _text(_field(artifact, "sha256"))
            name = _text(_field(artifact, "name"))
            display_name = _text(_field(artifact, "display_name")) or name
            description = _text(_field(artifact, "description"))

            values = [
                _text(_field(artifact, "category")),
                _text(_field(artifact, "scope")),
                _text(_field(artifact, "target")),
                name,
                _text(_field(artifact, "platform")),
                _text(_field(artifact, "arch")),
                _text(_field(artifact, "runtime")),
                _text(_field(artifact, "format")),
                format_size(_field(artifact, "size", 0)),
                _short_hash(full_hash),
                _text(_field(artifact, "source")),
            ]

            tooltip = "\n".join(
                part for part in (
                    f"Artifact ID: {artifact_id}" if artifact_id else "",
                    f"Name: {name}" if name else "",
                    f"Display: {display_name}" if display_name and display_name != name else "",
                    f"Scope: {_text(_field(artifact, 'scope'))}" if _text(_field(artifact, "scope")) else "",
                    f"Target: {_text(_field(artifact, 'target'))}" if _text(_field(artifact, "target")) else "",
                    f"Source: {_text(_field(artifact, 'source'))}" if _text(_field(artifact, "source")) else "",
                    f"Size: {format_size(_field(artifact, 'size', 0))}",
                    f"SHA256: {full_hash}" if full_hash else "",
                    description,
                )
                if part
            )

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                item.setData(Qt.ItemDataRole.UserRole, artifact_id)
                if tooltip:
                    item.setToolTip(tooltip)
                self.artifactTable.setItem(row, column, item)

        self.updateActionButtons()

    def selectedArtifact(self) -> Any | None:
        selected_rows = self.artifactTable.selectionModel().selectedRows() if self.artifactTable.selectionModel() else []
        if not selected_rows:
            return None

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.artifacts):
            return None
        return self.artifacts[row]

    def selectedArtifactId(self) -> str:
        artifact = self.selectedArtifact()
        if artifact is None:
            return ""

        return _text(_field(artifact, "artifact_id"))

    def isGeneratedArtifact(self, artifact: Any | None) -> bool:
        return artifact is not None and _text(_field(artifact, "scope")).lower() == "generated"

    def copySelectedArtifactId(self) -> None:
        artifact_id = self.selectedArtifactId()
        if not artifact_id:
            apply_status(self.statusLabel, "Artifacts: select an artifact first.", StatusKind.ERROR)
            return

        QApplication.clipboard().setText(artifact_id)
        apply_status(self.statusLabel, "Artifacts: artifact ID copied.", StatusKind.SUCCESS)

    def deleteSelectedGeneratedArtifact(self) -> None:
        artifact = self.selectedArtifact()
        artifact_id = self.selectedArtifactId()
        if not artifact_id:
            apply_status(self.statusLabel, "Artifacts: select an artifact first.", StatusKind.ERROR)
            return
        if not self.isGeneratedArtifact(artifact):
            apply_status(self.statusLabel, "Artifacts: only generated artifacts can be deleted.", StatusKind.ERROR)
            return

        name = _text(_field(artifact, "display_name")) or _text(_field(artifact, "name")) or artifact_id
        answer = QMessageBox.question(
            self,
            "Delete generated artifact",
            f"Delete generated artifact {name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            response = self.grpcClient.deleteGeneratedArtifact(artifact_id)
        except Exception as exc:
            apply_status(
                self.statusLabel,
                f"Artifacts: {compact_message(exc, limit=120)}",
                StatusKind.ERROR,
            )
            return

        if getattr(response, "status", TeamServerApi_pb2.KO) != TeamServerApi_pb2.OK:
            message = _text(getattr(response, "message", "")) or "delete failed"
            apply_status(self.statusLabel, f"Artifacts: {compact_message(message, limit=120)}", StatusKind.ERROR)
            return

        self.refreshArtifacts()
        message = _text(getattr(response, "message", "")) or "generated artifact deleted"
        apply_status(self.statusLabel, f"Artifacts: {message}", StatusKind.SUCCESS)

    def updateActionButtons(self) -> None:
        selected_artifact = self.selectedArtifact()
        self.copyIdButton.setEnabled(bool(selected_artifact))
        self.deleteButton.setEnabled(self.isGeneratedArtifact(selected_artifact))
