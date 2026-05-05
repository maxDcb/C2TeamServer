from __future__ import annotations

import html
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .console_style import CONSOLE_COLORS, apply_console_output_style
from .grpcClient import TeamServerApi_pb2
from .panel_style import apply_dark_panel_style
from .ui_status import StatusKind, apply_status, compact_message


CommandTabTitle = "Commands"

ALL_FILTER = "All"
KIND_FILTERS = [ALL_FILTER, "common", "module"]
TARGET_FILTERS = [ALL_FILTER, "beacon", "teamserver", "operator", "any"]
PLATFORM_FILTERS = [ALL_FILTER, "windows", "linux", "macos", "any"]

COL_NAME = 0
COL_KIND = 1
COL_TARGET = 2
COL_PLATFORMS = 3
COL_ARGS = 4
COL_EXAMPLES = 5
COL_SOURCE = 6


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


def _join_values(values: list[Any]) -> str:
    return ", ".join(_text(value) for value in values if _text(value))


def format_arg_summary(command: Any) -> str:
    args = _list_field(command, "args")
    if not args:
        return "-"
    labels = []
    for arg in args:
        label = _text(_field(arg, "name"))
        arg_type = _text(_field(arg, "type"))
        if arg_type:
            label += f":{arg_type}"
        if not bool(_field(arg, "required", False)):
            label = f"[{label}]"
        if bool(_field(arg, "variadic", False)):
            label += "..."
        labels.append(label)
    return " ".join(labels)


class Commands(QWidget):
    COLUMN_WIDTHS = [150, 78, 92, 160, 240, 240, 90]
    STRETCH_COLUMN = COL_EXAMPLES

    def __init__(self, parent: QWidget | None, grpcClient: Any) -> None:
        super().__init__(parent)
        self.grpcClient = grpcClient
        self.commands: list[Any] = []
        apply_dark_panel_style(self)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self.kindFilter = self.createFilter(KIND_FILTERS, "Filter by command kind.")
        self.targetFilter = self.createFilter(TARGET_FILTERS, "Filter by command target.")
        self.platformFilter = self.createFilter(PLATFORM_FILTERS, "Filter by supported platform.")
        self.searchInput = QLineEdit(self)
        self.searchInput.setPlaceholderText("Name contains")
        self.searchInput.setToolTip("Filter commands by name.")
        self.searchInput.returnPressed.connect(self.refreshCommands)

        self.refreshButton = self.createToolbarButton("Refresh", "Refresh command catalog.", width=72)
        self.refreshButton.clicked.connect(self.refreshCommands)

        toolbar.addWidget(QLabel("Kind"))
        toolbar.addWidget(self.kindFilter)
        toolbar.addWidget(QLabel("Target"))
        toolbar.addWidget(self.targetFilter)
        toolbar.addWidget(QLabel("Platform"))
        toolbar.addWidget(self.platformFilter)
        toolbar.addWidget(self.searchInput, 1)
        toolbar.addWidget(self.refreshButton)
        self.layout.addLayout(toolbar)

        self.statusLabel = QLabel("")
        self.statusLabel.setMinimumHeight(18)
        self.layout.addWidget(self.statusLabel)

        self.commandTable = QTableWidget(self)
        self.commandTable.setObjectName("C2CommandTable")
        self.commandTable.setShowGrid(False)
        self.commandTable.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.commandTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.commandTable.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.commandTable.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.commandTable.setRowCount(0)
        self.commandTable.setColumnCount(7)
        self.commandTable.verticalHeader().setVisible(False)
        self.commandTable.itemSelectionChanged.connect(self.updateDetails)
        self.configureTableColumns()
        self.layout.addWidget(self.commandTable, 3)

        self.details = QTextBrowser(self)
        apply_console_output_style(self.details)
        self.details.setReadOnly(True)
        self.layout.addWidget(self.details, 2)

        self.refreshCommands()

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
        header = self.commandTable.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(54)
        for index, width in enumerate(self.COLUMN_WIDTHS):
            if index == self.STRETCH_COLUMN:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
                self.commandTable.setColumnWidth(index, width)

    def buildQuery(self) -> Any:
        query = TeamServerApi_pb2.CommandQuery()
        kind = self.kindFilter.currentText()
        if kind != ALL_FILTER:
            query.kind = kind
        target = self.targetFilter.currentText()
        if target != ALL_FILTER:
            query.target = target
        platform = self.platformFilter.currentText()
        if platform != ALL_FILTER:
            query.platform = platform
        name_contains = self.searchInput.text().strip()
        if name_contains:
            query.name_contains = name_contains
        return query

    def refreshCommands(self) -> None:
        try:
            self.commands = list(self.grpcClient.listCommands(self.buildQuery()))
        except Exception as exc:
            self.commands = []
            self.printCommands()
            apply_status(
                self.statusLabel,
                f"Commands: {compact_message(exc, limit=120)}",
                StatusKind.ERROR,
            )
            return

        self.printCommands()
        apply_status(
            self.statusLabel,
            f"Commands: {len(self.commands)} item(s)",
            StatusKind.SUCCESS,
        )

    def printCommands(self) -> None:
        self.commandTable.setRowCount(len(self.commands))
        self.commandTable.setHorizontalHeaderLabels(
            ["Name", "Kind", "Target", "Platforms", "Args", "Examples", "Source"]
        )

        for row, command in enumerate(self.commands):
            values = [
                _text(_field(command, "name")),
                _text(_field(command, "kind")),
                _text(_field(command, "target")),
                _join_values(_list_field(command, "platforms")),
                format_arg_summary(command),
                _join_values(_list_field(command, "examples")),
                _text(_field(command, "source")),
            ]
            tooltip = _text(_field(command, "description"))

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                item.setData(Qt.ItemDataRole.UserRole, row)
                if tooltip:
                    item.setToolTip(tooltip)
                self.commandTable.setItem(row, column, item)

        self.updateDetails()

    def selectedCommand(self) -> Any | None:
        selected_rows = self.commandTable.selectionModel().selectedRows() if self.commandTable.selectionModel() else []
        if not selected_rows:
            return None
        row = selected_rows[0].row()
        if row < 0 or row >= len(self.commands):
            return None
        return self.commands[row]

    def updateDetails(self) -> None:
        command = self.selectedCommand()
        if command is None:
            self.details.setHtml(
                f'<p style="color:{CONSOLE_COLORS["muted"]}; margin:0;">Select a command to inspect its spec.</p>'
            )
            return

        parts = [
            f'<p style="margin:0 0 6px 0;"><span style="color:{CONSOLE_COLORS["header"]};">{html.escape(_text(_field(command, "name")))}</span>'
            f' <span style="color:{CONSOLE_COLORS["muted"]};">({_text(_field(command, "kind"))})</span></p>',
            f'<p style="margin:0 0 6px 0; color:{CONSOLE_COLORS["text"]};">{html.escape(_text(_field(command, "description")))}</p>',
            '<p style="margin:0 0 4px 0;">'
            f'<span style="color:{CONSOLE_COLORS["timestamp"]};">target</span> {html.escape(_text(_field(command, "target")))} '
            f'<span style="color:{CONSOLE_COLORS["timestamp"]};">platforms</span> {html.escape(_join_values(_list_field(command, "platforms")))} '
            f'<span style="color:{CONSOLE_COLORS["timestamp"]};">archs</span> {html.escape(_join_values(_list_field(command, "archs")))}'
            '</p>',
        ]

        args = _list_field(command, "args")
        if args:
            parts.append(f'<p style="margin:8px 0 4px 0; color:{CONSOLE_COLORS["timestamp"]};">args</p>')
            parts.append("<ul>")
            for arg in args:
                required = "required" if bool(_field(arg, "required", False)) else "optional"
                parts.append(
                    "<li>"
                    f'<span style="color:{CONSOLE_COLORS["header"]};">{html.escape(_text(_field(arg, "name")))}</span>'
                    f' <span style="color:{CONSOLE_COLORS["muted"]};">{html.escape(_text(_field(arg, "type")))} / {required}</span>'
                    f' {html.escape(_text(_field(arg, "description")))}'
                    "</li>"
                )
            parts.append("</ul>")

        examples = _list_field(command, "examples")
        if examples:
            parts.append(f'<p style="margin:8px 0 4px 0; color:{CONSOLE_COLORS["timestamp"]};">examples</p>')
            parts.append("<pre style='margin:0; white-space:pre-wrap;'>")
            parts.append(html.escape("\n".join(_text(example) for example in examples)))
            parts.append("</pre>")

        self.details.setHtml("".join(parts))
