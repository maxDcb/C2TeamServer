from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .console_style import CONSOLE_COLORS, console_font


@dataclass(frozen=True)
class CompletionOption:
    label: str
    insert_text: str
    full_text: str
    has_children: bool = False


def completion_entry_text(entry: tuple) -> str:
    return str(entry[0]).strip() if entry else ""


def completion_entry_children(entry: tuple) -> list[tuple]:
    if len(entry) < 2 or entry[1] is None:
        return []
    return entry[1]


def completion_entry_insert_text(entry: tuple) -> str:
    if len(entry) >= 3:
        insert_text = str(entry[2]).strip()
        if insert_text:
            return insert_text
    return completion_entry_text(entry)


def _find_entry(entries: Iterable[tuple], token: str) -> tuple | None:
    normalized_token = token.strip().lower()
    if not normalized_token:
        return None
    for entry in entries:
        label = completion_entry_text(entry).lower()
        insert_text = completion_entry_insert_text(entry).lower()
        if normalized_token in {label, insert_text}:
            return entry
    return None


def _entry_matches(entry: tuple, token: str) -> bool:
    normalized_token = token.strip().lower()
    if not normalized_token:
        return True
    label = completion_entry_text(entry).lower()
    insert_text = completion_entry_insert_text(entry).lower()
    return (
        label.startswith(normalized_token)
        or insert_text.startswith(normalized_token)
        or ("(" in label and normalized_token in label)
    )


def _options_for_level(entries: Iterable[tuple], prefix_parts: list[str], token: str = "") -> list[CompletionOption]:
    options: list[CompletionOption] = []
    seen: set[str] = set()
    for entry in entries:
        if not _entry_matches(entry, token):
            continue
        label = completion_entry_text(entry)
        insert_text = completion_entry_insert_text(entry)
        if not label or not insert_text:
            continue
        full_parts = [*prefix_parts, insert_text]
        full_text = " ".join(full_parts)
        if full_text in seen:
            continue
        seen.add(full_text)
        options.append(
            CompletionOption(
                label=label,
                insert_text=insert_text,
                full_text=full_text,
                has_children=bool(completion_entry_children(entry)),
            )
        )
    return options


def completion_options(
    completion_data: list[tuple],
    command_text: str,
    cursor_position: int | None = None,
    *,
    descend_exact: bool = False,
) -> list[CompletionOption]:
    text = command_text if cursor_position is None else command_text[:cursor_position]
    if text is None:
        text = ""

    trailing_space = text.endswith(" ")
    tokens = text.split(" ")
    if trailing_space:
        path_tokens = [token for token in tokens[:-1] if token]
        current_token = ""
    else:
        path_tokens = [token for token in tokens[:-1] if token]
        current_token = tokens[-1] if tokens else ""

    level = completion_data
    prefix_parts: list[str] = []
    for token in path_tokens:
        entry = _find_entry(level, token)
        if entry is None:
            return []
        prefix_parts.append(completion_entry_insert_text(entry))
        level = completion_entry_children(entry)

    if current_token:
        exact_entry = _find_entry(level, current_token)
        if exact_entry is not None:
            children = completion_entry_children(exact_entry)
            if children and descend_exact:
                return _options_for_level(children, [*prefix_parts, completion_entry_insert_text(exact_entry)])
            return []

    return _options_for_level(level, prefix_parts, current_token)


class CompletionInput(QWidget):
    returnPressed = pyqtSignal()
    tabPressed = pyqtSignal()
    completionAccepted = pyqtSignal(str)

    def __init__(
        self,
        parent=None,
        *,
        completion_data: list[tuple] | None = None,
        completion_provider: Callable[[], list[tuple]] | None = None,
        refresh_on_focus: bool = False,
        max_visible_items: int = 8,
    ):
        super().__init__(parent)
        self.completionData = list(completion_data or [])
        self._completionProvider = completion_provider
        self._refreshOnFocus = refresh_on_focus
        self._maxVisibleItems = max(1, max_visible_items)
        self._currentOptions: list[CompletionOption] = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)

        self.lineEdit = QLineEdit(self)
        self.lineEdit.setFont(console_font())
        self.lineEdit.setMinimumHeight(28)
        self.lineEdit.installEventFilter(self)
        self.lineEdit.textEdited.connect(self.scheduleCompletionPopup)

        self.dropdown = QListWidget(self)
        self.dropdown.setObjectName("completionDropdown")
        self.dropdown.setFont(console_font())
        self.dropdown.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.dropdown.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.dropdown.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.dropdown.setUniformItemSizes(True)
        self.dropdown.itemClicked.connect(self.acceptClickedCompletion)
        self.dropdown.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.addWidget(self.lineEdit)
        layout.addWidget(self.dropdown)
        self.setFocusProxy(self.lineEdit)
        self.applyStyle()

    def applyStyle(self) -> None:
        self.setStyleSheet(
            f"""
            QLineEdit {{
                background-color: {CONSOLE_COLORS["background"]};
                color: {CONSOLE_COLORS["text"]};
                border: 1px solid {CONSOLE_COLORS["border"]};
                padding: 4px 6px;
                selection-background-color: {CONSOLE_COLORS["selection"]};
                selection-color: {CONSOLE_COLORS["text"]};
            }}
            QListWidget#completionDropdown {{
                background-color: {CONSOLE_COLORS["background"]};
                color: {CONSOLE_COLORS["text"]};
                border: 1px solid {CONSOLE_COLORS["border"]};
                outline: 0;
                padding: 2px;
                selection-background-color: {CONSOLE_COLORS["selection"]};
            }}
            QListWidget#completionDropdown::item {{
                padding: 4px 6px;
            }}
            QListWidget#completionDropdown::item:selected {{
                background-color: {CONSOLE_COLORS["selection"]};
                color: {CONSOLE_COLORS["header"]};
            }}
            """
        )

    def refreshCompletions(self, force: bool = False) -> None:
        if self._completionProvider is None:
            return
        completion_data = self._completionProvider()
        if force or completion_data != self.completionData:
            self.completionData = completion_data
            self.hideCompletionPopup()

    def eventFilter(self, watched, event):
        if watched is self.lineEdit:
            if event.type() == QEvent.Type.FocusIn and self._refreshOnFocus:
                self.refreshCompletions()
            if event.type() == QEvent.Type.KeyPress:
                key = event.key()
                if key == Qt.Key.Key_Backtab or (
                    key == Qt.Key.Key_Tab
                    and event.modifiers() & Qt.KeyboardModifier.ShiftModifier
                ):
                    self.tabPressed.emit()
                    self.previousCompletion()
                    return True
                if key == Qt.Key.Key_Tab:
                    self.tabPressed.emit()
                    self.nextCompletion()
                    return True
                if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                    current_completion = None
                    if self.dropdown.isVisible():
                        selected_row = self.dropdown.currentRow()
                        self._currentOptions = self.buildCompletionOptions(descend_exact=False)
                        if 0 <= selected_row < len(self._currentOptions):
                            current_completion = self._currentOptions[selected_row]
                        elif self._currentOptions:
                            current_completion = self._currentOptions[0]
                    if current_completion is not None and current_completion.full_text.strip() != self.text().strip():
                        self.acceptCompletion(current_completion)
                    else:
                        self.hideCompletionPopup()
                        self.returnPressed.emit()
                    return True
                if key == Qt.Key.Key_Escape and self.dropdown.isVisible():
                    self.hideCompletionPopup()
                    return True
                if key == Qt.Key.Key_Down and self.dropdown.isVisible():
                    self.moveSelection(1)
                    return True
                if key == Qt.Key.Key_Up and self.dropdown.isVisible():
                    self.moveSelection(-1)
                    return True
        return super().eventFilter(watched, event)

    def scheduleCompletionPopup(self, _text: str | None = None) -> None:
        QTimer.singleShot(0, self.showCompletionPopup)

    def completionPrefix(self) -> str:
        return self.text()[: self.cursorPosition()]

    def showCompletionPopup(
        self,
        _text: str | None = None,
        allowEmpty: bool = False,
        descendExact: bool = False,
    ) -> bool:
        prefix = self.completionPrefix()
        if not prefix.strip() and not allowEmpty:
            self.hideCompletionPopup()
            return False

        self._currentOptions = self.buildCompletionOptions(descendExact)
        if not self._currentOptions:
            self.hideCompletionPopup()
            return False

        self.dropdown.clear()
        for index, option in enumerate(self._currentOptions):
            item = QListWidgetItem(option.label)
            item.setData(Qt.ItemDataRole.UserRole, index)
            item.setToolTip(option.full_text)
            self.dropdown.addItem(item)

        self.dropdown.setCurrentRow(0)
        self.updateDropdownHeight()
        self.dropdown.show()
        return True

    def buildCompletionOptions(self, descend_exact: bool = False) -> list[CompletionOption]:
        return completion_options(
            self.completionData,
            self.text(),
            self.cursorPosition(),
            descend_exact=descend_exact,
        )

    def hideCompletionPopup(self) -> None:
        self.dropdown.hide()
        self.dropdown.clear()
        self._currentOptions = []

    def updateDropdownHeight(self) -> None:
        visible_rows = min(max(len(self._currentOptions), 1), self._maxVisibleItems)
        row_height = max(self.dropdown.sizeHintForRow(0), self.dropdown.fontMetrics().height() + 8)
        frame = 2 * self.dropdown.frameWidth()
        self.dropdown.setMaximumHeight((row_height * visible_rows) + frame + 6)

    def moveSelection(self, step: int) -> None:
        if not self._currentOptions:
            return
        current = self.dropdown.currentRow()
        if current < 0:
            current = 0
        next_row = (current + step) % len(self._currentOptions)
        self.dropdown.setCurrentRow(next_row)

    def nextCompletion(self) -> None:
        if not self.dropdown.isVisible():
            self.showCompletionPopup(allowEmpty=True, descendExact=True)
            return
        self.moveSelection(1)

    def previousCompletion(self) -> None:
        if not self.dropdown.isVisible():
            if self.showCompletionPopup(allowEmpty=True, descendExact=True):
                self.moveSelection(-1)
            return
        self.moveSelection(-1)

    def currentCompletion(self) -> CompletionOption | None:
        row = self.dropdown.currentRow()
        if row < 0 or row >= len(self._currentOptions):
            return None
        return self._currentOptions[row]

    def acceptClickedCompletion(self, item: QListWidgetItem) -> None:
        index = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(index, int) and 0 <= index < len(self._currentOptions):
            self.acceptCompletion(self._currentOptions[index])

    def acceptCurrentCompletion(self) -> None:
        option = self.currentCompletion()
        if option is not None:
            self.acceptCompletion(option)

    def acceptCompletion(self, option: CompletionOption) -> None:
        self.lineEdit.setText(option.full_text)
        self.lineEdit.setCursorPosition(len(option.full_text))
        self.hideCompletionPopup()
        self.completionAccepted.emit(option.full_text)

    def text(self) -> str:
        return self.lineEdit.text()

    def displayText(self) -> str:
        return self.lineEdit.displayText()

    def setText(self, text: str) -> None:
        self.lineEdit.setText(text)

    def clear(self) -> None:
        self.lineEdit.clear()
        self.hideCompletionPopup()

    def setPlaceholderText(self, text: str) -> None:
        self.lineEdit.setPlaceholderText(text)

    def placeholderText(self) -> str:
        return self.lineEdit.placeholderText()

    def setCursorPosition(self, position: int) -> None:
        self.lineEdit.setCursorPosition(position)

    def cursorPosition(self) -> int:
        return self.lineEdit.cursorPosition()

    def setMinimumHeight(self, height: int) -> None:
        self.lineEdit.setMinimumHeight(height)
        super().setMinimumHeight(height)

    def setFocus(self, reason: Qt.FocusReason = Qt.FocusReason.OtherFocusReason) -> None:
        self.lineEdit.setFocus(reason)
