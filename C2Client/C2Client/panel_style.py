from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QComboBox, QMenu, QStyle, QStyledItemDelegate, QToolTip

from .console_style import CONSOLE_COLORS


def main_window_stylesheet() -> str:
    return f"""
        QMainWindow#C2MainWindow {{
            background-color: #070b10;
            color: {CONSOLE_COLORS["text"]};
        }}
        QWidget#C2CentralWidget {{
            background-color: #070b10;
            color: {CONSOLE_COLORS["text"]};
        }}
        QWidget#C2MainTab {{
            background-color: {CONSOLE_COLORS["background"]};
        }}
        QTabWidget {{
            background-color: #070b10;
        }}
        QTabWidget::pane {{
            background-color: {CONSOLE_COLORS["background"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            top: -1px;
        }}
        QTabWidget > QWidget,
        QStackedWidget {{
            background-color: {CONSOLE_COLORS["background"]};
        }}
        QTabBar {{
            background-color: #070b10;
        }}
        QTabBar::tab {{
            background-color: #101820;
            color: {CONSOLE_COLORS["muted"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            border-bottom: 0;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 6px 12px;
            margin-right: 2px;
            min-height: 20px;
        }}
        QTabBar::tab:selected {{
            background-color: {CONSOLE_COLORS["background"]};
            color: {CONSOLE_COLORS["header"]};
            border-color: {CONSOLE_COLORS["border"]};
        }}
        QTabBar::tab:hover {{
            color: {CONSOLE_COLORS["header"]};
            border-color: {CONSOLE_COLORS["focus_border"]};
        }}
        QTabBar::tab:!selected {{
            margin-top: 2px;
        }}
        QStatusBar {{
            background-color: {CONSOLE_COLORS["background"]};
            color: {CONSOLE_COLORS["text"]};
            border-top: 1px solid {CONSOLE_COLORS["border"]};
        }}
        QStatusBar QLabel {{
            padding: 2px 6px;
        }}
    """


def apply_main_window_style(window) -> None:
    window.setStyleSheet(main_window_stylesheet())


def create_dark_context_menu(parent=None) -> QMenu:
    menu = QMenu(parent)
    menu.setStyleSheet(
        f"""
        QMenu {{
            background-color: #101820;
            color: {CONSOLE_COLORS['text']};
            border: 1px solid {CONSOLE_COLORS['border']};
            padding: 4px;
        }}
        QMenu::item {{
            background-color: transparent;
            color: {CONSOLE_COLORS['text']};
            border-radius: 3px;
            padding: 6px 18px;
            margin: 1px 0;
        }}
        QMenu::item:selected {{
            background-color: {CONSOLE_COLORS['selection']};
            color: {CONSOLE_COLORS['header']};
        }}
        QMenu::item:disabled {{ color: {CONSOLE_COLORS['muted']}; }}
        QMenu::separator {{
            height: 1px;
            background-color: {CONSOLE_COLORS['border']};
            margin: 4px 8px;
        }}
        """
    )
    return menu


class DarkComboItemDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        size.setHeight(24)
        return size

    def paint(self, painter, option, index):
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        background = "selection" if selected else "hover" if hovered else "background"
        painter.save()
        painter.fillRect(option.rect, QColor(CONSOLE_COLORS[background]))
        painter.setPen(QColor(CONSOLE_COLORS["header" if selected else "text"]))
        painter.drawText(
            option.rect.adjusted(10, 0, -8, 0),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            str(index.data(Qt.ItemDataRole.DisplayRole) or ""),
        )
        painter.restore()


def style_dark_combo_popup(combo: QComboBox) -> None:
    """Style the popup itself; it is a separate window on some Qt platforms."""
    view = combo.view()
    view.setMinimumWidth(140)
    popup = view.window()
    popup.setObjectName("C2ComboPopup")
    popup.setStyleSheet(
        f"QFrame#C2ComboPopup {{ background-color: {CONSOLE_COLORS['background']}; "
        f"border: 1px solid {CONSOLE_COLORS['border']}; }}"
    )
    palette = view.palette()
    palette.setColor(QPalette.ColorRole.Base, QColor(CONSOLE_COLORS["background"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(CONSOLE_COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(CONSOLE_COLORS["selection"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(CONSOLE_COLORS["header"]))
    view.setPalette(palette)
    view.setItemDelegate(DarkComboItemDelegate(view))
    view.setStyleSheet(
        f"""
        QAbstractItemView {{
            background-color: {CONSOLE_COLORS['background']};
            color: {CONSOLE_COLORS['text']};
            border: 1px solid {CONSOLE_COLORS['border']};
            outline: none;
            selection-background-color: {CONSOLE_COLORS['selection']};
            selection-color: {CONSOLE_COLORS['header']};
        }}
        QAbstractItemView::item {{ padding: 0; margin: 0; }}
        QAbstractItemView::item:selected {{
            background-color: {CONSOLE_COLORS['selection']};
            color: {CONSOLE_COLORS['header']};
        }}
        """
    )


def apply_dark_panel_style(widget) -> None:
    tooltip_palette = QToolTip.palette()
    tooltip_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#101820"))
    tooltip_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(CONSOLE_COLORS["text"]))
    tooltip_palette.setColor(QPalette.ColorRole.Window, QColor("#101820"))
    tooltip_palette.setColor(QPalette.ColorRole.WindowText, QColor(CONSOLE_COLORS["text"]))
    QToolTip.setPalette(tooltip_palette)
    widget.setStyleSheet(
        f"""
        QWidget {{
            background-color: {CONSOLE_COLORS["background"]};
            color: {CONSOLE_COLORS["text"]};
        }}
        QLabel {{
            color: {CONSOLE_COLORS["text"]};
        }}
        QPushButton {{
            background-color: #101820;
            color: {CONSOLE_COLORS["text"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            border-radius: 4px;
            padding: 3px 8px;
        }}
        QPushButton:hover {{
            border-color: {CONSOLE_COLORS["focus_border"]};
        }}
        QPushButton:disabled {{
            background-color: {CONSOLE_COLORS["background"]};
            color: #667085;
            border-color: #1f2937;
        }}
        QLineEdit, QComboBox {{
            background-color: #101820;
            color: {CONSOLE_COLORS["text"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            border-radius: 4px;
            padding: 3px 6px;
            selection-background-color: {CONSOLE_COLORS["selection"]};
            selection-color: {CONSOLE_COLORS["text"]};
        }}
        QLineEdit:focus, QComboBox:focus {{
            border-color: {CONSOLE_COLORS["focus_border"]};
        }}
        QComboBox::drop-down {{
            border: 0;
            width: 22px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {CONSOLE_COLORS["background"]};
            color: {CONSOLE_COLORS["text"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            selection-background-color: {CONSOLE_COLORS["selection"]};
            selection-color: {CONSOLE_COLORS["text"]};
        }}
        QComboBox QAbstractItemView::item:selected {{
            background-color: {CONSOLE_COLORS["selection"]};
            color: {CONSOLE_COLORS["header"]};
        }}
        QScrollBar:vertical {{
            background-color: {CONSOLE_COLORS["background"]};
            border: 0;
            width: 10px;
            margin: 0;
        }}
        QScrollBar:horizontal {{
            background-color: {CONSOLE_COLORS["background"]};
            border: 0;
            height: 10px;
            margin: 0;
        }}
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
            background-color: {CONSOLE_COLORS["selection"]};
            border-radius: 4px;
            margin: 1px;
        }}
        QScrollBar::handle:vertical {{ min-height: 24px; }}
        QScrollBar::handle:horizontal {{ min-width: 24px; }}
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
            background-color: {CONSOLE_COLORS["focus_border"]};
        }}
        QScrollBar::add-line, QScrollBar::sub-line {{
            width: 0;
            height: 0;
        }}
        QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
        QTableWidget {{
            background-color: {CONSOLE_COLORS["background"]};
            alternate-background-color: #101820;
            color: {CONSOLE_COLORS["text"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            gridline-color: {CONSOLE_COLORS["border"]};
            selection-background-color: {CONSOLE_COLORS["selection"]};
            selection-color: {CONSOLE_COLORS["text"]};
        }}
        QTableWidget:focus {{
            border-color: {CONSOLE_COLORS["focus_border"]};
        }}
        QTableWidget::item {{
            padding: 3px 6px;
        }}
        QTableWidget::item:hover:!selected {{
            background-color: {CONSOLE_COLORS["hover"]};
        }}
        QTableWidget::item:selected {{
            background-color: {CONSOLE_COLORS["selection"]};
            color: {CONSOLE_COLORS["header"]};
        }}
        QHeaderView::section {{
            background-color: #111827;
            color: {CONSOLE_COLORS["header"]};
            border: 0;
            border-bottom: 1px solid {CONSOLE_COLORS["border"]};
            padding: 4px 6px;
        }}
        QTableCornerButton::section {{
            background-color: #111827;
            border: 0;
            border-bottom: 1px solid {CONSOLE_COLORS["border"]};
        }}
        """
    )
