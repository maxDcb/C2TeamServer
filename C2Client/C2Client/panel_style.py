from __future__ import annotations

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
            border-color: {CONSOLE_COLORS["timestamp"]};
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


def apply_dark_panel_style(widget) -> None:
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
            border-color: {CONSOLE_COLORS["timestamp"]};
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
            border-color: {CONSOLE_COLORS["timestamp"]};
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
        QTableWidget {{
            background-color: {CONSOLE_COLORS["background"]};
            alternate-background-color: #101820;
            color: {CONSOLE_COLORS["text"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            gridline-color: {CONSOLE_COLORS["border"]};
            selection-background-color: {CONSOLE_COLORS["selection"]};
            selection-color: {CONSOLE_COLORS["text"]};
        }}
        QTableWidget::item {{
            padding: 3px 6px;
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
