from __future__ import annotations

import html
from datetime import datetime

from PyQt6.QtGui import QFont, QTextCursor


CONSOLE_FONT_FAMILY = "JetBrainsMono Nerd Font"
CONSOLE_FONT_CSS = (
    "'JetBrainsMono Nerd Font','FiraCode Nerd Font','DejaVu Sans Mono',"
    "'Noto Sans Mono',monospace"
)

CONSOLE_COLORS = {
    "background": "#0b1117",
    "border": "#263241",
    "selection": "#184a73",
    "text": "#d0d5dd",
    "header": "#f2f4f7",
    "muted": "#98a2b3",
    "timestamp": "#7cd4fd",
    "info": "#7cd4fd",
    "system": "#7cd4fd",
    "user": "#fdb022",
    "assistant": "#32d583",
    "script": "#a6f4c5",
    "command": "#fdb022",
    "response": "#f97066",
    "success": "#32d583",
    "warning": "#fdb022",
    "error": "#f97066",
}


def console_font() -> QFont:
    return QFont(CONSOLE_FONT_FAMILY)


def apply_console_output_style(editor) -> None:
    editor.setFont(console_font())
    editor.setStyleSheet(
        f"""
        QTextEdit, QTextBrowser, QPlainTextEdit {{
            background-color: {CONSOLE_COLORS["background"]};
            color: {CONSOLE_COLORS["text"]};
            border: 1px solid {CONSOLE_COLORS["border"]};
            selection-background-color: {CONSOLE_COLORS["selection"]};
            selection-color: {CONSOLE_COLORS["text"]};
        }}
        """
    )


def move_editor_to_end(editor) -> None:
    cursor = editor.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    editor.setTextCursor(cursor)


def timestamp_text() -> str:
    return datetime.now().strftime("%Y:%m:%d %H:%M:%S").rstrip()


def tone_color(tone: str) -> str:
    return CONSOLE_COLORS.get(tone, CONSOLE_COLORS["info"])


def console_header_html(
    label: str,
    *,
    marker: str = "[+]",
    tone: str = "info",
    wrap: str = "pre",
    timestamp: str | None = None,
    show_label: bool = True,
) -> str:
    color = tone_color(tone)
    line = (
        f'<p style="white-space:{wrap}; margin:0 0 4px 0;">'
        f'<span style="color:{CONSOLE_COLORS["timestamp"]};">[{timestamp or timestamp_text()}]</span>'
        f' <span style="color:{color};">{html.escape(marker)}</span>'
    )
    if show_label and label:
        line += f' <span style="color:{CONSOLE_COLORS["header"]};">{html.escape(str(label))}</span>'
    return line + "</p>"


def console_status_html(
    status: str,
    command_id: str,
    message: str = "",
    *,
    tone: str = "info",
    timestamp: str | None = None,
) -> str:
    line = (
        '<p style="white-space:pre; margin:0 0 4px 0;">'
        f'<span style="color:{CONSOLE_COLORS["timestamp"]};">[{timestamp or timestamp_text()}]</span>'
        f' <span style="color:{tone_color(tone)};">[{html.escape(str(status))}]</span>'
        f' <span style="color:{CONSOLE_COLORS["muted"]};">{html.escape(str(command_id))}</span>'
    )
    if message:
        line += f' <span style="color:{CONSOLE_COLORS["text"]};">{html.escape(str(message))}</span>'
    return line + "</p>"


def console_pre_html(body: str) -> str:
    return (
        '<pre style="margin:0; white-space:pre-wrap;'
        f"font-family:{CONSOLE_FONT_CSS};"
        f'color:{CONSOLE_COLORS["text"]};">'
        f"{body}"
        "</pre>"
    )


def append_console_html(editor, body: str) -> None:
    if not body:
        return
    move_editor_to_end(editor)
    if hasattr(editor, "appendHtml"):
        editor.appendHtml(body)
    else:
        editor.insertHtml(body)
        editor.insertPlainText("\n")


def append_console_text(editor, text: str) -> None:
    if not text:
        return
    append_console_html(editor, console_pre_html(html.escape(str(text))))


def append_console_spacing(editor, lines: int = 1) -> None:
    if lines <= 0:
        return
    move_editor_to_end(editor)
    editor.insertPlainText("\n" * lines)


def append_console_block(
    editor,
    header: str = "",
    message: str = "",
    *,
    marker: str = "[+]",
    tone: str = "info",
    rich_message: bool = False,
    show_label: bool = True,
) -> None:
    if header:
        append_console_html(
            editor,
            console_header_html(
                header,
                marker=marker,
                tone=tone,
                wrap="pre-wrap",
                show_label=show_label,
            ),
        )
    if message:
        if rich_message:
            append_console_html(editor, f'<div style="color:{CONSOLE_COLORS["text"]};">{message}</div>')
        else:
            append_console_text(editor, message)
