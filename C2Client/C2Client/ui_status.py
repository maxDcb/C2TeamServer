"""Shared helpers for operator-visible UI status messages."""

from __future__ import annotations

from enum import Enum
from typing import Any


class StatusKind(str, Enum):
    NEUTRAL = "neutral"
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


STATUS_COLORS = {
    StatusKind.NEUTRAL: "",
    StatusKind.INFO: "#4b5563",
    StatusKind.SUCCESS: "#0a7f2e",
    StatusKind.WARNING: "#a05a00",
    StatusKind.ERROR: "#b00020",
}

DEFAULT_LAST_RPC_TEXT = "Last RPC: none"
DEFAULT_LAST_ERROR_TEXT = "Last error: none"


def compact_message(message: Any, limit: int = 160) -> str:
    """Collapse whitespace and trim long status text for compact UI labels."""

    text = " ".join(str(message or "").split())
    if limit < 4 or len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def status_kind_for_ok(ok: bool) -> StatusKind:
    return StatusKind.SUCCESS if ok else StatusKind.ERROR


def status_stylesheet(kind: StatusKind) -> str:
    color = STATUS_COLORS.get(kind, "")
    return f"color: {color};" if color else ""


def apply_status(label: Any, message: Any, kind: StatusKind = StatusKind.INFO) -> None:
    label.setText(str(message or ""))
    label.setStyleSheet(status_stylesheet(kind))


def apply_success(label: Any, message: Any) -> None:
    apply_status(label, message, StatusKind.SUCCESS)


def apply_error(label: Any, message: Any) -> None:
    apply_status(label, message, StatusKind.ERROR)


def clear_status(label: Any, message: str = "") -> None:
    apply_status(label, message, StatusKind.NEUTRAL)


def format_last_rpc(operation: str, timestamp: str) -> str:
    return f"Last RPC: {operation or 'unknown'} at {timestamp}"


def format_action_status(action: str, message: Any, limit: int = 160) -> str:
    action_text = compact_message(action, limit=48).rstrip(":")
    message_text = compact_message(message, limit=limit)
    if not action_text:
        return message_text
    if not message_text:
        return action_text
    if message_text.lower().startswith(action_text.lower()):
        return message_text
    return compact_message(f"{action_text}: {message_text}", limit=limit)


def format_last_error(operation: str, message: Any, limit: int = 160) -> str:
    return format_action_status(operation or "unknown", message, limit=limit)
