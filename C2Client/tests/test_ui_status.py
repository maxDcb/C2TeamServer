from C2Client.ui_status import (
    StatusKind,
    compact_message,
    format_action_status,
    format_last_error,
    status_kind_for_ok,
    status_stylesheet,
)


def test_compact_message_collapses_whitespace_and_truncates():
    message = compact_message("  ListSessions:\n deadline   exceeded while connecting  ", limit=32)

    assert message == "ListSessions: deadline exceed..."


def test_status_stylesheet_uses_shared_error_color():
    assert status_kind_for_ok(True) == StatusKind.SUCCESS
    assert status_kind_for_ok(False) == StatusKind.ERROR
    assert status_stylesheet(StatusKind.ERROR) == "color: #b00020;"


def test_format_last_error_keeps_operation_context():
    assert format_last_error("StopSession", "Session not found.") == "StopSession: Session not found."


def test_format_action_status_adds_action_context_once():
    assert format_action_status("Stop session", "Session not found.") == "Stop session: Session not found."
    assert format_action_status("Stop session", "Stop session failed.") == "Stop session failed."
