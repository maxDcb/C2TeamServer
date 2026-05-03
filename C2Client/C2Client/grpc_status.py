"""Helpers for TeamServer application-level gRPC statuses."""

from __future__ import annotations

from typing import Any

from .grpcClient import TeamServerApi_pb2


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def is_response_ok(response: Any) -> bool:
    return getattr(response, "status", TeamServerApi_pb2.OK) == TeamServerApi_pb2.OK


def response_message(response: Any, fallback: str = "") -> str:
    message = _to_text(getattr(response, "message", ""))
    return message or fallback


def operation_ack_text(response: Any, success_fallback: str = "", error_fallback: str = "Operation failed.") -> str:
    if is_response_ok(response):
        return response_message(response, success_fallback)
    return response_message(response, error_fallback)


def terminal_response_text(response: Any, error_fallback: str = "Terminal command failed.") -> str:
    result = _to_text(getattr(response, "result", ""))
    if is_response_ok(response):
        return result
    return response_message(response, result or error_fallback)
