from __future__ import annotations

import ctypes
import logging
import sys

from .console_style import CONSOLE_COLORS


logger = logging.getLogger(__name__)

DWMWA_USE_IMMERSIVE_DARK_MODE = (20, 19)
DWMWA_BORDER_COLOR = 34
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36


def colorref_from_hex(hex_color: str) -> int:
    """Convert #RRGGBB to Windows COLORREF 0x00bbggrr."""

    value = str(hex_color or "").strip().lstrip("#")
    if len(value) != 6:
        raise ValueError(f"Invalid color: {hex_color!r}")
    red = int(value[0:2], 16)
    green = int(value[2:4], 16)
    blue = int(value[4:6], 16)
    return red | (green << 8) | (blue << 16)


def _set_dwm_attribute(hwnd: int, attribute: int, value: int, c_type) -> bool:
    data = c_type(value)
    result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
        ctypes.c_void_p(hwnd),
        ctypes.c_uint(attribute),
        ctypes.byref(data),
        ctypes.sizeof(data),
    )
    return result == 0


def apply_dark_window_chrome(widget) -> bool:
    """Request dark native Windows titlebar and border colors.

    Qt stylesheets only affect client-area widgets. The titlebar and outer
    window frame are owned by the OS, so this is intentionally a Windows-only
    no-op on other platforms.
    """

    if sys.platform != "win32":
        return False

    try:
        hwnd = int(widget.winId())
        dark_mode_applied = any(
            _set_dwm_attribute(hwnd, attribute, 1, ctypes.c_int)
            for attribute in DWMWA_USE_IMMERSIVE_DARK_MODE
        )
        border_applied = _set_dwm_attribute(
            hwnd,
            DWMWA_BORDER_COLOR,
            colorref_from_hex(CONSOLE_COLORS["border"]),
            ctypes.c_uint,
        )
        caption_applied = _set_dwm_attribute(
            hwnd,
            DWMWA_CAPTION_COLOR,
            colorref_from_hex(CONSOLE_COLORS["background"]),
            ctypes.c_uint,
        )
        text_applied = _set_dwm_attribute(
            hwnd,
            DWMWA_TEXT_COLOR,
            colorref_from_hex(CONSOLE_COLORS["header"]),
            ctypes.c_uint,
        )
        return dark_mode_applied or border_applied or caption_applied or text_applied
    except Exception:
        logger.debug("Failed to apply Windows dark chrome", exc_info=True)
        return False
