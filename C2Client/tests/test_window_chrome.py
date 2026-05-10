import pytest

from C2Client import window_chrome


def test_colorref_from_hex_converts_rgb_to_windows_colorref():
    assert window_chrome.colorref_from_hex("#0b1117") == 0x0017110B
    assert window_chrome.colorref_from_hex("263241") == 0x00413226


def test_colorref_from_hex_rejects_invalid_values():
    with pytest.raises(ValueError):
        window_chrome.colorref_from_hex("#123")


def test_apply_dark_window_chrome_is_noop_off_windows(monkeypatch):
    class Widget:
        def winId(self):
            raise AssertionError("winId should not be requested off Windows")

    monkeypatch.setattr(window_chrome.sys, "platform", "linux")

    assert window_chrome.apply_dark_window_chrome(Widget()) is False
