from __future__ import annotations

import pytest

from C2Client.assistant_agent.tools.command_builder import build_command_line
from C2Client.assistant_agent.tools.loader import C2ToolSpec, load_tool_specs


def spec_by_name(name: str) -> C2ToolSpec:
    return {spec.name: spec for spec in load_tool_specs()}[name]


def test_build_command_line_quotes_paths_with_spaces():
    assert build_command_line(spec_by_name("cat"), {"beacon_hash": "b", "listener_hash": "l", "path": "C:\\Users\\Public\\notes.txt"}) == "cat C:\\Users\\Public\\notes.txt"
    assert build_command_line(spec_by_name("ls"), {"beacon_hash": "b", "listener_hash": "l", "path": "C:\\Program Files"}) == 'ls "C:\\Program Files"'


def test_build_command_line_supports_raw_command_tail():
    assert build_command_line(
        spec_by_name("run"),
        {"beacon_hash": "b", "listener_hash": "l", "command": "whoami /all"},
    ) == "run whoami /all"


def test_build_command_line_omits_empty_optional_argument():
    assert build_command_line(
        spec_by_name("enumerateShares"),
        {"beacon_hash": "b", "listener_hash": "l", "host": ""},
    ) == "enumerateShares"


def test_build_command_line_rejects_missing_required_argument():
    with pytest.raises(KeyError):
        build_command_line(spec_by_name("ls"), {"beacon_hash": "b", "listener_hash": "l"})
