from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.tools.loader import load_tool_specs
from C2Client.assistant_agent.tools.registry import build_c2_tool_registry


def test_tool_registry_registers_all_json_tools():
    registry = build_c2_tool_registry(SimpleNamespace(sendSessionCommand=lambda command: None))
    expected_names = sorted(spec.name for spec in load_tool_specs())

    assert registry.list_tool_names() == expected_names
