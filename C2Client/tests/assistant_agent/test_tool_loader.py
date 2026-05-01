from __future__ import annotations

from C2Client.assistant_agent.tools.loader import load_tool_specs


def test_tool_loader_loads_unique_json_tool_specs():
    specs = load_tool_specs()
    names = [spec.name for spec in specs]

    assert "ls" in names
    assert "run" in names
    assert len(names) == len(set(names))
    assert all(spec.description for spec in specs)
    assert all(spec.command_template for spec in specs)
    assert all(spec.parameters["type"] == "object" for spec in specs)
    assert all("beacon_hash" in spec.parameters["required"] for spec in specs)
    assert all("listener_hash" in spec.parameters["required"] for spec in specs)
