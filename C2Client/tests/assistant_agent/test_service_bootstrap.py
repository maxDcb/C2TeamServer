from __future__ import annotations

from types import SimpleNamespace

from C2Client.assistant_agent.domain.service import C2AssistantAgent
from C2Client.assistant_agent.tools.loader import load_tool_specs


def test_service_bootstrap_registers_only_c2_tools(tmp_path):
    service = C2AssistantAgent(SimpleNamespace(sendSessionCommand=lambda command: None), storage_dir=tmp_path)
    expected_names = sorted(spec.name for spec in load_tool_specs())

    assert service.orchestrator.registry.list_tool_names() == expected_names
    assert service.session_manager.session_id == "default"
