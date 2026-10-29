from __future__ import annotations

from typing import Any

from agent_core.spi import ToolRegistry

from ..capabilities.bundles import CONVERSATION_BUNDLES, resolve_tool_bundles
from .command_tool import C2CommandTool
from .command_specs import load_command_tool_specs
from .server_tool_catalog import server_tools


def build_c2_tool_registry(grpc_client: Any) -> ToolRegistry:
    registry = ToolRegistry()
    adapters = server_tools(grpc_client)
    if adapters:
        grant = resolve_tool_bundles(
            CONVERSATION_BUNDLES, registered_tools=(tool.name for tool in adapters),
        )
        allowed = set(grant.allowed_tools)
        for tool in adapters:
            if tool.name in allowed:
                registry.register(tool)
    # The TeamServer command catalog can gain new beacon modules at runtime.
    # Keep these command tools available in conversation independently of skills.
    for spec in load_command_tool_specs(grpc_client):
        registry.register(C2CommandTool(spec, grpc_client))
    return registry
