from __future__ import annotations

from typing import Any

from agent_core.spi import ToolRegistry

from .command_tool import C2CommandTool
from .command_specs import load_command_tool_specs
from .server_tool_catalog import server_tools


def build_c2_tool_registry(grpc_client: Any) -> ToolRegistry:
    registry = ToolRegistry()
    for tool in server_tools(grpc_client):
        registry.register(tool)
    for spec in load_command_tool_specs(grpc_client):
        registry.register(C2CommandTool(spec, grpc_client))
    return registry
