from __future__ import annotations

from typing import Any

from .command_help_tool import C2CommandHelpTool
from .command_tool import C2CommandTool
from .command_specs import load_command_tool_specs
from .module_state_tool import C2LoadedModulesTool
from .session_state_tool import C2LiveSessionsTool

from agent_core import ToolRegistry


def build_c2_tool_registry(grpc_client: Any) -> ToolRegistry:
    registry = ToolRegistry()
    if grpc_client is not None and hasattr(grpc_client, "getCommandHelp"):
        registry.register(C2CommandHelpTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "listModules"):
        registry.register(C2LoadedModulesTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "listSessions"):
        registry.register(C2LiveSessionsTool(grpc_client))
    for spec in load_command_tool_specs(grpc_client):
        registry.register(C2CommandTool(spec, grpc_client))
    return registry
