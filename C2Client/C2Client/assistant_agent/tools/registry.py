from __future__ import annotations

from pathlib import Path
from typing import Any

from ..bootstrap import ensure_agent_core_path
from .command_tool import C2CommandTool
from .loader import load_tool_specs

ensure_agent_core_path()

from agent_core import ToolRegistry


def build_c2_tool_registry(grpc_client: Any, *, schema_dir: Path | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    for spec in load_tool_specs(schema_dir):
        registry.register(C2CommandTool(spec, grpc_client))
    return registry
