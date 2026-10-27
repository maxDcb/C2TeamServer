from __future__ import annotations

from typing import Any

from .command_help_tool import C2CommandHelpTool
from .command_tool import C2CommandTool
from .command_specs import load_command_tool_specs
from .module_state_tool import C2LoadedModulesTool
from .session_state_tool import C2LiveSessionsTool
from .server_catalog_tools import C2ArtifactsTool, C2ListenersTool, C2ListenerInfoTool, C2BeaconBinaryInfoTool
from .server_action_tools import C2HostArtifactTool, C2SocksControlTool, C2ReloadModulesTool
from .server_file_tools import C2UploadListenerFileTool, C2InstallToolTool, C2InstallToolBundleTool

from agent_core.spi import ToolRegistry


def build_c2_tool_registry(grpc_client: Any) -> ToolRegistry:
    registry = ToolRegistry()
    if grpc_client is not None and hasattr(grpc_client, "getCommandHelp"):
        registry.register(C2CommandHelpTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "listModules"):
        registry.register(C2LoadedModulesTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "listSessions"):
        registry.register(C2LiveSessionsTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "listListeners"):
        registry.register(C2ListenersTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "listArtifacts"):
        registry.register(C2ArtifactsTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "getListenerInfo"):
        registry.register(C2ListenerInfoTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "getBeaconBinary"):
        registry.register(C2BeaconBinaryInfoTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "hostArtifact"):
        registry.register(C2HostArtifactTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "controlSocks"):
        registry.register(C2SocksControlTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "reloadModules"):
        registry.register(C2ReloadModulesTool(grpc_client))
    if grpc_client is not None and hasattr(grpc_client, "downloadArtifact"):
        for method, adapter in (
            ("uploadListenerFile", C2UploadListenerFileTool),
            ("installTool", C2InstallToolTool),
            ("installToolBundle", C2InstallToolBundleTool),
        ):
            if hasattr(grpc_client, method):
                registry.register(adapter(grpc_client))
    for spec in load_command_tool_specs(grpc_client):
        registry.register(C2CommandTool(spec, grpc_client))
    return registry
