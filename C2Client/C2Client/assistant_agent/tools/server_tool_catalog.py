"""One registration catalog for TeamServer operations used by conversations and skills."""

from __future__ import annotations

from typing import Any

from .artifact_upload_tool import C2ArtifactUploadTool
from .command_help_tool import C2CommandHelpTool
from .module_state_tool import C2LoadedModulesTool
from .session_state_tool import C2LiveSessionsTool
from .server_action_tools import C2HostArtifactTool, C2SocksControlTool, C2ReloadModulesTool
from .server_artifact_tools import C2ArtifactDownloadTool, C2ArtifactDeleteTool, C2ArtifactPromoteTool
from .local_generation_tool import C2LocalDroppersTool, C2GenerateDropperTool
from .server_catalog_tools import C2ArtifactsTool, C2ListenersTool, C2ListenerInfoTool, C2BeaconBinaryInfoTool, C2CommandsTool
from .server_credential_tools import (
    C2CredentialsTool, C2CredentialTool, C2AddCredentialTool, C2UpdateCredentialTool, C2DeleteCredentialTool,
)
from .server_file_tools import C2UploadListenerFileTool, C2InstallToolTool, C2InstallToolBundleTool
from .server_lifecycle_tools import C2AddListenerTool, C2StopListenerTool, C2StopSessionTool, C2SessionHistoryTool


_SERVER_TOOLS = (
    ("listCommands", C2CommandsTool),
    ("getCommandHelp", C2CommandHelpTool),
    ("listModules", C2LoadedModulesTool),
    ("listSessions", C2LiveSessionsTool),
    ("listSessionHistory", C2SessionHistoryTool),
    ("stopSession", C2StopSessionTool),
    ("listListeners", C2ListenersTool),
    ("addListener", C2AddListenerTool),
    ("stopListener", C2StopListenerTool),
    ("getListenerInfo", C2ListenerInfoTool),
    ("getBeaconBinary", C2BeaconBinaryInfoTool),
    ("listArtifacts", C2ArtifactsTool),
    ("downloadArtifact", C2ArtifactDownloadTool),
    ("deleteArtifact", C2ArtifactDeleteTool),
    ("hostArtifact", C2HostArtifactTool),
    ("controlSocks", C2SocksControlTool),
    ("reloadModules", C2ReloadModulesTool),
    ("listCredentials", C2CredentialsTool),
    ("getCredential", C2CredentialTool),
    ("addCredential", C2AddCredentialTool),
    ("updateCredential", C2UpdateCredentialTool),
    ("deleteCredential", C2DeleteCredentialTool),
)
_FILE_TOOLS = (
    ("uploadListenerFile", C2UploadListenerFileTool),
    ("installTool", C2InstallToolTool),
    ("installToolBundle", C2InstallToolBundleTool),
)


def server_tools(grpc_client: Any, *, artifact_name: str = "") -> list[Any]:
    if grpc_client is None:
        return []
    tools = [adapter(grpc_client) for method, adapter in _SERVER_TOOLS
             if hasattr(grpc_client, method)]
    if hasattr(grpc_client, "downloadArtifact"):
        tools.extend(adapter(grpc_client) for method, adapter in _FILE_TOOLS
                     if hasattr(grpc_client, method))
    if hasattr(grpc_client, "uploadArtifact") and hasattr(grpc_client, "listArtifacts"):
        tools.append(C2ArtifactUploadTool(grpc_client, artifact_name))
        if hasattr(grpc_client, "downloadArtifact"):
            tools.append(C2ArtifactPromoteTool(grpc_client))
    if all(hasattr(grpc_client, method) for method in (
            "getListenerInfo", "getBeaconBinary", "uploadListenerFile")):
        tools.extend((C2LocalDroppersTool(grpc_client), C2GenerateDropperTool(grpc_client)))
    return tools
