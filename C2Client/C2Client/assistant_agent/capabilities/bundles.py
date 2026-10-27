"""Business capabilities available to client-owned Agent Skills.

Bundle entries describe capabilities, not an implicit grant. A run only receives
tools that are both present in its selected bundles and registered at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class ToolBundle:
    name: str
    tools: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BundleResolution:
    bundle_names: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    unavailable_tools: tuple[str, ...]


TEAMSERVER_TOOL_NAMES = frozenset({
    "listC2Commands", "getCommandHelp", "listLoadedModules",
    "listC2Listeners", "infoListener", "listC2Artifacts", "getBeaconBinary",
    "hostArtifact", "uploadListenerFile", "installTool", "installToolBundle",
    "socksControl", "reloadModules", "addC2Listener", "stopC2Listener",
    "listLiveSessions", "listC2SessionHistory", "stopC2Session",
    "uploadC2Artifact", "downloadC2Artifact", "deleteC2Artifact",
    "listC2Credentials", "getC2Credential", "addC2Credential",
    "updateC2Credential", "deleteC2Credential",
})


# CommandSpec names are kept explicit so a newly installed beacon module never
# gains access to an existing skill merely by appearing in the server catalog.
# Client and TeamServer operations are granted only when an adapter is registered.
TOOL_BUNDLES: dict[str, ToolBundle] = {
    "teamserver.commands": ToolBundle("teamserver.commands", (
        "listC2Commands", "getCommandHelp",
    )),
    "teamserver.listeners": ToolBundle("teamserver.listeners", (
        "listC2Listeners", "infoListener", "addC2Listener", "stopC2Listener",
        "getBeaconBinary", "uploadListenerFile",
    )),
    "teamserver.sessions": ToolBundle("teamserver.sessions", (
        "listLiveSessions", "listC2SessionHistory", "stopC2Session", "listLoadedModules",
    )),
    "teamserver.artifacts": ToolBundle("teamserver.artifacts", (
        "listC2Artifacts", "uploadC2Artifact", "downloadC2Artifact",
        "deleteC2Artifact", "hostArtifact",
    )),
    "teamserver.credentials": ToolBundle("teamserver.credentials", (
        "listC2Credentials", "getC2Credential", "addC2Credential",
        "updateC2Credential", "deleteC2Credential",
    )),
    "teamserver.tools": ToolBundle("teamserver.tools", (
        "installTool", "installToolBundle", "reloadModules",
    )),
    "artifact.to_session": ToolBundle("artifact.to_session", (
        "uploadC2Artifact", "upload", "listC2Artifacts",
    )),
    "teamserver.inspect": ToolBundle("teamserver.inspect", (
        "listC2Listeners", "infoListener", "listC2Artifacts", "getBeaconBinary",
    )),
    "teamserver.publish": ToolBundle("teamserver.publish", (
        "listC2Listeners", "infoListener", "listC2Artifacts", "hostArtifact",
        "uploadListenerFile", "installTool", "installToolBundle",
    )),
    "teamserver.control": ToolBundle("teamserver.control", (
        "socksControl", "reloadModules",
    )),
    "recon.identity": ToolBundle("recon.identity", ("whoami",)),
    "recon.network": ToolBundle("recon.network", (
        "ipConfig", "hostContext", "netstat", "ps", "listC2Listeners",
    )),
    "recon.host": ToolBundle("recon.host", (
        "listLiveSessions", "listLoadedModules", "getCommandHelp",
        "whoami", "ipConfig", "hostContext", "getEnv", "netstat", "ps", "pwd", "ls", "tree",
        "cat", "enumerateShares", "enumerateRdpSessions", "screenShot",
        "listC2Listeners", "infoListener",
    )),
    "exec": ToolBundle("exec", (
        "run", "shell", "powershell", "pwSh", "script", "assemblyExec",
        "dotnetExec", "coffLoader", "cimExec", "dcomExec", "sshExec",
        "wmiExec", "winRm", "psExec", "spawnAs", "inject", "killProcess",
        "evasion", "taskScheduler", "registry",
    )),
    "pivot": ToolBundle("pivot", (
        "listener", "reversePortForward", "chisel", "listC2Listeners",
        "socksControl",
    )),
    "file_ops": ToolBundle("file_ops", (
        "cd", "mkDir", "remove", "upload", "download", "cat", "ls",
        "tree", "pwd",
    )),
    "payload_delivery": ToolBundle("payload_delivery", (
        "upload", "listC2Artifacts", "downloadC2Artifact", "uploadC2Artifact",
        "hostArtifact", "generateDropper", "getBeaconBinary",
        "uploadListenerFile", "installTool", "installToolBundle",
    )),
    "credentials": ToolBundle("credentials", (
        "makeToken", "kerberosUseTicket", "keyLogger", "miniDump",
        "stealToken", "rev2self", "listC2Credentials", "getC2Credential",
    )),
    "session_management": ToolBundle("session_management", (
        "end", "sleep", "loadModule", "unloadModule", "listModule",
        "help", "reloadModules",
    )),
}


def resolve_tool_bundles(
    bundle_names: Iterable[str],
    *,
    registered_tools: Iterable[str],
    required_tools: Iterable[str] = (),
) -> BundleResolution:
    """Resolve a skill grant against actual adapters; reject missing requirements."""
    names = tuple(dict.fromkeys(bundle_names))
    if not names:
        raise ValueError("A skill must select at least one tool bundle.")
    available = set(registered_tools)
    selected: list[str] = []
    for name in names:
        bundle = TOOL_BUNDLES.get(name)
        if bundle is None:
            raise ValueError(f"Unknown C2 tool bundle: {name}")
        selected.extend(bundle.tools)
    declared = tuple(dict.fromkeys(selected))
    required = tuple(dict.fromkeys(required_tools))
    undeclared = set(required) - set(declared)
    if undeclared:
        raise ValueError(f"Required tools are outside the selected bundles: {', '.join(sorted(undeclared))}")
    missing = set(required) - available
    if missing:
        raise ValueError(f"Required C2 tools are unavailable: {', '.join(sorted(missing))}")
    allowed = tuple(tool for tool in declared if tool in available)
    if not allowed:
        raise ValueError("No tools from the selected C2 bundles are available.")
    return BundleResolution(
        bundle_names=names,
        allowed_tools=allowed,
        unavailable_tools=tuple(tool for tool in declared if tool not in available),
    )
