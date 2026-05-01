from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .bootstrap import ensure_agent_core_path

ensure_agent_core_path()

from agent_core.execution_context import ExecutionContext
from agent_core.llm.base import LLMToolDefinition
from agent_core.tools import build_tool_definition
from agent_core.types import ToolResult

from ..grpcClient import TeamServerApi_pb2


def _quote_argument(value: object) -> str:
    if value is None:
        return '""'

    text = str(value)
    if not text:
        return '""'

    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text

    if any(ch.isspace() for ch in text) or '"' in text:
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'

    return text


def _session_properties(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "beacon_hash": {
            "type": "string",
            "description": "Full beacon hash identifying the session that should execute the command.",
        },
        "listener_hash": {
            "type": "string",
            "description": "Full listener hash for the target beacon session.",
        },
    }
    if extra:
        properties.update(extra)
    return properties


def _schema(name: str, description: str, extra: dict[str, Any] | None = None, required: list[str] | None = None) -> LLMToolDefinition:
    return build_tool_definition(
        name=name,
        description=description,
        parameters={
            "type": "object",
            "properties": _session_properties(extra),
            "required": ["beacon_hash", "listener_hash", *(required or [])],
            "additionalProperties": False,
        },
    )


TOOL_SCHEMAS: dict[str, LLMToolDefinition] = {
    "loadModule": _schema(
        "loadModule",
        "Load a beacon module into memory. Use this when a module is missing before retrying a command.",
        {"module_to_load": {"type": "string", "description": "Module name to load, for example ls, cd, cat, pwd, tree."}},
        ["module_to_load"],
    ),
    "ls": _schema(
        "ls",
        "List a directory on a beacon host.",
        {"path": {"type": "string", "description": "Directory path to list."}},
        ["path"],
    ),
    "cd": _schema(
        "cd",
        "Change the beacon working directory.",
        {"path": {"type": "string", "description": "Target working directory path."}},
        ["path"],
    ),
    "cat": _schema(
        "cat",
        "Read a file on a beacon host.",
        {"path": {"type": "string", "description": "File path to read."}},
        ["path"],
    ),
    "pwd": _schema("pwd", "Return the beacon current working directory."),
    "tree": _schema(
        "tree",
        "Recursively list a directory tree on a beacon host.",
        {"path": {"type": "string", "description": "Directory root to inspect."}},
        ["path"],
    ),
    "download": _schema(
        "download",
        "Download a file from a beacon host to the operator machine.",
        {
            "remote_path": {"type": "string", "description": "Path on the beacon host."},
            "local_path": {"type": "string", "description": "Destination path on the operator machine."},
        },
        ["remote_path", "local_path"],
    ),
    "upload": _schema(
        "upload",
        "Upload a local file from the operator machine to a beacon host.",
        {
            "local_path": {"type": "string", "description": "Path on the operator machine."},
            "remote_path": {"type": "string", "description": "Destination path on the beacon host."},
        },
        ["local_path", "remote_path"],
    ),
    "enumerateShares": _schema(
        "enumerateShares",
        "Enumerate SMB shares from the beacon context.",
        {"host": {"type": "string", "description": "Optional remote host to enumerate.", "default": ""}},
    ),
    "getEnv": _schema("getEnv", "List environment variables available to the beacon process."),
    "ipConfig": _schema("ipConfig", "Show local IP configuration for the beacon host."),
    "killProcess": _schema(
        "killProcess",
        "Terminate a process on the beacon host by PID.",
        {"pid": {"type": "integer", "description": "Process id to terminate."}},
        ["pid"],
    ),
    "listProcesses": _schema("listProcesses", "List running processes on the beacon host."),
    "netstat": _schema("netstat", "Show active network connections from the beacon host."),
    "remove": _schema(
        "remove",
        "Delete a file or directory recursively on the beacon host.",
        {"path": {"type": "string", "description": "Path to remove."}},
        ["path"],
    ),
    "run": _schema(
        "run",
        "Execute a system command on the beacon host and return stdout/stderr.",
        {"command": {"type": "string", "description": "Command line to execute."}},
        ["command"],
    ),
    "whoami": _schema("whoami", "Print the current beacon user context and group membership."),
}


def build_command_line(name: str, arguments: dict[str, Any]) -> str:
    if name == "pwd":
        return "pwd"
    if name == "loadModule":
        return f"loadModule {arguments['module_to_load']}"
    if name in {"ls", "cd", "cat", "tree"}:
        return f"{name} {_quote_argument(arguments['path'])}"
    if name == "download":
        remote_path = str(arguments["remote_path"]).strip()
        local_path = str(arguments["local_path"]).strip()
        if not remote_path or not local_path:
            raise ValueError("remote_path and local_path must not be empty")
        return f"download {_quote_argument(remote_path)} {_quote_argument(local_path)}"
    if name == "upload":
        local_path = str(arguments["local_path"]).strip()
        remote_path = str(arguments["remote_path"]).strip()
        if not local_path or not remote_path:
            raise ValueError("local_path and remote_path must not be empty")
        return f"upload {_quote_argument(local_path)} {_quote_argument(remote_path)}"
    if name == "enumerateShares":
        host = str(arguments.get("host", "")).strip()
        return f"enumerateShares {_quote_argument(host)}" if host else "enumerateShares"
    if name == "getEnv":
        return "getEnv"
    if name == "ipConfig":
        return "ipConfig"
    if name == "killProcess":
        pid = str(arguments["pid"]).strip()
        if not pid:
            raise ValueError("pid must not be empty")
        return f"killProcess {pid}"
    if name == "listProcesses":
        return "ps"
    if name == "netstat":
        return "netstat"
    if name == "remove":
        path = str(arguments["path"]).strip()
        if not path:
            raise ValueError("path must not be empty")
        return f"remove {_quote_argument(path)}"
    if name == "run":
        command = str(arguments["command"]).strip()
        if not command:
            raise ValueError("command must not be empty")
        return f"run {command}"
    if name == "whoami":
        return "whoami"
    raise ValueError(f"Unsupported C2 assistant tool: {name}")


@dataclass(slots=True)
class C2CommandTool:
    name: str
    grpc_client: Any

    @property
    def description(self) -> str:
        return TOOL_SCHEMAS[self.name].description

    def schema(self) -> LLMToolDefinition:
        return TOOL_SCHEMAS[self.name]

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        beacon_hash = arguments["beacon_hash"]
        listener_hash = arguments["listener_hash"]
        command_line = build_command_line(self.name, arguments)
        command = TeamServerApi_pb2.Command(
            beaconHash=beacon_hash,
            listenerHash=listener_hash,
            cmd=command_line,
        )
        self.grpc_client.sendCmdToSession(command)
        return ToolResult.pending_result(
            f'Sent `{command_line}` to beacon `{beacon_hash[:8]}`. Waiting for command output.',
            metadata={
                "beacon_hash": beacon_hash,
                "listener_hash": listener_hash,
                "command_line": command_line,
            },
        )
