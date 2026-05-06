import os
import time
import re, html
import uuid
import json
import logging
from datetime import datetime
from typing import Any

from PyQt6.QtCore import QObject, Qt, QEvent, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QStandardItem, QStandardItemModel, QTextCursor, QTextDocument, QShortcut
from PyQt6.QtWidgets import (
    QWidget,
    QTabBar,
    QTabWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QLineEdit,
    QCompleter,
    QCheckBox,
    QLabel,
    QPushButton,
)

from .grpcClient import TeamServerApi_pb2
from .TerminalPanel import Terminal
from .ScriptPanel import Script
from .AssistantPanel import Assistant
from .ArtifactPanel import Artifacts, ArtifactTabTitle
from .CommandPanel import Commands, CommandTabTitle
from .TerminalModules.Credentials import credentials
from .console_style import (
    CONSOLE_COLORS,
    apply_console_output_style,
    console_header_html,
    console_pre_html,
    console_status_html,
    move_editor_to_end,
)
from .env import env_path
from .grpc_status import is_response_ok, response_message

logger = logging.getLogger(__name__)
CONSOLE_EVENT_PREFIX = "[console] "


#
# Log
#
configuredLogsDir = env_path("C2_LOG_DIR")
if configuredLogsDir:
    logsDir = str(configuredLogsDir)
else:
    try:
        import pkg_resources
        logsDir = pkg_resources.resource_filename(
            'C2Client',
            'logs'
        )

    except ImportError:
        logsDir = os.path.join(os.path.dirname(__file__), 'logs')

if not os.path.exists(logsDir):
    os.makedirs(logsDir)

#
# Constant
#
TerminalTabTitle = "Terminal"
SYSTEM_TAB_COUNT = 5
CmdHistoryFileName = ".cmdHistory"

HelpInstruction = "help"
ListModuleInstruction = "listModule"
COMPLETER_REFRESH_SECONDS = 5.0

MODULE_COMMAND_ALIASES = {
    "changedirectory": "cd",
    "listdirectory": "ls",
    "listprocesses": "ps",
    "printworkingdirectory": "pwd",
}
PID_COMPLETION_PLACEHOLDER = "<pid>"
DOTNET_LOAD_NAME_PLACEHOLDER = "<name>"


def _completion_suffix(command_name: Any, example: Any):
    command_name = str(command_name or "").strip()
    example = str(example or "").strip()
    if not command_name or not example:
        return None
    if example == command_name:
        return None
    prefix = command_name + " "
    if example.startswith(prefix):
        return example[len(prefix):].strip()
    return example


def _entry_text(entry: tuple[str, list]) -> str:
    return entry[0]


def _find_entry(entries: list[tuple[str, list]], text: str):
    for entry in entries:
        if _entry_text(entry) == text:
            return entry
    return None


def _add_completion_path(entries: list[tuple[str, list]], parts: list[str]) -> None:
    if not parts:
        return
    text = str(parts[0] or "").strip()
    if not text:
        _add_completion_path(entries, parts[1:])
        return

    entry = _find_entry(entries, text)
    if entry is None:
        entry = (text, [])
        entries.append(entry)
    _add_completion_path(entry[1], parts[1:])


def _add_completion_value(entries: list[tuple[str, list]], value: Any) -> None:
    text = str(value or "").strip()
    if text:
        _add_completion_path(entries, text.split())


def _merge_completion_entries(destination: list[tuple[str, list]], source: list[tuple[str, list]]) -> None:
    for text, children in source:
        _add_completion_path(destination, [text])
        destination_entry = _find_entry(destination, text)
        if destination_entry is not None and children:
            _merge_completion_entries(destination_entry[1], children)


def _add_example_completions(children: list[tuple[str, list]], command: Any) -> None:
    if _command_has_artifact_args(command):
        return
    command_name = getattr(command, "name", "")
    for example in getattr(command, "examples", []):
        suffix = _completion_suffix(command_name, example)
        if suffix:
            _add_completion_value(children, suffix)


def _arg_is_flag(arg: Any) -> bool:
    name = str(getattr(arg, "name", "") or "").strip()
    arg_type = str(getattr(arg, "type", "") or "").strip().lower()
    return arg_type == "flag" or name.startswith("-")


def _arg_name(arg: Any) -> str:
    return str(getattr(arg, "name", "") or "").strip()


def _command_has_artifact_args(command: Any) -> bool:
    return any(_arg_has_artifact_filter(arg) for arg in getattr(command, "args", []))


def _flag_is_context_only(arg: Any) -> bool:
    return _arg_name(arg) in {"--method"}


def _source_flag_args(args: list[Any]) -> list[Any]:
    return [
        arg
        for arg in args
        if _arg_is_flag(arg) and _arg_name(arg) not in {"--mode", "--method"}
    ]


def _inject_payload_flag_args(args: list[Any]) -> list[Any]:
    return [
        arg
        for arg in args
        if _arg_name(arg) in {"--raw", "--donut-exe", "--donut-dll"}
    ]


def _argument_artifact_completion_values(artifact: Any) -> list[str]:
    return _dedupe_values([
        str(getattr(artifact, "name", "") or "").strip(),
        str(getattr(artifact, "display_name", "") or "").strip(),
    ])


def _artifact_value_continuations(arg: Any, command_name: str = "") -> list[str]:
    name = _arg_name(arg)
    if command_name == "inject":
        if name == "--donut-dll":
            return ["--pid", "--method", "--"]
        if name in {"--raw", "--donut-exe"}:
            continuations = ["--pid"]
            if name == "--donut-exe":
                continuations.append("--")
            return continuations
    if name == "--donut-exe":
        return ["--"]
    if name == "--donut-dll":
        return ["--method"]
    return []


def _artifact_specific_continuations(arg: Any, command_name: str, artifact_value: str) -> list[str]:
    if command_name == "dotnetExec" and _arg_name(arg) == "assembly_artifact":
        if artifact_value.lower().endswith(".dll"):
            return ["<type_for_dll>"]
    return []


def _add_inject_pid_continuations(children: list[tuple[str, list]], arg: Any) -> None:
    pid_entry = _find_entry(children, "--pid")
    if pid_entry is None:
        return

    _add_completion_path(pid_entry[1], [PID_COMPLETION_PLACEHOLDER])
    value_entry = _find_entry(pid_entry[1], PID_COMPLETION_PLACEHOLDER)
    if value_entry is None:
        return

    name = _arg_name(arg)
    if name == "--donut-exe":
        _add_completion_value(value_entry[1], "--")
    elif name == "--donut-dll":
        _add_completion_value(value_entry[1], "--method")
        _add_completion_value(value_entry[1], "--")


def _add_artifact_completions(
    children: list[tuple[str, list]],
    grpcClient: Any,
    arg: Any,
    session: Any | None,
    command_name: str = "",
) -> None:
    continuations = _artifact_value_continuations(arg, command_name)
    for artifact in _load_artifacts_for_arg(grpcClient, arg, session):
        for value in _argument_artifact_completion_values(artifact):
            _add_completion_value(children, value)
            artifact_entry = _find_entry(children, value)
            if artifact_entry is not None:
                artifact_continuations = [
                    *continuations,
                    *_artifact_specific_continuations(arg, command_name, value),
                ]
                for continuation in artifact_continuations:
                    _add_completion_value(artifact_entry[1], continuation)
                if command_name == "inject":
                    _add_inject_pid_continuations(artifact_entry[1], arg)


def _build_flag_entries(
    args: list[Any],
    grpcClient: Any = None,
    session: Any | None = None,
    *,
    include_context_only: bool = False,
    command_name: str = "",
) -> list[tuple[str, list]]:
    entries: list[tuple[str, list]] = []
    for arg in args:
        name = _arg_name(arg)
        if not _arg_is_flag(arg) or not name:
            continue
        if not include_context_only and _flag_is_context_only(arg):
            continue

        _add_completion_path(entries, [name])
        flag_entry = _find_entry(entries, name)
        if flag_entry is None:
            continue
        for value in getattr(arg, "values", []):
            _add_completion_value(flag_entry[1], value)
        _add_artifact_completions(flag_entry[1], grpcClient, arg, session, command_name)

        if command_name == "inject" and name == "--pid":
            _add_completion_path(flag_entry[1], [PID_COMPLETION_PLACEHOLDER])
            value_entry = _find_entry(flag_entry[1], PID_COMPLETION_PLACEHOLDER)
            if value_entry is not None:
                payload_flags = _build_flag_entries(
                    _inject_payload_flag_args(args),
                    grpcClient,
                    session,
                    command_name=command_name,
                )
                _merge_completion_entries(value_entry[1], payload_flags)
    return entries


def _add_mode_value_flag_completions(
    entries: list[tuple[str, list]],
    args: list[Any],
    grpcClient: Any,
    session: Any | None,
) -> None:
    mode_entry = _find_entry(entries, "--mode")
    if mode_entry is None:
        return

    source_flag_entries = _build_flag_entries(_source_flag_args(args), grpcClient, session)
    if not source_flag_entries:
        return
    for mode_value, children in mode_entry[1]:
        _merge_completion_entries(children, source_flag_entries)


def _add_arg_completions(
    children: list[tuple[str, list]],
    command: Any,
    grpcClient: Any = None,
    session: Any | None = None,
) -> None:
    args = list(getattr(command, "args", []))
    command_name = str(getattr(command, "name", "") or "")
    flag_entries = _build_flag_entries(args, grpcClient, session, command_name=command_name)
    _merge_completion_entries(children, flag_entries)
    _add_mode_value_flag_completions(children, args, grpcClient, session)

    first_positional_done = False
    for arg in args:
        if _arg_is_flag(arg):
            continue

        if first_positional_done:
            continue
        for value in getattr(arg, "values", []):
            _add_completion_value(children, value)
        _add_artifact_completions(children, grpcClient, arg, session, command_name)
        first_positional_done = True


def _normalized_module_name(value: Any) -> str:
    name = os.path.basename(str(value or "").strip())
    if "." in name:
        name = name.rsplit(".", 1)[0]
    if name.lower().startswith("lib") and len(name) > 3:
        name = name[3:]
    if not name:
        return ""
    return name[0].lower() + name[1:]


def _artifact_completion_values(artifact: Any) -> list[str]:
    names = [
        _normalized_module_name(getattr(artifact, "display_name", "")),
        _normalized_module_name(getattr(artifact, "name", "")),
        str(getattr(artifact, "display_name", "") or "").strip(),
        str(getattr(artifact, "name", "") or "").strip(),
    ]
    alias = MODULE_COMMAND_ALIASES.get(names[0].lower(), "") if names and names[0] else ""
    return _dedupe_values([alias, *names])


def _canonical_module_completion_name(value: Any) -> str:
    normalized = _normalized_module_name(value)
    if not normalized:
        return ""
    return MODULE_COMMAND_ALIASES.get(normalized.lower(), normalized)


def _remove_module_completions(children: list[tuple[str, list]], blocked_modules: set[str]) -> None:
    if not blocked_modules:
        return
    children[:] = [
        child
        for child in children
        if _canonical_module_completion_name(child[0]) not in blocked_modules
    ]


def _dedupe_values(values: list[Any]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        result.append(text)
        seen.add(text)
    return result


def _session_platform(session: Any | None) -> str:
    os_text = str(getattr(session, "os", "") or "").lower()
    if "windows" in os_text or os_text.startswith("win"):
        return "windows"
    if "linux" in os_text:
        return "linux"
    return ""


def _resolve_filter_value(value: Any, session: Any | None) -> str:
    text = str(value or "").strip()
    if text == "session.platform":
        return _session_platform(session)
    if text == "session.arch":
        return str(getattr(session, "arch", "") or "").strip()
    return text


def _artifact_filters_for_arg(arg: Any) -> list[Any]:
    artifact_filters = getattr(arg, "artifact_filters", None)
    if artifact_filters is not None:
        try:
            filters = [artifact_filter for artifact_filter in artifact_filters if artifact_filter is not None]
        except TypeError:
            filters = []
        if filters:
            return filters

    if not hasattr(arg, "artifact_filter"):
        return []

    artifact_filter = getattr(arg, "artifact_filter", None)
    if artifact_filter is None:
        return []
    if hasattr(arg, "HasField"):
        try:
            if not arg.HasField("artifact_filter"):
                return []
        except ValueError:
            pass
    return [artifact_filter]


def _arg_has_artifact_filter(arg: Any) -> bool:
    return bool(_artifact_filters_for_arg(arg))


def _artifact_query_from_filter(artifact_filter: Any, session: Any | None) -> Any:
    query = TeamServerApi_pb2.ArtifactQuery()
    for field_name in ("category", "scope", "target", "platform", "arch", "runtime", "name_contains"):
        value = _resolve_filter_value(getattr(artifact_filter, field_name, ""), session)
        if value:
            setattr(query, field_name, value)
    return query


def _load_commands(grpcClient: Any) -> list[Any]:
    if grpcClient is None or not hasattr(grpcClient, "listCommands"):
        return []
    try:
        query = TeamServerApi_pb2.CommandQuery()
        return list(grpcClient.listCommands(query))
    except Exception as exc:
        logger.debug("Command autocomplete could not load CommandSpec catalog: %s", exc)
        return []


def _load_current_session(grpcClient: Any, beaconHash: str, listenerHash: str) -> Any | None:
    if grpcClient is None or not hasattr(grpcClient, "listSessions") or not beaconHash:
        return None
    try:
        for session in grpcClient.listSessions():
            if getattr(session, "beacon_hash", "") != beaconHash:
                continue
            if listenerHash and getattr(session, "listener_hash", "") != listenerHash:
                continue
            return session
    except Exception as exc:
        logger.debug("Command autocomplete could not load session context: %s", exc)
    return None


def _load_listener_hashes(grpcClient: Any) -> list[str]:
    if grpcClient is None or not hasattr(grpcClient, "listListeners"):
        return []
    try:
        return _dedupe_values([getattr(listener, "listener_hash", "") for listener in grpcClient.listListeners()])
    except Exception as exc:
        logger.debug("Command autocomplete could not load listener context: %s", exc)
        return []


def _load_modules_for_session(grpcClient: Any, beaconHash: str, listenerHash: str) -> list[Any]:
    if grpcClient is None or not hasattr(grpcClient, "listModules") or not beaconHash:
        return []
    try:
        session = TeamServerApi_pb2.SessionSelector(beacon_hash=beaconHash, listener_hash=listenerHash)
        return list(grpcClient.listModules(session))
    except Exception as exc:
        logger.debug("Command autocomplete could not load module context: %s", exc)
        return []


def _load_artifacts_for_arg(grpcClient: Any, arg: Any, session: Any | None) -> list[Any]:
    if grpcClient is None or not hasattr(grpcClient, "listArtifacts") or not _arg_has_artifact_filter(arg):
        return []

    artifacts: list[Any] = []
    seen: set[tuple[str, str, str]] = set()
    for artifact_filter in _artifact_filters_for_arg(arg):
        try:
            query = _artifact_query_from_filter(artifact_filter, session)
            for artifact in grpcClient.listArtifacts(query):
                key = (
                    str(getattr(artifact, "artifact_id", "") or ""),
                    str(getattr(artifact, "name", "") or ""),
                    str(getattr(artifact, "display_name", "") or ""),
                )
                if key in seen:
                    continue
                seen.add(key)
                artifacts.append(artifact)
        except Exception as exc:
            logger.debug("Command autocomplete could not load artifact context: %s", exc)
    return artifacts


def _module_command_names(command_specs: list[Any]) -> list[str]:
    return _dedupe_values([
        getattr(command, "name", "")
        for command in command_specs
        if str(getattr(command, "kind", "") or "").lower() == "module"
    ])


def _tracked_module_names(modules: list[Any], states: set[str]) -> list[str]:
    return _dedupe_values([
        getattr(module, "name", "")
        for module in modules
        if str(getattr(module, "state", "") or "") in states
    ])


def _format_loaded_modules_for_console(modules: list[Any]) -> str:
    rows = []
    for module in modules:
        name = str(getattr(module, "name", "") or "").strip()
        if not name:
            continue
        status = str(getattr(module, "state", "") or "unknown").strip() or "unknown"
        rows.append((name, status))

    if not rows:
        return "No loaded modules."

    name_width = max(len("name"), *(len(name) for name, _status in rows))
    lines = [f"{'name'.ljust(name_width)}  status"]
    for name, status in rows:
        lines.append(f"{name.ljust(name_width)}  {status}")
    return "\n".join(lines)


def _add_contextual_completions(
    children: list[tuple[str, list]],
    command: Any,
    command_specs: list[Any],
    grpcClient: Any,
    session: Any | None,
    listener_hashes: list[str],
    tracked_modules: list[Any],
) -> None:
    name = str(getattr(command, "name", "") or "")
    active_module_names = set(_tracked_module_names(tracked_modules, {"loading", "loaded", "unloading"}))
    loaded_module_names = _tracked_module_names(tracked_modules, {"loaded"})

    if name == "listener":
        for listener_hash in listener_hashes:
            _add_completion_path(children, ["stop", listener_hash])

    if name == HelpInstruction:
        for command_name in _dedupe_values([getattr(spec, "name", "") for spec in command_specs]):
            if command_name != HelpInstruction:
                _add_completion_value(children, command_name)

    if name == "loadModule":
        _remove_module_completions(children, active_module_names)
        for module_name in _module_command_names(command_specs):
            if module_name not in active_module_names:
                _add_completion_value(children, module_name)
        for arg in getattr(command, "args", []):
            for artifact in _load_artifacts_for_arg(grpcClient, arg, session):
                for value in _artifact_completion_values(artifact):
                    if _canonical_module_completion_name(value) not in active_module_names:
                        _add_completion_value(children, value)

    if name == "unloadModule":
        children.clear()
        for module_name in loaded_module_names:
            _add_completion_value(children, module_name)

    if name == "dotnetExec":
        load_entry = _find_entry(children, "load")
        if load_entry is None:
            _add_completion_path(children, ["load"])
            load_entry = _find_entry(children, "load")
        if load_entry is not None:
            _add_completion_path(load_entry[1], [DOTNET_LOAD_NAME_PLACEHOLDER])
            name_entry = _find_entry(load_entry[1], DOTNET_LOAD_NAME_PLACEHOLDER)
            if name_entry is not None:
                for arg in getattr(command, "args", []):
                    if _arg_name(arg) == "assembly_artifact":
                        _add_artifact_completions(name_entry[1], grpcClient, arg, session, name)


def command_specs_to_completer_data(
    command_specs: list[Any],
    grpcClient: Any = None,
    session: Any | None = None,
    listener_hashes: list[str] | None = None,
    tracked_modules: list[Any] | None = None,
):
    entries: list[tuple[str, list]] = []
    listener_hashes = listener_hashes or []
    tracked_modules = tracked_modules or []
    for command in command_specs:
        name = str(getattr(command, "name", "") or "").strip()
        if not name:
            continue
        children: list[tuple[str, list]] = []
        _add_example_completions(children, command)
        _add_arg_completions(children, command, grpcClient, session)
        _add_contextual_completions(children, command, command_specs, grpcClient, session, listener_hashes, tracked_modules)
        _add_completion_path(entries, [name])
        entry = _find_entry(entries, name)
        if entry is not None:
            _merge_completion_entries(entry[1], children)
    return entries


def build_completer_data(grpcClient: Any = None, beaconHash: str = "", listenerHash: str = ""):
    command_specs = _load_commands(grpcClient)
    session = _load_current_session(grpcClient, beaconHash, listenerHash)
    listener_hashes = _load_listener_hashes(grpcClient)
    tracked_modules = _load_modules_for_session(grpcClient, beaconHash, listenerHash)
    return command_specs_to_completer_data(command_specs, grpcClient, session, listener_hashes, tracked_modules)


class CommandCompletionProvider:
    def __init__(self, grpcClient: Any = None, beaconHash: str = "", listenerHash: str = "") -> None:
        self.grpcClient = grpcClient
        self.beaconHash = beaconHash
        self.listenerHash = listenerHash
        self._cachedData: list[tuple[str, list]] = []
        self._loadedAt = 0.0

    def build(self, force: bool = False) -> list[tuple[str, list]]:
        now = time.monotonic()
        if not force and self._cachedData and now - self._loadedAt < COMPLETER_REFRESH_SECONDS:
            return self._cachedData
        self._cachedData = build_completer_data(self.grpcClient, self.beaconHash, self.listenerHash)
        self._loadedAt = now
        return self._cachedData


#
# Fix console rendering
#
# Regexes
SGR_RE = re.compile(r'\x1b\[([0-9;]*)m')  # keep these for color -> HTML
OSC_RE = re.compile(r'\x1b\].*?(?:\x07|\x1b\\)', re.DOTALL)  # OSC ... BEL/ST
# Any CSI (ESC [ ... finalbyte), we'll later keep only the ones ending with 'm'
CSI_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
# Single-char ESC sequences:
#  - ESC= / ESC> / ESC<  (keypad/app mode toggles)
#  - ESC @ .. ESC _      (misc single ESCs)
ESC_SINGLE_RE = re.compile(r'\x1b(?:[@-Z\\-_]|[=><])')

def normalize_cr(text: str) -> str:
    text = text.replace('\r\n', '\n')
    # treat stray CR as newline (instead of overwriting behavior)
    return re.sub(r'\r(?!\n)', '\n', text)

def apply_backspaces(text: str) -> str:
    out = []
    for ch in text:
        if ch == '\b':
            if out: out.pop()
        else:
            out.append(ch)
    return ''.join(out)

def strip_non_sgr_ansi(text: str) -> str:
    # 1) remove OSC
    text = OSC_RE.sub('', text)

    # 2) remove *non*-SGR CSI (keep those ending with 'm')
    def _keep_only_sgr(m):
        s = m.group(0)
        return s if s.endswith('m') else ''  # drop everything except SGR
    text = CSI_RE.sub(_keep_only_sgr, text)

    # 3) remove single-byte ESC sequences (ESC=, ESC>, ESCc, ESC(0, ESC)B, etc.)
    text = ESC_SINGLE_RE.sub('', text)

    return text

# Minimal SGR -> HTML
_BASE  = ['#000','#a00','#0a0','#a50','#00a','#a0a','#0aa','#aaa']
_BRIGHT= ['#555','#f55','#5f5','#ff5','#55f','#f5f','#5ff','#fff']

def _style_css(state):
    css=[]
    if state.get('bold'): css.append('font-weight:bold')
    if state.get('underline'): css.append('text-decoration:underline')
    if state.get('fg'): css.append(f"color:{state['fg']}")
    if state.get('bg'): css.append(f"background-color:{state['bg']}")
    return ';'.join(css)

def ansi_to_html(text: str) -> str:
    txt = html.escape(text)
    out=[]; pos=0; state={}; open_span=False
    for m in SGR_RE.finditer(txt):
        if m.start() > pos:
            chunk = txt[pos:m.start()].replace('\n','<br/>')
            if _style_css(state):
                if not open_span:
                    out.append(f'<span style="{_style_css(state)}">'); open_span=True
            out.append(chunk)
        pos = m.end()
        params = m.group(1)
        codes = [0] if params=='' else [int(c or 0) for c in params.split(';')]

        for c in codes:
            if c==0: state.clear()
            elif c==1: state['bold']=True
            elif c==4: state['underline']=True
            elif 30<=c<=37: state['fg']=_BASE[c-30]
            elif 90<=c<=97: state['fg']=_BRIGHT[c-90]
            elif 40<=c<=47: state['bg']=_BASE[c-40]
            elif 100<=c<=107: state['bg']=_BRIGHT[c-100]
            elif c==39: state.pop('fg',None)
            elif c==49: state.pop('bg',None)

        if open_span: out.append('</span>'); open_span=False
        if _style_css(state): out.append(f'<span style="{_style_css(state)}">'); open_span=True

    if pos < len(txt):
        chunk = txt[pos:].replace('\n','<br/>')
        if _style_css(state) and not open_span:
            out.append(f'<span style="{_style_css(state)}">'); open_span=True
        out.append(chunk)
    if open_span: out.append('</span>')
    return ''.join(out)
        

#
# Consoles Tab Implementation
#
class ConsolesTab(QWidget):
    
    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)
        self.setObjectName("C2ConsolesTab")
        self.setStyleSheet(
            f"""
            QWidget#C2ConsolesTab,
            QWidget#C2ConsolePage {{
                background-color: {CONSOLE_COLORS["background"]};
            }}
            QTabWidget#C2ConsoleTabs {{
                background-color: #070b10;
                border: 0;
            }}
            QTabWidget#C2ConsoleTabs::pane {{
                background-color: {CONSOLE_COLORS["background"]};
                border: 1px solid {CONSOLE_COLORS["border"]};
                top: -1px;
            }}
            QTabWidget#C2ConsoleTabs QStackedWidget {{
                background-color: {CONSOLE_COLORS["background"]};
                border: 0;
            }}
            QTabWidget#C2ConsoleTabs QTabBar {{
                background-color: #070b10;
            }}
            """
        )
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        
        # Initialize tab screen
        self.tabs = QTabWidget(self)
        self.tabs.setObjectName("C2ConsoleTabs")
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.closeTab) 
                
        # Add tabs to widget
        self.layout.addWidget(self.tabs)

        self.grpcClient = grpcClient

        self.terminal = Terminal(self, self.grpcClient)
        tab = self.createConsolePage(self.terminal)
        self.tabs.addTab(tab, TerminalTabTitle)
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        self.script = Script(self, self.grpcClient)
        tab = self.createConsolePage(self.script)
        self.tabs.addTab(tab, "Hooks")
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        self.artifacts = Artifacts(self, self.grpcClient)
        tab = self.createConsolePage(self.artifacts)
        self.tabs.addTab(tab, ArtifactTabTitle)
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        self.commands = Commands(self, self.grpcClient)
        tab = self.createConsolePage(self.commands)
        self.tabs.addTab(tab, CommandTabTitle)
        self.tabs.setCurrentIndex(self.tabs.count()-1)

        self.assistant = Assistant(self, self.grpcClient)
        tab = self.createConsolePage(self.assistant)
        self.tabs.addTab(tab, "Data AI")
        self.tabs.setCurrentIndex(self.tabs.count()-1)
        self.protectSystemTabs()

    def createConsolePage(self, child):
        tab = QWidget()
        tab.setObjectName("C2ConsolePage")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(child)
        return tab

    def protectSystemTabs(self):
        tabBar = self.tabs.tabBar()
        for index in range(min(SYSTEM_TAB_COUNT, self.tabs.count())):
            tabBar.setTabButton(index, QTabBar.ButtonPosition.LeftSide, None)
            tabBar.setTabButton(index, QTabBar.ButtonPosition.RightSide, None)
        
    def addConsole(self, beaconHash, listenerHash, hostname, username):
        tabAlreadyOpen=False
        for idx in range(0,self.tabs.count()):
            openTabKey = self.tabs.tabText(idx)
            if openTabKey==beaconHash[0:8]:
                self.tabs.setCurrentIndex(idx)
                tabAlreadyOpen=True

        if tabAlreadyOpen==False:
            console = Console(self, self.grpcClient, beaconHash, listenerHash, hostname, username)
            console.consoleScriptSignal.connect(self.script.consoleScriptMethod)
            console.consoleScriptSignal.connect(self.assistant.consoleAssistantMethod)
            tab = self.createConsolePage(console)
            self.tabs.addTab(tab, beaconHash[0:8])
            self.tabs.setCurrentIndex(self.tabs.count()-1)

    def closeTab(self, currentIndex):
        currentQWidget = self.tabs.widget(currentIndex)
        if currentIndex < SYSTEM_TAB_COUNT:
            return
        currentQWidget.deleteLater()
        self.tabs.removeTab(currentIndex)


class Console(QWidget):

    consoleScriptSignal = pyqtSignal(str, str, str, str, str, str, str)

    tabPressed = pyqtSignal()
    beaconHash=""
    hostname=""
    username=""
    logFileName=""
    listenerHash=""

    def __init__(self, parent, grpcClient, beaconHash, listenerHash, hostname, username):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        self.grpcClient = grpcClient

        self.beaconHash=beaconHash
        self.listenerHash=listenerHash
        self.hostname=hostname.replace("\\", "_").replace(" ", "_")
        self.username=username.replace("\\", "_").replace(" ", "_")
        self.logFileName=self.hostname+"_"+self.username+"_"+self.beaconHash+".log"
        self.lastCommandLine = ""
        self.commandStatusById = {}
        self.renderedResponseIds = set()

        self.searchInput = QLineEdit()
        self.searchInput.setPlaceholderText("Search output")
        self.searchInput.returnPressed.connect(self.findNextSearchMatch)

        self.findPreviousButton = QPushButton("Prev")
        self.findPreviousButton.clicked.connect(
            lambda _checked=False: self.findNextSearchMatch(backward=True)
        )
        self.findNextButton = QPushButton("Next")
        self.findNextButton.clicked.connect(
            lambda _checked=False: self.findNextSearchMatch()
        )
        self.clearOutputButton = QPushButton("Clear")
        self.clearOutputButton.clicked.connect(self.clearConsoleOutput)
        self.exportLogButton = QPushButton("Export")
        self.exportLogButton.clicked.connect(self.exportConsoleOutput)
        self.resendButton = QPushButton("Resend")
        self.resendButton.clicked.connect(self.resendLastCommand)
        self.pauseAutoscrollCheckBox = QCheckBox("Pause scroll")
        self.pauseAutoscrollCheckBox.toggled.connect(self.onAutoscrollToggled)
        self.consoleNoticeLabel = QLabel("")
        self.consoleNoticeLabel.setMinimumWidth(180)
        self.consoleNoticeLabel.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        toolbarLayout = QHBoxLayout()
        toolbarLayout.addWidget(self.searchInput, 3)
        toolbarLayout.addWidget(self.findPreviousButton)
        toolbarLayout.addWidget(self.findNextButton)
        toolbarLayout.addWidget(self.clearOutputButton)
        toolbarLayout.addWidget(self.exportLogButton)
        toolbarLayout.addWidget(self.resendButton)
        toolbarLayout.addWidget(self.pauseAutoscrollCheckBox)
        toolbarLayout.addWidget(self.consoleNoticeLabel, 2)
        self.layout.addLayout(toolbarLayout)

        self.editorOutput = QTextEdit()
        self.editorOutput.setReadOnly(True)
        self.editorOutput.setAcceptRichText(True)
        apply_console_output_style(self.editorOutput)
        self.layout.addWidget(self.editorOutput, 8)
        self.loadConsoleLog()

        self.commandEditor = CommandEditor(
            grpcClient=self.grpcClient,
            beaconHash=self.beaconHash,
            listenerHash=self.listenerHash,
        )
        self.layout.addWidget(self.commandEditor, 2)
        self.commandEditor.returnPressed.connect(self.runCommand)

        # Thread to get sessions response
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getSessionResponse = GetSessionResponse()
        self.getSessionResponse.moveToThread(self.thread)
        self.thread.started.connect(self.getSessionResponse.run)
        self.getSessionResponse.checkin.connect(self.displayResponse)
        self.thread.start()

    def __del__(self):
        self.getSessionResponse.quit()
        self.thread.quit()
        self.thread.wait()

    def nextCompletion(self):
        index = self._compl.currentIndex()
        self._compl.popup().setCurrentIndex(index)
        start = self._compl.currentRow()
        if not self._compl.setCurrentRow(start + 1):
            self._compl.setCurrentRow(0)

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def setConsoleNotice(self, message, is_error=False):
        self.consoleNoticeLabel.setText(message)
        color = CONSOLE_COLORS["error"] if is_error else CONSOLE_COLORS["muted"]
        self.consoleNoticeLabel.setStyleSheet(f"color: {color};")

    def findNextSearchMatch(self, backward=False):
        search_text = self.searchInput.text().strip()
        if search_text == "":
            self.setConsoleNotice("Search term required.", True)
            return False

        original_cursor = self.editorOutput.textCursor()
        flags = QTextDocument.FindFlag.FindBackward if backward else QTextDocument.FindFlag(0)
        if self.editorOutput.find(search_text, flags):
            self.setConsoleNotice("Match found.")
            return True

        cursor = self.editorOutput.textCursor()
        if backward:
            cursor.movePosition(QTextCursor.MoveOperation.End)
        else:
            cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editorOutput.setTextCursor(cursor)

        if self.editorOutput.find(search_text, flags):
            self.setConsoleNotice("Search wrapped.")
            return True

        self.editorOutput.setTextCursor(original_cursor)
        self.setConsoleNotice("No match.", True)
        return False

    def clearConsoleOutput(self):
        self.editorOutput.clear()
        self.setConsoleNotice("Output cleared.")

    def exportConsoleOutput(self):
        os.makedirs(logsDir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base_name = os.path.splitext(self.logFileName)[0]
        output_path = os.path.join(logsDir, f"{base_name}_console_{timestamp}.log")
        with open(output_path, "w", encoding="utf-8") as exportFile:
            exportFile.write(self.editorOutput.toPlainText().rstrip())
            exportFile.write("\n")
        self.setConsoleNotice("Exported " + os.path.basename(output_path))
        return output_path

    def onAutoscrollToggled(self, checked):
        if checked:
            self.setConsoleNotice("Autoscroll paused.")
            return
        self.setConsoleNotice("Autoscroll enabled.")
        self.setCursorEditorAtEnd(force=True)

    def isAutoscrollPaused(self):
        return self.pauseAutoscrollCheckBox.isChecked()

    def _shortCommandId(self, command_id):
        return (command_id or "unknown")[:8]

    def _shortText(self, text, limit=90):
        text = " ".join(str(text or "").split())
        if len(text) <= limit:
            return text
        return text[:limit - 3] + "..."

    def consoleLogPath(self):
        return os.path.join(logsDir, self.logFileName)

    def appendConsoleEvent(self, event, **payload):
        os.makedirs(logsDir, exist_ok=True)
        eventPayload = {
            "event": event,
            "timestamp": datetime.now().strftime("%Y:%m:%d %H:%M:%S"),
            **payload,
        }
        with open(self.consoleLogPath(), "a", encoding="utf-8") as logFile:
            logFile.write(CONSOLE_EVENT_PREFIX)
            logFile.write(json.dumps(eventPayload, sort_keys=True))
            logFile.write("\n")

    def loadConsoleLog(self):
        path = self.consoleLogPath()
        if not os.path.exists(path):
            return

        loadedEvents = 0
        with open(path, encoding="utf-8", errors="replace") as logFile:
            for line in logFile:
                if not line.startswith(CONSOLE_EVENT_PREFIX):
                    continue
                rawPayload = line[len(CONSOLE_EVENT_PREFIX):].strip()
                try:
                    eventPayload = json.loads(rawPayload)
                except json.JSONDecodeError:
                    continue
                if self.renderConsoleEvent(eventPayload):
                    loadedEvents += 1

        if loadedEvents:
            self.setConsoleNotice(f"Loaded {loadedEvents} log events.")
            self.setCursorEditorAtEnd(force=True)

    def renderConsoleEvent(self, eventPayload):
        status = eventPayload.get("event", "")
        if status not in {"queued", "done", "error"}:
            return False

        command_id = eventPayload.get("command_id", "")
        command = eventPayload.get("command", "")
        output = eventPayload.get("output", "")
        source = eventPayload.get("source", "")
        timestamp = eventPayload.get("timestamp", "")

        self.setCommandStatus(command_id, status, command, output if status == "error" else "")
        self.printCommandStatusInTerminal(command_id, status, command or output, timestamp=timestamp)
        if status in {"done", "error"} and output:
            self.printInTerminal("", "", output)
            if command_id and source != "ack":
                self.renderedResponseIds.add(command_id)
        return True

    def setCommandStatus(self, command_id, status, command_line="", message=""):
        if not command_id:
            return
        self.commandStatusById[command_id] = {
            "status": status,
            "command": command_line,
            "message": message,
            "updated_at": time.time(),
        }

        detail = self._shortText(command_line or message)
        notice = f"{status} {self._shortCommandId(command_id)}"
        if detail:
            notice += f" - {detail}"
        self.setConsoleNotice(notice, status == "error")

    def printCommandStatusInTerminal(self, command_id, status, message="", timestamp=None):
        tones = {
            "queued": "warning",
            "done": "success",
            "error": "error",
        }
        terminal_line = console_status_html(
            status,
            self._shortCommandId(command_id or "unknown"),
            self._shortText(message, 140),
            tone=tones.get(status, "info"),
            timestamp=timestamp,
        )
        self.editorOutput.insertHtml(terminal_line)
        self.editorOutput.insertPlainText("\n")

    def printInTerminal(self, cmdSent, cmdReived, result):
        if cmdSent:
            self.editorOutput.insertHtml(
                console_header_html(cmdSent, marker="[>>]", tone="command")
            )
            self.editorOutput.insertPlainText("\n")
        elif cmdReived:
            self.editorOutput.insertHtml(
                console_header_html(cmdReived, marker="[<<]", tone="response")
            )
            self.editorOutput.insertPlainText("\n")
        if result:

            s = normalize_cr(result)
            s = apply_backspaces(s)
            s = strip_non_sgr_ansi(s)
            # Convert remaining color SGR
            html_body = ansi_to_html(s)

            self.editorOutput.insertHtml(console_pre_html(html_body))
            self.editorOutput.insertHtml("<br/>")
            self.editorOutput.insertPlainText("\n")

    def printLocalCommandQueued(self, command_id, command_line):
        self.setCommandStatus(command_id, "queued", command_line)
        self.printCommandStatusInTerminal(command_id, "queued", command_line)
        self.appendConsoleEvent(
            "queued",
            command_id=command_id,
            command=command_line,
            source="local",
        )

    def printLocalCommandFinished(self, command_id, command_line, output, status="done"):
        self.setCommandStatus(command_id, status, command_line, output if status == "error" else "")
        self.printCommandStatusInTerminal(command_id, status, command_line)
        if output:
            self.printInTerminal("", "", output)
        self.appendConsoleEvent(
            status,
            command_id=command_id,
            command=command_line,
            output=output,
            source="local",
        )

    def resendLastCommand(self):
        if self.lastCommandLine == "":
            self.setConsoleNotice("No command to resend.", True)
            return
        self.executeCommand(self.lastCommandLine)

    def runCommand(self):
        commandLine = self.commandEditor.displayText()
        self.commandEditor.clearLine()
        self.executeCommand(commandLine)

    def executeCommand(self, commandLine):
        self.setCursorEditorAtEnd()

        if commandLine == "":
            self.printInTerminal("", "", "")
            self.setCursorEditorAtEnd()
            return

        self.lastCommandLine = commandLine

        with open(CmdHistoryFileName, 'a') as cmdHistoryFile:
            cmdHistoryFile.write(commandLine)
            cmdHistoryFile.write('\n')

        with open(os.path.join(logsDir, self.logFileName), 'a') as logFile:
            logFile.write('[+] send: \"' + commandLine + '\"')
            logFile.write('\n')

        self.commandEditor.setCmdHistory()
        instructions = commandLine.split()
        if instructions[0]==HelpInstruction:
            command_id = uuid.uuid4().hex
            self.printLocalCommandQueued(command_id, commandLine)
            try:
                command = TeamServerApi_pb2.CommandHelpRequest(
                    session=TeamServerApi_pb2.SessionSelector(
                        beacon_hash=self.beaconHash,
                        listener_hash=self.listenerHash,
                    ),
                    command=commandLine,
                )
                response = self.grpcClient.getCommandHelp(command)
                command_text = getattr(response, "command", commandLine) or commandLine
                if is_response_ok(response):
                    output = getattr(response, "help", "") or response_message(response, "No help available.")
                    self.printLocalCommandFinished(command_id, command_text, output)
                else:
                    self.printLocalCommandFinished(
                        command_id,
                        command_text,
                        response_message(response, "No help available."),
                        "error",
                    )
            except Exception as exc:
                self.printLocalCommandFinished(command_id, commandLine, f"Error: {exc}", "error")
            self.setCursorEditorAtEnd()
            return

        if instructions[0] == ListModuleInstruction:
            command_id = uuid.uuid4().hex
            self.printLocalCommandQueued(command_id, commandLine)
            try:
                modules = list(self.grpcClient.listModules(
                    TeamServerApi_pb2.SessionSelector(
                        beacon_hash=self.beaconHash,
                        listener_hash=self.listenerHash,
                    )
                ))
                self.printLocalCommandFinished(command_id, commandLine, _format_loaded_modules_for_console(modules))
            except Exception as exc:
                self.printLocalCommandFinished(command_id, commandLine, f"Error: {exc}", "error")
                self.setConsoleNotice("listModule failed.", True)
            self.setCursorEditorAtEnd()
            return

        command_id = uuid.uuid4().hex
        command = TeamServerApi_pb2.SessionCommandRequest(
            session=TeamServerApi_pb2.SessionSelector(
                beacon_hash=self.beaconHash,
                listener_hash=self.listenerHash,
            ),
            command=commandLine,
            command_id=command_id,
        )
        result = self.grpcClient.sendSessionCommand(command)
        command_id = getattr(result, "command_id", command_id) or command_id
        if not is_response_ok(result):
            message = response_message(result, "Command was rejected by TeamServer.")
            self.setCommandStatus(command_id, "error", commandLine, message)
            self.printCommandStatusInTerminal(command_id, "error", commandLine)
            self.printInTerminal("", "", message)
            self.appendConsoleEvent(
                "error",
                command_id=command_id,
                command=commandLine,
                output=message,
                source="ack",
            )
            with open(os.path.join(logsDir, self.logFileName), 'a') as logFile:
                logFile.write('[+] rejected: \"' + commandLine + '\"')
                logFile.write('\n' + message + '\n')
            self.setCursorEditorAtEnd()
            return

        self.setCommandStatus(command_id, "queued", commandLine)
        self.printCommandStatusInTerminal(command_id, "queued", commandLine)
        self.appendConsoleEvent("queued", command_id=command_id, command=commandLine)
        context = "Host " + self.hostname + " - Username " + self.username
        self.consoleScriptSignal.emit("send", self.beaconHash, self.listenerHash, context, commandLine, "", command_id)
        ack_message = response_message(result)
        if ack_message:
            self.printInTerminal("", "", ack_message)

        self.setCursorEditorAtEnd()

    def displayResponse(self):
        session = TeamServerApi_pb2.SessionSelector(beacon_hash=self.beaconHash, listener_hash=self.listenerHash)
        responses = self.grpcClient.streamSessionCommandResults(session)
        for response in responses:
            context = "Host " + self.hostname + " - Username " + self.username
            command_id = getattr(response, "command_id", "")
            if command_id and command_id in self.renderedResponseIds:
                continue
            listener_hash = response.session.listener_hash or self.listenerHash
            command_text = response.command or response.instruction
            decoded_response = response.output.decode('utf-8', 'replace')
            response_ok = is_response_ok(response)
            if not response_ok:
                decoded_response = response_message(response) or decoded_response or "Command failed."
            self.consoleScriptSignal.emit("receive", self.beaconHash, listener_hash, context, command_text, decoded_response, command_id)
            # check the response for mimikatz and not the cmd line ???
            if "-e mimikatz.exe" in command_text:
                credentials.handleMimikatzCredentials(decoded_response, self.grpcClient, TeamServerApi_pb2)
            status = "done" if response_ok else "error"
            self.setCommandStatus(command_id, status, command_text, decoded_response if not response_ok else "")
            self.printCommandStatusInTerminal(command_id, status, command_text)
            self.printInTerminal("", "", decoded_response)
            if command_id:
                self.renderedResponseIds.add(command_id)
            self.appendConsoleEvent(
                status,
                command_id=command_id,
                command=command_text,
                output=decoded_response,
                source="response",
            )
            self.setCursorEditorAtEnd()

            with open(os.path.join(logsDir, self.logFileName), 'a') as logFile:
                logFile.write('[+] result: \"' + command_text + '\"')
                logFile.write('\n' + decoded_response  + '\n')
                logFile.write('\n')

    def setCursorEditorAtEnd(self, force=False):
        if not force and self.isAutoscrollPaused():
            return
        move_editor_to_end(self.editorOutput)
    

class GetSessionResponse(QObject):
    """Background worker querying session responses."""

    checkin = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.exit = False

    def run(self) -> None:
        while not self.exit:
            self.checkin.emit()
            time.sleep(1)

    def quit(self) -> None:
        self.exit = True


class CommandEditor(QLineEdit):
    tabPressed = pyqtSignal()

    def __init__(
        self,
        parent: QWidget | None = None,
        grpcClient=None,
        beaconHash: str = "",
        listenerHash: str = "",
    ) -> None:
        super().__init__(parent)

        self.cmdHistory: list[str] = []
        self.idx: int = 0
        self.completionProvider = CommandCompletionProvider(grpcClient, beaconHash, listenerHash)

        if os.path.isfile(CmdHistoryFileName):
            with open(CmdHistoryFileName) as cmdHistoryFile:
                self.cmdHistory = cmdHistoryFile.readlines()
            self.idx = len(self.cmdHistory) - 1

        QShortcut(Qt.Key.Key_Up, self, self.historyUp)
        QShortcut(Qt.Key.Key_Down, self, self.historyDown)

        self.completionData = self.completionProvider.build(force=True)
        self.codeCompleter = CodeCompleter(self.completionData, self)
        # needed to clear the completer after activation
        self.codeCompleter.activated.connect(self.onActivated)
        self.setCompleter(self.codeCompleter)
        self.tabPressed.connect(self.nextCompletion)

    def refreshCompleter(self, force: bool = False):
        completionData = self.completionProvider.build(force=force)
        if completionData != self.completionData:
            self.completionData = completionData
            self.codeCompleter.updateData(completionData)

    def nextCompletion(self):
        self.refreshCompleter()
        index = self.codeCompleter.currentIndex()
        self.codeCompleter.popup().setCurrentIndex(index)
        start = self.codeCompleter.currentRow()
        if not self.codeCompleter.setCurrentRow(start + 1):
            self.codeCompleter.setCurrentRow(0)

    def event(self, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.tabPressed.emit()
            return True
        return super().event(event)

    def historyUp(self):
        if(self.idx<len(self.cmdHistory) and self.idx>=0):
            cmd = self.cmdHistory[self.idx%len(self.cmdHistory)]
            self.idx=max(self.idx-1,0)
            self.setText(cmd.strip())

    def historyDown(self):
        if(self.idx<len(self.cmdHistory) and self.idx>=0):
            self.idx=min(self.idx+1,len(self.cmdHistory)-1)
            cmd = self.cmdHistory[self.idx%len(self.cmdHistory)]
            self.setText(cmd.strip())

    def setCmdHistory(self) -> None:
        with open(CmdHistoryFileName) as cmdHistoryFile:
            self.cmdHistory = cmdHistoryFile.readlines()
        self.idx = len(self.cmdHistory) - 1

    def clearLine(self):
        self.clear()

    def onActivated(self):
        QTimer.singleShot(0, self.clear)


class CodeCompleter(QCompleter):
    ConcatenationRole = Qt.ItemDataRole.UserRole + 1

    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.placeholderValues: dict[str, str] = {}
        self.createModel(data)

    def updateData(self, data):
        self.createModel(data)

    def splitPath(self, path):
        parts = path.split(' ')
        self.placeholderValues = {}
        if parts and parts[0] == "inject":
            for index, part in enumerate(parts[:-1]):
                if part == "--pid" and parts[index + 1]:
                    self.placeholderValues[PID_COMPLETION_PLACEHOLDER] = parts[index + 1]
                    parts[index + 1] = PID_COMPLETION_PLACEHOLDER
                    break
        if len(parts) >= 3 and parts[0] == "dotnetExec" and parts[1] == "load" and parts[2]:
            self.placeholderValues[DOTNET_LOAD_NAME_PLACEHOLDER] = parts[2]
            parts[2] = DOTNET_LOAD_NAME_PLACEHOLDER
        return parts

    def pathFromIndex(self, ix):
        value = ix.data(CodeCompleter.ConcatenationRole)
        for placeholder, replacement in self.placeholderValues.items():
            value = value.replace(placeholder, replacement)
        return value

    def createModel(self, data):
        def addItems(parent, elements, t=""):
            for text, children in elements:
                item = QStandardItem(text)
                data = t + " " + text if t else text
                item.setData(data, CodeCompleter.ConcatenationRole)
                parent.appendRow(item)
                if children:
                    addItems(item, children, data)
        model = QStandardItemModel(self)
        addItems(model, data)
        self.setModel(model)
