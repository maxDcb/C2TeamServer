"""Typed access to the Terminal's installed local dropper generators."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agent_core import ExecutionContext
from agent_core.spi import LLMToolDefinition, ToolResult, build_tool_definition

from .validation import validate_tool_arguments


def _terminal():
    # TerminalPanel owns the local generator registry. Import only when needed:
    # loading its module configuration may import third-party generator packages.
    from ... import TerminalPanel
    return TerminalPanel


@dataclass(slots=True)
class C2LocalDroppersTool:
    grpc_client: Any

    name = "listLocalDroppers"
    description = "Find installed local dropper modules; optionally show one module's usage."

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "module": {"type": "string", "description": "Optional exact module name for usage help."},
            }, "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        try:
            terminal = _terminal()
            modules = []
            selected = arguments.get("module", "").casefold()
            for item in terminal.DropperModules:
                if selected and item.__name__.casefold() != selected:
                    continue
                try:
                    target_os = str(getattr(item, "getTargetOsExploration", lambda: "windows")()).lower()
                except Exception:
                    target_os = "unknown"
                record = {"name": item.__name__.lower(), "target_os": target_os}
                if selected:
                    help_function = getattr(item, terminal.DropperModuleGetHelpFunction, None)
                    if callable(help_function):
                        record["usage"] = str(help_function())
                modules.append(record)
            generators = [terminal.ShellcodeGeneratorDonut] + [item.__name__.lower()
                                                               for item in terminal.ShellCodeModules]
        except Exception as error:
            return ToolResult(ok=False, content=f"Could not load local generators: {error}")
        if selected and not modules:
            return ToolResult(ok=False, content="Dropper module is not installed.")
        return ToolResult(ok=True, content=json.dumps({"droppers": modules,
                                                       "shellcode_generators": generators}))


@dataclass(slots=True)
class C2GenerateDropperTool:
    grpc_client: Any

    name = "generateDropper"
    description = ("Generate a local dropper using an installed Terminal module, host its files "
                   "on a selected listener, and return the resulting execution command.")

    def schema(self) -> LLMToolDefinition:
        return build_tool_definition(name=self.name, description=self.description, parameters={
            "type": "object", "properties": {
                "module": {"type": "string"},
                "download_listener_hash": {"type": "string"},
                "beacon_listener_hash": {"type": "string"},
                "target_arch": {"type": "string", "enum": ["x64", "x86"]},
                "shellcode_generator": {"type": "string"},
                "additional_args": {"type": "array", "items": {"type": "string"}},
            }, "required": ["module", "download_listener_hash", "beacon_listener_hash"],
            "additionalProperties": False,
        })

    def execute(self, arguments: dict, context: ExecutionContext,
                *, operation_id: str | None = None) -> ToolResult:
        invalid = validate_tool_arguments(self.name, self.schema().parameters, arguments)
        if invalid is not None:
            return invalid
        try:
            terminal = _terminal()
            module_name = arguments["module"].lower()
            if module_name not in {item.__name__.lower() for item in terminal.DropperModules}:
                return ToolResult(ok=False, content="Dropper module is not installed; call listLocalDroppers.")
            generator = arguments.get("shellcode_generator", terminal.ShellcodeGeneratorDonut)
            if generator.lower() not in {terminal.ShellcodeGeneratorDonut.lower()} | {
                    item.__name__.lower() for item in terminal.ShellCodeModules}:
                return ToolResult(ok=False, content="Shellcode generator is not installed; call listLocalDroppers.")
            worker = terminal.DropperWorker(
                self.grpc_client, "generateDropper", module_name,
                arguments["download_listener_hash"], arguments["beacon_listener_hash"],
                arguments.get("additional_args", []), generator,
                arguments.get("target_arch", terminal.DefaultWindowsArch),
            )
            results: list[str] = []
            worker.finished.connect(lambda _command, result: results.append(result))
            worker.run()
            if not results:
                return ToolResult(ok=False, content="Dropper generation returned no result.")
            result = results[0]
            if not getattr(worker, "result_ok", not result.startswith("Error:")):
                return ToolResult(ok=False, content=result)
            return ToolResult(ok=True, content=json.dumps({
                "module": module_name, "download_listener_hash": arguments["download_listener_hash"],
                "beacon_listener_hash": arguments["beacon_listener_hash"],
                "execution_command": result,
            }, ensure_ascii=False))
        except Exception as error:
            return ToolResult(ok=False, content=f"Dropper generation failed: {error}")
