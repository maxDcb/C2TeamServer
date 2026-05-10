from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from C2Client.assistant_agent.tools.command_specs import command_arg_property_name, command_spec_to_tool_spec, load_command_tool_specs

from helpers import arg, command_spec

_PLACEHOLDER_RE = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::(?:raw|q|flag))?\??\}")


class StubGrpc:
    def __init__(self, commands):
        self.commands = commands
        self.queries = []

    def listCommands(self, query):
        self.queries.append(query)
        return iter(self.commands)


def test_command_specs_are_loaded_from_teamserver_list_commands():
    grpc = StubGrpc(
        [
            command_spec("whoami", "whoami"),
            command_spec("ls", "ls {path:q?}", [arg("path", arg_type="path")]),
        ]
    )

    specs = load_command_tool_specs(grpc)

    assert [spec.name for spec in specs] == ["ls", "whoami"]
    assert len(grpc.queries) == 1
    assert all(spec.command_template for spec in specs)


def test_command_spec_tool_schema_is_derived_from_template_and_args():
    spec = command_spec_to_tool_spec(
        command_spec(
            "assemblyExec",
            "assemblyExec [--mode {mode}] [--donut-exe {donut_exe:q}] [-- {arguments:raw}]",
            [
                arg("--mode", values=["thread", "process"]),
                arg("--donut-exe", arg_type="artifact", artifact=True),
                arg("source_path", arg_type="path", required=True),
                arg("arguments", variadic=True),
            ],
            examples=["assemblyExec --mode process --donut-exe Rubeus.exe -- triage"],
        )
    )

    assert spec.parameters["required"] == ["beacon_hash", "listener_hash"]
    assert spec.parameters["properties"]["mode"]["enum"] == ["thread", "process"]
    assert "donut_exe" in spec.parameters["properties"]
    assert "source_path" not in spec.parameters["properties"]
    assert "TeamServer" in spec.description or "Template:" in spec.description


def test_command_spec_rejects_missing_command_template():
    with pytest.raises(ValueError, match="command_template"):
        command_spec_to_tool_spec(command_spec("ls", ""))


def test_command_arg_property_names_are_stable_for_flags():
    assert command_arg_property_name(arg("--donut-exe")) == "donut_exe"
    assert command_arg_property_name(arg("-P")) == "P"
    assert command_arg_property_name(arg("remote_path")) == "remote_path"


def test_repository_command_specs_have_assistant_render_templates():
    repo_root = Path(__file__).resolve().parents[3]
    paths = sorted((repo_root / "core/modules").glob("*/*.json"))
    paths += sorted((repo_root / "core/modules/ModuleCmd/CommandSpecs/common").glob("*.json"))

    assert paths
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        template = str(payload.get("command_template", "")).strip()
        assert template, f"{path} is missing command_template"
        assert template.split()[0] == payload["name"], f"{path} template must start with the command name"

        arg_properties = {
            command_arg_property_name(SimpleNamespace(name=arg_payload.get("name", "")))
            for arg_payload in payload.get("args", [])
        }
        unknown = {
            match.group("name")
            for match in _PLACEHOLDER_RE.finditer(template)
            if match.group("name") not in arg_properties
        }
        assert not unknown, f"{path} has template placeholders without matching args: {sorted(unknown)}"

        placeholders = {match.group("name") for match in _PLACEHOLDER_RE.finditer(template)}
        omitted_required = {
            arg_payload.get("name", "")
            for arg_payload in payload.get("args", [])
            if arg_payload.get("required") and command_arg_property_name(SimpleNamespace(name=arg_payload.get("name", ""))) not in placeholders
        }
        assert omitted_required <= {"source_path"}, f"{path} omits required args from template: {sorted(omitted_required)}"
