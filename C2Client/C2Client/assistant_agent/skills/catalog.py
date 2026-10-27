"""Versioned fixed plans and Agent Skills instructions."""

from dataclasses import dataclass
from pathlib import Path
import re

import yaml

from .tool_bundles import TOOL_BUNDLES, resolve_tool_bundles


@dataclass(frozen=True, slots=True)
class SkillStep:
    step_id: str
    command_name: str
    description: str


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    skill_id: str
    version: int
    title: str
    description: str
    steps: tuple[SkillStep, ...]
    supports_any_session: bool = False


@dataclass(frozen=True, slots=True)
class AgenticSkillDefinition:
    skill_id: str
    version: int
    title: str
    description: str
    instructions: str
    tool_bundles: tuple[str, ...]
    required_tools: tuple[str, ...]
    declared_tools: tuple[str, ...]
    max_tool_calls: int
    max_iterations: int
    supports_any_session: bool = False


def _string_tuple(value: object, field_name: str, path: Path, *, optional: bool = False) -> tuple[str, ...]:
    if optional and value is None:
        return ()
    if not isinstance(value, list) or (not optional and not value) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError(f"Invalid {field_name} in skill configuration: {path}")
    return tuple(value)


def load_agentic_skill(path: Path) -> AgenticSkillDefinition:
    """Read portable instructions and the C2-owned capability configuration."""
    source = path.read_text(encoding="utf-8")
    parts = source.split("---\n", 2)
    if len(parts) != 3 or parts[0] != "":
        raise ValueError(f"Invalid SKILL.md frontmatter: {path}")
    metadata = yaml.safe_load(parts[1])
    if not isinstance(metadata, dict):
        raise ValueError(f"Invalid SKILL.md metadata: {path}")
    name = metadata.get("name")
    description = metadata.get("description")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise ValueError(f"Invalid skill name: {path}")
    if name != path.parent.name or len(name) > 64:
        raise ValueError(f"Skill name must match its directory: {path}")
    if not isinstance(description, str) or not description.strip() or len(description) > 1024:
        raise ValueError(f"Invalid skill description: {path}")
    extension = metadata.get("metadata") or {}
    if not isinstance(extension, dict):
        raise ValueError(f"Invalid skill metadata extension: {path}")
    try:
        version = int(extension.get("version", 1))
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid skill version: {path}") from error
    instructions = parts[2].strip()
    config_path = path.parent / "skill.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError(f"Invalid skill configuration: {config_path}")
    bundles = _string_tuple(config.get("tool_bundles"), "tool_bundles", config_path)
    required = _string_tuple(config.get("required_tools"), "required_tools", config_path, optional=True)
    if type(config.get("max_tool_calls")) is not int or config["max_tool_calls"] < 1:
        raise ValueError(f"Invalid max_tool_calls in skill configuration: {config_path}")
    if type(config.get("max_iterations")) is not int or config["max_iterations"] < 1:
        raise ValueError(f"Invalid max_iterations in skill configuration: {config_path}")
    declared = {tool for bundle in TOOL_BUNDLES.values() for tool in bundle.tools}
    resolution = resolve_tool_bundles(bundles, registered_tools=declared, required_tools=required)
    if version < 1 or not instructions:
        raise ValueError(f"Incomplete skill definition: {path}")
    return AgenticSkillDefinition(
        skill_id=name, version=version, title=name.replace("-", " ").title(),
        description=description.strip(), instructions=instructions,
        tool_bundles=bundles, required_tools=required,
        declared_tools=resolution.allowed_tools,
        max_tool_calls=config["max_tool_calls"], max_iterations=config["max_iterations"],
    )


INVENTORY_LOCAL = SkillDefinition(
    skill_id="inventory_local",
    version=2,
    title="Local inventory",
    description="Collects identity and network configuration from one beacon session.",
    steps=(
        SkillStep("identity", "whoami", "Beacon identity and groups"),
        SkillStep("network", "ipConfig", "Network interfaces and addresses"),
    ),
)

IDENTIFY_USER = load_agentic_skill(
    Path(__file__).parent / "identify-user" / "SKILL.md",
)

SKILLS = {skill.skill_id: skill for skill in (INVENTORY_LOCAL, IDENTIFY_USER)}
