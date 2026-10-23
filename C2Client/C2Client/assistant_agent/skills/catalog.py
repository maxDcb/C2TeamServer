"""Versioned fixed plans and Agent Skills instructions."""

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


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
    allowed_tools: tuple[str, ...]
    supports_any_session: bool = False


def load_agentic_skill(path: Path, *, allowed_tools: tuple[str, ...]) -> AgenticSkillDefinition:
    """Read standard SKILL.md instructions; tool permissions remain application-owned."""
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
    if version < 1 or not instructions or not allowed_tools:
        raise ValueError(f"Incomplete skill definition: {path}")
    return AgenticSkillDefinition(
        skill_id=name, version=version, title=name.replace("-", " ").title(),
        description=description.strip(), instructions=instructions,
        allowed_tools=allowed_tools,
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
    Path(__file__).parent / "identify-user" / "SKILL.md", allowed_tools=("whoami",),
)

SKILLS = {skill.skill_id: skill for skill in (INVENTORY_LOCAL, IDENTIFY_USER)}
