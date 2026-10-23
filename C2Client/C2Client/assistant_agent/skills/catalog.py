"""Versioned plans. The model never adds commands to these plans."""

from dataclasses import dataclass


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

SKILLS = {INVENTORY_LOCAL.skill_id: INVENTORY_LOCAL}
