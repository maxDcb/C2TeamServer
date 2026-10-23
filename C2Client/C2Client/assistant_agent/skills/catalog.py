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
    version=1,
    title="Inventaire local",
    description="Collecte l'identité et la configuration réseau d'une session.",
    steps=(
        SkillStep("identity", "whoami", "Identité et groupes du beacon"),
        SkillStep("network", "ipConfig", "Interfaces et adresses réseau"),
    ),
)

SKILLS = {INVENTORY_LOCAL.skill_id: INVENTORY_LOCAL}
