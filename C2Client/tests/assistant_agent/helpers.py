from __future__ import annotations

from types import SimpleNamespace


def arg(
    name: str,
    *,
    arg_type: str = "text",
    required: bool = False,
    description: str = "",
    values: list[str] | None = None,
    variadic: bool = False,
    artifact: bool = False,
):
    return SimpleNamespace(
        name=name,
        type=arg_type,
        required=required,
        description=description or name,
        values=values or [],
        variadic=variadic,
        artifact_filters=[SimpleNamespace(category="tool")] if artifact else [],
    )


def command_spec(
    name: str,
    command_template: str,
    args: list | None = None,
    *,
    description: str | None = None,
    examples: list[str] | None = None,
):
    return SimpleNamespace(
        name=name,
        display_name=name,
        kind="module",
        description=description or f"{name} command",
        target="beacon",
        requires_session=True,
        platforms=["windows", "linux"],
        archs=["any"],
        args=args or [],
        examples=examples or [],
        source="test",
        command_template=command_template,
    )
