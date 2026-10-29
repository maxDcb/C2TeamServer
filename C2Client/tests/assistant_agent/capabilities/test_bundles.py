from __future__ import annotations

import json
from pathlib import Path

import pytest

from C2Client.assistant_agent.capabilities.bundles import TOOL_BUNDLES, resolve_tool_bundles


def test_bundle_resolution_preserves_order_and_deduplicates():
    resolution = resolve_tool_bundles(
        ("recon.identity", "recon.host", "recon.identity"),
        registered_tools=("whoami", "ipConfig", "listLiveSessions"),
        required_tools=("whoami",),
    )
    assert resolution.bundle_names == ("recon.identity", "recon.host")
    assert resolution.allowed_tools == ("whoami", "listLiveSessions", "ipConfig")
    assert "infoListener" in resolution.unavailable_tools


def test_bundle_resolution_rejects_unknown_and_missing_required_tools():
    with pytest.raises(ValueError, match="Unknown C2 tool bundle"):
        resolve_tool_bundles(("unknown",), registered_tools=("whoami",))
    with pytest.raises(ValueError, match="unavailable"):
        resolve_tool_bundles(
            ("recon.identity",), registered_tools=(), required_tools=("whoami",),
        )
    with pytest.raises(ValueError, match="outside"):
        resolve_tool_bundles(
            ("recon.identity",), registered_tools=("whoami",), required_tools=("socksControl",),
        )


def test_planned_terminal_capabilities_do_not_grant_unregistered_tools():
    resolution = resolve_tool_bundles(
        ("pivot", "payload_delivery"), registered_tools=("listener", "upload"),
    )
    assert resolution.allowed_tools == ("listener", "upload")
    assert {"socksControl", "hostArtifact", "generateDropper"} <= set(resolution.unavailable_tools)


def test_every_shipped_beacon_command_has_a_business_bundle():
    repository = Path(__file__).resolve().parents[4]
    command_names = {
        json.loads(path.read_text(encoding="utf-8"))["name"]
        for path in (repository / "core" / "modules").rglob("*.json")
    }
    bundled = {tool for bundle in TOOL_BUNDLES.values() for tool in bundle.tools}
    assert command_names <= bundled
