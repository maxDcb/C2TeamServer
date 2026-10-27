from __future__ import annotations

import json
from types import SimpleNamespace

from C2Client.assistant_agent.tools.registry import build_c2_tool_registry
from C2Client.assistant_agent.tools.terminal_action_tools import C2HostArtifactTool, C2SocksControlTool
from C2Client.assistant_agent.tools.terminal_catalog_tools import C2ArtifactsTool, C2ListenersTool
from C2Client.grpcClient import TeamServerApi_pb2


class FakeTerminalGrpc:
    def __init__(self):
        self.commands = []
        self.response = SimpleNamespace(status=TeamServerApi_pb2.OK, result="https://c2.test/payload.exe")

    def executeTerminalCommand(self, request):
        self.commands.append(request.command)
        return self.response

    def listListeners(self):
        return [SimpleNamespace(
            listener_hash="listener-1", type="https", ip="127.0.0.1", port=443,
            domain="c2.test", state=1, session_count=2,
        )]

    def listArtifacts(self, query):
        assert query.name_contains == "beacon"
        return [SimpleNamespace(
            artifact_id="artifact-1", name="beacon.exe", display_name="Beacon",
            category="generated", platform="windows", arch="x64", size=123,
            description="Test artifact",
        )]


def test_terminal_capabilities_are_shared_with_conversation_registry():
    client = FakeTerminalGrpc()
    registry = build_c2_tool_registry(client)
    assert {"listC2Listeners", "listC2Artifacts", "hostArtifact", "socksControl"} <= set(registry.list_tool_names())
    listeners = C2ListenersTool(client).execute({}, None)
    assert listeners.ok
    assert json.loads(listeners.content)["listeners"][0]["listener_hash"] == "listener-1"
    artifacts = C2ArtifactsTool(client).execute({"name_contains": "beacon"}, None)
    assert artifacts.ok
    assert json.loads(artifacts.content)["artifacts"][0]["artifact_id"] == "artifact-1"


def test_host_artifact_builds_typed_command_and_checks_response():
    client = FakeTerminalGrpc()
    tool = C2HostArtifactTool(client)
    result = tool.execute({
        "artifact_reference": "artifact 1", "listener_hash": "listener-1",
        "hosted_filename": "payload.exe",
    }, None)
    assert result.ok
    assert client.commands == ["hostArtifact listener-1 'artifact 1' payload.exe"]
    assert not tool.execute({"artifact_reference": "bad'name", "listener_hash": "listener-1"}, None).ok
    assert len(client.commands) == 1
    client.response = SimpleNamespace(status=TeamServerApi_pb2.KO, message="Listener is stopped", result="")
    assert not tool.execute({"artifact_reference": "artifact-1", "listener_hash": "listener-1"}, None).ok


def test_socks_control_accepts_only_typed_actions():
    client = FakeTerminalGrpc()
    tool = C2SocksControlTool(client)
    assert tool.execute({"action": "bind", "beacon_hash": "beacon-1"}, None).ok
    assert client.commands == ["socks bind beacon-1"]
    assert not tool.execute({"action": "bind"}, None).ok
    assert not tool.execute({"action": "start", "beacon_hash": "beacon-1"}, None).ok
    assert not tool.execute({"action": "status"}, None).ok
    assert len(client.commands) == 1


def test_terminal_transport_error_has_uncertain_outcome():
    client = FakeTerminalGrpc()
    def disconnected(_request):
        raise ConnectionError("connection lost")
    client.executeTerminalCommand = disconnected
    artifact = C2HostArtifactTool(client).execute({
        "artifact_reference": "artifact-1", "listener_hash": "listener-1",
    }, None)
    socks = C2SocksControlTool(client).execute({"action": "start"}, None)
    assert not artifact.ok and artifact.metadata["outcome_unknown"]
    assert not socks.ok and socks.metadata["outcome_unknown"]
