from __future__ import annotations

import json
from types import SimpleNamespace

import grpc

from C2Client.assistant_agent.tools.registry import build_c2_tool_registry
from C2Client.assistant_agent.tools.server_action_tools import C2HostArtifactTool, C2SocksControlTool, C2ReloadModulesTool
from C2Client.assistant_agent.tools.server_catalog_tools import C2ArtifactsTool, C2ListenersTool
from C2Client.grpcClient import TeamServerApi_pb2


class FakeTerminalGrpc:
    def __init__(self):
        self.host_requests = []
        self.socks_requests = []
        self.reload_requests = []
        self.response = SimpleNamespace(job_id="job-1", state="succeeded",
                                        output_inline=b"https://c2.test/payload.exe", error_message="")

    def hostArtifact(self, request):
        self.host_requests.append(request)
        return SimpleNamespace(job_id=request.job_id, state=self.response.state,
                               output_inline=self.response.output_inline,
                               error_message=self.response.error_message)

    def controlSocks(self, request):
        self.socks_requests.append(request)
        return SimpleNamespace(job_id=request.job_id, state=self.response.state,
                               output_inline=self.response.output_inline,
                               error_message=self.response.error_message)

    def reloadModules(self, request):
        self.reload_requests.append(request)
        return SimpleNamespace(job_id=request.job_id, state=self.response.state,
                               output_inline=self.response.output_inline,
                               error_message=self.response.error_message)

    def getJobExecution(self, job_id):
        return SimpleNamespace(job_id=job_id, state=self.response.state,
                               output_inline=self.response.output_inline,
                               error_message=self.response.error_message)

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
    assert {"listC2Listeners", "listC2Artifacts", "hostArtifact", "socksControl", "reloadModules"} <= set(registry.list_tool_names())
    listeners = C2ListenersTool(client).execute({}, None)
    assert listeners.ok
    assert json.loads(listeners.content)["listeners"][0]["listener_hash"] == "listener-1"
    artifacts = C2ArtifactsTool(client).execute({"name_contains": "beacon"}, None)
    assert artifacts.ok
    assert json.loads(artifacts.content)["artifacts"][0]["artifact_id"] == "artifact-1"


def test_host_artifact_uses_typed_operation_and_checks_response():
    client = FakeTerminalGrpc()
    tool = C2HostArtifactTool(client)
    result = tool.execute({
        "artifact_reference": "artifact 1", "listener_hash": "listener-1",
        "hosted_filename": "payload.exe",
    }, None)
    assert result.ok
    assert [(request.listener_hash, request.artifact_reference, request.hosted_filename)
            for request in client.host_requests] == [("listener-1", "artifact 1", "payload.exe")]
    assert tool.execute({"artifact_reference": "bad'name", "listener_hash": "listener-1"}, None).ok
    assert len(client.host_requests) == 2
    client.response = SimpleNamespace(job_id="job-2", state="failed", error_message="Listener is stopped", output_inline=b"")
    assert not tool.execute({"artifact_reference": "artifact-1", "listener_hash": "listener-1"}, None).ok


def test_socks_control_accepts_only_typed_actions():
    client = FakeTerminalGrpc()
    tool = C2SocksControlTool(client)
    assert tool.execute({"action": "bind", "beacon_hash": "beacon-1"}, None).ok
    assert [(request.action, request.beacon_hash) for request in client.socks_requests] == [("bind", "beacon-1")]
    assert not tool.execute({"action": "bind"}, None).ok
    assert not tool.execute({"action": "start", "beacon_hash": "beacon-1"}, None).ok
    assert not tool.execute({"action": "status"}, None).ok
    assert len(client.socks_requests) == 1


def test_reload_modules_uses_typed_operation():
    client = FakeTerminalGrpc()
    result = C2ReloadModulesTool(client).execute({}, None, operation_id="reload-1")
    assert result.ok
    assert client.reload_requests[0].job_id == "reload-1"
    assert not C2ReloadModulesTool(client).execute({"unexpected": True}, None).ok


def test_terminal_transport_error_has_uncertain_outcome():
    client = FakeTerminalGrpc()
    def disconnected(_request):
        raise ConnectionError("connection lost")
    client.hostArtifact = disconnected
    client.controlSocks = disconnected
    client.getJobExecution = lambda _job_id: (_ for _ in ()).throw(ConnectionError("lookup lost"))
    artifact = C2HostArtifactTool(client).execute({
        "artifact_reference": "artifact-1", "listener_hash": "listener-1",
    }, None)
    socks = C2SocksControlTool(client).execute({"action": "start"}, None)
    assert not artifact.ok and artifact.metadata["outcome_unknown"]
    assert not socks.ok and socks.metadata["outcome_unknown"]


def test_lost_response_is_recovered_from_persisted_job():
    client = FakeTerminalGrpc()
    client.hostArtifact = lambda _request: (_ for _ in ()).throw(ConnectionError("response lost"))
    result = C2HostArtifactTool(client).execute({
        "artifact_reference": "artifact-1", "listener_hash": "listener-1",
    }, None, operation_id="known-job")
    assert result.ok
    assert result.metadata["job_id"] == "known-job"


def test_old_server_reports_unsupported_typed_operation_as_failure():
    class Unimplemented(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.UNIMPLEMENTED

        def details(self):
            return "HostArtifact is unavailable"

    client = FakeTerminalGrpc()
    client.hostArtifact = lambda _request: (_ for _ in ()).throw(Unimplemented())
    result = C2HostArtifactTool(client).execute({
        "artifact_reference": "artifact-1", "listener_hash": "listener-1",
    }, None)
    assert not result.ok
    assert not result.metadata["outcome_unknown"]
    assert "unavailable" in result.content
