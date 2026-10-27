from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from C2Client.assistant_agent.capabilities.bundles import TOOL_BUNDLES, resolve_tool_bundles
from C2Client.assistant_agent.domain.service import C2AssistantAgent
from C2Client.assistant_agent.skills.service import C2SkillService, _stored_tool_arguments
from C2Client.assistant_agent.tools.registry import build_c2_tool_registry
from C2Client.assistant_agent.tools.server_artifact_tools import C2ArtifactDeleteTool, C2ArtifactDownloadTool, C2ArtifactPromoteTool
from C2Client.assistant_agent.tools.server_catalog_tools import C2CommandsTool, C2ArtifactsTool
from C2Client.assistant_agent.tools.local_generation_tool import C2GenerateDropperTool, C2LocalDroppersTool
from C2Client.assistant_agent.tools.server_credential_tools import (
    C2AddCredentialTool, C2CredentialTool, C2CredentialsTool, C2DeleteCredentialTool, C2UpdateCredentialTool,
)
from C2Client.assistant_agent.tools.server_lifecycle_tools import (
    C2AddListenerTool, C2SessionHistoryTool, C2StopListenerTool, C2StopSessionTool,
)
from C2Client.assistant_agent.tools.artifact_upload_tool import C2ArtifactUploadTool
from C2Client.grpcClient import TeamServerApi_pb2


UI_ACTION_TOOLS = {
    "teamserver.commands": {"listC2Commands", "getCommandHelp"},
    "teamserver.listeners": {"listC2Listeners", "infoListener", "addC2Listener", "stopC2Listener",
                             "getBeaconBinary", "uploadListenerFile"},
    "teamserver.sessions": {"listLiveSessions", "listC2SessionHistory", "stopC2Session", "listLoadedModules"},
    "teamserver.artifacts": {"listC2Artifacts", "uploadC2Artifact", "downloadC2Artifact",
                             "deleteC2Artifact", "promoteC2Artifact", "hostArtifact"},
    "teamserver.generation": {"listLocalDroppers", "generateDropper"},
    "teamserver.credentials": {"listC2Credentials", "getC2Credential", "addC2Credential",
                               "updateC2Credential", "deleteC2Credential"},
    "teamserver.tools": {"installTool", "installToolBundle", "reloadModules"},
    "teamserver.control": {"socksControl"},
}


class FakeGrpc:
    available_listener_types = ["http", "https", "tcp", "dns", "github"]

    def __init__(self):
        self.listeners_added = []
        self.listeners_stopped = []
        self.sessions_stopped = []
        self.artifacts_uploaded = []
        self.artifacts_deleted = []
        self.credentials_added = []
        self.credentials_updated = []
        self.credentials_deleted = []
        self.reveal_flags = []
        self.artifact = None
        self.command_queries = []
        self.artifact_queries = []
        self.summary = TeamServerApi_pb2.CredentialSummary(
            credential_id="cred-1", display_name="Example", type="password",
            username="alice", secret_fields=["password"],
        )

    def listCommands(self, query):
        self.command_queries.append(query)
        return [TeamServerApi_pb2.CommandSpec(name="ipConfig", kind="common", target="beacon",
                                               description="Network interfaces", command_template="ipConfig")]

    def getCommandHelp(self, _request):
        return TeamServerApi_pb2.CommandHelpResponse(status=TeamServerApi_pb2.OK, help="ipConfig help")

    def listModules(self, _request):
        return []

    def listListeners(self):
        return [TeamServerApi_pb2.Listener(listener_hash="listener-1", type="http", ip="127.0.0.1", port=8080)]

    def addListener(self, request):
        self.listeners_added.append(request)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK, listener_hash="listener-new")

    def stopListener(self, selector):
        self.listeners_stopped.append(selector)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK)

    def getListenerInfo(self, _selector):
        return SimpleNamespace(status=TeamServerApi_pb2.OK, type="http", address="127.0.0.1",
                               port="8080", download_uri="/files")

    def listSessions(self):
        return self.listSessionHistory()

    def listSessionHistory(self):
        return [TeamServerApi_pb2.Session(beacon_hash="beacon-1", listener_hash="listener-1",
                                         state=TeamServerApi_pb2.SESSION_STATE_RUNNING)]

    def stopSession(self, selector):
        self.sessions_stopped.append(selector)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK, message="queued")

    def listArtifacts(self, _query=None):
        self.artifact_queries.append(_query)
        return [self.artifact] if self.artifact is not None else []

    def uploadArtifact(self, name, data, platform="any", arch="any"):
        self.artifacts_uploaded.append((name, data, platform, arch))
        self.artifact = SimpleNamespace(
            artifact_id="artifact-1", name=name, category="upload", scope="operator",
            target="beacon", platform=platform, arch=arch, size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK)

    def downloadArtifact(self, artifact_id):
        return TeamServerApi_pb2.ArtifactContent(status=TeamServerApi_pb2.OK,
                                                 artifact_id=artifact_id, data=b"artifact bytes")

    def deleteArtifact(self, artifact_id):
        self.artifacts_deleted.append(artifact_id)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK)

    def listCredentials(self, _query=None):
        return [self.summary]

    def getCredential(self, credential_id, reveal_secret=False):
        self.reveal_flags.append((credential_id, reveal_secret))
        response = TeamServerApi_pb2.CredentialDetail(status=TeamServerApi_pb2.OK, summary=self.summary)
        if reveal_secret:
            response.secrets.add(name="password", value="sensitive")
        return response

    def addCredential(self, request):
        self.credentials_added.append(request)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK)

    def updateCredential(self, request):
        self.credentials_updated.append(request)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK)

    def deleteCredential(self, credential_id):
        self.credentials_deleted.append(credential_id)
        return TeamServerApi_pb2.OperationAck(status=TeamServerApi_pb2.OK)

    def getBeaconBinary(self, _request):
        return SimpleNamespace(status=TeamServerApi_pb2.OK, data=b"beacon")

    def hostArtifact(self, _request):
        return None

    def controlSocks(self, _request):
        return None

    def reloadModules(self, _request):
        return None

    def uploadListenerFile(self, _request):
        return None

    def installTool(self, _request):
        return None

    def installToolBundle(self, _request):
        return None


def test_every_ui_business_action_has_a_specific_bundle_and_registered_adapter(tmp_path: Path):
    registered = set(build_c2_tool_registry(FakeGrpc()).list_tool_names())
    skill_registered = {tool.name for tool in C2SkillService(FakeGrpc(), storage_dir=tmp_path)._catalog_tools()}
    for bundle_name, action_tools in UI_ACTION_TOOLS.items():
        assert action_tools <= set(TOOL_BUNDLES[bundle_name].tools)
        assert action_tools <= registered
        assert action_tools <= skill_registered
        resolution = resolve_tool_bundles((bundle_name,), registered_tools=registered,
                                          required_tools=action_tools)
        assert action_tools <= set(resolution.allowed_tools)


def test_conversation_grants_every_declared_bundle(tmp_path: Path):
    agent = C2AssistantAgent(FakeGrpc(), storage_dir=tmp_path)
    capabilities = agent.conversation_capabilities()
    assert set(capabilities) == set(TOOL_BUNDLES)
    for bundle_name, action_tools in UI_ACTION_TOOLS.items():
        assert action_tools <= set(capabilities[bundle_name])


def test_command_catalog_filter_is_shared_with_ui_operations():
    client = FakeGrpc()
    listed = C2CommandsTool(client).execute({"target": "beacon", "name_contains": "ip"}, None)
    assert listed.ok
    assert json.loads(listed.content)["commands"][0]["name"] == "ipConfig"
    assert client.command_queries[0].target == "beacon"
    assert client.command_queries[0].name_contains == "ip"
    assert not C2CommandsTool(client).execute({"target": "bad"}, None).ok


def test_artifact_inventory_filters_are_forwarded_to_catalog():
    client = FakeGrpc()
    result = C2ArtifactsTool(client).execute({"category": "download", "name_contains": "hosts",
                                              "platform": "linux"}, None)
    assert result.ok
    query = client.artifact_queries[-1]
    assert (query.category, query.name_contains, query.platform) == ("download", "hosts", "linux")


def test_listener_and_session_mutations_use_typed_requests():
    client = FakeGrpc()
    created = C2AddListenerTool(client).execute({"type": "https", "ip": "127.0.0.1", "port": 8443}, None)
    assert created.ok
    assert json.loads(created.content)["listener_hash"] == "listener-new"
    assert (client.listeners_added[0].type, client.listeners_added[0].port) == ("https", 8443)
    assert not C2AddListenerTool(client).execute({"type": "https", "ip": "127.0.0.1"}, None).ok
    assert len(client.listeners_added) == 1
    assert C2StopListenerTool(client).execute({"listener_hash": "listener-1"}, None).ok
    assert client.listeners_stopped[0].listener_hash == "listener-1"
    assert C2StopSessionTool(client).execute({"beacon_hash": "beacon-1", "listener_hash": "listener-1"}, None).ok
    assert client.sessions_stopped[0].beacon_hash == "beacon-1"
    history = C2SessionHistoryTool(client).execute({}, None)
    assert json.loads(history.content)["sessions"][0]["beacon_hash"] == "beacon-1"


def test_missing_mutation_ack_is_unknown_and_skill_snapshot_redacts_secrets():
    client = FakeGrpc()
    client.stopListener = lambda _selector: None
    result = C2StopListenerTool(client).execute({"listener_hash": "listener-1"}, None)
    assert not result.ok and result.metadata["outcome_unknown"]
    arguments = {"credential_id": "cred-1", "secrets": [{"name": "password", "value": "sensitive"}]}
    stored = _stored_tool_arguments("updateC2Credential", arguments)
    assert stored["secrets"][0]["value"] == "[redacted]"
    assert arguments["secrets"][0]["value"] == "sensitive"


def test_artifact_upload_download_and_delete_cover_the_ui_operations(tmp_path: Path):
    client = FakeGrpc()
    source = tmp_path / "payload.bin"
    source.write_bytes(b"payload")
    uploaded = C2ArtifactUploadTool(client).execute({
        "source_file": str(source), "platform": "linux", "arch": "x64",
    }, None)
    assert uploaded.ok
    assert client.artifacts_uploaded == [("payload.bin", b"payload", "linux", "x64")]
    target = tmp_path / "received.bin"
    download = C2ArtifactDownloadTool(client)
    saved = download.execute({"artifact_id": "artifact-1", "destination_path": str(target)}, None)
    assert saved.ok and target.read_bytes() == b"artifact bytes"
    assert not download.execute({"artifact_id": "artifact-1", "destination_path": str(target)}, None).ok
    assert C2ArtifactDeleteTool(client).execute({"artifact_id": "artifact-1"}, None).ok
    assert client.artifacts_deleted == ["artifact-1"]


def test_downloaded_artifact_can_be_promoted_to_verified_beacon_upload():
    client = FakeGrpc()
    promoted = C2ArtifactPromoteTool(client).execute({
        "artifact_id": "download-1", "name": "hosts", "platform": "linux", "arch": "x64",
    }, None)
    assert promoted.ok
    payload = json.loads(promoted.content)
    assert payload["source_artifact_id"] == "download-1"
    assert payload["artifact_id"] == "artifact-1"
    assert client.artifacts_uploaded == [("hosts", b"artifact bytes", "linux", "x64")]


def test_local_generation_uses_terminal_generator_registry(monkeypatch):
    class Signal:
        def __init__(self):
            self.callback = None

        def connect(self, callback):
            self.callback = callback

    class Worker:
        def __init__(self, _client, _command, module, download, beacon, args, generator, arch):
            self.values = (module, download, beacon, args, generator, arch)
            self.finished = Signal()

        def run(self):
            self.finished.callback("generateDropper", "run generated payload")

    fake = SimpleNamespace(DropperModules=[SimpleNamespace(__name__="Demo")],
                           ShellCodeModules=[], ShellcodeGeneratorDonut="donut",
                           DefaultWindowsArch="x64", DropperWorker=Worker)
    monkeypatch.setattr("C2Client.assistant_agent.tools.local_generation_tool._terminal", lambda: fake)
    client = FakeGrpc()
    listed = C2LocalDroppersTool(client).execute({}, None)
    assert json.loads(listed.content)["droppers"][0]["name"] == "demo"
    result = C2GenerateDropperTool(client).execute({
        "module": "demo", "download_listener_hash": "l1", "beacon_listener_hash": "l2",
        "additional_args": ["--example"],
    }, None)
    assert result.ok and json.loads(result.content)["execution_command"] == "run generated payload"


def test_credential_crud_and_explicit_reveal():
    client = FakeGrpc()
    listed = C2CredentialsTool(client).execute({}, None)
    assert "sensitive" not in listed.content
    assert C2CredentialTool(client).execute({"credential_id": "cred-1"}, None).ok
    assert "sensitive" not in C2CredentialTool(client).execute({"credential_id": "cred-1"}, None).content
    revealed = C2CredentialTool(client).execute({"credential_id": "cred-1", "reveal_secret": True}, None)
    assert "sensitive" in revealed.content
    created = C2AddCredentialTool(client).execute({
        "display_name": "Example", "type": "password", "username": "alice",
        "secrets": [{"name": "password", "value": "sensitive"}],
    }, None)
    assert created.ok and "sensitive" not in created.content
    assert client.credentials_added[0].secrets[0].value == "sensitive"
    updated = C2UpdateCredentialTool(client).execute({
        "credential_id": "cred-1", "description": "new", "username": "",
    }, None)
    assert updated.ok
    assert set(client.credentials_updated[0].update_fields) == {"description", "username"}
    assert C2DeleteCredentialTool(client).execute({"credential_id": "cred-1"}, None).ok
    assert client.credentials_deleted == ["cred-1"]
