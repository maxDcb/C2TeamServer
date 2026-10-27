from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from agent_core.llm.base import LLMCompletionResult, LLMToolCall

from C2Client.assistant_agent.capabilities.bundles import resolve_tool_bundles
from C2Client.assistant_agent.skills.catalog import SKILLS, load_agentic_skill
from C2Client.assistant_agent.skills.service import C2SkillService
from C2Client.assistant_agent.tools.registry import build_c2_tool_registry
from C2Client.assistant_agent.tools.server_catalog_tools import C2BeaconBinaryInfoTool
from C2Client.assistant_agent.tools.server_file_tools import (
    C2InstallToolBundleTool, C2InstallToolTool, C2UploadListenerFileTool,
)
from C2Client.grpcClient import TeamServerApi_pb2


class TeamServerGrpc:
    def __init__(self):
        self.downloaded = []
        self.uploads = []
        self.installs = []
        self.bundles = []
        self.hosts = []
        self.sessions_called = False
        self.commands_called = False

    def listSessions(self):
        self.sessions_called = True
        raise AssertionError("Server-only skills must not look up a beacon session")

    def listCommands(self, query):
        self.commands_called = True
        raise AssertionError("Server-only skills must not load beacon commands")

    def listListeners(self):
        return [SimpleNamespace(listener_hash="listener-1", type="https", ip="127.0.0.1",
                                port=443, domain="localhost", state=1, session_count=0)]

    def listArtifacts(self, query):
        return [SimpleNamespace(artifact_id="artifact-1", name="sample.bin",
                                display_name="Sample", category="test", platform="any",
                                arch="any", size=6, description="Local test artifact")]

    def getListenerInfo(self, request):
        assert request.listener_hash == "listener-1"
        return SimpleNamespace(status=TeamServerApi_pb2.OK, type="https",
                               address="127.0.0.1", port="443", download_uri="/files")

    def getBeaconBinary(self, request):
        assert request.listener_hash == "listener-1"
        return SimpleNamespace(status=TeamServerApi_pb2.OK, data=b"binary")

    def downloadArtifact(self, artifact_id):
        self.downloaded.append(artifact_id)
        if artifact_id == "missing":
            return SimpleNamespace(status=TeamServerApi_pb2.KO, message="No such artifact", data=b"")
        return SimpleNamespace(status=TeamServerApi_pb2.OK, data=b"sample")

    def uploadListenerFile(self, request):
        self.uploads.append(request)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="ok")

    def installTool(self, request):
        self.installs.append(request)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="ok")

    def installToolBundle(self, request):
        self.bundles.append(request)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="ok")

    def hostArtifact(self, request):
        self.hosts.append(request)
        return SimpleNamespace(job_id=request.job_id, state="succeeded",
                               output_inline=b"https://localhost/files/sample.bin", error_message="")


def test_new_bundles_expose_only_registered_adapters():
    names = set(build_c2_tool_registry(TeamServerGrpc()).list_tool_names())
    inspect = resolve_tool_bundles(("teamserver.inspect",), registered_tools=names)
    publish = resolve_tool_bundles(("teamserver.publish",), registered_tools=names)
    assert set(inspect.allowed_tools) == {
        "listC2Listeners", "infoListener", "listC2Artifacts", "getBeaconBinary"}
    assert {"hostArtifact", "uploadListenerFile", "installTool", "installToolBundle"} <= set(publish.allowed_tools)
    assert "hostArtifact" not in inspect.allowed_tools
    assert SKILLS["teamserver-inspect"].target_scope == "teamserver"
    assert SKILLS["teamserver-publish-test"].supports_any_session


def test_server_only_skill_rejects_beacon_bundle(tmp_path):
    directory = tmp_path / "server-test"
    directory.mkdir()
    skill_file = directory / "SKILL.md"
    skill_file.write_text("---\nname: server-test\ndescription: Test scope.\n---\nTest.\n")
    (directory / "skill.yaml").write_text(
        "target: teamserver\ntool_bundles: [recon.host]\nmax_tool_calls: 2\nmax_iterations: 3\n")
    with pytest.raises(ValueError, match="contain beacon commands"):
        load_agentic_skill(skill_file)


def test_file_adapters_use_existing_artifact_bytes_and_validate_destinations():
    client = TeamServerGrpc()
    upload = C2UploadListenerFileTool(client)
    install = C2InstallToolTool(client)
    bundle = C2InstallToolBundleTool(client)
    assert upload.execute({"listener_hash": "listener-1", "artifact_id": "artifact-1",
                           "filename": "sample.bin"}, None).ok
    assert (client.uploads[0].listener_hash, client.uploads[0].filename,
            client.uploads[0].data) == ("listener-1", "sample.bin", b"sample")
    assert install.execute({"artifact_id": "artifact-1", "filename": "tool.bin"}, None).ok
    assert (client.installs[0].filename, client.installs[0].data) == ("tool.bin", b"sample")
    assert bundle.execute({"files": [{"artifact_id": "artifact-1", "filename": "one.bin"},
                                     {"artifact_id": "artifact-2", "filename": "two.bin"}]}, None).ok
    assert [(item.filename, item.data) for item in client.bundles[0].files] == [
        ("one.bin", b"sample"), ("two.bin", b"sample")]
    before = len(client.downloaded)
    assert not upload.execute({"listener_hash": "listener-1", "artifact_id": "artifact-1",
                               "filename": "../escape"}, None).ok
    assert not bundle.execute({"files": [{"artifact_id": "artifact-1", "filename": "same"},
                                         {"artifact_id": "artifact-2", "filename": "same"}]}, None).ok
    assert len(client.downloaded) == before
    assert not install.execute({"artifact_id": "missing", "filename": "safe.bin"}, None).ok
    assert len(client.installs) == 1


def test_file_write_transport_loss_is_uncertain_and_binary_stays_out_of_tool_output():
    client = TeamServerGrpc()
    binary = C2BeaconBinaryInfoTool(client).execute({
        "listener_hash": "listener-1", "target_os": "linux"}, None)
    assert binary.ok
    assert json.loads(binary.content)["sha256"] == hashlib.sha256(b"binary").hexdigest()
    assert "binary" not in binary.content
    client.installTool = lambda request: (_ for _ in ()).throw(ConnectionError("response lost"))
    outcome = C2InstallToolTool(client).execute({"artifact_id": "artifact-1", "filename": "tool.bin"}, None)
    assert not outcome.ok and outcome.metadata["outcome_unknown"]


class ScriptedProvider:
    def __init__(self, calls):
        self.calls = calls
        self.index = 0
        self.service = None

    def complete_with_tools(self, **kwargs):
        call = self.calls[min(self.index, len(self.calls) - 1)]
        self.index += 1
        if isinstance(call, tuple):
            name, arguments = call
            assert name in [tool.name for tool in kwargs["tools"]]
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id=f"call-{self.index}", name=name, arguments_json=json.dumps(arguments))])
        run = self.service.list_runs()[0]
        ids = [item["observation_id"] for item in run["terminal_observations"] if item["ok"]]
        return LLMCompletionResult(content=json.dumps({
            "summary": call, "observations": [
                {"source_id": source_id, "finding": f"Observed result {index}"}
                for index, source_id in enumerate(ids)], "limitations": [],
        }))


def test_inspect_skill_runs_without_beacon_and_reports_sources(tmp_path):
    client = TeamServerGrpc()
    provider = ScriptedProvider([
        ("listC2Listeners", {}), ("listC2Artifacts", {}),
        ("infoListener", {"listener_hash": "listener-1"}), "Local inventory inspected.",
    ])
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    run = service.start("teamserver-inspect", "*", "*")
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete", run["report"]
    assert run["server_only"]
    assert not client.sessions_called and not client.commands_called
    assert len(run["terminal_observations"]) == 3


def test_publish_skill_runs_typed_write_once_and_reconciles(tmp_path):
    client = TeamServerGrpc()
    provider = ScriptedProvider([
        ("listC2Artifacts", {}),
        ("installTool", {"artifact_id": "artifact-1", "filename": "sample.bin"}),
        "Local publication tested.",
    ])
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    run = service.start("teamserver-publish-test", "*", "*",
                        "Install artifact-1 as sample.bin for this local test.")
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete", run["report"]
    assert run["terminal_observations"][1]["state"] == "succeeded"
    assert "job_id" not in run["terminal_observations"][1]
    assert len(client.installs) == 1
    service.reconcile(run["run_id"])
    assert len(client.installs) == 1


def test_interrupted_file_action_has_no_fake_job_receipt_or_replay(tmp_path):
    client = TeamServerGrpc()
    client.getJobExecution = lambda job_id: (_ for _ in ()).throw(
        AssertionError("File actions have no job receipt"))
    service = C2SkillService(client, storage_dir=tmp_path / "skills")
    observation_id = "terminal-run-1"
    run = {"run_id": "run", "terminal_observations": [{
        "observation_id": observation_id, "tool": "installTool", "state": "dispatching",
    }], "active_terminal_call": observation_id, "manual_uncertainty": False}
    result = service._uncertain_terminal_action(run, "installTool", {
        "artifact_id": "artifact-1", "filename": "sample.bin"}, "call-1")
    assert not result.ok
    assert run["terminal_observations"][0]["state"] == "outcome_unknown"
    assert "job_id" not in run["terminal_observations"][0]
    assert not client.installs
