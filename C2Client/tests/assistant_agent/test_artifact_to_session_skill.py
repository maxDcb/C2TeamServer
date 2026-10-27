from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from agent_core.llm.base import LLMCompletionResult, LLMToolCall

from C2Client.assistant_agent.skills.catalog import SKILLS
from C2Client.assistant_agent.skills.service import C2SkillService, _artifact_transfer_input
from C2Client.assistant_agent.tools.artifact_upload_tool import C2ArtifactUploadTool
from C2Client.grpcClient import TeamServerApi_pb2


class TransferGrpc:
    def __init__(self):
        self.uploads = []
        self.artifact = None
        self.jobs = {}
        self.submissions = []

    def listSessions(self):
        return [SimpleNamespace(
            beacon_hash="beacon-1", listener_hash="listener-1",
            os="linux", arch="x64", killed=False,
        )]

    def listCommands(self, query):
        return [TeamServerApi_pb2.CommandSpec(
            name="upload", kind="module",
            command_template="upload {upload_artifact:q} {remote_path:q}",
            platforms=["linux", "windows"], archs=["any"],
        )]

    def listModules(self, selector):
        return [SimpleNamespace(name="upload", state="loaded")]

    def uploadArtifact(self, name, data, platform="any", arch="any"):
        self.uploads.append((name, data, platform, arch))
        self.artifact = SimpleNamespace(
            artifact_id="artifact-verified", name=name, category="upload",
            scope="operator", target="beacon", size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="stored")

    def listArtifacts(self, query):
        if self.artifact is None or query.name_contains not in self.artifact.name:
            return []
        return [self.artifact]

    def submitJob(self, job_id, operation, payload):
        assert operation == "session_command"
        self.submissions.append((job_id, json.loads(payload)["command"]))
        return self.jobs.setdefault(job_id, SimpleNamespace(
            job_id=job_id, state="queued", output_inline=b"", output_size=0,
            error_code="", error_message="",
        ))

    def getJobExecution(self, job_id):
        return self.jobs[job_id]

    def complete(self, job_id):
        self.jobs[job_id] = SimpleNamespace(
            job_id=job_id, state="succeeded", output_inline=b"Success.", output_size=8,
            error_code="", error_message="",
        )


class TransferProvider:
    def __init__(self):
        self.calls = 0
        self.service = None

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.calls <= 2:
            name = "uploadC2Artifact" if self.calls == 1 else "upload"
            assert name in [tool.name for tool in kwargs["tools"]]
            if name == "upload":
                schema = next(tool for tool in kwargs["tools"] if tool.name == "upload")
                assert "remote_path" not in str(schema)
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id=f"transfer-{self.calls}", name=name, arguments_json="{}")])
        run = self.service.list_runs()[0]
        upload_observation = run["terminal_observations"][0]["observation_id"]
        job_id = run["steps"][-1]["job_id"]
        return LLMCompletionResult(content=json.dumps({
            "summary": "File transferred to the selected session.",
            "observations": [
                {"source_id": upload_observation, "finding": "The artifact was stored."},
                {"source_id": job_id, "finding": "The beacon reported transfer success."},
            ], "limitations": [],
        }))


def test_artifact_to_session_uploads_once_then_waits_for_beacon_after_restart(tmp_path):
    source = tmp_path / "local sample.txt"
    source.write_bytes(b"local transfer payload")
    client = TransferGrpc()
    provider = TransferProvider()
    storage = tmp_path / "skills"
    service = C2SkillService(client, storage_dir=storage, provider=provider)
    provider.service = service
    context = f'transfert "{source}" sur /tmp de la session'

    run = service.start("artifact-to-session", "beacon-1", "listener-1", context)
    assert run["status"] == "running"
    assert run["report"] is None
    assert len(client.uploads) == 1
    assert client.uploads[0][1:] == (b"local transfer payload", "any", "any")
    assert run["artifact_transfer"]["artifact_id"] == "artifact-verified"
    assert [command for _, command in client.submissions] == [
        "upload artifact-verified '/tmp/local sample.txt'",
    ]
    assert run["terminal_observations"][0]["state"] == "succeeded"
    assert run["steps"][-1]["state"] == "waiting_for_job"
    upload_tool = next(tool for tool in service._catalog_tools(run["artifact_transfer"])
                       if tool.name == "uploadC2Artifact")
    repeat = service.dispatch_catalog_tool(run["run_id"], upload_tool, {}, None)
    assert not repeat.ok
    assert len(client.uploads) == 1

    service = C2SkillService(client, storage_dir=storage, provider=provider)
    provider.service = service
    assert service.reconcile(run["run_id"])["status"] == "running"
    client.complete(client.submissions[0][0])
    finished = service.reconcile(run["run_id"])
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "complete", finished["report"]
    assert len(client.uploads) == 1
    assert len(client.submissions) == 1
    assert {item["source_id"] for item in finished["report"]["observations"]} == {
        finished["terminal_observations"][0]["observation_id"], client.submissions[0][0],
    }


def test_transfer_requires_explicit_existing_local_file_and_remote_path(tmp_path):
    client = TransferGrpc()
    service = C2SkillService(client, storage_dir=tmp_path / "skills")
    assert SKILLS["artifact-to-session"].required_tools == ("uploadC2Artifact", "upload")
    for context in ("", "{}", "transfert /tmp/file sur dossier de la session",
                    json.dumps({"source_file": "relative.txt", "remote_path": "/tmp/a"}),
                    json.dumps({"source_file": str(tmp_path / "missing"), "remote_path": "/tmp/a"})):
        with pytest.raises(ValueError):
            service.start("artifact-to-session", "beacon-1", "listener-1", context)
    assert not client.uploads and not client.submissions


def test_natural_context_treats_destination_as_session_directory(tmp_path):
    source = tmp_path / "hosts"
    source.write_bytes(b"127.0.0.1 localhost\n")
    transfer = _artifact_transfer_input(f"ok transfert {source} sur /tmp de la session", "run-1", "linux")
    assert transfer["remote_path"] == "/tmp/hosts"
    assert transfer["source_file"] == str(source)
    windows = _artifact_transfer_input(f"transfert {source} sur C:\\Temp de la session", "run-2", "windows")
    assert windows["remote_path"] == "C:\\Temp\\hosts"


def test_natural_context_uses_explicit_received_filename(tmp_path):
    source = tmp_path / "hosts"
    source.write_bytes(b"127.0.0.1 localhost\n")
    for context in (
        f"transfert {source} sur /tmp de la session sous le nom hosts-copie",
        f"transfert {source} sur /tmp sous le nom hosts-copie de la session",
        f"transfert {source} sur /tmp nom du fichier de réception hosts-copie",
    ):
        transfer = _artifact_transfer_input(context, "run-1", "linux")
        assert transfer["remote_path"] == "/tmp/hosts-copie"
    quoted = _artifact_transfer_input(
        f'transfert {source} sur /tmp de la session sous le nom "hosts copie"', "run-2", "linux")
    assert quoted["remote_path"] == "/tmp/hosts copie"
    for unsafe in ('"../other"', '"sub/file"', '""', '".."'):
        with pytest.raises(ValueError):
            _artifact_transfer_input(
                f"transfert {source} sur /tmp sous le nom {unsafe}", "run-3", "linux")


def test_received_filename_reaches_the_beacon_command(tmp_path):
    source = tmp_path / "hosts"
    source.write_bytes(b"127.0.0.1 localhost\n")
    client = TransferGrpc()
    provider = TransferProvider()
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    run = service.start("artifact-to-session", "beacon-1", "listener-1",
                        f"transfert {source} sur /tmp de la session sous le nom hosts-copie")
    assert run["artifact_transfer"]["remote_path"] == "/tmp/hosts-copie"
    assert [command for _, command in client.submissions] == ["upload artifact-verified /tmp/hosts-copie"]


def test_upload_tool_rejects_changed_source_before_rpc(tmp_path):
    source = tmp_path / "selected.bin"
    source.write_bytes(b"original")
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    source.write_bytes(b"changed")
    client = TransferGrpc()
    result = C2ArtifactUploadTool(client, str(source), expected, "skill-test.bin").execute({}, None)
    assert not result.ok
    assert "changed" in result.content
    assert not client.uploads


def test_unanswered_beacon_transfer_preserves_artifact_evidence_and_is_partial(tmp_path):
    source = tmp_path / "local.bin"
    source.write_bytes(b"local transfer payload")
    client = TransferGrpc()
    provider = TransferProvider()
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    context = json.dumps({"source_file": str(source), "remote_path": "/tmp/local.bin"})
    run = service.start("artifact-to-session", "beacon-1", "listener-1", context)
    finished = service.confirm_no_result(run["run_id"], "Beacon did not return a result.")
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "partial"
    assert finished["terminal_observations"][0]["state"] == "succeeded"
    assert finished["steps"][-1]["state"] == "no_result_confirmed"
    assert len(client.uploads) == len(client.submissions) == 1
