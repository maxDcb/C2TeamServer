from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from agent_core.llm.base import LLMCompletionResult, LLMToolCall

from C2Client.assistant_agent.skills.catalog import SKILLS
from C2Client.assistant_agent.skills.panel import format_run_details
from C2Client.assistant_agent.skills.service import C2SkillService
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
    def __init__(self, source_file: str | None, remote_paths: list[str]):
        self.source_file = source_file
        self.remote_paths = remote_paths
        self.calls = 0
        self.service = None

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.source_file is not None and self.calls == 1:
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id="upload-artifact", name="uploadC2Artifact",
                arguments_json=json.dumps({"source_file": self.source_file}))])
        upload_index = self.calls - 2
        if self.source_file is not None and 0 <= upload_index < len(self.remote_paths):
            tool = next(item for item in kwargs["tools"] if item.name == "upload")
            assert "remote_path" in str(tool)
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id=f"upload-beacon-{upload_index}", name="upload",
                arguments_json=json.dumps({"remote_path": self.remote_paths[upload_index]}))])
        run = self.service.list_runs()[0]
        observations = [
            {"source_id": item["observation_id"], "finding": "The artifact was stored."}
            for item in run["terminal_observations"] if item["ok"]
        ] + [
            {"source_id": step["job_id"], "finding": "The beacon confirmed transfer."}
            for step in run["steps"] if step["purpose"] == "command" and step["state"] == "succeeded"
        ]
        return LLMCompletionResult(content=json.dumps({
            "summary": ("Requested files transferred." if observations else
                        "I need a local source file and a session destination."),
            "observations": observations,
            "limitations": ([] if observations else ["Source file and destination are missing from the context."]),
        }))


class RetryProvider(TransferProvider):
    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id="bad-source", name="uploadC2Artifact",
                arguments_json=json.dumps({"source_file": "/missing/source"}))])
        if self.calls == 2:
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id="correct-source", name="uploadC2Artifact",
                arguments_json=json.dumps({"source_file": self.source_file}))])
        if self.calls == 3:
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id="upload-beacon", name="upload",
                arguments_json=json.dumps({"remote_path": self.remote_paths[0]}))])
        return super().complete_with_tools(**kwargs)


def test_free_context_drives_one_artifact_and_two_beacon_transfers_after_restart(tmp_path):
    source = tmp_path / "hosts"
    source.write_bytes(b"127.0.0.1 localhost\n")
    client = TransferGrpc()
    provider = TransferProvider(str(source), ["/tmp/toto", "/tmp/hotsss"])
    storage = tmp_path / "skills"
    service = C2SkillService(client, storage_dir=storage, provider=provider)
    provider.service = service
    context = f"ok transfert {source} dans /tmp/toto et /tmp/hotsss"

    run = service.start("artifact-to-session", "beacon-1", "listener-1", context)
    assert run["additional_context"] == context
    assert run["status"] == "running"
    assert run["artifact_transfer"]["source_file"] == str(source)
    assert run["artifact_transfer"]["artifact_id"] == "artifact-verified"
    assert len(client.uploads) == 1
    assert [command for _, command in client.submissions] == ["upload artifact-verified /tmp/toto"]

    service = C2SkillService(client, storage_dir=storage, provider=provider)
    provider.service = service
    client.complete(client.submissions[0][0])
    run = service.reconcile(run["run_id"])
    assert run["status"] == "running"
    assert [command for _, command in client.submissions] == [
        "upload artifact-verified /tmp/toto", "upload artifact-verified /tmp/hotsss",
    ]
    client.complete(client.submissions[1][0])
    run = service.reconcile(run["run_id"])
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete"
    assert len(client.uploads) == 1
    assert {item["source_id"] for item in run["report"]["observations"]} == {
        run["terminal_observations"][0]["observation_id"],
        client.submissions[0][0], client.submissions[1][0],
    }


def test_missing_context_creates_visible_error_instead_of_report(tmp_path):
    client = TransferGrpc()
    provider = TransferProvider(None, [])
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    run = service.start("artifact-to-session", "beacon-1", "listener-1", "please transfer it")
    assert run["status"] == "failed"
    assert "Source file and destination are missing" in run["error_message"]
    visible = format_run_details(run)
    assert "Error:" in visible
    assert "What I found" not in visible
    assert not client.uploads and not client.submissions


def test_context_is_not_parsed_or_checked_at_start(tmp_path):
    client = TransferGrpc()
    provider = TransferProvider(None, [])
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    assert SKILLS["artifact-to-session"].required_tools == ("uploadC2Artifact", "upload")
    for context in ("", "{}", "no path format at all"):
        run = service.start("artifact-to-session", "beacon-1", "listener-1", context)
        assert run["additional_context"] == context
        assert run["status"] == "failed"


def test_artifact_upload_tool_uses_model_supplied_source_path(tmp_path):
    source = tmp_path / "selected.bin"
    source.write_bytes(b"payload")
    client = TransferGrpc()
    tool = C2ArtifactUploadTool(client, "skill-test.bin")
    assert "source_file" in str(tool.schema())
    assert not tool.execute({}, None).ok
    assert not tool.execute({"source_file": str(tmp_path / "missing")}, None).ok
    assert not client.uploads
    result = tool.execute({"source_file": str(source)}, None)
    assert result.ok
    assert result.metadata["source_file"] == str(source)
    assert client.uploads[0][1] == b"payload"


def test_model_can_correct_local_path_before_any_artifact_rpc(tmp_path):
    source = tmp_path / "hosts"
    source.write_bytes(b"127.0.0.1 localhost\n")
    client = TransferGrpc()
    provider = RetryProvider(str(source), ["/tmp/hosts"])
    service = C2SkillService(client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = service
    run = service.start("artifact-to-session", "beacon-1", "listener-1",
                        f"The source is {source}; put it at /tmp/hosts on the session.")
    assert len(client.uploads) == 1
    assert [item["state"] for item in run["terminal_observations"]] == ["failed", "succeeded"]
    assert run["status"] == "running"
    client.complete(client.submissions[0][0])
    run = service.reconcile(run["run_id"])
    assert run["status"] == "completed"
