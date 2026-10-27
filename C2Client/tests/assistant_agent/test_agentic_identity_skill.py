from __future__ import annotations

import json
from types import SimpleNamespace

import grpc
import pytest

from agent_core.llm.base import LLMCompletionResult, LLMToolCall

from C2Client.assistant_agent.skills.catalog import SKILLS, discover_agentic_skills, load_agentic_skill
from C2Client.assistant_agent.skills.service import C2SkillService
from C2Client.grpcClient import TeamServerApi_pb2


IDENTIFY_USER = SKILLS["identify-user"]


class MissingJob(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.NOT_FOUND


class FakeGrpc:
    def __init__(self):
        self.jobs = {}
        self.submissions = []

    def listSessions(self):
        return [SimpleNamespace(
            beacon_hash="beacon-1", listener_hash="listener-1", os="linux", arch="x64", killed=False,
        )]

    def listCommands(self, query):
        return [TeamServerApi_pb2.CommandSpec(
            name="whoami", kind="module", command_template="whoami",
            platforms=["linux", "windows"], archs=["any"],
        )]

    def listModules(self, session):
        return [SimpleNamespace(name="whoami", state="loaded")]

    def submitJob(self, job_id, operation, payload):
        assert operation == "session_command"
        command = json.loads(payload)["command"]
        self.submissions.append((job_id, command))
        return self.jobs.setdefault(job_id, SimpleNamespace(
            job_id=job_id, state="queued", output_inline=b"", output_size=0,
            error_code="", error_message="",
        ))

    def getJobExecution(self, job_id):
        if job_id not in self.jobs:
            raise MissingJob()
        return self.jobs[job_id]

    def complete(self, job_id, output: bytes):
        self.jobs[job_id] = SimpleNamespace(
            job_id=job_id, state="succeeded", output_inline=output, output_size=len(output),
            error_code="", error_message="",
        )


class IdentityProvider:
    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.calls = 0

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            assert [tool.name for tool in kwargs["tools"]] == ["whoami"]
            return LLMCompletionResult(content="", tool_calls=[
                LLMToolCall(id="identity-call", name="whoami", arguments_json="{}"),
            ])
        job_id = next(job for job, command in self.grpc_client.submissions if command == "whoami")
        observed = self.grpc_client.jobs[job_id].state == "succeeded"
        return LLMCompletionResult(content=json.dumps({
            "summary": "The account is operator." if observed else "Identity could not be verified.",
            "observations": [{"source_id": job_id, "finding": "The account is operator."}] if observed else [],
            "limitations": [] if observed else ["No identity result was received."],
        }))


def service(tmp_path, grpc_client, provider):
    return C2SkillService(grpc_client, storage_dir=tmp_path / "skills", provider=provider)


def test_skill_md_follows_agent_skills_frontmatter(tmp_path):
    assert IDENTIFY_USER.skill_id == "identify-user"
    assert IDENTIFY_USER.version == 1
    assert IDENTIFY_USER.tool_bundles == ("recon.identity",)
    assert IDENTIFY_USER.declared_tools == ("whoami",)
    assert "Call the `whoami` tool once" in IDENTIFY_USER.instructions

    path = tmp_path / "wrong-name" / "SKILL.md"
    path.parent.mkdir()
    path.write_text("---\nname: identify-user\ndescription: Test\n---\n# Body\n")
    with pytest.raises(ValueError, match="match its directory"):
        load_agentic_skill(path)


def test_skill_manifest_allows_optional_requirements_and_rejects_boolean_limits(tmp_path):
    skill_dir = tmp_path / "inspect-host"
    skill_dir.mkdir()
    path = skill_dir / "SKILL.md"
    path.write_text(
        "---\nname: inspect-host\ndescription: Inspect a host.\nmetadata:\n  version: '1'\n---\nInspect the selected host.\n",
        encoding="utf-8",
    )
    manifest = skill_dir / "skill.yaml"
    manifest.write_text("tool_bundles: [recon.host]\nmax_tool_calls: 3\nmax_iterations: 5\n", encoding="utf-8")
    skill = load_agentic_skill(path)
    assert skill.required_tools == ()
    assert "ipConfig" in skill.declared_tools
    assert discover_agentic_skills(tmp_path)["inspect-host"].objective == "Inspect a host."

    manifest.write_text("tool_bundles: [recon.host]\nmax_tool_calls: true\nmax_iterations: 5\n", encoding="utf-8")
    with pytest.raises(ValueError, match="max_tool_calls"):
        load_agentic_skill(path)


def test_identity_uses_generic_executor_and_context_survives_restart(tmp_path):
    grpc_client = FakeGrpc()
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("identify-user", "beacon-1", "listener-1", "Focus on the account name.")

    assert run["mode"] == "agentic_skill"
    assert run["allowed_tools"] == ["whoami"]
    assert run["additional_context"] == "Focus on the account name."
    assert [command for _, command in grpc_client.submissions] == ["whoami"]
    job_id = grpc_client.submissions[0][0]

    restored = service(tmp_path, grpc_client, provider)
    _, spec, _ = restored._agentic_skill_agent(restored.get(run["run_id"]))
    assert "Focus on the account name." in spec.context
    grpc_client.complete(job_id, b"operator")
    finished = restored.on_job_event(run["run_id"], job_id, 1)
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "complete"
    assert finished["report"]["observations"][0]["source_id"] == job_id
    assert grpc_client.submissions == [(job_id, "whoami")]


def test_no_result_produces_partial_report_without_resubmission(tmp_path):
    grpc_client = FakeGrpc()
    tasks = service(tmp_path, grpc_client, IdentityProvider(grpc_client))
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    finished = tasks.confirm_no_result(run["run_id"], "Beacon disconnected")
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "partial"
    assert len(grpc_client.submissions) == 1


def test_retired_run_formats_are_not_available(tmp_path):
    tasks = service(tmp_path, FakeGrpc(), IdentityProvider(FakeGrpc()))
    tasks.store.save({"schema_version": 1, "run_id": "old-run", "mode": "agentic_identity",
                      "created_at": "2026-01-01", "status": "running"})
    assert tasks.list_runs() == []
    with pytest.raises(ValueError, match="retired"):
        tasks.get("old-run")
