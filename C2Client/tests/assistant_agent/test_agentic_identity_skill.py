from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import grpc
import pytest

from agent_core.llm.base import LLMCompletionResult, LLMToolCall
from agent_core.run_models import AgentRunState

from C2Client.assistant_agent.skills.catalog import IDENTIFY_USER, discover_agentic_skills, load_agentic_skill
from C2Client.assistant_agent.skills.service import C2SkillService
from C2Client.grpcClient import TeamServerApi_pb2


class MissingJob(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.NOT_FOUND


class FakeGrpc:
    def __init__(self, *, loaded=True):
        self.jobs = {}
        self.submissions = []
        self.loaded = loaded

    def listSessions(self):
        return [SimpleNamespace(
            beacon_hash="beacon-1", listener_hash="listener-1", os="linux", arch="x64", killed=False,
        )]

    def listCommands(self, query):
        _ = query
        return [
            TeamServerApi_pb2.CommandSpec(
                name="whoami", kind="module", command_template="whoami",
                platforms=["linux", "windows"], archs=["any"],
            ),
            TeamServerApi_pb2.CommandSpec(
                name="loadModule", kind="common", command_template="loadModule {module:q}",
                platforms=["linux", "windows"], archs=["any"],
            ),
        ]

    def listModules(self, session):
        _ = session
        return [SimpleNamespace(name="whoami", state="loaded")] if self.loaded else []

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

    def complete(self, job_id, output: bytes, *, state="succeeded", error_message=""):
        self.jobs[job_id] = SimpleNamespace(
            job_id=job_id, state=state, output_inline=output, output_size=len(output),
            error_code="command_failed" if state == "failed" else "", error_message=error_message,
        )
        if state == "succeeded" and any(item == (job_id, "loadModule whoami") for item in self.submissions):
            self.loaded = True


class IdentityProvider:
    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.calls = 0

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            assert [tool.name for tool in kwargs["tools"]] == ["whoami"]
            assert self.grpc_client.submissions == []
            return LLMCompletionResult(content="", tool_calls=[
                LLMToolCall(id="identity-call", name="whoami", arguments_json="{}"),
            ])
        whoami_job = next((job_id for job_id, command in self.grpc_client.submissions if command == "whoami"), "")
        return LLMCompletionResult(content=json.dumps({
            "summary": "The session is running as operator." if whoami_job else "Identity is unverified.",
            "observations": [{"job_id": whoami_job, "finding": "The account is operator."}] if whoami_job else [],
            "limitations": [] if whoami_job else ["No identity output was received."],
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


def test_identity_skill_uses_structured_pending_and_resumes_after_restart(tmp_path):
    grpc_client = FakeGrpc()
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)

    run = tasks.start("identify-user", "beacon-1", "listener-1")
    assert run["mode"] == "agentic_identity"
    assert run["tool_bundles"] == ["recon.identity"]
    assert run["allowed_tools"] == ["whoami"]
    assert run["status"] == "running"
    assert provider.calls == 1
    assert [(command) for _, command in grpc_client.submissions] == ["whoami"]
    agent, _spec, context = tasks._identity_agent(run)
    agent_state = agent.get(namespace_id=context.namespace_id, run_id=f"agentic-{run['run_id']}")
    assert agent_state.status == "pending"

    restored = service(tmp_path, grpc_client, provider)
    assert restored.reconcile(run["run_id"])["status"] == "running"
    assert len(grpc_client.submissions) == 1
    job_id = run["steps"][0]["job_id"]
    grpc_client.complete(job_id, b"operator\x00")
    finished = restored.reconcile(run["run_id"])

    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "complete"
    assert finished["report"]["verified_identity"] == "operator"
    assert finished["report"]["observations"][0]["job_id"] == job_id
    assert base64.b64decode(finished["steps"][0]["output_base64"]) == b"operator\x00"
    assert provider.calls == 3
    assert len(grpc_client.submissions) == 1
    assert restored.reconcile(run["run_id"])["report"] == finished["report"]


def test_identity_skill_loads_module_then_resumes_same_tool_call(tmp_path):
    grpc_client = FakeGrpc(loaded=False)
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    assert [command for _, command in grpc_client.submissions] == ["loadModule whoami"]
    assert provider.calls == 1

    load_id = run["steps"][0]["job_id"]
    grpc_client.complete(load_id, b"Error: Module already loaded", state="failed",
                         error_message="Error: Module already loaded")
    run = tasks.reconcile(run["run_id"])
    assert run["steps"][0]["state"] == "already_loaded"
    assert [command for _, command in grpc_client.submissions] == ["loadModule whoami", "whoami"]
    assert provider.calls == 1

    grpc_client.complete(run["steps"][1]["job_id"], b"operator")
    run = tasks.reconcile(run["run_id"])
    assert run["report"]["outcome"] == "complete"
    assert provider.calls == 3


def test_identity_skill_manual_no_result_produces_partial_report(tmp_path):
    grpc_client = FakeGrpc()
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    finished = tasks.confirm_no_result(run["run_id"], "Beacon is offline")
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "partial"
    assert finished["report"]["verified_identity"] == ""
    assert finished["steps"][0]["state"] == "no_result_confirmed"
    assert len(grpc_client.submissions) == 1


def test_identity_skill_module_load_without_result_does_not_send_whoami(tmp_path):
    grpc_client = FakeGrpc(loaded=False)
    tasks = service(tmp_path, grpc_client, IdentityProvider(grpc_client))
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    finished = tasks.confirm_no_result(run["run_id"], "No module load response")
    assert finished["report"]["outcome"] == "partial"
    assert finished["steps"][1]["state"] == "skipped"
    assert [command for _, command in grpc_client.submissions] == ["loadModule whoami"]


def test_identity_skill_event_cursor_deduplicates_completion(tmp_path):
    grpc_client = FakeGrpc()
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    job_id = run["steps"][0]["job_id"]
    grpc_client.complete(job_id, b"operator")
    finished = tasks.on_job_event(run["run_id"], job_id, 12)
    assert finished["status"] == "completed"
    assert finished["after_event_id"] == 12
    assert tasks.on_job_event(run["run_id"], job_id, 12) == finished
    assert len(grpc_client.submissions) == 1


def test_identity_skill_does_not_send_unlisted_tools(tmp_path):
    grpc_client = FakeGrpc()

    class WrongToolProvider:
        def complete_with_tools(self, **kwargs):
            _ = kwargs
            return LLMCompletionResult(content="", tool_calls=[
                LLMToolCall(id="wrong", name="ipConfig", arguments_json="{}"),
            ])

    tasks = service(tmp_path, grpc_client, WrongToolProvider())
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    assert grpc_client.submissions == []
    assert run["report"]["outcome"] == "partial"


def test_restart_after_terminal_model_result_does_not_dispatch_command(tmp_path, monkeypatch):
    grpc_client = FakeGrpc()

    class WrongToolProvider:
        def complete_with_tools(self, **kwargs):
            _ = kwargs
            return LLMCompletionResult(content="", tool_calls=[
                LLMToolCall(id="wrong", name="ipConfig", arguments_json="{}"),
            ])

    tasks = service(tmp_path, grpc_client, WrongToolProvider())

    def crash_before_c2_report(_run, _result):
        raise RuntimeError("crash")

    monkeypatch.setattr(tasks, "_apply_agentic_result", crash_before_c2_report)
    with pytest.raises(RuntimeError, match="crash"):
        tasks.start("identify-user", "beacon-1", "listener-1")
    assert grpc_client.submissions == []

    restored = service(tmp_path, grpc_client, WrongToolProvider())
    run_id = restored.list_runs()[0]["run_id"]
    finished = restored.reconcile(run_id)
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "partial"
    assert grpc_client.submissions == []


@pytest.mark.parametrize("created_agent_state", [False, True])
def test_restart_before_model_decision_does_not_send_command_itself(
    tmp_path, monkeypatch, created_agent_state,
):
    grpc_client = FakeGrpc()
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)
    original = tasks._drive_agentic_identity

    def crash(_run):
        raise RuntimeError("crash")

    monkeypatch.setattr(tasks, "_drive_agentic_identity", crash)
    with pytest.raises(RuntimeError, match="crash"):
        tasks.start("identify-user", "beacon-1", "listener-1")
    assert grpc_client.submissions == []

    monkeypatch.setattr(tasks, "_drive_agentic_identity", original)
    run_id = tasks.list_runs()[0]["run_id"]
    if created_agent_state:
        agent, spec, context = tasks._identity_agent(tasks.get(run_id))
        agent_id = f"agentic-{run_id}"
        agent.run_store.create(AgentRunState(
            run_id=agent_id, strategy="structured", spec_id=spec.task_id,
            context=context.with_run_id(agent_id),
        ))
    run = tasks.reconcile(run_id)
    assert provider.calls == 1
    assert run["status"] == "running"
    assert [command for _, command in grpc_client.submissions] == ["whoami"]


def test_ambiguous_agent_checkpoint_reconciles_stable_job_without_resend(tmp_path):
    grpc_client = FakeGrpc()
    provider = IdentityProvider(grpc_client)
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("identify-user", "beacon-1", "listener-1")
    agent, _spec, context = tasks._identity_agent(run)
    agent_id = f"agentic-{run['run_id']}"
    state = agent.get(namespace_id=context.namespace_id, run_id=agent_id)
    state.status = "interrupted"
    state.result = None
    state.checkpoint.payload["pending_tool_calls"][0]["status"] = "running"
    state.checkpoint.payload["pending_tool_calls"][0]["pending_id"] = None
    agent.run_store.save(state)

    restored = service(tmp_path, grpc_client, provider)
    waiting = restored.reconcile(run["run_id"])
    assert waiting["status"] == "running"
    assert waiting["agent_recovery"] == "ambiguous_tool"
    assert len(grpc_client.submissions) == 1

    grpc_client.complete(run["steps"][0]["job_id"], b"operator")
    finished = restored.reconcile(run["run_id"])
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "complete"
    assert len(grpc_client.submissions) == 1
