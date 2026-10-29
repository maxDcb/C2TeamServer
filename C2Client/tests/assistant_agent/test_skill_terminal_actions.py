from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace

from agent_core.llm.base import LLMCompletionResult, LLMToolCall

from C2Client.assistant_agent.skills.catalog import SKILLS
from C2Client.assistant_agent.skills.service import C2SkillService
from C2Client.grpcClient import TeamServerApi_pb2


class TerminalGrpc:
    def __init__(self):
        self.commands = []

    def listSessions(self):
        return [SimpleNamespace(
            beacon_hash="beacon-1", listener_hash="listener-1",
            os="linux", arch="x64", killed=False,
        )]

    def listCommands(self, query):
        return []

    def hostArtifact(self, request):
        self.commands.append(request)
        return SimpleNamespace(job_id=request.job_id, state="succeeded",
                               output_inline=b"https://c2.test/payload.exe", error_message="")

    def getJobExecution(self, job_id):
        raise LookupError(job_id)


class ArtifactProvider:
    def __init__(self):
        self.calls = 0
        self.service = None

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            assert [tool.name for tool in kwargs["tools"]] == ["hostArtifact"]
            return LLMCompletionResult(content="", tool_calls=[LLMToolCall(
                id="host-1", name="hostArtifact",
                arguments_json=json.dumps({
                    "artifact_reference": "artifact-1", "listener_hash": "listener-1",
                }),
            )])
        run = self.service.list_runs()[0]
        observation_id = run["terminal_observations"][0]["observation_id"]
        return LLMCompletionResult(content=json.dumps({
            "summary": "The artifact is hosted.",
            "observations": [{"source_id": observation_id, "finding": "A hosted URL was returned."}],
            "limitations": [],
        }))


def test_skill_can_use_typed_terminal_action_from_bundle(tmp_path, monkeypatch):
    monkeypatch.setitem(SKILLS, "host-test", replace(
        SKILLS["recon-host"], skill_id="host-test", tool_bundles=("payload_delivery",),
        required_tools=("hostArtifact",), completion_tools=("hostArtifact",),
        max_tool_calls=1, max_iterations=3,
    ))
    grpc_client = TerminalGrpc()
    provider = ArtifactProvider()
    tasks = C2SkillService(grpc_client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = tasks

    run = tasks.start("host-test", "beacon-1", "listener-1")
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete"
    assert run["terminal_observations"][0]["state"] == "succeeded"
    assert [(request.listener_hash, request.artifact_reference) for request in grpc_client.commands] == [
        ("listener-1", "artifact-1")]
    tasks.reconcile(run["run_id"])
    assert len(grpc_client.commands) == 1


def test_interrupted_terminal_action_is_recorded_as_uncertain_without_replay(tmp_path, monkeypatch):
    grpc_client = TerminalGrpc()
    tasks = C2SkillService(grpc_client, storage_dir=tmp_path / "skills")
    run = {
        "schema_version": 1, "mode": "agentic_skill", "run_id": "test-run",
        "created_at": "2026-01-01", "updated_at": "2026-01-01", "status": "running",
        "terminal_observations": [], "active_terminal_call": None, "active_tool_call": None,
        "manual_uncertainty": False, "after_event_id": 0, "steps": [],
        "completion_tools": ["hostArtifact"],
    }
    tasks.store.save(run)
    class BlockedAgent:
        def __init__(self):
            self.result = None

        def get(self, **kwargs):
            return SimpleNamespace(
                status="blocked", error=SimpleNamespace(kind="ambiguous_tool_execution"),
                checkpoint=SimpleNamespace(payload={
                    "pending_tool_calls": [{
                        "tool_name": "hostArtifact", "tool_call_id": "call-1",
                        "arguments_json": json.dumps({
                            "artifact_reference": "artifact-1", "listener_hash": "listener-1",
                        }),
                    }],
                    "next_tool_call_index": 0,
                }),
            )

        def resolve_ambiguous_tool(self, **kwargs):
            self.result = kwargs["result"]
            return SimpleNamespace(status="completed", output={
                "summary": "Action outcome is unknown.", "observations": [], "limitations": [],
            })

    agent = BlockedAgent()
    monkeypatch.setattr(tasks, "_agentic_skill_agent", lambda run: (
        agent, None, SimpleNamespace(namespace_id="test"),
    ))
    finished = tasks.reconcile("test-run")
    assert not agent.result.ok
    assert grpc_client.commands == []
    assert finished["manual_uncertainty"]
    assert finished["report"]["outcome"] == "partial"
    assert finished["terminal_observations"][0]["state"] == "outcome_unknown"
    tasks.reconcile("test-run")
    assert len(tasks.get("test-run")["terminal_observations"]) == 1


def test_terminal_transport_loss_makes_skill_report_partial(tmp_path, monkeypatch):
    monkeypatch.setitem(SKILLS, "host-test", replace(
        SKILLS["recon-host"], skill_id="host-test", tool_bundles=("payload_delivery",),
        required_tools=("hostArtifact",), completion_tools=("hostArtifact",),
        max_tool_calls=1, max_iterations=3,
    ))
    grpc_client = TerminalGrpc()
    calls = []
    def lost_response(request):
        calls.append(request)
        raise ConnectionError("response lost")
    grpc_client.hostArtifact = lost_response
    provider = ArtifactProvider()
    tasks = C2SkillService(grpc_client, storage_dir=tmp_path / "skills", provider=provider)
    provider.service = tasks
    run = tasks.start("host-test", "beacon-1", "listener-1")
    assert run["terminal_observations"][0]["state"] == "outcome_unknown"
    assert run["manual_uncertainty"]
    assert run["report"]["outcome"] == "partial"
    assert [(request.listener_hash, request.artifact_reference) for request in calls] == [
        ("listener-1", "artifact-1")]


def test_interrupted_action_resolves_persisted_receipt(tmp_path):
    grpc_client = TerminalGrpc()
    grpc_client.getJobExecution = lambda job_id: SimpleNamespace(
        job_id=job_id, state="succeeded", output_inline=b"https://c2.test/payload.exe",
        error_message="",
    )
    tasks = C2SkillService(grpc_client, storage_dir=tmp_path / "skills")
    observation_id = "terminal-run-1"
    run = {
        "run_id": "run", "terminal_observations": [{
            "observation_id": observation_id, "job_id": observation_id,
            "tool": "hostArtifact", "state": "dispatching",
        }], "active_terminal_call": observation_id, "manual_uncertainty": False,
    }
    result = tasks._uncertain_terminal_action(run, "hostArtifact", {}, "call-1")
    assert result.ok
    assert json.loads(result.content)["state"] == "succeeded"
    assert run["active_terminal_call"] is None
    assert not run["manual_uncertainty"]
    assert grpc_client.commands == []
