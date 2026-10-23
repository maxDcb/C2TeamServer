from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
from types import SimpleNamespace

import grpc
import pytest

from agent_core.llm.base import LLMCompletionResult

from C2Client.assistant_agent.skills.service import C2SkillService
from C2Client.grpcClient import TeamServerApi_pb2


class ReportProvider:
    def __init__(self):
        self.calls = 0

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        evidence = json.loads(json.loads(kwargs["messages"][-1].content)["context"])
        successful = [item for item in evidence if item["state"] == "succeeded" and item["purpose"] == "command"]
        return LLMCompletionResult(content=json.dumps({
            "summary": "Observed inventory",
            "observations": [{"job_id": item["job_id"], "finding": item["output_preview"]} for item in successful],
            "limitations": [],
        }))


class NotFound(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.NOT_FOUND


class FakeGrpc:
    def __init__(self):
        self.jobs = {}
        self.submissions = []
        self.loaded_modules = {"whoami", "ipConfig"}

    def listSessions(self):
        return [SimpleNamespace(beacon_hash="beacon-1", listener_hash="listener-1", os="windows", arch="x64", killed=False)]

    def listCommands(self, query):
        _ = query
        commands = [TeamServerApi_pb2.CommandSpec(
            name=name, kind="module", command_template=name, platforms=["windows", "linux"], archs=["any"],
        ) for name in ("whoami", "ipConfig")]
        commands.append(TeamServerApi_pb2.CommandSpec(
            name="loadModule", kind="common", command_template="loadModule {module:q}",
            platforms=["windows", "linux"], archs=["any"],
        ))
        return commands

    def listModules(self, session):
        _ = session
        return [SimpleNamespace(name=name, state="loaded") for name in self.loaded_modules]

    def submitJob(self, job_id, operation, payload):
        assert operation == "session_command"
        self.submissions.append((job_id, json.loads(payload)))
        return self.jobs.setdefault(job_id, SimpleNamespace(
            job_id=job_id, state="queued", output_inline=b"", output_size=0,
            error_code="", error_message="",
        ))

    def getJobExecution(self, job_id):
        if job_id not in self.jobs:
            raise NotFound()
        return self.jobs[job_id]

    def complete(self, job_id, output: bytes):
        command = next((item[1]["command"] for item in self.submissions if item[0] == job_id), "")
        if command.startswith("loadModule "):
            self.loaded_modules.add(command.removeprefix("loadModule "))
        self.jobs[job_id] = SimpleNamespace(
            job_id=job_id, state="succeeded", output_inline=output, output_size=len(output),
            error_code="", error_message="",
        )


def service(tmp_path, grpc_client, provider):
    return C2SkillService(grpc_client, storage_dir=tmp_path / "skills", provider=provider)


def test_inventory_waits_indefinitely_then_reports_exact_evidence(tmp_path):
    grpc_client = FakeGrpc()
    provider = ReportProvider()
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    first = run["steps"][0]["job_id"]
    assert run["status"] == "running"
    assert run["steps"][0]["state"] == "waiting_for_job"
    assert len(grpc_client.submissions) == 1
    assert provider.calls == 0

    grpc_client.jobs[first].state = "outcome_unknown"
    run = tasks.on_job_event(run["run_id"], first, 5)
    assert run["steps"][0]["state"] == "waiting_uncertain"
    assert tasks.reconcile(run["run_id"])["status"] == "running"
    assert len(grpc_client.submissions) == 1

    original = b"user\x00\xff"
    grpc_client.complete(first, original)
    run = tasks.on_job_event(run["run_id"], first, 6)
    assert base64.b64decode(run["steps"][0]["output_base64"]) == original
    assert len(grpc_client.submissions) == 2
    second = run["steps"][1]["job_id"]
    grpc_client.complete(second, b"ip=127.0.0.1")
    run = tasks.on_job_event(run["run_id"], second, 9)
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete"
    assert [item["job_id"] for item in run["report"]["evidence"]] == [first, second]
    assert [item["job_id"] for item in run["report"]["observations"]] == [first, second]
    assert provider.calls == 1
    assert tasks.on_job_event(run["run_id"], second, 9) == run


def test_restart_reconciles_without_resubmitting_and_operator_closes_partial(tmp_path):
    grpc_client = FakeGrpc()
    provider = ReportProvider()
    first_client = service(tmp_path, grpc_client, provider)
    run = first_client.start("inventory_local", "beacon-1", "listener-1")
    first = run["steps"][0]["job_id"]

    restored = service(tmp_path, grpc_client, provider)
    assert restored.reconcile_all()[0]["status"] == "running"
    assert [item[0] for item in grpc_client.submissions] == [first]
    run = restored.confirm_no_result(run["run_id"], "Beacon hors ligne")
    assert run["steps"][0]["state"] == "no_result_confirmed"
    second = run["steps"][1]["job_id"]
    grpc_client.complete(second, b"network")
    run = restored.on_job_event(run["run_id"], second, 15)
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "partial"
    assert run["report"]["evidence"][0]["manual_reason"] == "Beacon hors ligne"
    grpc_client.complete(first, b"late")
    late = restored.on_job_event(run["run_id"], first, 16)
    assert late["status"] == "completed"
    assert late["steps"][0]["late_server_state"] == "succeeded"
    assert late["report"] == run["report"]


def test_operator_can_fail_run_without_dispatching_next_step(tmp_path):
    grpc_client = FakeGrpc()
    tasks = service(tmp_path, grpc_client, ReportProvider())
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    failed = tasks.fail_run(run["run_id"], "Périmètre retiré")
    assert failed["status"] == "failed"
    assert failed["manual_failure"] == "Périmètre retiré"
    assert len(grpc_client.submissions) == 1
    assert tasks.reconcile(run["run_id"])["status"] == "failed"


def test_uncertain_submission_reuses_id_after_restart(tmp_path):
    class LostReplyGrpc(FakeGrpc):
        def __init__(self):
            super().__init__()
            self.lose_reply = True

        def submitJob(self, job_id, operation, payload):
            job = super().submitJob(job_id, operation, payload)
            if self.lose_reply:
                self.lose_reply = False
                raise RuntimeError("Connection dropped after commit")
            return job

    grpc_client = LostReplyGrpc()
    first_client = service(tmp_path, grpc_client, ReportProvider())
    run = first_client.start("inventory_local", "beacon-1", "listener-1")
    job_id = run["steps"][0]["job_id"]
    assert run["steps"][0]["state"] == "submission_uncertain"

    restored = service(tmp_path, grpc_client, ReportProvider())
    run = restored.reconcile_all()[0]
    assert run["steps"][0]["state"] == "waiting_for_job"
    assert [submitted[0] for submitted in grpc_client.submissions] == [job_id]


def test_report_failure_keeps_evidence_and_marks_analysis_unavailable(tmp_path):
    class BrokenProvider:
        def complete_with_tools(self, **kwargs):
            _ = kwargs
            raise RuntimeError("Model unavailable")

    grpc_client = FakeGrpc()
    tasks = service(tmp_path, grpc_client, BrokenProvider())
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    first = run["steps"][0]["job_id"]
    grpc_client.complete(first, b"identity\x00\xff")
    run = tasks.reconcile(run["run_id"])
    second = run["steps"][1]["job_id"]
    grpc_client.complete(second, b"network")
    run = tasks.reconcile(run["run_id"])
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "partial"
    assert run["report"]["analysis_status"] == "unavailable"
    assert base64.b64decode(run["steps"][0]["output_base64"]) == b"identity\x00\xff"
    assert run["report"]["limitations"]


def test_preflight_rejects_unknown_skill_and_missing_loader(tmp_path):
    grpc_client = FakeGrpc()
    tasks = service(tmp_path, grpc_client, ReportProvider())
    with pytest.raises(ValueError, match="Unknown skill"):
        tasks.start("missing", "beacon-1", "listener-1")
    grpc_client.loaded_modules.clear()
    grpc_client.listCommands = lambda query: FakeGrpc.listCommands(grpc_client, query)[:2]
    with pytest.raises(ValueError, match="does not offer loadModule"):
        tasks.start("inventory_local", "beacon-1", "listener-1")
    assert tasks.list_runs() == []
    assert grpc_client.submissions == []


def test_missing_modules_are_loaded_before_commands_and_resume_after_restart(tmp_path):
    grpc_client = FakeGrpc()
    grpc_client.loaded_modules.clear()
    provider = ReportProvider()
    first_client = service(tmp_path, grpc_client, provider)
    run = first_client.start("inventory_local", "beacon-1", "listener-1")
    assert [step["command"] for step in run["steps"]] == [
        "loadModule whoami", "whoami", "loadModule ipConfig", "ipConfig",
    ]
    assert [item[1]["command"] for item in grpc_client.submissions] == ["loadModule whoami"]

    restored = service(tmp_path, grpc_client, provider)
    assert restored.reconcile_all()[0]["steps"][0]["state"] == "waiting_for_job"
    assert len(grpc_client.submissions) == 1

    for index in range(4):
        current = restored.get(run["run_id"])
        job_id = current["steps"][index]["job_id"]
        grpc_client.complete(job_id, f"output-{index}".encode())
        restored.reconcile(run["run_id"])

    finished = restored.get(run["run_id"])
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "complete"
    assert [item["purpose"] for item in finished["report"]["evidence"]] == [
        "module_load", "command", "module_load", "command",
    ]
    assert [item["job_id"] for item in finished["report"]["observations"]] == [
        finished["steps"][1]["job_id"], finished["steps"][3]["job_id"],
    ]


def test_missing_load_result_skips_dependent_command_and_reports_uncertainty(tmp_path):
    grpc_client = FakeGrpc()
    grpc_client.loaded_modules.clear()
    provider = ReportProvider()
    tasks = service(tmp_path, grpc_client, provider)
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    run = tasks.confirm_no_result(run["run_id"], "Beacon did not answer module load")
    assert run["steps"][1]["state"] == "skipped"
    assert [item[1]["command"] for item in grpc_client.submissions] == [
        "loadModule whoami", "loadModule ipConfig",
    ]
    run = tasks.confirm_no_result(run["run_id"], "Beacon still offline")
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "partial"
    assert provider.calls == 0
    assert all(step["command_name"] != "whoami" or step["state"] == "skipped" for step in run["steps"])


def test_existing_module_load_is_followed_without_duplicate(tmp_path):
    grpc_client = FakeGrpc()
    grpc_client.loaded_modules = {"ipConfig"}
    grpc_client.jobs["external-load"] = SimpleNamespace(
        job_id="external-load", state="queued", output_inline=b"", output_size=0,
        error_code="", error_message="",
    )
    grpc_client.listModules = lambda session: [
        SimpleNamespace(name="whoami", state="loading", command_id="external-load"),
        SimpleNamespace(name="ipConfig", state="loaded", command_id=""),
    ]
    tasks = service(tmp_path, grpc_client, ReportProvider())
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    assert run["steps"][0]["job_id"] == "external-load"
    assert run["steps"][0]["state"] == "waiting_for_job"
    assert grpc_client.submissions == []


def test_failed_module_load_never_dispatches_dependent_command(tmp_path):
    grpc_client = FakeGrpc()
    grpc_client.loaded_modules = {"ipConfig"}
    tasks = service(tmp_path, grpc_client, ReportProvider())
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    load_id = run["steps"][0]["job_id"]
    grpc_client.jobs[load_id] = SimpleNamespace(
        job_id=load_id, state="failed", output_inline=b"", output_size=0,
        error_code="module_load_failed", error_message="Beacon rejected module",
    )
    run = tasks.reconcile(run["run_id"])
    assert run["steps"][1]["state"] == "skipped"
    assert [item[1]["command"] for item in grpc_client.submissions] == [
        "loadModule whoami", "ipConfig",
    ]


def test_concurrent_reconciliation_advances_step_only_once(tmp_path):
    grpc_client = FakeGrpc()
    tasks = service(tmp_path, grpc_client, ReportProvider())
    run = tasks.start("inventory_local", "beacon-1", "listener-1")
    grpc_client.complete(run["steps"][0]["job_id"], b"identity")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(tasks.reconcile, [run["run_id"], run["run_id"]]))

    assert len(grpc_client.submissions) == 2
    assert results[-1]["steps"][1]["state"] == "waiting_for_job"
