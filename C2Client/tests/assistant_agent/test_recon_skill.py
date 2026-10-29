from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import grpc
import pytest

from agent_core.llm.base import LLMCompletionResult, LLMToolCall

from C2Client.assistant_agent.skills.catalog import SKILLS
from C2Client.assistant_agent.skills.service import C2SkillService
from C2Client.grpcClient import TeamServerApi_pb2


RECON_HOST = SKILLS["recon-host"]


class MissingJob(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.NOT_FOUND


class ReconGrpc:
    def __init__(self, *, loaded=True):
        self.jobs = {}
        self.submissions = []
        self.loaded = loaded
        self.lose_submit_response_once = False
        self.events = []
        self.skip_event_reads = 0

    def _event(self, job_id, event_type):
        self.events.append(SimpleNamespace(
            event_id=len(self.events) + 1, job_id=job_id, event_type=event_type,
        ))

    def subscribeJobEvents(self, after_event_id=0, *, job_id="", follow=False):
        if self.skip_event_reads:
            self.skip_event_reads -= 1
            return iter(())
        return iter(event for event in self.events
                    if event.event_id > after_event_id and (not job_id or event.job_id == job_id))

    def listSessions(self):
        return [SimpleNamespace(
            beacon_hash="beacon-1", listener_hash="listener-1", os="linux", arch="x64", killed=False,
        )]

    def listCommands(self, query):
        return [TeamServerApi_pb2.CommandSpec(
            name=name, kind="module" if name != "loadModule" else "common",
            command_template=template, platforms=["linux", "windows"], archs=["any"],
        ) for name, template in (
            ("whoami", "whoami"), ("ipConfig", "ipConfig"),
            ("hostContext", "hostContext"), ("netstat", "netstat"), ("ps", "ps"),
            ("loadModule", "loadModule {module:q}"),
        )]

    def listModules(self, session):
        return [SimpleNamespace(name=name, state="loaded")
                for name in ("whoami", "ipConfig", "hostContext", "netstat", "ps")] if self.loaded else []

    def listListeners(self):
        return [SimpleNamespace(
            listener_hash="listener-1", type="http", ip="127.0.0.1", port=8080,
            domain="", state=1, session_count=1,
        )]

    def submitJob(self, job_id, operation, payload):
        assert operation == "session_command"
        self.submissions.append((job_id, json.loads(payload)["command"]))
        if job_id not in self.jobs:
            self._event(job_id, "accepted")
            self._event(job_id, "queued")
        job = self.jobs.setdefault(job_id, SimpleNamespace(
            job_id=job_id, state="queued", output_inline=b"", output_size=0,
            error_code="", error_message="",
        ))
        if self.lose_submit_response_once:
            self.lose_submit_response_once = False
            raise RuntimeError("response lost after TeamServer accepted the job")
        return job

    def getJobExecution(self, job_id):
        if job_id not in self.jobs:
            raise MissingJob()
        return self.jobs[job_id]

    def complete(self, job_id, output):
        self.jobs[job_id] = SimpleNamespace(
            job_id=job_id, state="succeeded", output_inline=output,
            output_size=len(output), error_code="", error_message="",
        )
        if (job_id, "loadModule whoami") in self.submissions:
            self.loaded = True
        self._event(job_id, "succeeded")


class ReconProvider:
    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.calls = 0

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        if self.calls <= 3:
            tool_names = {tool.name for tool in kwargs["tools"]}
            assert {"whoami", "ipConfig", "listC2Listeners"} <= tool_names
            name = ("listC2Listeners", "whoami", "ipConfig")[self.calls - 1]
            return LLMCompletionResult(content="", tool_calls=[
                LLMToolCall(id=f"recon-{self.calls}", name=name, arguments_json="{}"),
            ])
        whoami_job = next(job_id for job_id, command in self.grpc_client.submissions if command == "whoami")
        ip_job = next(job_id for job_id, command in self.grpc_client.submissions if command == "ipConfig")
        run_id = whoami_job.removeprefix("skill-").rsplit("-call-", 1)[0]
        return LLMCompletionResult(content=json.dumps({
            "summary": "The host user and network configuration were observed.",
            "observations": [
                {"source_id": f"terminal-{run_id}-1", "finding": "The TeamServer has an HTTP listener."},
                {"source_id": whoami_job, "finding": "The beacon runs as operator."},
                {"source_id": ip_job, "finding": "The host has a network interface."},
            ],
            "limitations": [],
        }))


def test_recon_skill_uses_multiple_capabilities_and_resumes_after_restart(tmp_path):
    assert RECON_HOST.tool_bundles == ("recon.identity", "recon.host")
    grpc_client = ReconGrpc()
    provider = ReconProvider(grpc_client)
    storage_dir = tmp_path / "skills"
    service = C2SkillService(grpc_client, storage_dir=storage_dir, provider=provider)

    run = service.start("recon-host", "beacon-1", "listener-1")
    assert run["mode"] == "agentic_skill"
    assert run["terminal_observations"][0]["tool"] == "listC2Listeners"
    assert [command for _, command in grpc_client.submissions] == ["whoami"]
    whoami_job = grpc_client.submissions[0][0]
    assert run["active_tool_call"] == "call-1"

    grpc_client.complete(whoami_job, b"operator\x00")
    restored = C2SkillService(grpc_client, storage_dir=storage_dir, provider=provider)
    waiting = restored.reconcile(run["run_id"])
    assert [command for _, command in grpc_client.submissions] == ["whoami", "ipConfig"]
    assert waiting["status"] == "running"
    ip_job = grpc_client.submissions[1][0]

    grpc_client.complete(ip_job, b"eth0 10.0.0.5\x00")
    finished = restored.on_job_event(run["run_id"], ip_job, 10)
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "complete", finished["report"]
    assert len(finished["report"]["observations"]) == 3
    assert base64.b64decode(finished["steps"][1]["output_base64"]) == b"eth0 10.0.0.5\x00"
    assert len(grpc_client.submissions) == 2
    assert finished["after_event_id"] >= 6
    assert all(step["observed_event_id"] for step in finished["steps"])


def test_recon_skill_records_event_when_polling_finishes_first(tmp_path):
    grpc_client = ReconGrpc()
    service = C2SkillService(
        grpc_client, storage_dir=tmp_path / "skills", provider=ReconProvider(grpc_client),
    )
    run = service.start("recon-host", "beacon-1", "listener-1")
    first_job = grpc_client.submissions[0][0]
    grpc_client.complete(first_job, b"operator")
    grpc_client.skip_event_reads = 1
    next_run = service.reconcile(run["run_id"])
    assert next_run["steps"][0]["observed_event_id"] == 3
    assert next_run["after_event_id"] >= 3
    assert [command for _, command in grpc_client.submissions] == ["whoami", "ipConfig"]


def test_recon_skill_replays_late_event_after_client_restart(tmp_path):
    grpc_client = ReconGrpc()
    provider = ReconProvider(grpc_client)
    root = tmp_path / "skills"
    service = C2SkillService(grpc_client, storage_dir=root, provider=provider)
    run = service.start("recon-host", "beacon-1", "listener-1")
    first_job = grpc_client.submissions[0][0]
    restored = C2SkillService(grpc_client, storage_dir=root, provider=provider)
    grpc_client.complete(first_job, b"operator")
    resumed = restored.reconcile(run["run_id"])
    assert resumed["steps"][0]["observed_event_id"] == 3
    assert resumed["after_event_id"] >= 3
    assert [command for _, command in grpc_client.submissions] == ["whoami", "ipConfig"]
    assert restored.reconcile(run["run_id"])["after_event_id"] >= 3
    assert [command for _, command in grpc_client.submissions] == ["whoami", "ipConfig"]


def test_recon_skill_collects_linux_host_and_teamserver_context(tmp_path):
    grpc_client = ReconGrpc()

    class HostProvider:
        def __init__(self):
            self.calls = 0

        def complete_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls <= 4:
                name = ("listC2Listeners", "whoami", "ipConfig", "hostContext")[self.calls - 1]
                return LLMCompletionResult(content="", tool_calls=[
                    LLMToolCall(id=f"host-{self.calls}", name=name, arguments_json="{}"),
                ])
            jobs = {command: job_id for job_id, command in grpc_client.submissions}
            run_id = jobs["whoami"].removeprefix("skill-").rsplit("-call-", 1)[0]
            return LLMCompletionResult(content=json.dumps({
                "summary": "The selected Linux host and TeamServer listener were inspected.",
                "observations": [
                    {"source_id": f"terminal-{run_id}-1", "finding": "A TeamServer listener is active."},
                    {"source_id": jobs["whoami"], "finding": "The user is operator."},
                    {"source_id": jobs["ipConfig"], "finding": "The host has eth0."},
                    {"source_id": jobs["hostContext"], "finding": "The host uses Linux."},
                ],
                "limitations": [],
            }))

    service = C2SkillService(
        grpc_client, storage_dir=tmp_path / "skills", provider=HostProvider(),
    )
    run = service.start("recon-host", "beacon-1", "listener-1")
    assert "hostContext" in run["allowed_tools"]
    assert run["terminal_observations"][0]["tool"] == "listC2Listeners"
    for command, output in (
        ("whoami", b"operator"), ("ipConfig", b"eth0 10.0.0.5"),
        ("hostContext", b"Hostname: test\nKernel: Linux\n"),
    ):
        job_id = next(job for job, submitted in grpc_client.submissions if submitted == command)
        grpc_client.complete(job_id, output)
        run = service.reconcile(run["run_id"])
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete"
    assert {item["tool"] for item in run["terminal_observations"]} == {"listC2Listeners"}
    assert [step["command"] for step in run["steps"]] == ["whoami", "ipConfig", "hostContext"]


@pytest.mark.parametrize("citation_style", ["invented", "combined"])
def test_recon_skill_preserves_report_with_unusual_citation(tmp_path, citation_style):
    grpc_client = ReconGrpc()

    class InvalidCitationProvider(ReconProvider):
        def complete_with_tools(self, **kwargs):
            if self.calls >= 3:
                self.calls += 1
                whoami_job = next(job for job, command in grpc_client.submissions if command == "whoami")
                run_id = whoami_job.removeprefix("skill-").rsplit("-call-", 1)[0]
                citation = (
                    f"{whoami_job}; terminal-{run_id}-1"
                    if citation_style == "combined" else "invented"
                )
                return LLMCompletionResult(content=json.dumps({
                    "summary": "Host observations are available.", "observations": [
                        {"source_id": whoami_job, "finding": "The user is operator."},
                        {"source_id": citation, "finding": "A comparison needs review."},
                    ], "limitations": [],
                }))
            return super().complete_with_tools(**kwargs)

    provider = InvalidCitationProvider(grpc_client)
    service = C2SkillService(grpc_client, storage_dir=tmp_path / "skills", provider=provider)
    run = service.start("recon-host", "beacon-1", "listener-1")
    first = grpc_client.submissions[0][0]
    grpc_client.complete(first, b"operator")
    service.reconcile(run["run_id"])
    second = grpc_client.submissions[1][0]
    grpc_client.complete(second, b"eth0")
    finished = service.reconcile(run["run_id"])
    report = finished["report"]
    assert report["outcome"] == "complete"
    assert report["analysis_status"] == "available"
    assert [item["finding"] for item in report["observations"]] == [
        "The user is operator.", "A comparison needs review.",
    ]
    assert len(report["validation_warnings"]) == 1
    assert "source_id" in report["validation_warnings"][0]
    assert report["observations"][1]["source_id"] in report["raw_output"]


@pytest.mark.parametrize("model_output", [
    '{"summary":"Observed user and interface.","observations":[],"limitations":[],"extra_note":"Keep this."}',
    "Observed user and interface, but the report was not JSON.",
])
def test_recon_skill_retains_model_output_outside_schema(tmp_path, model_output):
    grpc_client = ReconGrpc()

    class LooseProvider(ReconProvider):
        def complete_with_tools(self, **kwargs):
            if self.calls >= 3:
                self.calls += 1
                return LLMCompletionResult(content=model_output)
            return super().complete_with_tools(**kwargs)

    service = C2SkillService(
        grpc_client, storage_dir=tmp_path / "skills", provider=LooseProvider(grpc_client),
    )
    run = service.start("recon-host", "beacon-1", "listener-1")
    for command, output in (("whoami", b"operator"), ("ipConfig", b"eth0")):
        job_id = next(job for job, submitted in grpc_client.submissions if submitted == command)
        grpc_client.complete(job_id, output)
        run = service.reconcile(run["run_id"])

    report = run["report"]
    assert report["outcome"] == "complete"
    assert report["raw_output"] == model_output
    assert report["validation_warnings"]
    if model_output.startswith("{"):
        assert report["analysis_status"] == "available"
        assert report["summary"] == "Observed user and interface."
    else:
        assert report["analysis_status"] == "raw"
        assert report["summary"] == model_output


def test_recon_skill_manual_no_result_keeps_partial_evidence(tmp_path):
    grpc_client = ReconGrpc()

    class NoResultProvider:
        def __init__(self):
            self.calls = 0

        def complete_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return LLMCompletionResult(content="", tool_calls=[
                    LLMToolCall(id="whoami", name="whoami", arguments_json="{}"),
                ])
            return LLMCompletionResult(content=json.dumps({
                "summary": "The user identity is unverified because the beacon did not return.",
                "observations": [], "limitations": ["whoami did not return."],
            }))

    service = C2SkillService(
        grpc_client, storage_dir=tmp_path / "skills", provider=NoResultProvider(),
    )
    run = service.start("recon-host", "beacon-1", "listener-1")
    job_id = grpc_client.submissions[0][0]
    finished = service.confirm_no_result(run["run_id"], "Beacon disconnected")
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "partial"
    assert finished["steps"][0]["manual_reason"] == "Beacon disconnected"
    assert len(grpc_client.submissions) == 1

    grpc_client.complete(job_id, b"late user")
    late = service.on_job_event(run["run_id"], job_id, 11)
    assert late["steps"][0]["late_server_state"] == "succeeded"
    assert late["report"] == finished["report"]


def test_recon_skill_loads_missing_module_before_command_once(tmp_path):
    grpc_client = ReconGrpc(loaded=False)

    class WhoamiProvider:
        def __init__(self):
            self.calls = 0

        def complete_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return LLMCompletionResult(content="", tool_calls=[
                    LLMToolCall(id="identity", name="whoami", arguments_json="{}"),
                ])
            job_id = next(job for job, command in grpc_client.submissions if command == "whoami")
            return LLMCompletionResult(content=json.dumps({
                "summary": "The beacon runs as operator.",
                "observations": [{"source_id": job_id, "finding": "The user is operator."}],
                "limitations": [],
            }))

    provider = WhoamiProvider()
    service = C2SkillService(grpc_client, storage_dir=tmp_path / "skills", provider=provider)
    run = service.start("recon-host", "beacon-1", "listener-1")
    assert [command for _, command in grpc_client.submissions] == ["loadModule whoami"]
    load_job = grpc_client.submissions[0][0]
    grpc_client.complete(load_job, b"loaded")
    waiting = service.reconcile(run["run_id"])
    assert [command for _, command in grpc_client.submissions] == ["loadModule whoami", "whoami"]
    assert waiting["status"] == "running"
    command_job = grpc_client.submissions[1][0]
    grpc_client.complete(command_job, b"operator")
    finished = service.reconcile(run["run_id"])
    assert finished["report"]["outcome"] == "partial"
    assert "ipConfig" in finished["report"]["limitations"][-1]
    assert len(grpc_client.submissions) == 2


def test_recon_skill_checks_stable_job_after_lost_submit_response(tmp_path):
    grpc_client = ReconGrpc()
    grpc_client.lose_submit_response_once = True

    class WhoamiProvider:
        def __init__(self):
            self.calls = 0

        def complete_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return LLMCompletionResult(content="", tool_calls=[
                    LLMToolCall(id="identity", name="whoami", arguments_json="{}"),
                ])
            job_id = grpc_client.submissions[0][0]
            return LLMCompletionResult(content=json.dumps({
                "summary": "The user is operator.",
                "observations": [{"source_id": job_id, "finding": "The account is operator."}],
                "limitations": [],
            }))

    provider = WhoamiProvider()
    storage_dir = tmp_path / "skills"
    service = C2SkillService(grpc_client, storage_dir=storage_dir, provider=provider)
    run = service.start("recon-host", "beacon-1", "listener-1")
    assert run["steps"][0]["state"] == "submission_uncertain"
    restored = C2SkillService(grpc_client, storage_dir=storage_dir, provider=provider)
    restored.reconcile(run["run_id"])
    assert len(grpc_client.submissions) == 1
    grpc_client.complete(grpc_client.submissions[0][0], b"operator")
    finished = restored.reconcile(run["run_id"])
    assert finished["report"]["outcome"] == "partial"
    assert "ipConfig" in finished["report"]["limitations"][-1]
    assert len(grpc_client.submissions) == 1


class NetworkProvider:
    """Choose the next tool from completed observations, including the ps branch."""

    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.calls = 0

    def complete_with_tools(self, **kwargs):
        self.calls += 1
        names = {tool.name for tool in kwargs["tools"]}
        if names:
            assert {"ipConfig", "hostContext", "netstat", "ps", "listC2Listeners"} <= names
        jobs = {command: job_id for job_id, command in self.grpc_client.submissions}
        if not jobs:
            name = "listC2Listeners" if self.calls == 1 else "ipConfig"
        elif "ipConfig" not in jobs:
            name = "ipConfig"
        else:
            ip_output = self.grpc_client.jobs[jobs["ipConfig"]].output_inline
            if b"no default route" in ip_output and "hostContext" not in jobs:
                name = "hostContext"
            elif "netstat" not in jobs:
                name = "netstat"
            elif "hostContext" not in jobs:
                name = "hostContext"
            elif b"pid=4242" in self.grpc_client.jobs[jobs["netstat"]].output_inline and "ps" not in jobs:
                name = "ps"
            else:
                run_id = jobs["ipConfig"].removeprefix("skill-").rsplit("-call-", 1)[0]
                listener_id = f"terminal-{run_id}-1"
                return LLMCompletionResult(content=json.dumps({
                    "summary": f"Compared host socket {jobs['netstat']} with TeamServer listener {listener_id}.",
                    "observations": [
                        {"source_id": listener_id, "finding": "TeamServer reports an HTTP listener on 127.0.0.1:8080."},
                        *({"source_id": job_id, "finding": f"Observed {command} output."}
                          for command, job_id in jobs.items()),
                    ],
                    "limitations": [],
                }))
        return LLMCompletionResult(content="", tool_calls=[
            LLMToolCall(id=f"network-{self.calls}", name=name, arguments_json="{}"),
        ])


@pytest.mark.parametrize(
    ("ip_output", "netstat_output", "expected_commands"),
    [
        (
            b"eth0 10.0.0.5; no default route", b"TCP 10.0.0.5:443 LISTEN pid=?",
            ["ipConfig", "hostContext", "netstat"],
        ),
        (
            b"eth0 10.0.0.5; default via 10.0.0.1", b"TCP 10.0.0.5:443 LISTEN pid=4242",
            ["ipConfig", "netstat", "hostContext", "ps"],
        ),
    ],
)
def test_recon_network_adapts_and_resumes_after_restart(
    tmp_path, ip_output, netstat_output, expected_commands,
):
    skill = SKILLS["recon-network"]
    assert skill.tool_bundles == ("recon.network",)
    assert skill.required_tools == ("ipConfig", "hostContext", "netstat", "listC2Listeners")
    grpc_client = ReconGrpc()
    provider = NetworkProvider(grpc_client)
    storage_dir = tmp_path / "skills"
    service = C2SkillService(grpc_client, storage_dir=storage_dir, provider=provider)

    run = service.start("recon-network", "beacon-1", "listener-1")
    assert run["allowed_tools"] == ["ipConfig", "hostContext", "netstat", "ps", "listC2Listeners"]
    assert [item["tool"] for item in run["terminal_observations"]] == ["listC2Listeners"]
    assert [command for _, command in grpc_client.submissions] == ["ipConfig"]
    assert service.reconcile(run["run_id"])["status"] == "running"
    assert len(grpc_client.submissions) == 1

    # Simulate the client closing while a beacon result is outstanding.
    service = C2SkillService(grpc_client, storage_dir=storage_dir, provider=provider)
    for command in expected_commands:
        job_id = next(job for job, submitted in grpc_client.submissions if submitted == command)
        output = {
            "ipConfig": ip_output,
            "hostContext": b"Hostname: test; IPv4 route: 10.0.0.0/24",
            "netstat": netstat_output,
            "ps": b"4242 web-service",
        }[command]
        grpc_client.complete(job_id, output)
        run = service.reconcile(run["run_id"])

    assert [command for _, command in grpc_client.submissions] == expected_commands
    assert run["status"] == "completed"
    assert run["report"]["outcome"] == "complete"
    assert {item["source_id"] for item in run["report"]["observations"]} == {
        *(job_id for job_id, _ in grpc_client.submissions),
        run["terminal_observations"][0]["observation_id"],
    }
    assert run["after_event_id"] >= len(expected_commands) * 3
    assert service.reconcile(run["run_id"])["report"] == run["report"]
    assert len(grpc_client.submissions) == len(expected_commands)


def test_recon_network_no_beacon_result_is_partial_and_not_resent(tmp_path):
    grpc_client = ReconGrpc()

    class NoResultProvider:
        def __init__(self):
            self.calls = 0

        def complete_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls <= 2:
                name = ("listC2Listeners", "ipConfig")[self.calls - 1]
                return LLMCompletionResult(content="", tool_calls=[
                    LLMToolCall(id=f"no-result-{self.calls}", name=name, arguments_json="{}"),
                ])
            run_id = grpc_client.submissions[0][0].removeprefix("skill-").rsplit("-call-", 1)[0]
            return LLMCompletionResult(content=json.dumps({
                "summary": "The host network state could not be verified.",
                "observations": [{
                    "source_id": f"terminal-{run_id}-1",
                    "finding": "TeamServer reports an HTTP listener.",
                }],
                "limitations": ["ipConfig did not return, so host addresses and sockets are unknown."],
            }))

    service = C2SkillService(
        grpc_client, storage_dir=tmp_path / "skills", provider=NoResultProvider(),
    )
    run = service.start("recon-network", "beacon-1", "listener-1")
    job_id = grpc_client.submissions[0][0]
    finished = service.confirm_no_result(run["run_id"], "Beacon disconnected")
    assert finished["status"] == "completed"
    assert finished["report"]["outcome"] == "partial"
    assert finished["report"]["observations"][0]["source_id"] == finished["terminal_observations"][0]["observation_id"]
    assert "ipConfig" in finished["report"]["limitations"][-1]
    assert grpc_client.submissions == [(job_id, "ipConfig")]

    grpc_client.complete(job_id, b"late interface")
    late = service.on_job_event(run["run_id"], job_id, 4)
    assert late["steps"][0]["late_server_state"] == "succeeded"
    assert late["report"] == finished["report"]


def test_skill_passes_full_large_command_output_with_completeness_metadata(tmp_path):
    service = C2SkillService(ReconGrpc(), storage_dir=tmp_path / "skills")
    output = b"socket entry\n" * 3000
    step = service._new_step("call-1", "netstat", "netstat", "job-1", state="succeeded")
    step["output_base64"] = base64.b64encode(output).decode("ascii")
    step["output_size"] = len(output)
    run = {"active_tool_call": "call-1", "steps": [step]}

    content, ok = service._agentic_skill_tool_content(run)
    received = json.loads(content)
    assert ok
    assert received["output"] == output.decode("utf-8")
    assert received["stored_output_size"] == len(output)
    assert received["output_complete"] is True

    step["output_size"] += 100
    incomplete, _ = service._agentic_skill_tool_content(run)
    assert json.loads(incomplete)["output_complete"] is False


def test_skill_reports_incomplete_server_output_without_losing_analysis(tmp_path):
    service = C2SkillService(ReconGrpc(), storage_dir=tmp_path / "skills")
    step = service._new_step("call-1", "netstat", "netstat", "job-1", state="succeeded")
    step["output_base64"] = base64.b64encode(b"TCP 0.0.0.0:8443 LISTEN\n").decode("ascii")
    step["output_size"] = 100
    run = {
        "run_id": "incomplete-output", "steps": [step], "terminal_observations": [],
        "completion_tools": ["netstat"], "manual_uncertainty": False,
    }
    result = SimpleNamespace(
        status="completed", raw_content="", failure_reason="",
        output={"summary": "A listener was observed.", "observations": [
            {"source_id": "job-1", "finding": "TCP 8443 is listening."},
        ], "limitations": []},
    )
    report = service._apply_agentic_skill_result(run, result)["report"]
    assert report["outcome"] == "partial"
    assert report["summary"] == "A listener was observed."
    assert report["observations"][0]["source_id"] == "job-1"
    assert "netstat returned" in report["limitations"][0]
    assert report["evidence"][0]["output_complete"] is False
