import json
import os
import stat
from unittest import mock

from C2Client.grpcClient import GrpcClient, TeamServerApi_pb2


def test_client_audit_records_exact_stop_target_without_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_LOG_DIR", str(tmp_path))
    client = object.__new__(GrpcClient)
    client.client_id = "client-1"
    client.username = "operator"
    client.endpoint = "127.0.0.1:50051"
    client.metadata = []
    client.session_stop_timeout_seconds = 3
    client.stub = mock.MagicMock()
    client.stub.StopSession.return_value = TeamServerApi_pb2.OperationAck(
        status=TeamServerApi_pb2.OK, session_beacon_hash="child-beacon",
        session_listener_hash="current-listener",
    )
    client._unary_rpc = lambda operation, call: call()

    selector = TeamServerApi_pb2.SessionSelector(beacon_hash="child-beacon", listener_hash="child-listener")
    client.stopSession(selector)

    path = tmp_path / "Client.audit.jsonl"
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [entry["outcome"] for entry in records] == ["requested", "accepted"]
    assert records[0]["details"] == {"beacon_hash": "child-beacon", "listener_hash": "child-listener"}
    assert records[1]["details"] == {
        "beacon_hash": "child-beacon", "listener_hash": "child-listener",
        "resolved_beacon_hash": "child-beacon", "resolved_listener_hash": "current-listener",
    }
    assert all(entry["actor"] == "operator" and entry["action"] == "StopSession" for entry in records)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_client_audit_omits_job_command_and_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_LOG_DIR", str(tmp_path))
    client = object.__new__(GrpcClient)
    client.client_id = "client-1"
    client.username = "operator"
    client.endpoint = "127.0.0.1:50051"
    client.metadata = []
    client.stub = mock.MagicMock()
    client.stub.SubmitJob.return_value = TeamServerApi_pb2.JobExecutionRecord(job_id="job-1", state="queued")
    client._unary_rpc = lambda operation, call: call()

    client.submitJob("job-1", "session_command", json.dumps({
        "beacon_hash": "child-beacon", "listener_hash": "child-listener", "command": "password secret-value",
    }))

    text = (tmp_path / "Client.audit.jsonl").read_text(encoding="utf-8")
    assert "secret-value" not in text
    records = [json.loads(line) for line in text.splitlines()]
    assert records[-1]["details"] == {"job_id": "job-1", "operation": "session_command",
                                       "beacon_hash": "child-beacon", "listener_hash": "child-listener",
                                       "state": "queued"}


def test_client_auth_audit_omits_password_and_token(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_LOG_DIR", str(tmp_path))
    client = object.__new__(GrpcClient)
    client.client_id = "client-1"
    client.endpoint = "127.0.0.1:50051"
    client.auth_generation = 0
    client._notify_rpc_status = lambda operation, ok: None
    client.stub = mock.MagicMock()
    client.stub.Authenticate.return_value = TeamServerApi_pb2.AuthResponse(
        status=TeamServerApi_pb2.OK, token="private-token",
    )

    assert client._authenticate("operator", "private-password") == "private-token"
    text = (tmp_path / "Client.audit.jsonl").read_text(encoding="utf-8")
    assert "private-password" not in text
    assert "private-token" not in text
    assert [json.loads(line)["outcome"] for line in text.splitlines()] == ["requested", "accepted"]
