import grpc
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import mock

import pytest

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client.grpcClient import GrpcClient, TeamServerApi_pb2, TeamServerApi_pb2_grpc


class DummyFuture:
    def result(self, timeout=None):
        return None


class FakeRpcError(grpc.RpcError):
    def __init__(self, code):
        self._code = code

    def code(self):
        return self._code

    def details(self):
        return self._code.name


def test_session_history_uses_separate_rpc_from_active_sessions():
    client = object.__new__(GrpcClient)
    active = TeamServerApi_pb2.Session(beacon_hash="active", archived=False)
    archived = TeamServerApi_pb2.Session(beacon_hash="old", archived=True)
    client.metadata = []
    client.stub = mock.MagicMock()
    client.stub.ListSessions.return_value = iter((active,))
    client.stub.ListSessionHistory.return_value = iter((active, archived))
    client._stream_rpc = lambda operation, call: call()
    assert list(client.listSessions()) == [active]
    assert list(client.listSessionHistory()) == [active, archived]
    assert client.stub.ListSessions.call_count == 1
    assert client.stub.ListSessionHistory.call_count == 1


def test_session_history_falls_back_to_active_list_on_old_server():
    client = object.__new__(GrpcClient)
    client.metadata = []
    client.stub = mock.MagicMock()
    active = TeamServerApi_pb2.Session(beacon_hash="active")
    client.stub.ListSessionHistory.side_effect = FakeRpcError(grpc.StatusCode.UNIMPLEMENTED)
    client.stub.ListSessions.return_value = iter((active,))
    client._stream_rpc = lambda operation, call: call()
    assert list(client.listSessionHistory()) == [active]


def test_grpc_client_reads_certificate_and_sets_metadata(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    assert ("authorization", "Bearer tok") in client.metadata
    assert ("clientid", client.client_id) in client.metadata
    assert client.endpoint == "127.0.0.1:50051"
    assert client.ca_cert_path == str(cert)


def test_grpc_client_reports_rpc_status(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.ListListeners.return_value = iter([])
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    events = []
    client.set_status_callback(lambda operation, ok, message: events.append((operation, ok, message)))

    assert list(client.listListeners()) == []
    assert events == [("ListListeners", True, "")]


def test_grpc_client_lists_artifacts(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    query = object()
    artifact = object()
    stub.ListArtifacts.return_value = iter([artifact])
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    events = []
    client.set_status_callback(lambda operation, ok, message: events.append((operation, ok, message)))

    assert list(client.listArtifacts(query)) == [artifact]
    stub.ListArtifacts.assert_called_once_with(query, metadata=client.metadata, timeout=10.0)
    assert events == [("ListArtifacts", True, "")]


def test_terminal_rpc_uses_configurable_deadline(monkeypatch):
    client = object.__new__(GrpcClient)
    client.stub = mock.MagicMock()
    client.metadata = []
    client._unary_rpc = lambda operation, call: call()
    monkeypatch.setenv("C2_GRPC_TERMINAL_TIMEOUT_SEC", "7")

    command = TeamServerApi_pb2.TerminalCommandRequest(command="reloadModules")
    client.executeTerminalCommand(command)

    client.stub.ExecuteTerminalCommand.assert_called_once_with(
        command, metadata=[], timeout=7,
    )


def test_grpc_client_downloads_artifact(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    response = object()
    stub.DownloadArtifact.return_value = response
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    events = []
    client.set_status_callback(lambda operation, ok, message: events.append((operation, ok, message)))

    assert client.downloadArtifact("artifact-1") is response
    request = stub.DownloadArtifact.call_args.args[0]
    assert isinstance(request, TeamServerApi_pb2.ArtifactSelector)
    assert request.artifact_id == "artifact-1"
    assert stub.DownloadArtifact.call_args.kwargs["metadata"] == client.metadata
    assert events == [("DownloadArtifact", True, "")]


def test_grpc_client_uploads_artifact(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    response = object()
    stub.UploadArtifact.return_value = response
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    events = []
    client.set_status_callback(lambda operation, ok, message: events.append((operation, ok, message)))

    assert client.uploadArtifact("payload.bin", b"payload", "windows", "x64") is response
    request = stub.UploadArtifact.call_args.args[0]
    assert isinstance(request, TeamServerApi_pb2.ArtifactUploadRequest)
    assert request.name == "payload.bin"
    assert request.data == b"payload"
    assert request.platform == "windows"
    assert request.arch == "x64"
    assert stub.UploadArtifact.call_args.kwargs["metadata"] == client.metadata
    assert events == [("UploadArtifact", True, "")]


def test_grpc_client_deletes_artifact(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    response = object()
    stub.DeleteGeneratedArtifact.return_value = response
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    events = []
    client.set_status_callback(lambda operation, ok, message: events.append((operation, ok, message)))

    assert client.deleteArtifact("artifact-1") is response
    request = stub.DeleteGeneratedArtifact.call_args.args[0]
    assert isinstance(request, TeamServerApi_pb2.ArtifactSelector)
    assert request.artifact_id == "artifact-1"
    assert stub.DeleteGeneratedArtifact.call_args.kwargs["metadata"] == client.metadata
    assert events == [("DeleteGeneratedArtifact", True, "")]


def test_grpc_client_lists_commands(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    query = object()
    command = object()
    stub.ListCommands.return_value = iter([command])
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    events = []
    client.set_status_callback(lambda operation, ok, message: events.append((operation, ok, message)))

    assert list(client.listCommands(query)) == [command]
    stub.ListCommands.assert_called_once_with(query, metadata=client.metadata)
    assert events == [("ListCommands", True, "")]


def test_command_result_stream_has_deadline_for_worker_shutdown(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.SubscribeJobEvents.return_value = iter([])
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)
    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    selector = TeamServerApi_pb2.SessionSelector(beacon_hash="beacon", listener_hash="listener")

    assert list(client.streamSessionCommandResults(selector)) == []

    stub.SubscribeJobEvents.assert_called_once()
    request = stub.SubscribeJobEvents.call_args.args[0]
    assert isinstance(request, TeamServerApi_pb2.SubscribeJobEventsRequest)
    assert request.after_event_id == 0
    assert request.follow is False
    assert stub.SubscribeJobEvents.call_args.kwargs["metadata"] == client.metadata


def test_v2_job_submit_get_and_cursor(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    expected = TeamServerApi_pb2.JobExecutionRecord(job_id="id-1", state="succeeded")
    stub.SubmitJob.return_value = expected
    stub.GetJobExecution.return_value = expected
    stub.SubscribeJobEvents.return_value = iter([
        TeamServerApi_pb2.JobEventRecord(event_id=9, job_id="id-1", event_type="succeeded")])
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)
    client = GrpcClient("127.0.0.1", 50051, False, token="tok")

    assert client.submitJob("id-1", "echo", "hello", origin="hook:demo:invocation") is expected
    assert stub.SubmitJob.call_args.args[0].job_id == "id-1"
    assert stub.SubmitJob.call_args.args[0].origin == "hook:demo:invocation"
    assert client.getJobExecution("id-1") is expected
    assert [event.event_id for event in client.subscribeJobEvents(8)] == [9]
    assert stub.SubscribeJobEvents.call_args.args[0].after_event_id == 8


def test_session_result_uses_event_state_when_late_result_already_arrived(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.SubscribeJobEvents.return_value = iter([
        TeamServerApi_pb2.JobEventRecord(event_id=10, job_id="job", event_type="outcome_unknown"),
        TeamServerApi_pb2.JobEventRecord(event_id=11, job_id="job", event_type="succeeded"),
    ])
    stub.GetJobExecution.return_value = TeamServerApi_pb2.JobExecutionRecord(
        job_id="job", operation="session_command", state="succeeded",
        normalized_input='{"beacon_hash":"beacon","listener_hash":"listener","command":"whoami"}',
        output_inline=b"ok",
    )
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)
    client = GrpcClient("127.0.0.1", 50051, False, token="tok")
    selector = TeamServerApi_pb2.SessionSelector(beacon_hash="beacon", listener_hash="listener")
    results = list(client.streamSessionCommandResults(selector))
    assert [result.job_state for result in results] == ["outcome_unknown", "succeeded"]
    assert [result.status for result in results] == [TeamServerApi_pb2.KO, TeamServerApi_pb2.OK]
    assert [result.output for result in results] == [b"", b"ok"]


def test_session_result_cursor_retries_after_job_lookup_failure():
    client = object.__new__(GrpcClient)
    client._session_cursors = {}
    selector = TeamServerApi_pb2.SessionSelector(beacon_hash="beacon", listener_hash="listener")
    events = [
        TeamServerApi_pb2.JobEventRecord(event_id=5, job_id="job", event_type="queued"),
        TeamServerApi_pb2.JobEventRecord(event_id=6, job_id="job", event_type="succeeded"),
    ]
    requested_cursors = []

    def subscribe(*, after_event_id, follow):
        requested_cursors.append(after_event_id)
        return (event for event in events if event.event_id > after_event_id)

    client.subscribeJobEvents = subscribe
    job = TeamServerApi_pb2.JobExecutionRecord(
        job_id="job", operation="session_command", state="succeeded",
        normalized_input='{"beacon_hash":"beacon","listener_hash":"listener","command":"whoami"}',
        output_inline=b"user",
    )
    attempts = 0

    def get_job(_job_id):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("transient lookup failure")
        return job

    client.getJobExecution = get_job
    with pytest.raises(RuntimeError, match="transient lookup failure"):
        list(client.streamSessionCommandResults(selector))
    assert client._session_cursors[("listener", "beacon")] == 5

    results = list(client.streamSessionCommandResults(selector))
    assert [result.event_id for result in results] == [6]
    assert results[0].output == b"user"
    assert requested_cursors == [0, 5]
    assert client._session_cursors[("listener", "beacon")] == 6


def test_session_result_cursor_replays_if_consumer_stops_before_acknowledging():
    client = object.__new__(GrpcClient)
    client._session_cursors = {}
    selector = TeamServerApi_pb2.SessionSelector(beacon_hash="beacon", listener_hash="listener")
    event = TeamServerApi_pb2.JobEventRecord(event_id=7, job_id="job", event_type="succeeded")
    client.subscribeJobEvents = lambda *, after_event_id, follow: (
        item for item in [event] if item.event_id > after_event_id)
    client.getJobExecution = lambda _job_id: TeamServerApi_pb2.JobExecutionRecord(
        job_id="job", operation="session_command", state="succeeded",
        normalized_input='{"beacon_hash":"beacon","listener_hash":"listener","command":"whoami"}',
        output_inline=b"user",
    )

    stream = client.streamSessionCommandResults(selector)
    assert next(stream).event_id == 7
    stream.close()
    assert client._session_cursors == {}
    assert [result.event_id for result in client.streamSessionCommandResults(selector)] == [7]
    assert client._session_cursors[("listener", "beacon")] == 7


def test_grpc_client_credential_vault_rpcs(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    summary = object()
    detail = object()
    ack = object()
    stub.ListCredentials.return_value = iter([summary])
    stub.GetCredential.return_value = detail
    stub.AddCredential.return_value = ack
    stub.UpdateCredential.return_value = ack
    stub.DeleteCredential.return_value = ack
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")

    query = TeamServerApi_pb2.CredentialQuery(username="alice")
    assert list(client.listCredentials(query)) == [summary]
    stub.ListCredentials.assert_called_once_with(query, metadata=client.metadata)

    assert client.getCredential("cred-1", reveal_secret=True) is detail
    selector = stub.GetCredential.call_args.args[0]
    assert selector.credential_id == "cred-1"
    assert selector.reveal_secret is True

    request = TeamServerApi_pb2.CredentialUpsertRequest(username="alice")
    assert client.addCredential(request) is ack
    stub.AddCredential.assert_called_once_with(request, metadata=client.metadata)
    assert client.updateCredential(request) is ack
    stub.UpdateCredential.assert_called_once_with(request, metadata=client.metadata)
    assert client.deleteCredential("cred-1") is ack
    delete_selector = stub.DeleteCredential.call_args.args[0]
    assert delete_selector.credential_id == "cred-1"


def test_grpc_client_uses_env_certificate_and_grpc_options(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setenv("C2_GRPC_MAX_MESSAGE_MB", "42")
    monkeypatch.setenv("C2_GRPC_CONNECT_TIMEOUT_MS", "2500")
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())

    captured = {}

    def fake_secure_channel(target, credentials, options):
        captured["target"] = target
        captured["options"] = options
        return object()

    class CapturingFuture:
        def result(self, timeout=None):
            captured["timeout"] = timeout
            return None

    monkeypatch.setattr(grpc, "secure_channel", fake_secure_channel)
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: CapturingFuture())
    stub = mock.MagicMock()
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="tok")

    assert client.ca_cert_path == str(cert.resolve())
    assert captured["target"] == "127.0.0.1:50051"
    assert ("grpc.max_send_message_length", 42 * 1024 * 1024) in captured["options"]
    assert ("grpc.max_receive_message_length", 42 * 1024 * 1024) in captured["options"]
    assert captured["timeout"] == 2.5


def test_grpc_client_rejects_missing_configured_certificate(tmp_path, monkeypatch):
    missing_cert = tmp_path / "missing.crt"
    monkeypatch.setenv("C2_CERT_PATH", str(missing_cert))

    with pytest.raises(ValueError, match="configured certificate not found"):
        GrpcClient("127.0.0.1", 50051, False, token="tok")


def test_grpc_client_connection_error(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())

    class FailingFuture:
        def result(self, timeout=None):
            raise grpc.RpcError("err")

    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: FailingFuture())

    with pytest.raises(ValueError):
        GrpcClient("127.0.0.1", 50051, False)


def test_client_reauthenticates_after_server_restart(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.Authenticate.side_effect = [
        TeamServerApi_pb2.AuthResponse(status=TeamServerApi_pb2.OK, token="old"),
        TeamServerApi_pb2.AuthResponse(status=TeamServerApi_pb2.OK, token="new"),
    ]

    def list_listeners(_request, *, metadata, timeout):
        assert timeout == 3.0
        if ("authorization", "Bearer old") in metadata:
            raise FakeRpcError(grpc.StatusCode.UNAUTHENTICATED)
        return iter(["restored"])

    stub.ListListeners.side_effect = list_listeners
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, username="admin", password="secret")
    assert list(client.listListeners()) == ["restored"]
    assert stub.Authenticate.call_count == 2
    assert stub.ListListeners.call_count == 2
    assert ("authorization", "Bearer new") in client.metadata


def test_unavailable_mutation_is_not_replayed(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.AddListener.side_effect = FakeRpcError(grpc.StatusCode.UNAVAILABLE)
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, token="existing")
    with pytest.raises(grpc.RpcError):
        client.addListener(object())
    stub.AddListener.assert_called_once()


def test_listener_mutations_have_deadlines_and_auth_advertises_types(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setenv("C2_LISTENER_MUTATION_TIMEOUT_SECONDS", "6")
    monkeypatch.setenv("C2_SESSION_STOP_TIMEOUT_SECONDS", "7")
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.Authenticate.return_value = TeamServerApi_pb2.AuthResponse(
        status=TeamServerApi_pb2.OK, token="token",
        available_listener_types=["http", "https", "tcp", "dns"],
    )
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)

    client = GrpcClient("127.0.0.1", 50051, False, username="admin", password="secret")
    assert client.available_listener_types == ("http", "https", "tcp", "dns")
    assert client.auth_generation == 1
    client.addListener(TeamServerApi_pb2.Listener(type="tcp", ip="127.0.0.1", port=4444))
    client.stopListener(TeamServerApi_pb2.ListenerSelector(listener_hash="listener"))
    client.stopSession(TeamServerApi_pb2.SessionSelector(beacon_hash="beacon", listener_hash="listener"))
    assert stub.AddListener.call_args.kwargs["timeout"] == 6
    assert stub.StopListener.call_args.kwargs["timeout"] == 6
    assert stub.StopSession.call_args.kwargs["timeout"] == 7


def test_parallel_polls_share_one_token_refresh(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())
    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: DummyFuture())
    stub = mock.MagicMock()
    stub.Authenticate.side_effect = [
        TeamServerApi_pb2.AuthResponse(status=TeamServerApi_pb2.OK, token="old"),
        TeamServerApi_pb2.AuthResponse(status=TeamServerApi_pb2.OK, token="new"),
    ]
    old_token_calls = Barrier(2)

    def list_listeners(_request, *, metadata, timeout):
        if ("authorization", "Bearer old") in metadata:
            old_token_calls.wait(timeout=2)
            raise FakeRpcError(grpc.StatusCode.UNAUTHENTICATED)
        return iter(["restored"])

    stub.ListListeners.side_effect = list_listeners
    monkeypatch.setattr(TeamServerApi_pb2_grpc, "TeamServerApiStub", lambda channel: stub)
    client = GrpcClient("127.0.0.1", 50051, False, username="admin", password="secret")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: list(client.listListeners()), range(2)))

    assert results == [["restored"], ["restored"]]
    assert stub.Authenticate.call_count == 2
