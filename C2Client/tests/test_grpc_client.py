import grpc
from unittest import mock

import pytest

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client.grpcClient import GrpcClient, TeamServerApi_pb2_grpc


class DummyFuture:
    def result(self, timeout=None):
        return None


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
    stub.ListArtifacts.assert_called_once_with(query, metadata=client.metadata)
    assert events == [("ListArtifacts", True, "")]


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
