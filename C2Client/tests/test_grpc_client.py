import grpc
import os
from types import SimpleNamespace
from unittest import mock

import pytest

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

from C2Client.grpcClient import GrpcClient, TeamServerApi_pb2_grpc


class DummyFuture:
    def result(self):
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


def test_grpc_client_connection_error(tmp_path, monkeypatch):
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    monkeypatch.setenv("C2_CERT_PATH", str(cert))
    monkeypatch.setattr(grpc, "ssl_channel_credentials", lambda _: object())
    monkeypatch.setattr(grpc, "secure_channel", lambda *args, **kwargs: object())

    class FailingFuture:
        def result(self):
            raise grpc.RpcError("err")

    monkeypatch.setattr(grpc, "channel_ready_future", lambda channel: FailingFuture())

    with pytest.raises(ValueError):
        GrpcClient("127.0.0.1", 50051, False)
