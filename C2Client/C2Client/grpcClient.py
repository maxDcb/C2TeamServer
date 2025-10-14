"""gRPC client utilities for the C2 client.

This module provides the :class:`GrpcClient` which wraps the generated
TeamServer stubs with a small convenience layer for certificate handling,
metadata injection and basic error reporting.
"""

import logging
import os
import sys
import uuid
from typing import Any, Iterable, List, Tuple, Optional

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/libGrpcMessages/build/py/')

import grpc
import TeamServerApi_pb2
import TeamServerApi_pb2_grpc


MetadataType = List[Tuple[str, str]]


class GrpcClient:
    """Thin wrapper around the gRPC TeamServer API client.

    Parameters
    ----------
    ip:
        IP address of the TeamServer.
    port:
        Port exposed by the TeamServer.
    devMode:
        If ``True`` the SSL hostname check is disabled.
    token:
        Bearer token used for authentication metadata.
    """

    def __init__(self, ip: str, port: int, devMode: bool, token: Optional[str] = None) -> None:
        env_cert_path = os.getenv('C2_CERT_PATH')

        if env_cert_path and os.path.isfile(env_cert_path):
            ca_cert = env_cert_path
            logging.info("Using certificate from environment variable: %s", ca_cert)
        else:
            try:
                import pkg_resources
                ca_cert = pkg_resources.resource_filename('C2Client', 'server.crt')
            except ImportError:
                ca_cert = os.path.join(os.path.dirname(__file__), 'server.crt')
            logging.info(
                "Using default certificate: %s. To use a custom C2 certificate, set the C2_CERT_PATH environment variable.",
                ca_cert,
            )

        if os.path.exists(ca_cert):
            with open(ca_cert, 'rb') as fh:
                root_certs = fh.read()
        else:
            logging.error(
                "%s not found, this file is needed to secure the communication between the client and server.",
                ca_cert,
            )
            raise ValueError("grpcClient: Certificate not found")

        credentials = grpc.ssl_channel_credentials(root_certs)
        if devMode:
            self.channel = grpc.secure_channel(
                f"{ip}:{port}",
                credentials,
                options=[
                    ('grpc.ssl_target_name_override', 'localhost'),
                    ('grpc.max_send_message_length', 512 * 1024 * 1024),
                    ('grpc.max_receive_message_length', 512 * 1024 * 1024),
                ],
            )
        else:
            self.channel = grpc.secure_channel(
                f"{ip}:{port}",
                credentials,
                options=[
                    ('grpc.max_send_message_length', 512 * 1024 * 1024),
                    ('grpc.max_receive_message_length', 512 * 1024 * 1024),
                ],
            )

        try:
            grpc.channel_ready_future(self.channel).result()
        except grpc.RpcError as exc:
            logging.error("Failed to connect to gRPC server: %s", exc)
            raise ValueError("grpcClient: unable to connect") from exc

        self.stub = TeamServerApi_pb2_grpc.TeamServerApiStub(self.channel)

        if token is None:
            username, password = self._load_credentials_from_env()
            token = self._authenticate(username, password)

        self.metadata: MetadataType = [
            ("authorization", f"Bearer {token}"),
            ("clientid", str(uuid.uuid4())[:16]),
        ]

    def _load_credentials_from_env(self) -> Tuple[str, str]:
        username = os.getenv("C2_USERNAME")
        password = os.getenv("C2_PASSWORD")
        if not username or not password:
            raise ValueError(
                "grpcClient: missing C2_USERNAME or C2_PASSWORD environment variables for authentication",
            )
        return username, password

    def _authenticate(self, username: str, password: str) -> str:
        request = TeamServerApi_pb2.AuthRequest(username=username, password=password)
        response = self.stub.Authenticate(request)
        if response.status != TeamServerApi_pb2.OK or not response.token:
            message = response.message or "unknown authentication error"
            logging.error("Authentication failed for user %s: %s", username, message)
            raise ValueError(f"grpcClient: authentication failed: {message}")

        logging.info("Authenticated against TeamServer as %s", username)
        return response.token

    def getListeners(self) -> Any:
        """Return the list of listeners registered on the TeamServer."""

        empty = TeamServerApi_pb2.Empty()
        try:
            return self.stub.GetListeners(empty, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("GetListeners RPC failed: %s", exc)
            raise

    def addListener(self, listener: Any) -> Any:
        """Add a new listener on the TeamServer."""

        try:
            return self.stub.AddListener(listener, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("AddListener RPC failed: %s", exc)
            raise

    def stopListener(self, listener: Any) -> Any:
        """Stop a running listener."""

        try:
            return self.stub.StopListener(listener, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("StopListener RPC failed: %s", exc)
            raise

    def getSessions(self) -> Any:
        """Return all active sessions."""

        empty = TeamServerApi_pb2.Empty()
        try:
            return self.stub.GetSessions(empty, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("GetSessions RPC failed: %s", exc)
            raise

    def stopSession(self, session: Any) -> Any:
        """Terminate a session."""

        try:
            return self.stub.StopSession(session, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("StopSession RPC failed: %s", exc)
            raise

    def sendCmdToSession(self, command: Any) -> Any:
        """Send a command to the specified session."""

        try:
            return self.stub.SendCmdToSession(command, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("SendCmdToSession RPC failed: %s", exc)
            raise

    def getResponseFromSession(self, session: Any) -> Iterable[Any]:
        """Yield responses for a given session."""

        try:
            return self.stub.GetResponseFromSession(session, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("GetResponseFromSession RPC failed: %s", exc)
            raise

    def getHelp(self, command: Any) -> Any:
        """Return help information for a command."""

        try:
            return self.stub.GetHelp(command, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("GetHelp RPC failed: %s", exc)
            raise

    def sendTermCmd(self, command: Any) -> Any:
        """Send a command to the TeamServer terminal."""

        try:
            return self.stub.SendTermCmd(command, metadata=self.metadata)
        except grpc.RpcError as exc:
            logging.error("SendTermCmd RPC failed: %s", exc)
            raise

