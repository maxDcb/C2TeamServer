"""gRPC client utilities for the C2 client.

This module provides the :class:`GrpcClient` which wraps the generated
TeamServer stubs with a small convenience layer for certificate handling,
metadata injection and basic error reporting.
"""

import logging
import os
import uuid
from typing import Any, Callable, Iterable, List, Tuple, Optional

import grpc
from .env import env_int, env_path
from .protocol_bindings import TeamServerApi_pb2, TeamServerApi_pb2_grpc


MetadataType = List[Tuple[str, str]]
StatusCallback = Callable[[str, bool, str], None]


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
    username:
        Username to authenticate with. If omitted, environment variables are used.
    password:
        Password to authenticate with. If omitted, environment variables are used.
    """

    def __init__(
        self,
        ip: str,
        port: int,
        devMode: bool,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self.ip = ip
        self.port = port
        self.endpoint = f"{ip}:{port}"
        self.devMode = devMode
        self.username = username or ""
        self.ca_cert_path = ""
        self.client_id = str(uuid.uuid4())[:16]
        self.last_rpc_operation = ""
        self.last_rpc_ok = True
        self.last_rpc_message = ""
        self._status_callback: Optional[StatusCallback] = None

        configured_cert_path = env_path("C2_CERT_PATH")

        if configured_cert_path:
            if not configured_cert_path.is_file():
                logging.error(
                    "Configured C2 certificate does not exist: %s",
                    configured_cert_path,
                )
                raise ValueError(f"grpcClient: configured certificate not found: {configured_cert_path}")
            ca_cert = str(configured_cert_path)
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
        self.ca_cert_path = ca_cert

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
        self.max_message_mb = env_int("C2_GRPC_MAX_MESSAGE_MB", 512, minimum=1)
        self.max_message_bytes = self.max_message_mb * 1024 * 1024
        self.connect_timeout_ms = env_int("C2_GRPC_CONNECT_TIMEOUT_MS", 0, minimum=0)
        channel_options = [
            ('grpc.max_send_message_length', self.max_message_bytes),
            ('grpc.max_receive_message_length', self.max_message_bytes),
        ]
        if devMode:
            self.channel = grpc.secure_channel(
                f"{ip}:{port}",
                credentials,
                options=[
                    ('grpc.ssl_target_name_override', 'localhost'),
                    *channel_options,
                ],
            )
        else:
            self.channel = grpc.secure_channel(
                f"{ip}:{port}",
                credentials,
                options=channel_options,
            )

        try:
            timeout = self.connect_timeout_ms / 1000 if self.connect_timeout_ms else None
            grpc.channel_ready_future(self.channel).result(timeout=timeout)
        except grpc.RpcError as exc:
            logging.error("Failed to connect to gRPC server: %s", exc)
            raise ValueError("grpcClient: unable to connect") from exc

        self.stub = TeamServerApi_pb2_grpc.TeamServerApiStub(self.channel)

        if token is None:
            if username is None or password is None:
                username, password = self._load_credentials_from_env()
            self.username = username
            token = self._authenticate(username, password)

        self.metadata: MetadataType = [
            ("authorization", f"Bearer {token}"),
            ("clientid", self.client_id),
        ]
        self._notify_rpc_status("Connect", True)

    def set_status_callback(self, callback: Optional[StatusCallback]) -> None:
        """Register a callback receiving RPC status updates."""

        self._status_callback = callback

    def _notify_rpc_status(self, operation: str, ok: bool, message: str = "") -> None:
        self.last_rpc_operation = operation
        self.last_rpc_ok = ok
        self.last_rpc_message = message
        if self._status_callback:
            self._status_callback(operation, ok, message)

    def _rpc_error_message(self, exc: grpc.RpcError) -> str:
        details = ""
        try:
            details = exc.details() or ""
        except Exception:
            details = ""
        return details or str(exc)

    def _unary_rpc(self, operation: str, call: Callable[[], Any]) -> Any:
        try:
            response = call()
            self._notify_rpc_status(operation, True)
            return response
        except grpc.RpcError as exc:
            message = self._rpc_error_message(exc)
            logging.error("%s RPC failed: %s", operation, exc)
            self._notify_rpc_status(operation, False, message)
            raise

    def _stream_rpc(self, operation: str, call: Callable[[], Iterable[Any]]) -> Iterable[Any]:
        try:
            for response in call():
                yield response
            self._notify_rpc_status(operation, True)
        except grpc.RpcError as exc:
            message = self._rpc_error_message(exc)
            logging.error("%s RPC failed: %s", operation, exc)
            self._notify_rpc_status(operation, False, message)
            raise

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
        self._notify_rpc_status("Authenticate", True)
        return response.token

    def listListeners(self) -> Any:
        """Return the list of listeners registered on the TeamServer."""

        empty = TeamServerApi_pb2.Empty()
        return self._stream_rpc("ListListeners", lambda: self.stub.ListListeners(empty, metadata=self.metadata))

    def addListener(self, listener: Any) -> Any:
        """Add a new listener on the TeamServer."""

        return self._unary_rpc("AddListener", lambda: self.stub.AddListener(listener, metadata=self.metadata))

    def stopListener(self, listener: Any) -> Any:
        """Stop a running listener."""

        return self._unary_rpc("StopListener", lambda: self.stub.StopListener(listener, metadata=self.metadata))

    def listSessions(self) -> Any:
        """Return all active sessions."""

        empty = TeamServerApi_pb2.Empty()
        return self._stream_rpc("ListSessions", lambda: self.stub.ListSessions(empty, metadata=self.metadata))

    def listArtifacts(self, query: Optional[Any] = None) -> Iterable[Any]:
        """Return artifacts indexed by the TeamServer catalog."""

        if query is None:
            query = TeamServerApi_pb2.ArtifactQuery()
        return self._stream_rpc("ListArtifacts", lambda: self.stub.ListArtifacts(query, metadata=self.metadata))

    def stopSession(self, session: Any) -> Any:
        """Terminate a session."""

        return self._unary_rpc("StopSession", lambda: self.stub.StopSession(session, metadata=self.metadata))

    def sendSessionCommand(self, command: Any) -> Any:
        """Send a command to the specified session."""

        return self._unary_rpc("SendSessionCommand", lambda: self.stub.SendSessionCommand(command, metadata=self.metadata))

    def streamSessionCommandResults(self, session: Any) -> Iterable[Any]:
        """Yield responses for a given session."""

        return self._stream_rpc(
            "StreamSessionCommandResults",
            lambda: self.stub.StreamSessionCommandResults(session, metadata=self.metadata),
        )

    def getCommandHelp(self, command: Any) -> Any:
        """Return help information for a command."""

        return self._unary_rpc("GetCommandHelp", lambda: self.stub.GetCommandHelp(command, metadata=self.metadata))

    def executeTerminalCommand(self, command: Any) -> Any:
        """Send a command to the TeamServer terminal."""

        return self._unary_rpc(
            "ExecuteTerminalCommand",
            lambda: self.stub.ExecuteTerminalCommand(command, metadata=self.metadata),
        )
