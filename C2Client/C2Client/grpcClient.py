"""gRPC client utilities for the C2 client.

This module provides the :class:`GrpcClient` which wraps the generated
TeamServer stubs with a small convenience layer for certificate handling,
metadata injection and basic error reporting.
"""

import logging
import json
import os
import uuid
from threading import Lock
from typing import Any, Callable, Iterable, List, Tuple, Optional

import grpc
from .env import env_int, env_path
from .protocol_bindings import TeamServerApi_pb2, TeamServerApi_pb2_grpc
from .operator_audit import record_client_audit


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
        self._session_cursors: dict[tuple[str, str], int] = {}
        self.last_rpc_operation = ""
        self.last_rpc_ok = True
        self.last_rpc_message = ""
        self._status_callback: Optional[StatusCallback] = None
        self._auth_lock = Lock()
        self._auth_password: Optional[str] = None
        self._token = token
        self.auth_generation = 0
        self.available_listener_types: tuple[str, ...] = ("http", "https", "tcp", "dns")
        self.listener_mutation_timeout_seconds = env_int(
            "C2_LISTENER_MUTATION_TIMEOUT_SECONDS", 8, minimum=1,
        )
        self.session_stop_timeout_seconds = env_int(
            "C2_SESSION_STOP_TIMEOUT_SECONDS", 8, minimum=1,
        )

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
            self._auth_password = password
            token = self._authenticate(username, password)

        self._token = token
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

    @staticmethod
    def _is_unauthenticated(exc: grpc.RpcError) -> bool:
        try:
            return exc.code() == grpc.StatusCode.UNAUTHENTICATED
        except (AttributeError, NotImplementedError):
            return False

    def _refresh_auth(self, rejected_token: Optional[str]) -> bool:
        """Renew a rejected token once, even when several polling threads fail together."""
        if not self._auth_password:
            return False
        with self._auth_lock:
            if self._token != rejected_token:
                return True
            token = self._authenticate(self.username, self._auth_password)
            self.metadata = [
                ("authorization", f"Bearer {token}"),
                ("clientid", self.client_id),
            ]
            self._token = token
            return True

    def _retry_after_auth_failure(self, exc: grpc.RpcError, rejected_token: Optional[str]) -> bool:
        if not self._is_unauthenticated(exc):
            return False
        try:
            return self._refresh_auth(rejected_token)
        except (grpc.RpcError, ValueError) as auth_exc:
            logging.warning("Reauthentication failed: %s", auth_exc)
            return False

    def _unary_rpc(self, operation: str, call: Callable[[], Any]) -> Any:
        for attempt in range(2):
            rejected_token = self._token
            try:
                response = call()
                self._notify_rpc_status(operation, True)
                return response
            except grpc.RpcError as exc:
                if attempt == 0 and self._retry_after_auth_failure(exc, rejected_token):
                    continue
                message = self._rpc_error_message(exc)
                logging.error("%s RPC failed: %s", operation, exc)
                self._notify_rpc_status(operation, False, message)
                raise

    def _audited_rpc(self, operation: str, call: Callable[[], Any], details: dict | None = None,
                     *, audit_action: str | None = None) -> Any:
        fields = {
            "client_id": getattr(self, "client_id", ""),
            "username": getattr(self, "username", ""),
            "endpoint": getattr(self, "endpoint", ""),
            "action": audit_action or operation,
            "details": details or {},
        }
        record_client_audit(**fields, outcome="requested")
        try:
            response = self._unary_rpc(operation, call)
        except Exception:
            record_client_audit(**fields, outcome="error")
            raise
        accepted = (getattr(response, "status", TeamServerApi_pb2.OK) == TeamServerApi_pb2.OK
                    and getattr(response, "state", "") not in {"failed", "outcome_unknown"})
        result_fields = dict(fields)
        result_details = dict(details or {})
        if operation == "StopSession":
            result_details["resolved_beacon_hash"] = getattr(response, "session_beacon_hash", "")
            result_details["resolved_listener_hash"] = getattr(response, "session_listener_hash", "")
        elif operation == "AddListener":
            result_details["listener_hash"] = getattr(response, "listener_hash", "")
        elif operation == "SubmitJob":
            result_details["state"] = getattr(response, "state", "")
        result_fields["details"] = result_details
        record_client_audit(**result_fields, outcome="accepted" if accepted else "rejected")
        return response

    def _stream_rpc(self, operation: str, call: Callable[[], Iterable[Any]]) -> Iterable[Any]:
        for attempt in range(2):
            rejected_token = self._token
            yielded = False
            try:
                for response in call():
                    yielded = True
                    yield response
                self._notify_rpc_status(operation, True)
                return
            except grpc.RpcError as exc:
                if attempt == 0 and not yielded and self._retry_after_auth_failure(exc, rejected_token):
                    continue
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
        fields = {"client_id": self.client_id, "username": username, "endpoint": self.endpoint,
                  "action": "Authenticate"}
        record_client_audit(**fields, outcome="requested")
        try:
            response = self.stub.Authenticate(request, timeout=5.0)
        except Exception:
            record_client_audit(**fields, outcome="error")
            raise
        if response.status != TeamServerApi_pb2.OK or not response.token:
            record_client_audit(**fields, outcome="rejected")
            message = response.message or "unknown authentication error"
            logging.error("Authentication failed for user %s: %s", username, message)
            raise ValueError(f"grpcClient: authentication failed: {message}")

        record_client_audit(**fields, outcome="accepted")
        logging.info("Authenticated against TeamServer as %s", username)
        available_types = tuple(response.available_listener_types)
        if available_types:
            self.available_listener_types = available_types
        self.auth_generation += 1
        self._notify_rpc_status("Authenticate", True)
        return response.token

    def listListeners(self) -> Any:
        """Return the list of listeners registered on the TeamServer."""

        empty = TeamServerApi_pb2.Empty()
        return self._stream_rpc("ListListeners", lambda: self.stub.ListListeners(empty, metadata=self.metadata, timeout=3.0))

    def addListener(self, listener: Any) -> Any:
        """Add a new listener on the TeamServer."""

        return self._audited_rpc(
            "AddListener",
            lambda: self.stub.AddListener(
                listener, metadata=self.metadata, timeout=self.listener_mutation_timeout_seconds,
            ),
            {"type": getattr(listener, "type", ""), "ip": getattr(listener, "ip", ""),
             "port": getattr(listener, "port", 0)},
        )

    def stopListener(self, listener: Any) -> Any:
        """Stop a running listener."""

        return self._audited_rpc(
            "StopListener",
            lambda: self.stub.StopListener(
                listener, metadata=self.metadata, timeout=self.listener_mutation_timeout_seconds,
            ),
            {"listener_hash": listener.listener_hash},
        )

    def listSessions(self) -> Any:
        """Return current sessions for active-session consumers."""

        empty = TeamServerApi_pb2.Empty()
        return self._stream_rpc("ListSessions", lambda: self.stub.ListSessions(empty, metadata=self.metadata, timeout=3.0))

    def listSessionHistory(self) -> Any:
        """Return current and archived sessions for the Sessions view."""

        empty = TeamServerApi_pb2.Empty()
        try:
            yield from self._stream_rpc("ListSessionHistory", lambda: self.stub.ListSessionHistory(
                empty, metadata=self.metadata, timeout=3.0))
        except grpc.RpcError as exc:
            if exc.code() != grpc.StatusCode.UNIMPLEMENTED:
                raise
            yield from self.listSessions()

    def listArtifacts(self, query: Optional[Any] = None) -> Iterable[Any]:
        """Return artifacts indexed by the TeamServer catalog."""

        if query is None:
            query = TeamServerApi_pb2.ArtifactQuery()
        return self._stream_rpc("ListArtifacts", lambda: self.stub.ListArtifacts(query, metadata=self.metadata, timeout=10.0))

    def downloadArtifact(self, artifact_id: str) -> Any:
        """Return artifact payload bytes by id."""

        selector = TeamServerApi_pb2.ArtifactSelector(artifact_id=artifact_id)
        return self._audited_rpc(
            "DownloadArtifact",
            lambda: self.stub.DownloadArtifact(selector, metadata=self.metadata),
            {"artifact_id": artifact_id},
        )

    def uploadArtifact(self, name: str, data: bytes, platform: str = "any", arch: str = "any") -> Any:
        """Upload an operator artifact to the TeamServer artifact store."""

        request = TeamServerApi_pb2.ArtifactUploadRequest(
            name=name,
            platform=platform,
            arch=arch,
            data=data,
        )
        return self._audited_rpc(
            "UploadArtifact",
            lambda: self.stub.UploadArtifact(request, metadata=self.metadata),
            {"name": name, "platform": platform, "arch": arch, "size": len(data)},
        )

    def deleteArtifact(self, artifact_id: str) -> Any:
        """Delete a deletable TeamServer artifact by id."""

        selector = TeamServerApi_pb2.ArtifactSelector(artifact_id=artifact_id)
        return self._audited_rpc(
            "DeleteGeneratedArtifact",
            lambda: self.stub.DeleteGeneratedArtifact(selector, metadata=self.metadata),
            {"artifact_id": artifact_id},
        )

    def deleteGeneratedArtifact(self, artifact_id: str) -> Any:
        """Delete a generated artifact by id."""

        return self.deleteArtifact(artifact_id)

    def listCredentials(self, query: Optional[Any] = None) -> Iterable[Any]:
        """Return credential metadata from the TeamServer vault without secrets."""

        if query is None:
            query = TeamServerApi_pb2.CredentialQuery()
        return self._stream_rpc("ListCredentials", lambda: self.stub.ListCredentials(query, metadata=self.metadata))

    def getCredential(self, credential_id: str, reveal_secret: bool = False) -> Any:
        """Return one credential; secrets are included only when explicitly requested."""

        selector = TeamServerApi_pb2.CredentialSelector(
            credential_id=credential_id,
            reveal_secret=reveal_secret,
        )
        call = lambda: self.stub.GetCredential(selector, metadata=self.metadata)
        if reveal_secret:
            return self._audited_rpc("GetCredential", call, {"credential_id": credential_id},
                                     audit_action="RevealCredential")
        return self._unary_rpc("GetCredential", call)

    def addCredential(self, request: Any) -> Any:
        """Add a credential to the TeamServer vault."""

        return self._audited_rpc("AddCredential", lambda: self.stub.AddCredential(request, metadata=self.metadata),
                                 {"credential_id": request.credential_id, "type": request.type})

    def updateCredential(self, request: Any) -> Any:
        """Update a credential in the TeamServer vault."""

        return self._audited_rpc("UpdateCredential", lambda: self.stub.UpdateCredential(request, metadata=self.metadata),
                                 {"credential_id": request.credential_id})

    def deleteCredential(self, credential_id: str) -> Any:
        """Delete a credential from the TeamServer vault."""

        selector = TeamServerApi_pb2.CredentialSelector(credential_id=credential_id)
        return self._audited_rpc("DeleteCredential", lambda: self.stub.DeleteCredential(selector, metadata=self.metadata),
                                 {"credential_id": credential_id})

    def listCommands(self, query: Optional[Any] = None) -> Iterable[Any]:
        """Return command specs exposed by the TeamServer catalog."""

        if query is None:
            query = TeamServerApi_pb2.CommandQuery()
        return self._stream_rpc("ListCommands", lambda: self.stub.ListCommands(query, metadata=self.metadata))

    def listModules(self, session: Optional[Any] = None) -> Iterable[Any]:
        """Return modules tracked for a beacon session."""

        if session is None:
            session = TeamServerApi_pb2.SessionSelector()
        return self._stream_rpc("ListModules", lambda: self.stub.ListModules(session, metadata=self.metadata))

    def stopSession(self, session: Any) -> Any:
        """Terminate a session."""

        return self._audited_rpc(
            "StopSession",
            lambda: self.stub.StopSession(
                session, metadata=self.metadata, timeout=self.session_stop_timeout_seconds,
            ),
            {"beacon_hash": session.beacon_hash, "listener_hash": session.listener_hash},
        )

    def sendSessionCommand(self, command: Any, *, origin: str = "") -> Any:
        """Submit a session command through the durable V2 job API."""

        payload = json.dumps({
            "beacon_hash": command.session.beacon_hash,
            "listener_hash": command.session.listener_hash,
            "command": command.command,
        }, separators=(",", ":"))
        job_args = (command.command_id or uuid.uuid4().hex, "session_command", payload)
        job = self.submitJob(*job_args, origin=origin) if origin else self.submitJob(*job_args)
        return TeamServerApi_pb2.CommandAck(
            status=TeamServerApi_pb2.KO if job.state == "failed" else TeamServerApi_pb2.OK,
            command_id=job.job_id,
            message=job.error_message,
        )

    def streamSessionCommandResults(self, session: Any) -> Iterable[Any]:
        """Yield completed V2 jobs for a session, advancing the local event cursor."""
        key = (session.listener_hash, session.beacon_hash)
        cursor = self._session_cursors.get(key, 0)
        for event in self.subscribeJobEvents(after_event_id=cursor, follow=False):
            if event.event_id <= cursor:
                continue
            if event.event_type in {"succeeded", "failed", "outcome_unknown"}:
                job = self.getJobExecution(event.job_id)
                if job.operation == "session_command":
                    job_input = json.loads(job.normalized_input)
                    if (job_input["listener_hash"], job_input["beacon_hash"]) == key:
                        event_state = event.event_type
                        yield TeamServerApi_pb2.CommandResult(
                            status=TeamServerApi_pb2.OK if event_state == "succeeded" else TeamServerApi_pb2.KO,
                            session=session,
                            command_id=job.job_id,
                            command=job_input["command"],
                            output=job.output_inline if event_state == "succeeded" else b"",
                            message=(job.error_message if job.state == event_state else
                                "Delivery or completion could not be established after restart."),
                            event_id=event.event_id,
                            job_state=event_state,
                        )
            cursor = event.event_id
            self._session_cursors[key] = cursor

    def submitJob(self, job_id: str, operation: str, input: str, *, origin: str = "") -> Any:
        request = TeamServerApi_pb2.SubmitJobRequest(job_id=job_id, operation=operation, input=input, origin=origin)
        details = {"job_id": job_id, "operation": operation}
        if operation == "session_command":
            try:
                payload = json.loads(input)
                if isinstance(payload, dict):
                    details.update({key: payload[key] for key in ("beacon_hash", "listener_hash")
                                    if isinstance(payload.get(key), str)})
            except (ValueError, TypeError):
                pass
        job = self._audited_rpc("SubmitJob", lambda: self.stub.SubmitJob(
            request, metadata=self.metadata,
            timeout=env_int("C2_GRPC_JOB_TIMEOUT_SEC", 10, minimum=1),
        ), details)
        return self._complete_job_output(job)

    def getJobExecution(self, job_id: str) -> Any:
        request = TeamServerApi_pb2.GetJobExecutionRequest(job_id=job_id)
        job = self._unary_rpc("GetJobExecution", lambda: self.stub.GetJobExecution(
            request, metadata=self.metadata, timeout=env_int("C2_GRPC_JOB_TIMEOUT_SEC", 10, minimum=1)))
        return self._complete_job_output(job)

    def _complete_job_output(self, job: Any) -> Any:
        if not hasattr(job, "output_size"):
            return job
        expected = int(job.output_size)
        data = bytearray(job.output_inline)
        if expected == 0 and data:
            # Older/fake records may omit the size while carrying inline bytes.
            return job
        while len(data) < expected and job.error_code != "output_too_large":
            chunk = self.getJobOutputChunk(job.job_id, len(data))
            if int(chunk.total_size) != expected or int(chunk.next_offset) != len(data) + len(chunk.data) \
                    or not chunk.data:
                raise ValueError("TeamServer returned an inconsistent job output chunk.")
            data.extend(chunk.data)
        if len(data) != expected and job.error_code != "output_too_large":
            raise ValueError("TeamServer returned an inconsistent job output length.")
        if expected > len(job.output_inline):
            job.output_inline = bytes(data)
        return job

    def getJobOutputChunk(self, job_id: str, offset: int, max_bytes: int = 64 * 1024) -> Any:
        request = TeamServerApi_pb2.GetJobOutputChunkRequest(
            job_id=job_id, offset=offset, max_bytes=max_bytes)
        return self._unary_rpc("GetJobOutputChunk", lambda: self.stub.GetJobOutputChunk(
            request, metadata=self.metadata, timeout=env_int("C2_GRPC_JOB_TIMEOUT_SEC", 10, minimum=1)))

    def listJobExecutions(self, after_created_at: int = 0, after_job_id: str = "", page_size: int = 100) -> Any:
        request = TeamServerApi_pb2.ListJobExecutionsRequest(
            after_created_at=after_created_at, after_job_id=after_job_id, page_size=page_size)
        return self._unary_rpc("ListJobExecutions", lambda: self.stub.ListJobExecutions(request, metadata=self.metadata))

    def subscribeJobEvents(self, after_event_id: int = 0, *, job_id: str = "",
                           state: str = "", page_size: int = 100, follow: bool = False) -> Iterable[Any]:
        request = TeamServerApi_pb2.SubscribeJobEventsRequest(
            after_event_id=after_event_id, job_id=job_id, state=state,
            page_size=page_size, follow=follow)
        return self._stream_rpc("SubscribeJobEvents", lambda: self.stub.SubscribeJobEvents(
            request, metadata=self.metadata, timeout=3.0 if follow else 5.0))

    def getCommandHelp(self, command: Any) -> Any:
        """Return help information for a command."""

        return self._unary_rpc("GetCommandHelp", lambda: self.stub.GetCommandHelp(command, metadata=self.metadata))

    def hostArtifact(self, request: Any) -> Any:
        """Host an existing artifact, returning a durable operation receipt."""
        return self._audited_rpc(
            "HostArtifact",
            lambda: self.stub.HostArtifact(
                request, metadata=self.metadata,
                timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1),
            ),
            {"job_id": request.job_id, "listener_hash": request.listener_hash,
             "artifact_reference": request.artifact_reference},
        )

    def controlSocks(self, request: Any) -> Any:
        """Control the TeamServer SOCKS bridge with a durable operation receipt."""
        return self._audited_rpc(
            "ControlSocks",
            lambda: self.stub.ControlSocks(
                request, metadata=self.metadata,
                timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1),
            ),
            {"job_id": request.job_id, "action": request.action,
             "beacon_hash": request.beacon_hash},
        )

    def reloadModules(self, request: Any) -> Any:
        """Reload TeamServer modules with a durable operation receipt."""
        return self._audited_rpc(
            "ReloadModules",
            lambda: self.stub.ReloadModules(
                request, metadata=self.metadata,
                timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1),
            ),
            {"job_id": request.job_id},
        )

    def getListenerInfo(self, request: Any) -> Any:
        return self._unary_rpc("GetListenerInfo", lambda: self.stub.GetListenerInfo(
            request, metadata=self.metadata,
            timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1)))

    def getBeaconBinary(self, request: Any) -> Any:
        return self._unary_rpc("GetBeaconBinary", lambda: self.stub.GetBeaconBinary(
            request, metadata=self.metadata,
            timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1)))

    def uploadListenerFile(self, request: Any) -> Any:
        return self._audited_rpc("UploadListenerFile", lambda: self.stub.UploadListenerFile(
            request, metadata=self.metadata,
            timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1)),
            {"listener_hash": request.listener_hash, "filename": request.filename})

    def installTool(self, request: Any) -> Any:
        return self._audited_rpc("InstallTool", lambda: self.stub.InstallTool(
            request, metadata=self.metadata,
            timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1)),
            {"filename": request.filename})

    def installToolBundle(self, request: Any) -> Any:
        return self._audited_rpc("InstallToolBundle", lambda: self.stub.InstallToolBundle(
            request, metadata=self.metadata,
            timeout=env_int("C2_GRPC_TERMINAL_TIMEOUT_SEC", 60, minimum=1)),
            {"file_count": len(request.files)})
