"""TeamServer operations shared by Qt panels and assistant tools.

Presentation layers supply typed arguments. The server owns execution and the
durable job receipt for state-changing operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import grpc

from .grpcClient import TeamServerApi_pb2


@dataclass(frozen=True, slots=True)
class OperationOutcome:
    job_id: str
    state: str
    output: str

    @property
    def ok(self) -> bool:
        return self.state == "succeeded"

    @property
    def outcome_unknown(self) -> bool:
        return self.state not in {"succeeded", "failed"}


def _outcome(job: Any) -> OperationOutcome:
    state = str(job.state)
    if state == "succeeded":
        output = bytes(job.output_inline).decode("utf-8", "replace")
    else:
        output = str(job.error_message or "Operation outcome is not available yet.")
    return OperationOutcome(str(job.job_id), state, output)


class TeamServerOperations:
    def __init__(self, grpc_client: Any):
        self.grpc_client = grpc_client

    def list_listeners(self) -> list[Any]:
        return list(self.grpc_client.listListeners())

    def list_commands(self, query: Any = None) -> list[Any]:
        return list(self.grpc_client.listCommands(query))

    def add_listener(self, listener: Any) -> Any:
        return self.grpc_client.addListener(listener)

    def stop_listener(self, selector: Any) -> Any:
        return self.grpc_client.stopListener(selector)

    def list_sessions(self) -> list[Any]:
        return list(self.grpc_client.listSessions())

    def list_session_history(self) -> list[Any]:
        return list(self.grpc_client.listSessionHistory())

    def stop_session(self, selector: Any) -> Any:
        return self.grpc_client.stopSession(selector)

    def list_artifacts(self, query: Any = None) -> list[Any]:
        return list(self.grpc_client.listArtifacts(query))

    def download_artifact(self, artifact_id: str) -> Any:
        return self.grpc_client.downloadArtifact(artifact_id)

    def upload_artifact(self, name: str, data: bytes, platform: str, arch: str) -> Any:
        return self.grpc_client.uploadArtifact(name, data, platform, arch)

    def delete_artifact(self, artifact_id: str) -> Any:
        return self.grpc_client.deleteArtifact(artifact_id)

    def list_credentials(self, query: Any = None) -> list[Any]:
        return list(self.grpc_client.listCredentials(query))

    def get_credential(self, credential_id: str, *, reveal_secret: bool = False) -> Any:
        return self.grpc_client.getCredential(credential_id, reveal_secret=reveal_secret)

    def add_credential(self, request: Any) -> Any:
        return self.grpc_client.addCredential(request)

    def update_credential(self, request: Any) -> Any:
        return self.grpc_client.updateCredential(request)

    def delete_credential(self, credential_id: str) -> Any:
        return self.grpc_client.deleteCredential(credential_id)

    def get_operation(self, job_id: str) -> OperationOutcome:
        return _outcome(self.grpc_client.getJobExecution(job_id))

    def _submit(self, job_id: str, send: Any) -> OperationOutcome:
        try:
            outcome = _outcome(send())
            if outcome.job_id != job_id:
                raise ValueError("TeamServer returned a different operation ID.")
            return outcome
        except Exception as error:
            if isinstance(error, grpc.RpcError) and error.code() in {
                grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.ALREADY_EXISTS,
                grpc.StatusCode.PERMISSION_DENIED, grpc.StatusCode.FAILED_PRECONDITION,
                grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.UNIMPLEMENTED,
            }:
                return OperationOutcome(job_id, "failed", str(error.details() or error))
            try:
                return self.get_operation(job_id)
            except Exception:
                return OperationOutcome(job_id, "outcome_unknown", f"Operation outcome unknown: {error}")

    def host_artifact(self, listener_hash: str, artifact_reference: str,
                      hosted_filename: str = "", *, job_id: str | None = None,
                      origin: str = "terminal") -> OperationOutcome:
        operation_id = job_id or uuid4().hex
        request = TeamServerApi_pb2.HostArtifactRequest(
            job_id=operation_id, listener_hash=listener_hash,
            artifact_reference=artifact_reference, hosted_filename=hosted_filename,
            origin=origin,
        )
        return self._submit(operation_id, lambda: self.grpc_client.hostArtifact(request))

    def control_socks(self, action: str, beacon_hash: str = "", *,
                      job_id: str | None = None, origin: str = "terminal") -> OperationOutcome:
        operation_id = job_id or uuid4().hex
        request = TeamServerApi_pb2.SocksControlRequest(
            job_id=operation_id, action=action, beacon_hash=beacon_hash, origin=origin,
        )
        return self._submit(operation_id, lambda: self.grpc_client.controlSocks(request))

    def reload_modules(self, *, job_id: str | None = None,
                       origin: str = "terminal") -> OperationOutcome:
        operation_id = job_id or uuid4().hex
        request = TeamServerApi_pb2.OperationRequest(job_id=operation_id, origin=origin)
        return self._submit(operation_id, lambda: self.grpc_client.reloadModules(request))

    def get_listener_info(self, listener_hash: str) -> Any:
        return self.grpc_client.getListenerInfo(
            TeamServerApi_pb2.ListenerSelector(listener_hash=listener_hash))

    def get_beacon_binary(self, listener_hash: str, target_os: str = "windows",
                          target_arch: str = "") -> Any:
        return self.grpc_client.getBeaconBinary(TeamServerApi_pb2.BeaconBinaryRequest(
            listener_hash=listener_hash, target_os=target_os, target_arch=target_arch))

    def upload_listener_file(self, listener_hash: str, filename: str, data: bytes) -> Any:
        return self.grpc_client.uploadListenerFile(TeamServerApi_pb2.ListenerFileRequest(
            listener_hash=listener_hash, filename=filename, data=data))

    def install_tool(self, filename: str, data: bytes) -> Any:
        return self.grpc_client.installTool(TeamServerApi_pb2.ToolFile(filename=filename, data=data))

    def install_tool_bundle(self, files: list[tuple[str, bytes]]) -> Any:
        request = TeamServerApi_pb2.ToolBundleRequest()
        for filename, data in files:
            request.files.add(filename=filename, data=data)
        return self.grpc_client.installToolBundle(request)
