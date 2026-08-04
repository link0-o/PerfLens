"""Unix-socket client for the restricted collector broker."""

from __future__ import annotations

import hashlib
import math
import secrets
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from perflens.collector_broker.protocol import (
    MAX_BROKER_MESSAGE_BYTES,
    BrokerCollectRequest,
    BrokerHealthRequest,
    BrokerResponse,
)
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionPlanArtifact,
    CollectorHealthArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_PEER_CREDENTIALS = struct.Struct("3i")


class CollectorBrokerClient:
    def __init__(self, socket_path: Path, *, timeout_seconds: float = 310.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 86_500
        ):
            raise ValueError("Broker timeout is invalid")
        self._socket = _socket_identity(socket_path)
        self._socket_path = self._socket.path
        self._timeout_seconds = float(timeout_seconds)

    def collect(self, plan: CollectionPlanArtifact) -> CollectionArtifact:
        identity = f"{plan.plan_id}\0{plan.target_pid}\0{plan.expires_at}"
        request = BrokerCollectRequest(
            request_id=f"request-{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
            plan=plan,
        )
        response, _server_pid, _server_uid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n",
            expected_request_id=request.request_id,
        )
        if not response.ok:
            _raise_rejected_response(response, request.request_id)
        if response.result is None:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned no result",
            )
        try:
            artifact = CollectionArtifact.model_validate(response.result)
        except ValidationError as exc:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned an invalid collection artifact",
            ) from exc
        if (
            artifact.target_type != "pid"
            or artifact.target_pid != plan.target_pid
            or artifact.mode != plan.mode
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector result does not match the authorized collection plan",
            )
        return artifact

    def health(self, *, expected_service_uid: int | None = None) -> CollectorHealthArtifact:
        """Perform one authenticated, read-only protocol round trip."""
        if expected_service_uid is not None and (
            isinstance(expected_service_uid, bool) or expected_service_uid < 0
        ):
            raise ValueError("Expected Collector service UID is invalid")
        request = BrokerHealthRequest(request_id=f"request-{secrets.token_hex(12)}")
        response, server_pid, server_uid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n",
            expected_request_id=request.request_id,
        )
        if not response.ok:
            _raise_rejected_response(response, request.request_id)
        if response.result is None:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned no health result",
            )
        try:
            artifact = CollectorHealthArtifact.model_validate(response.result)
        except ValidationError as exc:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned an invalid health artifact",
            ) from exc
        if artifact.service_pid != server_pid or artifact.service_uid != server_uid:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector health identity does not match Unix peer credentials",
                recoverable=True,
                details={"server_pid": server_pid, "server_uid": server_uid},
            )
        if expected_service_uid is not None and server_uid != expected_service_uid:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector Unix peer UID does not match the dedicated service account",
                recoverable=True,
                details={
                    "server_uid": server_uid,
                    "expected_service_uid": expected_service_uid,
                },
            )
        return artifact

    def _exchange(
        self,
        payload: bytes,
        *,
        expected_request_id: str,
    ) -> tuple[BrokerResponse, int, int]:
        if len(payload) > MAX_BROKER_MESSAGE_BYTES:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker request exceeds the protocol limit",
            )
        server_pid = -1
        server_uid = -1
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(str(self._socket_path))
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    _PEER_CREDENTIALS.size,
                )
                server_pid, server_uid, _server_gid = _PEER_CREDENTIALS.unpack(credentials)
                _validate_connected_peer(self._socket, server_pid, server_uid)
                connection.sendall(payload)
                line = _read_response_frame(connection)
        except PerfLensError:
            raise
        except TimeoutError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_TIMEOUT,
                "collector_broker",
                "Collector broker response timed out before a complete frame",
                recoverable=True,
                retryable=True,
                details={"socket": str(self._socket_path)},
            ) from exc
        except (OSError, struct.error) as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "collector_broker",
                "Unable to communicate with the collector broker",
                recoverable=True,
                details={"socket": str(self._socket_path)},
            ) from exc
        try:
            response = BrokerResponse.model_validate_json(line)
        except ValidationError as exc:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned invalid JSON",
            ) from exc
        if response.request_id != expected_request_id:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector response request ID does not match the request",
            )
        return response, server_pid, server_uid


@dataclass(frozen=True, slots=True)
class _SocketIdentity:
    path: Path
    device: int
    inode: int
    uid: int
    mode: int
    parent_device: int
    parent_inode: int
    parent_uid: int
    parent_mode: int


def _socket_identity(path: Path) -> _SocketIdentity:
    if not path.expanduser().is_absolute():
        raise ValueError("Collector broker socket path must be absolute")
    try:
        safe_path = path.expanduser().resolve(strict=True)
        metadata = safe_path.stat()
        parent_metadata = safe_path.parent.stat()
    except OSError as exc:
        raise ValueError("Collector broker socket does not exist") from exc
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ValueError("Collector broker path is not a Unix socket")
    if parent_metadata.st_mode & 0o022:
        raise ValueError("Collector broker socket directory is group/world writable")
    if parent_metadata.st_uid not in {0, metadata.st_uid}:
        raise ValueError("Collector broker socket directory owner is unsafe")
    if metadata.st_mode & 0o007:
        raise ValueError("Collector broker socket is accessible to other users")
    return _SocketIdentity(
        path=safe_path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        parent_device=parent_metadata.st_dev,
        parent_inode=parent_metadata.st_ino,
        parent_uid=parent_metadata.st_uid,
        parent_mode=stat.S_IMODE(parent_metadata.st_mode),
    )


def _validate_connected_peer(identity: _SocketIdentity, server_pid: int, server_uid: int) -> None:
    if server_pid <= 0 or server_uid < 0 or server_uid != identity.uid:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_broker",
            "Collector Unix peer credentials do not match the socket owner",
        )
    try:
        metadata = identity.path.stat(follow_symlinks=False)
        parent_metadata = identity.path.parent.stat()
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_broker",
            "Collector socket identity changed before the request",
        ) from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IMODE(metadata.st_mode))
        != (identity.device, identity.inode, identity.uid, identity.mode)
        or (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
            parent_metadata.st_uid,
            stat.S_IMODE(parent_metadata.st_mode),
        )
        != (
            identity.parent_device,
            identity.parent_inode,
            identity.parent_uid,
            identity.parent_mode,
        )
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_broker",
            "Collector socket identity changed before the request",
        )


def _read_response_frame(connection: socket.socket) -> bytes:
    received = bytearray()
    while b"\n" not in received:
        remaining = MAX_BROKER_MESSAGE_BYTES - len(received)
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker response exceeds the protocol limit",
            )
        chunk = connection.recv(min(16 << 10, remaining))
        if not chunk:
            break
        received.extend(chunk)
    line, separator, trailing = bytes(received).partition(b"\n")
    if not separator or trailing:
        raise PerfLensError(
            ErrorCode.INTERNAL_ERROR,
            "collector_broker",
            "Collector broker returned a malformed response frame",
        )
    return line


def _raise_rejected_response(response: BrokerResponse, request_id: str) -> None:
    error = response.error
    if error is None:  # Defensive: BrokerResponse validates this invariant.
        raise PerfLensError(
            ErrorCode.INTERNAL_ERROR,
            "collector_broker",
            "Collector broker returned no error for a rejected request",
        )
    try:
        code = ErrorCode(error.code)
    except ValueError:
        code = ErrorCode.EXTERNAL_TOOL_FAILED
    raise PerfLensError(
        code,
        error.stage,
        error.message,
        recoverable=error.recoverable,
        details={"request_id": request_id},
    )
