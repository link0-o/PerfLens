"""Unix-socket client for the restricted collector broker."""

from __future__ import annotations

import hashlib
import secrets
import socket
import stat
import struct
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
        if timeout_seconds <= 0 or timeout_seconds > 86_500:
            raise ValueError("Broker timeout is invalid")
        self._socket_path = _socket_path(socket_path)
        self._timeout_seconds = timeout_seconds

    def collect(self, plan: CollectionPlanArtifact) -> CollectionArtifact:
        identity = f"{plan.plan_id}\0{plan.target_pid}\0{plan.expires_at}"
        request = BrokerCollectRequest(
            request_id=f"request-{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
            plan=plan,
        )
        response, _server_pid, _server_uid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n"
        )
        if not response.ok:
            error = response.error or {}
            raw_code = error.get("code", ErrorCode.EXTERNAL_TOOL_FAILED.value)
            try:
                code = ErrorCode(str(raw_code))
            except ValueError:
                code = ErrorCode.EXTERNAL_TOOL_FAILED
            raise PerfLensError(
                code,
                str(error.get("stage", "collector_broker")),
                str(error.get("message", "Collector broker rejected the request")),
                recoverable=bool(error.get("recoverable", True)),
                details={"request_id": request.request_id},
            )
        if response.result is None:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned no result",
            )
        try:
            return CollectionArtifact.model_validate(response.result)
        except ValidationError as exc:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned an invalid collection artifact",
            ) from exc

    def health(self, *, expected_service_uid: int | None = None) -> CollectorHealthArtifact:
        """Perform one authenticated, read-only protocol round trip."""
        if expected_service_uid is not None and expected_service_uid < 0:
            raise ValueError("Expected Collector service UID is invalid")
        request = BrokerHealthRequest(request_id=f"request-{secrets.token_hex(12)}")
        response, server_pid, server_uid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n"
        )
        if not response.ok:
            error = response.error or {}
            raw_code = error.get("code", ErrorCode.EXTERNAL_TOOL_FAILED.value)
            try:
                code = ErrorCode(str(raw_code))
            except ValueError:
                code = ErrorCode.EXTERNAL_TOOL_FAILED
            raise PerfLensError(
                code,
                str(error.get("stage", "collector_broker")),
                str(error.get("message", "Collector broker rejected the health request")),
                recoverable=bool(error.get("recoverable", True)),
                details={"request_id": request.request_id},
            )
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

    def _exchange(self, payload: bytes) -> tuple[BrokerResponse, int, int]:
        if len(payload) > MAX_BROKER_MESSAGE_BYTES:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker request exceeds the protocol limit",
            )
        received = bytearray()
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
                connection.sendall(payload)
                while b"\n" not in received:
                    chunk = connection.recv(
                        min(16 << 10, MAX_BROKER_MESSAGE_BYTES + 1 - len(received))
                    )
                    if not chunk:
                        break
                    received.extend(chunk)
                    if len(received) > MAX_BROKER_MESSAGE_BYTES:
                        raise PerfLensError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "collector_broker",
                            "Collector broker response exceeds the protocol limit",
                        )
        except PerfLensError:
            raise
        except (OSError, TimeoutError, struct.error) as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "collector_broker",
                "Unable to communicate with the collector broker",
                recoverable=True,
                details={"socket": str(self._socket_path)},
            ) from exc
        line, separator, trailing = bytes(received).partition(b"\n")
        if not separator or trailing:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned a malformed response frame",
            )
        try:
            response = BrokerResponse.model_validate_json(line)
        except ValidationError as exc:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker returned invalid JSON",
            ) from exc
        if server_pid <= 0 or server_uid < 0:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector Unix peer credentials are invalid",
            )
        return response, server_pid, server_uid


def _socket_path(path: Path) -> Path:
    if not path.expanduser().is_absolute():
        raise ValueError("Collector broker socket path must be absolute")
    try:
        safe_path = path.expanduser().resolve(strict=True)
        metadata = safe_path.stat()
    except OSError as exc:
        raise ValueError("Collector broker socket does not exist") from exc
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ValueError("Collector broker path is not a Unix socket")
    return safe_path
