"""Authenticated Python client for the independent Rust Trace Helper."""

from __future__ import annotations

import secrets
import socket
import stat
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.trace_helper.protocol import (
    MAX_TRACE_HELPER_MESSAGE_BYTES,
    TraceHelperCollectionReadyResult,
    TraceHelperCollectionResult,
    TraceHelperCollectPidRequest,
    TraceHelperHealthRequest,
    TraceHelperHealthResult,
    TraceHelperResponse,
    parse_trace_helper_response_frame,
)

_PEER_CREDENTIALS = struct.Struct("3i")


@dataclass(frozen=True, slots=True)
class _SocketIdentity:
    device: int
    inode: int
    uid: int
    mode: int
    parent_device: int
    parent_inode: int
    parent_uid: int
    parent_mode: int


class TraceHelperClient:
    """Perform identity-pinned requests without exposing the private socket to users."""

    def __init__(
        self,
        socket_path: Path,
        *,
        expected_helper_uid: int,
        timeout_seconds: float = 1.0,
    ) -> None:
        if expected_helper_uid < 0:
            raise ValueError("expected Trace Helper UID must be non-negative")
        if timeout_seconds <= 0 or timeout_seconds > 15:
            raise ValueError("Trace Helper timeout must be between zero and 15 seconds")
        self._socket_path = socket_path
        self._expected_helper_uid = expected_helper_uid
        self._timeout_seconds = timeout_seconds

    def health(self) -> TraceHelperHealthResult:
        request = TraceHelperHealthRequest(
            request_id=f"request-{secrets.token_hex(16)}"
        )
        response, peer_pid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n",
            expected_request_id=request.request_id,
        )
        if not response.ok or response.result is None:
            raise _response_error(response, "Trace Helper rejected health")
        result = response.result
        if not isinstance(result, TraceHelperHealthResult) or (
            result.helper_uid != self._expected_helper_uid
            or result.helper_pid != peer_pid
            or not result.ready
        ):
            raise _unsafe_identity()
        return result

    def collect(
        self,
        request: TraceHelperCollectPidRequest,
        *,
        ready_callback: Callable[[], None] | None = None,
    ) -> TraceHelperCollectionResult:
        """Submit one typed request; the Helper still revalidates every field."""
        response, _peer_pid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n",
            expected_request_id=request.request_id,
            expected_ready=(request.plan_id, request.target.pid)
            if ready_callback is not None
            else None,
            ready_callback=ready_callback,
        )
        if not response.ok or response.result is None:
            raise _response_error(response, "Trace Helper rejected collection")
        result = response.result
        if not isinstance(result, TraceHelperCollectionResult) or (
            result.plan_id != request.plan_id
            or result.mode != request.mode
            or result.target_pid != request.target.pid
            or result.target_start_time_ticks != request.target.start_time_ticks
            or result.artifact_name != f"{request.plan_id}.trace.ndjson"
            or result.output_bytes > request.max_output_bytes
            or result.capture_backend != request.expected_capture_backend
            or result.policy_sha256 != request.expected_policy_sha256
        ):
            raise _unsafe_identity()
        return result

    def _exchange(
        self,
        payload: bytes,
        *,
        expected_request_id: str,
        expected_ready: tuple[str, int] | None = None,
        ready_callback: Callable[[], None] | None = None,
    ) -> tuple[TraceHelperResponse, int]:
        identity = _safe_socket_identity(self._socket_path, self._expected_helper_uid)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(str(self._socket_path))
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    _PEER_CREDENTIALS.size,
                )
                peer_pid, peer_uid, _peer_gid = _PEER_CREDENTIALS.unpack(credentials)
                if peer_uid != self._expected_helper_uid:
                    raise _unsafe_identity()
                _recheck_socket_identity(
                    self._socket_path,
                    identity,
                    self._expected_helper_uid,
                )
                connection.sendall(payload)
                response_buffer = bytearray()
                response = _parse_response(
                    _read_frame(connection, response_buffer),
                    expected_request_id,
                )
                if expected_ready is not None and response.ok:
                    ready = response.result
                    if not isinstance(ready, TraceHelperCollectionReadyResult) or (
                        ready.plan_id,
                        ready.target_pid,
                    ) != expected_ready:
                        raise _unsafe_identity()
                    assert ready_callback is not None
                    ready_callback()
                    response = _parse_response(
                        _read_frame(connection, response_buffer),
                        expected_request_id,
                    )
                if response_buffer:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "trace_helper",
                        "Trace Helper returned an unexpected extra response frame",
                    )
        except PerfLensError:
            raise
        except TimeoutError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_TIMEOUT,
                "trace_helper",
                "Trace Helper response timed out",
                recoverable=True,
                retryable=True,
            ) from exc
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "trace_helper",
                "Unable to communicate with the Trace Helper",
                recoverable=True,
            ) from exc
        return response, peer_pid


def _safe_socket_identity(path: Path, expected_uid: int) -> _SocketIdentity:
    if not path.expanduser().is_absolute():
        raise _unsafe_identity()
    try:
        candidate = path.expanduser()
        parent = candidate.parent.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        metadata = candidate.stat(follow_symlinks=False)
        parent_metadata = parent.stat()
    except OSError as exc:
        raise _unsafe_identity() from exc
    mode = stat.S_IMODE(metadata.st_mode)
    parent_mode = stat.S_IMODE(parent_metadata.st_mode)
    if (
        resolved != candidate
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or mode & 0o007
        or mode & 0o600 != 0o600
        or parent_metadata.st_uid != expected_uid
        or parent_mode & 0o022
    ):
        raise _unsafe_identity()
    return _SocketIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        mode=mode,
        parent_device=parent_metadata.st_dev,
        parent_inode=parent_metadata.st_ino,
        parent_uid=parent_metadata.st_uid,
        parent_mode=parent_mode,
    )


def _recheck_socket_identity(
    path: Path,
    expected: _SocketIdentity,
    expected_uid: int,
) -> None:
    if _safe_socket_identity(path, expected_uid) != expected:
        raise _unsafe_identity()


def _read_frame(connection: socket.socket, received: bytearray) -> bytes:
    while b"\n" not in received:
        remaining = MAX_TRACE_HELPER_MESSAGE_BYTES + 1 - len(received)
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "trace_helper",
                "Trace Helper response exceeds the protocol limit",
            )
        chunk = connection.recv(min(16 << 10, remaining))
        if not chunk:
            break
        received.extend(chunk)
    newline = received.find(b"\n")
    if newline >= MAX_TRACE_HELPER_MESSAGE_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "trace_helper",
            "Trace Helper response exceeds the protocol limit",
        )
    if newline < 0:
        raise PerfLensError(
            ErrorCode.INTERNAL_ERROR,
            "trace_helper",
            "Trace Helper returned a malformed response frame",
        )
    frame = bytes(received[: newline + 1])
    del received[: newline + 1]
    return frame


def _parse_response(frame: bytes, expected_request_id: str) -> TraceHelperResponse:
    response = parse_trace_helper_response_frame(frame)
    if response.request_id != expected_request_id:
        raise _unsafe_identity()
    return response


def _response_error(response: TraceHelperResponse, fallback: str) -> PerfLensError:
    error = response.error
    try:
        code = ErrorCode(error.code) if error is not None else ErrorCode.INTERNAL_ERROR
    except ValueError:
        code = ErrorCode.INTERNAL_ERROR
    return PerfLensError(
        code,
        error.stage if error is not None else "trace_helper",
        error.message if error is not None else fallback,
        recoverable=error.recoverable if error is not None else False,
    )


def _unsafe_identity() -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "trace_helper",
        "Trace Helper socket or peer identity is unsafe",
    )
