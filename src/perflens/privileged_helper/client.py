"""Authenticated Python client for the private Rust Helper socket."""

from __future__ import annotations

import secrets
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.privileged_helper.protocol import (
    MAX_HELPER_MESSAGE_BYTES,
    HelperHealthRequest,
    HelperHealthResult,
    HelperResponse,
    parse_helper_response_frame,
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


class HelperClient:
    """Perform authenticated, identity-pinned requests to the private Helper."""

    def __init__(
        self,
        socket_path: Path,
        *,
        expected_helper_uid: int,
        timeout_seconds: float = 1.0,
    ) -> None:
        if expected_helper_uid < 0:
            raise ValueError("expected Helper UID must be non-negative")
        if timeout_seconds <= 0 or timeout_seconds > 5:
            raise ValueError("Helper timeout must be between zero and five seconds")
        self._socket_path = socket_path
        self._expected_helper_uid = expected_helper_uid
        self._timeout_seconds = timeout_seconds

    def health(self) -> HelperHealthResult:
        request = HelperHealthRequest(
            request_id=f"request-{secrets.token_hex(16)}",
        )
        response, peer_pid = self._exchange(
            request.model_dump_json().encode("utf-8") + b"\n",
            expected_request_id=request.request_id,
        )
        if not response.ok or response.result is None:
            error = response.error
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                error.stage if error is not None else "privileged_helper",
                error.message if error is not None else "Privileged Helper rejected health",
                recoverable=True,
            )
        result = response.result
        if (
            result.helper_uid != self._expected_helper_uid
            or result.helper_pid != peer_pid
            or result.privilege_mode != "paranoid3_helper"
            or not result.ready
        ):
            raise _unsafe_helper_identity()
        return result

    def _exchange(
        self, payload: bytes, *, expected_request_id: str
    ) -> tuple[HelperResponse, int]:
        identity = _safe_socket_identity(self._socket_path, self._expected_helper_uid)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(str(self._socket_path))
                raw_credentials = connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    _PEER_CREDENTIALS.size,
                )
                peer_pid, peer_uid, _peer_gid = _PEER_CREDENTIALS.unpack(raw_credentials)
                if peer_uid != self._expected_helper_uid:
                    raise _unsafe_helper_identity()
                _recheck_socket_identity(
                    self._socket_path,
                    identity,
                    self._expected_helper_uid,
                )
                connection.sendall(payload)
                response_frame = _read_frame(connection)
        except PerfLensError:
            raise
        except TimeoutError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_TIMEOUT,
                "privileged_helper",
                "Privileged Helper response timed out",
                recoverable=True,
                retryable=True,
            ) from exc
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "privileged_helper",
                "Unable to communicate with the privileged Helper",
                recoverable=True,
            ) from exc
        response = parse_helper_response_frame(response_frame)
        if response.request_id != expected_request_id:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "privileged_helper",
                "Privileged Helper response ID does not match the request",
            )
        return response, peer_pid


def _safe_socket_identity(path: Path, expected_uid: int) -> _SocketIdentity:
    if not path.expanduser().is_absolute():
        raise _unsafe_helper_identity()
    try:
        candidate = path.expanduser()
        parent = candidate.parent.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        metadata = candidate.stat(follow_symlinks=False)
        parent_metadata = parent.stat()
    except OSError as exc:
        raise _unsafe_helper_identity() from exc
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
        raise _unsafe_helper_identity()
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


def _recheck_socket_identity(path: Path, expected: _SocketIdentity, expected_uid: int) -> None:
    current = _safe_socket_identity(path, expected_uid)
    if current != expected:
        raise _unsafe_helper_identity()


def _read_frame(connection: socket.socket) -> bytes:
    received = bytearray()
    while b"\n" not in received:
        remaining = MAX_HELPER_MESSAGE_BYTES - len(received)
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "privileged_helper",
                "Privileged Helper response exceeds the protocol limit",
            )
        chunk = connection.recv(min(16 << 10, remaining))
        if not chunk:
            break
        received.extend(chunk)
    line, separator, trailing = bytes(received).partition(b"\n")
    if not separator or trailing:
        raise PerfLensError(
            ErrorCode.INTERNAL_ERROR,
            "privileged_helper",
            "Privileged Helper returned a malformed response frame",
        )
    return line + b"\n"


def _unsafe_helper_identity() -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "privileged_helper",
        "Privileged Helper socket or peer identity is unsafe",
    )
