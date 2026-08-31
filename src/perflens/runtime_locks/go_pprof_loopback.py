"""Same-UID, PID/socket-bound access to a literal loopback Go pprof endpoint."""

from __future__ import annotations

import hashlib
import http.client
import math
import os
import stat
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from perflens.collection.planning import inspect_pid_identity
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockProcessTargetBinding,
    derive_runtime_lock_process_target_identity,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.go_pprof_converter import GoProfileKind

_MAX_PROFILE_BYTES = 64 << 20
_MAX_HEADERS = 32
_MAX_HEADER_BYTES = 16 << 10
_MAX_TARGET_FDS = 4096
_TCP_LISTEN = "0A"
_LOOPBACK_HEX = "0100007F"


@dataclass(frozen=True, slots=True)
class GoPprofLoopbackCapture:
    private_root: Path
    profile_path: Path
    profile_sha256: str
    profile_size: int
    profile_device: int
    profile_inode: int
    profile_kind: GoProfileKind
    target: RuntimeLockProcessTargetBinding
    started_at: str
    finished_at: str
    accounted_active_seconds: int


def inspect_go_pprof_loopback_target(
    target_pid: int,
    loopback_port: int,
    *,
    invoking_uid: int | None = None,
) -> RuntimeLockProcessTargetBinding:
    """Bind one same-UID process to the socket inode that owns a loopback listener."""

    uid = os.geteuid() if invoking_uid is None else invoking_uid
    if uid != os.geteuid():
        raise _error("Go pprof target UID override is forbidden")
    if isinstance(loopback_port, bool) or not 1 <= loopback_port <= 65535:
        raise _error("Go pprof loopback port is outside its fixed bound")
    owner_uid, start_ticks = inspect_pid_identity(target_pid)
    if owner_uid != uid:
        raise _error("Go pprof loopback target must belong to the invoking UID")
    socket_inode = _listening_socket_inode(target_pid, loopback_port)
    _require_process_socket(target_pid, socket_inode)
    current_uid, current_ticks = inspect_pid_identity(target_pid)
    if (current_uid, current_ticks) != (owner_uid, start_ticks):
        raise _error("Go pprof target identity changed during socket binding")
    identity = derive_runtime_lock_process_target_identity(
        target_pid,
        owner_uid,
        start_ticks,
        loopback_port,
        socket_inode,
    )
    return RuntimeLockProcessTargetBinding(
        target_pid=target_pid,
        target_uid=owner_uid,
        target_start_time_ticks=start_ticks,
        loopback_address="127.0.0.1",
        loopback_port=loopback_port,
        socket_inode=socket_inode,
        target_identity_sha256=identity,
    )


def capture_go_pprof_loopback_profile(
    target: RuntimeLockProcessTargetBinding,
    profile_kind: GoProfileKind,
    *,
    private_output_root: Path,
    maximum_bytes: int = _MAX_PROFILE_BYTES,
    timeout_seconds: int = 10,
) -> GoPprofLoopbackCapture:
    """Fetch one fixed pprof endpoint after and before revalidating PID/socket identity."""

    if isinstance(maximum_bytes, bool) or not 1 <= maximum_bytes <= _MAX_PROFILE_BYTES:
        raise _limit("Go pprof loopback profile limit is invalid")
    if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
        raise _limit("Go pprof loopback timeout is invalid")
    _assert_target_current(target)
    root, root_stat = _private_root(private_output_root)
    root_fd = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    token = os.urandom(10).hex()
    name = f"go-pprof-loopback-{token}.{profile_kind}.pb.gz"
    path = root / name
    descriptor = -1
    connection: http.client.HTTPConnection | None = None
    created = False
    success = False
    started_wall = datetime.now(tz=UTC)
    started_mono = time.monotonic_ns()
    try:
        if _directory_identity(os.fstat(root_fd)) != _directory_identity(root_stat):
            raise _error("Go pprof private output directory identity changed")
        descriptor = os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_fd,
        )
        created = True
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            target.loopback_port,
            timeout=timeout_seconds,
        )
        endpoint = f"/debug/pprof/{profile_kind}?debug=0"
        connection.request(
            "GET",
            endpoint,
            headers={"Host": "127.0.0.1", "Connection": "close", "Accept": "*/*"},
        )
        response = connection.getresponse()
        headers = response.getheaders()
        header_bytes = sum(
            len(name_.encode("latin-1")) + len(value.encode("latin-1")) + 4
            for name_, value in headers
        )
        if len(headers) > _MAX_HEADERS or header_bytes > _MAX_HEADER_BYTES:
            raise _limit("Go pprof loopback response headers exceed their fixed bound")
        if response.status != 200:
            raise _error("Go pprof loopback endpoint did not return HTTP 200")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length, 10)
            except ValueError as exc:
                raise _error("Go pprof loopback Content-Length is malformed") from exc
            if not 1 <= declared_length <= maximum_bytes:
                raise _limit("Go pprof loopback profile exceeds its fixed bound")
        digest = hashlib.sha256()
        size = 0
        while chunk := response.read(min(1 << 20, maximum_bytes + 1 - size)):
            size += len(chunk)
            if size > maximum_bytes:
                raise _limit("Go pprof loopback profile exceeds its fixed bound")
            digest.update(chunk)
            _write_all(descriptor, chunk)
        if size == 0:
            raise _error("Go pprof loopback endpoint returned an empty profile")
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        _assert_private_file(metadata, os.geteuid(), size)
        _assert_target_current(target)
        finished_mono = time.monotonic_ns()
        finished_wall = datetime.now(tz=UTC)
        success = True
        return GoPprofLoopbackCapture(
            private_root=root,
            profile_path=path,
            profile_sha256=digest.hexdigest(),
            profile_size=size,
            profile_device=metadata.st_dev,
            profile_inode=metadata.st_ino,
            profile_kind=profile_kind,
            target=target,
            started_at=started_wall.isoformat(),
            finished_at=finished_wall.isoformat(),
            accounted_active_seconds=max(1, math.ceil((finished_mono - started_mono) / 1e9)),
        )
    except (OSError, http.client.HTTPException) as exc:
        raise _error("Go pprof loopback profile could not be fetched safely") from exc
    finally:
        if connection is not None:
            connection.close()
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if created and not success:
            with suppress(OSError):
                os.unlink(name, dir_fd=root_fd)
        os.close(root_fd)


def open_go_pprof_loopback_capture(capture: GoPprofLoopbackCapture) -> int:
    root, root_stat = _private_root(capture.private_root)
    if capture.profile_path.parent != root:
        raise _error("Go pprof loopback profile escaped its private root")
    root_fd = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        if _directory_identity(os.fstat(root_fd)) != _directory_identity(root_stat):
            raise _error("Go pprof private output directory identity changed")
        descriptor = os.open(
            capture.profile_path.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
    finally:
        os.close(root_fd)
    try:
        metadata = os.fstat(descriptor)
        _assert_private_file(metadata, os.geteuid(), capture.profile_size)
        if (
            metadata.st_dev != capture.profile_device
            or metadata.st_ino != capture.profile_inode
            or _hash_fd(descriptor) != capture.profile_sha256
        ):
            raise _error("Go pprof loopback profile differs from its captured identity")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def cleanup_go_pprof_loopback_capture(capture: GoPprofLoopbackCapture) -> None:
    root, root_stat = _private_root(capture.private_root)
    if capture.profile_path.parent != root:
        raise _error("Go pprof loopback profile escaped its private root")
    root_fd = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        if _directory_identity(os.fstat(root_fd)) != _directory_identity(root_stat):
            raise _error("Go pprof private output directory identity changed")
        try:
            descriptor = os.open(
                capture.profile_path.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return
        try:
            metadata = os.fstat(descriptor)
            _assert_private_file(metadata, os.geteuid(), capture.profile_size)
            if (
                metadata.st_dev != capture.profile_device
                or metadata.st_ino != capture.profile_inode
                or _hash_fd(descriptor) != capture.profile_sha256
            ):
                raise _error("Go pprof loopback cleanup refused a replaced file")
        finally:
            os.close(descriptor)
        os.unlink(capture.profile_path.name, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def _assert_target_current(target: RuntimeLockProcessTargetBinding) -> None:
    current = inspect_go_pprof_loopback_target(target.target_pid, target.loopback_port)
    if current != target:
        raise _error("Go pprof loopback PID or socket identity changed")


def _listening_socket_inode(pid: int, port: int) -> int:
    path = Path("/proc") / str(pid) / "net" / "tcp"
    try:
        with path.open("r", encoding="ascii", errors="strict") as stream:
            next(stream)
            matches: list[int] = []
            for line_number, line in enumerate(stream, start=1):
                if line_number > 65_536:
                    raise _limit("Go pprof TCP table exceeds its fixed bound")
                fields = line.split()
                if len(fields) < 10:
                    raise _error("Go pprof TCP table is malformed")
                local = fields[1].split(":", maxsplit=1)
                if (
                    len(local) == 2
                    and local[0] == _LOOPBACK_HEX
                    and int(local[1], 16) == port
                    and fields[3] == _TCP_LISTEN
                ):
                    matches.append(int(fields[9], 10))
    except (OSError, StopIteration, ValueError) as exc:
        raise _error("Go pprof loopback listener cannot be inspected") from exc
    if len(matches) != 1 or matches[0] <= 0:
        raise _error("Go pprof requires one exact literal-loopback listening socket")
    return matches[0]


def _require_process_socket(pid: int, inode: int) -> None:
    directory = Path("/proc") / str(pid) / "fd"
    expected = f"socket:[{inode}]"
    try:
        entries = sorted(directory.iterdir(), key=lambda item: int(item.name))
        if len(entries) > _MAX_TARGET_FDS:
            raise _limit("Go pprof target file-descriptor count exceeds its fixed bound")
        if not any(os.readlink(entry) == expected for entry in entries):
            raise _error("Go pprof listener is not owned by the authorized target process")
    except (OSError, ValueError) as exc:
        raise _error("Go pprof target sockets cannot be inspected safely") from exc


def _private_root(path: Path) -> tuple[Path, os.stat_result]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _error("Go pprof private output directory is unsafe")
    return resolved, metadata


def _assert_private_file(metadata: os.stat_result, uid: int, size: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != size
        or not 1 <= size <= _MAX_PROFILE_BYTES
    ):
        raise _error("Go pprof private profile identity is unsafe")


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1 << 20):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "go_pprof_loopback",
        message,
        recoverable=True,
    )


def _limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "go_pprof_loopback",
        message,
        recoverable=True,
    )
