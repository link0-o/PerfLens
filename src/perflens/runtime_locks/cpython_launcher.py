"""Unprivileged startup launcher for the CPython threading bootstrap."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import math
import os
import signal
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.cpython_adapter import (
    CpythonDirectoryIdentity,
    CpythonFileIdentity,
    CpythonLaunchPolicy,
)
from perflens.runtime_locks.linux_memfd import F_ADD_SEALS, IMMUTABLE_MEMFD_SEALS
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorCpythonThreadingRequest,
    RuntimeSupervisorRequest,
    discover_runtime_supervisor_policy,
    runtime_supervisor_directory_identity,
    runtime_supervisor_file_identity,
    runtime_supervisor_request_id,
    runtime_supervisor_writable_identity,
)

_MAX_SCRIPT_BYTES = 64 << 20
_MAX_STREAM_BYTES = 64 << 20


@dataclass(frozen=True, slots=True)
class CpythonTargetIdentity:
    project_relative_path: str
    script_sha256: str
    size: int
    device: int
    inode: int
    owner_uid: int
    mode: int
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class CpythonLaunchRequest:
    arguments: tuple[str, ...]
    semantics: Literal["exact", "thresholded"]
    threshold_ns: int | None
    duration_seconds: int
    max_events: int

    def __post_init__(self) -> None:
        if not 1 <= self.duration_seconds <= 30 or not 1 <= self.max_events <= 20_000:
            raise _error("CPython launch request exceeds fixed budgets")
        if self.semantics == "exact":
            if self.threshold_ns is not None or self.duration_seconds > 3:
                raise _error("CPython exact launch controls are invalid")
        elif self.threshold_ns != 10_000:
            raise _error("CPython thresholded launch requires the fixed 10 us threshold")
        if (
            len(self.arguments) > 128
            or sum(len(value.encode()) for value in self.arguments) > 32 << 10
        ):
            raise _error("CPython workload arguments exceed fixed bounds")
        if any("\x00" in value for value in self.arguments):
            raise _error("CPython workload argument contains NUL")


@dataclass(frozen=True, slots=True)
class CpythonLaunchResult:
    stream_path: Path
    stream_sha256: str
    stream_size: int
    target_identity_sha256: str
    target_pid: int
    target_uid: int
    target_start_ticks: int
    started_at: str
    finished_at: str
    accounted_active_seconds: int
    exit_code: int | None
    termination_reason: Literal["exited", "duration_limit"]
    supervisor_sha256: str
    interpreter_sha256: str
    bootstrap_sha256: str


class CpythonThreadingLauncher:
    def __init__(
        self,
        *,
        project_root: Path,
        private_output_root: Path,
        policy: CpythonLaunchPolicy,
        supervisor_client: RuntimeSupervisorClient | None = None,
    ) -> None:
        self._uid = os.geteuid()
        if self._uid == 0:
            raise _error("CPython threading launcher must not run as root")
        self._project_root = _directory(project_root, self._uid, None)
        self._output_root = _directory(private_output_root, self._uid, 0o700)
        self._policy = policy
        _assert_runtime_file(policy.interpreter)
        _assert_runtime_home(policy.runtime_home)
        _assert_runtime_file(policy.bootstrap)
        if supervisor_client is None:
            discovered = discover_runtime_supervisor_policy()
            if discovered.policy is None:
                raise _error("The fixed Runtime Lock supervisor is unavailable")
            supervisor_client = RuntimeSupervisorClient(discovered.policy)
        self._supervisor = supervisor_client

    def inspect_target(self, script: Path) -> CpythonTargetIdentity:
        return inspect_cpython_target(self._project_root[0], script, invoking_uid=self._uid)

    def launch(
        self,
        script: Path,
        request: CpythonLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> CpythonLaunchResult:
        target = self.inspect_target(script)
        if target.identity_sha256 != expected_target_identity_sha256:
            raise _error("CPython script differs from the authorized Preview")
        _assert_runtime_file(self._policy.interpreter)
        _assert_runtime_home(self._policy.runtime_home)
        _assert_runtime_file(self._policy.bootstrap)
        script_fd = interpreter_fd = runtime_home_fd = bootstrap_fd = -1
        project_fd = root_fd = output_fd = -1
        stream_name = f"cpython-threading-{os.urandom(10).hex()}.ndjson"
        stream_path = self._output_root[0] / stream_name
        created = False
        success = False
        started_at = datetime.now(tz=UTC)
        try:
            script_fd = _sealed_script_snapshot(self._project_root[0], target)
            interpreter_fd = _open_identity(self._policy.interpreter)
            runtime_home_fd = _open_runtime_home(self._policy.runtime_home)
            bootstrap_fd = _open_identity(self._policy.bootstrap)
            project_fd = _open_directory(self._project_root)
            root_fd = _open_directory(self._output_root)
            output_fd = os.open(
                stream_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_fd,
            )
            created = True
            supervisor_request = RuntimeSupervisorRequest(
                request_id=runtime_supervisor_request_id(),
                expected_parent_pid=os.getpid(),
                expected_supervisor_sha256=self._supervisor.policy.sha256,
                executable=runtime_supervisor_file_identity(interpreter_fd),
                working_directory=runtime_supervisor_directory_identity(project_fd),
                arguments=request.arguments,
                timeout_milliseconds=math.ceil(request.duration_seconds * 1_000),
                request=RuntimeSupervisorCpythonThreadingRequest(
                    runtime_home=runtime_supervisor_directory_identity(runtime_home_fd),
                    bootstrap=runtime_supervisor_file_identity(bootstrap_fd),
                    script=runtime_supervisor_file_identity(script_fd),
                    script_label=target.project_relative_path,
                    output=runtime_supervisor_writable_identity(
                        output_fd, maximum_size=_MAX_STREAM_BYTES
                    ),
                    semantics=request.semantics,
                    threshold_ns=request.threshold_ns,
                    max_events=request.max_events,
                ),
            )
            receipt = self._supervisor.execute(supervisor_request)
            if receipt.terminating_signal == signal.SIGXFSZ:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "cpython_threading_launcher",
                    "CPython private evidence exceeded 64 MiB",
                    recoverable=True,
                )
            if receipt.termination_reason not in {"exited", "timeout"}:
                raise _error("Runtime supervisor could not prove the CPython workload lifecycle")
            os.fsync(output_fd)
            os.close(output_fd)
            output_fd = -1
            os.fsync(root_fd)
            stream_sha256, stream_size = _inspect_stream(stream_path, self._uid)
            finished_at = started_at + timedelta(
                microseconds=(receipt.elapsed_monotonic_ns + 999) // 1_000
            )
            success = True
            return CpythonLaunchResult(
                stream_path=stream_path,
                stream_sha256=stream_sha256,
                stream_size=stream_size,
                target_identity_sha256=target.identity_sha256,
                target_pid=receipt.workload_pid,
                target_uid=self._uid,
                target_start_ticks=receipt.workload_start_ticks,
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                accounted_active_seconds=receipt.accounted_active_seconds,
                exit_code=receipt.exit_code,
                termination_reason=(
                    "duration_limit" if receipt.termination_reason == "timeout" else "exited"
                ),
                supervisor_sha256=receipt.supervisor_sha256,
                interpreter_sha256=self._policy.interpreter.sha256,
                bootstrap_sha256=self._policy.bootstrap.sha256,
            )
        finally:
            for descriptor in (
                output_fd,
                script_fd,
                interpreter_fd,
                runtime_home_fd,
                bootstrap_fd,
                project_fd,
                root_fd,
            ):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if created and not success:
                cleanup_fd = -1
                try:
                    cleanup_fd = _open_directory(self._output_root)
                    os.unlink(stream_name, dir_fd=cleanup_fd)
                except OSError:
                    pass
                finally:
                    if cleanup_fd >= 0:
                        os.close(cleanup_fd)


def inspect_cpython_target(
    project_root: Path,
    script: Path,
    *,
    invoking_uid: int | None = None,
) -> CpythonTargetIdentity:
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    if invoking_uid is not None and uid != os.geteuid():
        raise _error("CPython target UID override is forbidden")
    root = project_root.resolve(strict=True)
    if script.is_symlink():
        raise _error("CPython target script cannot be a symlink")
    try:
        resolved = script.resolve(strict=True)
        relative = resolved.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise _error("CPython target script is outside the project root") from exc
    if resolved != script or relative in {"", "."}:
        raise _error("CPython target script identity is not canonical")
    descriptor = os.open(
        resolved,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_nlink != 1
            or before.st_mode & 0o6022
            or not 1 <= before.st_size <= _MAX_SCRIPT_BYTES
        ):
            raise _error("CPython target owner, mode, links, privileges, or size is unsafe")
        _reject_file_capabilities(descriptor, "CPython target")
        payload = bytearray()
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            payload.extend(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise _error("CPython target changed while it was inspected")
        sha256 = digest.hexdigest()
        identity = hashlib.sha256(
            "\0".join(
                (
                    "perflens-cpython-target-v1",
                    relative,
                    sha256,
                    str(before.st_size),
                    str(before.st_dev),
                    str(before.st_ino),
                    str(uid),
                    str(mode),
                )
            ).encode("utf-8")
        ).hexdigest()
        return CpythonTargetIdentity(
            project_relative_path=relative,
            script_sha256=sha256,
            size=before.st_size,
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=uid,
            mode=mode,
            identity_sha256=identity,
        )
    finally:
        os.close(descriptor)


def open_cpython_private_stream(result: CpythonLaunchResult) -> int:
    descriptor = os.open(
        result.stream_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        _reject_file_capabilities(descriptor, "CPython target")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != result.stream_size
            or digest.hexdigest() != result.stream_sha256
        ):
            raise _error("CPython private evidence identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def cleanup_cpython_launch_result(result: CpythonLaunchResult) -> None:
    descriptor = open_cpython_private_stream(result)
    metadata = os.fstat(descriptor)
    os.close(descriptor)
    parent_fd = os.open(
        result.stream_path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        current = os.stat(result.stream_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise _error("CPython private evidence changed before cleanup")
        os.unlink(result.stream_path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _sealed_script_snapshot(project_root: Path, target: CpythonTargetIdentity) -> int:
    source = project_root / target.project_relative_path
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    snapshot = os.memfd_create("perflens-cpython-script", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        metadata = os.fstat(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
            os.write(snapshot, chunk)
        after = os.fstat(descriptor)
        if (
            _target_file_identity(metadata) != _target_file_identity(after)
            or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
                metadata.st_size,
            )
            != (
                target.device,
                target.inode,
                target.owner_uid,
                target.mode,
                1,
                target.size,
            )
            or digest.hexdigest() != target.script_sha256
        ):
            raise _error("CPython target changed before launch")
        os.fchmod(snapshot, 0o400)
        fcntl.fcntl(snapshot, F_ADD_SEALS, IMMUTABLE_MEMFD_SEALS)
        os.lseek(snapshot, 0, os.SEEK_SET)
        return snapshot
    except Exception:
        os.close(snapshot)
        raise
    finally:
        os.close(descriptor)


def _inspect_stream(path: Path, uid: int) -> tuple[str, int]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_STREAM_BYTES
        ):
            raise _error("CPython private stream is unsafe or incomplete")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        return digest.hexdigest(), metadata.st_size
    finally:
        os.close(descriptor)


def _directory(path: Path, uid: int, expected_mode: int | None) -> tuple[Path, int, int, int]:
    if not path.is_absolute() or path.is_symlink():
        raise _error("CPython launcher directory must be absolute and non-symlinked")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise _error("CPython launcher directory identity changed")
    metadata = path.stat(follow_symlinks=False)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_mode & 0o022
        or (expected_mode is not None and mode != expected_mode)
    ):
        raise _error("CPython launcher directory owner or mode is unsafe")
    return path, metadata.st_dev, metadata.st_ino, mode


def _open_directory(identity: tuple[Path, int, int, int]) -> int:
    path, device, inode, mode = identity
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode)) != (
        device,
        inode,
        mode,
    ):
        os.close(descriptor)
        raise _error("CPython launcher directory identity changed")
    return descriptor


def _open_identity(identity: CpythonFileIdentity) -> int:
    descriptor = os.open(
        identity.path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        current = runtime_supervisor_file_identity(descriptor)
        _reject_file_capabilities(descriptor, "CPython runtime file")
        if (
            current.sha256 != identity.sha256
            or current.device != identity.device
            or current.inode != identity.inode
            or current.owner_uid != identity.owner_uid
            or current.mode != identity.mode
            or current.links != identity.links
            or current.size != identity.size
        ):
            raise _error("CPython runtime file identity changed")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _assert_runtime_file(identity: CpythonFileIdentity) -> None:
    descriptor = _open_identity(identity)
    os.close(descriptor)


def _assert_runtime_home(identity: CpythonDirectoryIdentity) -> None:
    descriptor = _open_runtime_home(identity)
    os.close(descriptor)


def _open_runtime_home(identity: CpythonDirectoryIdentity) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(identity.path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != identity.device
            or metadata.st_ino != identity.inode
            or metadata.st_uid != identity.owner_uid
            or stat.S_IMODE(metadata.st_mode) != identity.mode
            or identity.mode & 0o022
        ):
            raise _error("CPython runtime home identity changed")
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise _error("CPython runtime home cannot be opened safely") from exc
    except PerfLensError:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _target_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _reject_file_capabilities(descriptor: int, label: str) -> None:
    try:
        os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise _error(f"{label} capabilities cannot be checked safely") from exc
    raise _error(f"{label} with file capabilities is unsupported")


def _error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "cpython_threading_launcher",
        message,
        recoverable=True,
    )
