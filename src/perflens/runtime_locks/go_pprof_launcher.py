"""Unprivileged launch and fixed ``go tool pprof -raw`` execution."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import math
import os
import re
import signal
import stat
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.go_pprof_adapter import GoToolIdentity
from perflens.runtime_locks.go_pprof_converter import GoProfileKind
from perflens.runtime_locks.linux_memfd import F_ADD_SEALS, IMMUTABLE_MEMFD_SEALS
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorGoPprofRawRequest,
    RuntimeSupervisorGoPprofWorkloadRequest,
    RuntimeSupervisorRequest,
    discover_runtime_supervisor_policy,
    runtime_supervisor_directory_identity,
    runtime_supervisor_file_identity,
    runtime_supervisor_request_id,
    runtime_supervisor_writable_identity,
)

_MAX_BINARY_BYTES = 512 << 20
_MAX_PROFILE_BYTES = 64 << 20
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_BYTES = 32 << 10
_GO_BUILD_VERSION = re.compile(r"^[^\n]+: go(1\.(?:24|25|26|27)(?:\.[0-9]+)?)$")
_MEMFD_SEALS = IMMUTABLE_MEMFD_SEALS


@dataclass(frozen=True, slots=True)
class GoTargetIdentity:
    project_relative_path: str
    binary_sha256: str
    size: int
    device: int
    inode: int
    owner_uid: int
    mode: int
    go_version: str
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class GoPprofLaunchRequest:
    arguments: tuple[str, ...]
    duration_seconds: int

    def __post_init__(self) -> None:
        if not 1 <= self.duration_seconds <= 30:
            raise _error("Go workload duration exceeds the fixed 30 second bound")
        if (
            len(self.arguments) > _MAX_ARGUMENTS
            or sum(len(value.encode("utf-8")) for value in self.arguments) > _MAX_ARGUMENT_BYTES
            or any("\x00" in value for value in self.arguments)
        ):
            raise _error("Go workload arguments exceed their fixed safe bound")


@dataclass(frozen=True, slots=True)
class GoPprofLaunchResult:
    private_root: Path
    mutex_profile_path: Path
    mutex_profile_sha256: str
    mutex_profile_size: int
    mutex_profile_device: int
    mutex_profile_inode: int
    block_profile_path: Path
    block_profile_sha256: str
    block_profile_size: int
    block_profile_device: int
    block_profile_inode: int
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
    go_tool_sha256: str
    pprof_tool_sha256: str


@dataclass(frozen=True, slots=True)
class GoPprofRawResult:
    private_root: Path
    raw_path: Path
    raw_sha256: str
    raw_size: int
    raw_device: int
    raw_inode: int
    profile_kind: GoProfileKind
    accounted_active_seconds: int


class GoPprofLauncher:
    def __init__(
        self,
        *,
        project_root: Path,
        private_output_root: Path,
        go_tool: GoToolIdentity,
        pprof_tool: GoToolIdentity,
        supervisor_client: RuntimeSupervisorClient | None = None,
    ) -> None:
        self._uid = os.geteuid()
        if self._uid == 0:
            raise _error("Go pprof launcher must not run as root")
        self._project_root = _directory(project_root, self._uid, None)
        self._output_root = _directory(private_output_root, self._uid, 0o700)
        self._go_tool = go_tool
        self._pprof_tool = pprof_tool
        _assert_go_tool(go_tool)
        _assert_go_tool(pprof_tool)
        if supervisor_client is None:
            discovery = discover_runtime_supervisor_policy()
            if discovery.policy is None:
                raise _error("The fixed Runtime Lock supervisor is unavailable")
            supervisor_client = RuntimeSupervisorClient(discovery.policy)
        self._supervisor = supervisor_client

    def inspect_target(self, executable: Path) -> GoTargetIdentity:
        return inspect_go_target(
            self._project_root[0],
            executable,
            go_tool=self._go_tool,
            invoking_uid=self._uid,
        )

    def launch(
        self,
        executable: Path,
        request: GoPprofLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> GoPprofLaunchResult:
        target = self.inspect_target(executable)
        if target.identity_sha256 != expected_target_identity_sha256:
            raise _error("Go workload differs from the authorized Preview")
        _assert_go_tool(self._go_tool)
        target_fd = project_fd = output_root_fd = mutex_fd = block_fd = -1
        token = os.urandom(10).hex()
        mutex_name = f"go-pprof-{token}.mutex.pb.gz"
        block_name = f"go-pprof-{token}.block.pb.gz"
        mutex_path = self._output_root[0] / mutex_name
        block_path = self._output_root[0] / block_name
        created = False
        success = False
        created_identities: tuple[tuple[int, int], tuple[int, int]] | None = None
        started_at = datetime.now(tz=UTC)
        try:
            target_fd = _sealed_target_snapshot(self._project_root[0], target)
            project_fd = _open_directory(self._project_root)
            output_root_fd = _open_directory(self._output_root)
            mutex_fd = _create_private(output_root_fd, mutex_name)
            block_fd = _create_private(output_root_fd, block_name)
            mutex_created = os.fstat(mutex_fd)
            block_created = os.fstat(block_fd)
            created_identities = (
                (mutex_created.st_dev, mutex_created.st_ino),
                (block_created.st_dev, block_created.st_ino),
            )
            created = True
            supervisor_request = RuntimeSupervisorRequest(
                request_id=runtime_supervisor_request_id(),
                expected_parent_pid=os.getpid(),
                expected_supervisor_sha256=self._supervisor.policy.sha256,
                executable=runtime_supervisor_file_identity(target_fd),
                working_directory=runtime_supervisor_directory_identity(project_fd),
                arguments=request.arguments,
                timeout_milliseconds=math.ceil(request.duration_seconds * 1_000),
                request=RuntimeSupervisorGoPprofWorkloadRequest(
                    mutex_profile=runtime_supervisor_writable_identity(
                        mutex_fd, maximum_size=_MAX_PROFILE_BYTES
                    ),
                    block_profile=runtime_supervisor_writable_identity(
                        block_fd, maximum_size=_MAX_PROFILE_BYTES
                    ),
                ),
            )
            receipt = self._supervisor.execute(supervisor_request)
            if receipt.termination_reason not in {"exited", "timeout"}:
                raise _error("Runtime supervisor could not prove the Go workload lifecycle")
            for descriptor in (mutex_fd, block_fd):
                os.fsync(descriptor)
            mutex_sha256, mutex_size, mutex_device, mutex_inode = _inspect_profile_fd(
                mutex_fd, self._uid
            )
            block_sha256, block_size, block_device, block_inode = _inspect_profile_fd(
                block_fd, self._uid
            )
            os.close(mutex_fd)
            mutex_fd = -1
            os.close(block_fd)
            block_fd = -1
            os.fsync(output_root_fd)
            finished_at = started_at + timedelta(
                microseconds=(receipt.elapsed_monotonic_ns + 999) // 1_000
            )
            success = True
            return GoPprofLaunchResult(
                private_root=self._output_root[0],
                mutex_profile_path=mutex_path,
                mutex_profile_sha256=mutex_sha256,
                mutex_profile_size=mutex_size,
                mutex_profile_device=mutex_device,
                mutex_profile_inode=mutex_inode,
                block_profile_path=block_path,
                block_profile_sha256=block_sha256,
                block_profile_size=block_size,
                block_profile_device=block_device,
                block_profile_inode=block_inode,
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
                go_tool_sha256=self._go_tool.sha256,
                pprof_tool_sha256=self._pprof_tool.sha256,
            )
        finally:
            for descriptor in (target_fd, project_fd, output_root_fd, mutex_fd, block_fd):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if created and not success:
                assert created_identities is not None
                _unlink_private(
                    self._output_root,
                    (mutex_name, block_name),
                    created_identities,
                )

    def render_raw(
        self,
        result: GoPprofLaunchResult,
        profile_kind: GoProfileKind,
    ) -> GoPprofRawResult:
        _assert_go_tool(self._go_tool)
        profile_path = (
            result.mutex_profile_path if profile_kind == "mutex" else result.block_profile_path
        )
        if result.private_root != self._output_root[0]:
            raise _error("Go profile result belongs to a different private root")
        profile_fd = -1
        expected_profile = (
            (
                result.mutex_profile_device,
                result.mutex_profile_inode,
                result.mutex_profile_sha256,
                result.mutex_profile_size,
            )
            if profile_kind == "mutex"
            else (
                result.block_profile_device,
                result.block_profile_inode,
                result.block_profile_sha256,
                result.block_profile_size,
            )
        )
        try:
            profile_fd = _open_private_profile(
                profile_path,
                self._uid,
                private_root=self._output_root,
                expected=expected_profile,
            )
            return self.render_pinned_raw(profile_fd, profile_kind)
        finally:
            if profile_fd >= 0:
                os.close(profile_fd)

    def render_pinned_raw(
        self,
        profile_fd: int,
        profile_kind: GoProfileKind,
    ) -> GoPprofRawResult:
        """Convert one caller-pinned, same-UID profile with the fixed pprof tool."""

        _assert_go_tool(self._pprof_tool)
        _inspect_profile_fd(profile_fd, self._uid)
        go_fd = root_fd = output_root_fd = raw_fd = -1
        raw_name = f"go-pprof-{os.urandom(10).hex()}.{profile_kind}.raw"
        raw_path = self._output_root[0] / raw_name
        created = False
        success = False
        raw_created_identity: tuple[int, int] | None = None
        try:
            go_fd = _open_go_tool(self._pprof_tool)
            root_fd = os.open("/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
            output_root_fd = _open_directory(self._output_root)
            raw_fd = _create_private(output_root_fd, raw_name)
            raw_created = os.fstat(raw_fd)
            raw_created_identity = (raw_created.st_dev, raw_created.st_ino)
            created = True
            receipt = self._supervisor.execute(
                RuntimeSupervisorRequest(
                    request_id=runtime_supervisor_request_id(),
                    expected_parent_pid=os.getpid(),
                    expected_supervisor_sha256=self._supervisor.policy.sha256,
                    executable=runtime_supervisor_file_identity(go_fd),
                    working_directory=runtime_supervisor_directory_identity(root_fd),
                    arguments=(),
                    timeout_milliseconds=30_000,
                    request=RuntimeSupervisorGoPprofRawRequest(
                        profile=runtime_supervisor_file_identity(profile_fd),
                        output=runtime_supervisor_writable_identity(
                            raw_fd, maximum_size=_MAX_PROFILE_BYTES
                        ),
                    ),
                )
            )
            if receipt.terminating_signal == signal.SIGXFSZ:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "go_pprof_launcher",
                    "Go pprof raw output exceeded 64 MiB",
                    recoverable=True,
                )
            if receipt.termination_reason != "exited" or receipt.exit_code != 0:
                raise _error("fixed go tool pprof -raw conversion failed")
            os.fsync(raw_fd)
            raw_sha256, raw_size, raw_device, raw_inode = _inspect_profile_fd(raw_fd, self._uid)
            os.close(raw_fd)
            raw_fd = -1
            os.fsync(output_root_fd)
            success = True
            return GoPprofRawResult(
                private_root=self._output_root[0],
                raw_path=raw_path,
                raw_sha256=raw_sha256,
                raw_size=raw_size,
                raw_device=raw_device,
                raw_inode=raw_inode,
                profile_kind=profile_kind,
                accounted_active_seconds=receipt.accounted_active_seconds,
            )
        finally:
            for descriptor in (go_fd, root_fd, output_root_fd, raw_fd):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if created and not success:
                assert raw_created_identity is not None
                _unlink_private(self._output_root, (raw_name,), (raw_created_identity,))


def inspect_go_target(
    project_root: Path,
    executable: Path,
    *,
    go_tool: GoToolIdentity,
    invoking_uid: int | None = None,
) -> GoTargetIdentity:
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    if uid != os.geteuid():
        raise _error("Go target UID override is forbidden")
    root = project_root.resolve(strict=True)
    if executable.is_symlink():
        raise _error("Go target cannot be a symlink")
    try:
        resolved = executable.resolve(strict=True)
        relative = resolved.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise _error("Go target is outside the project root") from exc
    descriptor = os.open(
        resolved,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_nlink != 1
            or before.st_mode & 0o6022
            or mode & 0o111 == 0
            or not 1 <= before.st_size <= _MAX_BINARY_BYTES
        ):
            raise _error("Go target owner, mode, privileges, links, or size is unsafe")
        _reject_file_capabilities(descriptor, "Go target")
        digest = _hash_fd(descriptor)
        go_version = _go_binary_version(go_tool, descriptor)
        after = os.fstat(descriptor)
        _assert_unchanged(before, after, "Go target")
    finally:
        os.close(descriptor)
    if not go_version.startswith(tuple(f"1.{minor}" for minor in range(24, 28))):
        raise _error("Go target version is outside the reviewed 1.24-1.27 matrix")
    identity = hashlib.sha256(
        "\0".join(
            (
                "perflens-go-target-v1",
                relative,
                digest,
                str(before.st_size),
                go_version,
            )
        ).encode("utf-8")
    ).hexdigest()
    return GoTargetIdentity(
        project_relative_path=relative,
        binary_sha256=digest,
        size=before.st_size,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        mode=mode,
        go_version=go_version,
        identity_sha256=identity,
    )


def inspect_pinned_go_executable_version(
    go_tool: GoToolIdentity,
    executable_fd: int,
) -> str:
    """Read a descriptor-pinned container executable with the fixed local Go tool."""

    try:
        metadata = os.fstat(executable_fd)
    except OSError as exc:
        raise _error("Pinned Go target descriptor is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o111 == 0:
        raise _error("Pinned Go target is not an executable regular file")
    _assert_go_tool(go_tool)
    version = _go_binary_version(go_tool, executable_fd)
    if not version.startswith(tuple(f"1.{minor}" for minor in range(24, 28))):
        raise _error("Go target version is outside the reviewed 1.24-1.27 matrix")
    return version


def open_go_pprof_raw(result: GoPprofRawResult) -> int:
    if result.raw_path.parent != result.private_root:
        raise _error("Go raw result belongs to a different private root")
    root = _directory(result.private_root, os.geteuid(), 0o700)
    return _open_private_profile(
        result.raw_path,
        os.geteuid(),
        private_root=root,
        expected=(result.raw_device, result.raw_inode, result.raw_sha256, result.raw_size),
    )


def cleanup_go_pprof_raw_result(result: GoPprofRawResult) -> None:
    if result.raw_path.parent != result.private_root:
        raise _error("Go raw result belongs to a different private root")
    root = _directory(result.private_root, os.geteuid(), 0o700)
    _unlink_verified_private(
        root,
        result.raw_path,
        (result.raw_device, result.raw_inode, result.raw_sha256, result.raw_size),
    )


def cleanup_go_pprof_result(
    launch: GoPprofLaunchResult,
    raw: GoPprofRawResult | tuple[GoPprofRawResult, ...] | None = None,
) -> None:
    root = _directory(launch.private_root, os.geteuid(), 0o700)
    _unlink_verified_private(
        root,
        launch.mutex_profile_path,
        (
            launch.mutex_profile_device,
            launch.mutex_profile_inode,
            launch.mutex_profile_sha256,
            launch.mutex_profile_size,
        ),
    )
    _unlink_verified_private(
        root,
        launch.block_profile_path,
        (
            launch.block_profile_device,
            launch.block_profile_inode,
            launch.block_profile_sha256,
            launch.block_profile_size,
        ),
    )
    raw_results = () if raw is None else ((raw,) if isinstance(raw, GoPprofRawResult) else raw)
    for item in raw_results:
        if item.private_root != launch.private_root or item.raw_path.parent != launch.private_root:
            raise _error("Go raw result belongs to a different private root")
        _unlink_verified_private(
            root,
            item.raw_path,
            (item.raw_device, item.raw_inode, item.raw_sha256, item.raw_size),
        )


def _go_binary_version(tool: GoToolIdentity, target_fd: int) -> str:
    go_fd = _open_go_tool(tool)
    try:
        completed = subprocess.run(  # noqa: S603 - executable is a pinned, revalidated FD
            ("go", "version", "-m", f"/proc/self/fd/{target_fd}"),  # noqa: S607
            executable=f"/proc/self/fd/{go_fd}",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
            pass_fds=(go_fd, target_fd),
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error("Go target build identity could not be inspected") from exc
    finally:
        os.close(go_fd)
    if completed.returncode != 0 or completed.stderr:
        raise _error("Go target is not a readable Go executable")
    try:
        first = completed.stdout.decode("utf-8").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise _error("Go target build identity output is malformed") from exc
    match = _GO_BUILD_VERSION.fullmatch(first)
    if match is None:
        raise _error("Go target build version is outside the reviewed matrix")
    return match.group(1)


def _sealed_target_snapshot(root: Path, target: GoTargetIdentity) -> int:
    source = os.open(
        root / target.project_relative_path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(source)
        if _target_metadata(before) != (
            target.device,
            target.inode,
            target.owner_uid,
            target.mode,
            target.size,
        ):
            raise _error("Go target changed after Preview")
        snapshot = os.memfd_create("perflens-go-target", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            digest = hashlib.sha256()
            while chunk := os.read(source, 1 << 20):
                digest.update(chunk)
                os.write(snapshot, chunk)
            if digest.hexdigest() != target.binary_sha256:
                raise _error("Go target content changed after Preview")
            os.fchmod(snapshot, 0o500)
            fcntl.fcntl(snapshot, F_ADD_SEALS, _MEMFD_SEALS)
            os.lseek(snapshot, 0, os.SEEK_SET)
            return snapshot
        except BaseException:
            os.close(snapshot)
            raise
    finally:
        os.close(source)


def _target_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
    )


def _directory(path: Path, uid: int, required_mode: int | None) -> tuple[Path, os.stat_result]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not resolved.is_dir()
        or metadata.st_uid != uid
        or metadata.st_mode & 0o022
        or (required_mode is not None and stat.S_IMODE(metadata.st_mode) != required_mode)
    ):
        raise _error("Go launcher directory ownership or mode is unsafe")
    return resolved, metadata


def _open_directory(identity: tuple[Path, os.stat_result]) -> int:
    descriptor = os.open(identity[0], os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    metadata = os.fstat(descriptor)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    ) != (
        identity[1].st_dev,
        identity[1].st_ino,
        identity[1].st_uid,
        stat.S_IMODE(identity[1].st_mode),
    ):
        os.close(descriptor)
        raise _error("Go launcher directory identity changed")
    return descriptor


def _create_private(root_fd: int, name: str) -> int:
    return os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=root_fd,
    )


def _open_private_profile(
    path: Path,
    uid: int,
    *,
    private_root: tuple[Path, os.stat_result] | None = None,
    expected: tuple[int, int, str, int] | None = None,
) -> int:
    if private_root is not None and path.parent != private_root[0]:
        raise _error("Go profile path is outside its private root")
    root_fd = _open_directory(private_root) if private_root is not None else -1
    try:
        descriptor = os.open(
            path.name if private_root is not None else path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=(root_fd if root_fd >= 0 else None),
        )
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 1 <= metadata.st_size <= _MAX_PROFILE_BYTES
        ):
            raise _error("Go private profile identity or size is invalid")
        if expected is not None:
            digest = _hash_fd(descriptor)
            if (metadata.st_dev, metadata.st_ino, digest, metadata.st_size) != expected:
                raise _error("Go private profile differs from its captured identity")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _inspect_profile_fd(descriptor: int, uid: int) -> tuple[str, int, int, int]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 1 <= metadata.st_size <= _MAX_PROFILE_BYTES
    ):
        raise _error("Go private profile identity or size is invalid")
    return _hash_fd(descriptor), metadata.st_size, metadata.st_dev, metadata.st_ino


def _open_go_tool(tool: GoToolIdentity) -> int:
    descriptor = os.open(tool.path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_nlink,
            metadata.st_size,
        ) != (
            tool.device,
            tool.inode,
            tool.owner_uid,
            tool.mode,
            tool.links,
            tool.size,
        ) or _hash_fd(descriptor) != tool.sha256:
            raise _error("Go tool identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _assert_go_tool(tool: GoToolIdentity) -> None:
    descriptor = _open_go_tool(tool)
    os.close(descriptor)


def assert_go_tool_identity(tool: GoToolIdentity) -> None:
    """Revalidate an authorized Go/pprof executable without invoking it."""

    _assert_go_tool(tool)


def _hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1 << 20):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _assert_unchanged(before: os.stat_result, after: os.stat_result, label: str) -> None:
    if (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise _error(f"{label} changed during inspection")


def _reject_file_capabilities(descriptor: int, label: str) -> None:
    try:
        value = os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP}:
            return
        raise _error(f"{label} file capabilities could not be inspected") from exc
    if value:
        raise _error(f"{label} file capabilities are forbidden")


def _unlink_private(
    root: tuple[Path, os.stat_result],
    names: tuple[str, ...],
    identities: tuple[tuple[int, int], ...],
) -> None:
    if len(names) != len(identities):
        raise _error("Go private cleanup identity count is invalid")
    descriptor = -1
    try:
        descriptor = _open_directory(root)
        for name, identity in zip(names, identities, strict=True):
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or (metadata.st_dev, metadata.st_ino) != identity
            ):
                raise _error("Go private cleanup refused an identity mismatch")
            os.unlink(name, dir_fd=descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _unlink_verified_private(
    root: tuple[Path, os.stat_result],
    path: Path,
    expected: tuple[int, int, str, int],
) -> None:
    if path.parent != root[0]:
        raise _error("Go private cleanup path is outside its root")
    root_fd = _open_directory(root)
    file_fd = -1
    try:
        try:
            file_fd = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return
        metadata = os.fstat(file_fd)
        digest = _hash_fd(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino, digest, metadata.st_size) != expected
        ):
            raise _error("Go private cleanup refused an identity mismatch")
        current = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise _error("Go private cleanup target changed before unlink")
        os.unlink(path.name, dir_fd=root_fd)
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(root_fd)


def _error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "go_pprof_launcher",
        message,
        recoverable=True,
    )
