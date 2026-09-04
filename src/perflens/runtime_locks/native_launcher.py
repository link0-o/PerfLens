"""Unprivileged, identity-pinned launcher for the Native pthread probe.

The launcher never accepts an environment, preload path, output path, or Docker
argument from its caller.  A trusted integration binds the project root,
private output root, and packaged probe identity when the launcher is created;
each launch then accepts only an already-authorized executable, argv, and
bounded measurement controls.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import math
import os
import re
import signal
import stat
from collections.abc import Iterable, Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, cast

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from perflens.contracts.runtime_locks import MeasurementSemantics
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.native_pthread_abi import (
    NATIVE_PTHREAD_PROBE_ABI_VERSION,
    NATIVE_PTHREAD_PROBE_EXPORTS,
    NATIVE_PTHREAD_PROBE_MARKER_EXPORTS,
    NATIVE_PTHREAD_PROBE_NEEDED_LIBRARIES,
    NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION,
    native_pthread_visible_lock_kinds,
)
from perflens.runtime_locks.native_pthread_converter import parse_native_pthread_probe_footer
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorNativePthreadRequest,
    RuntimeSupervisorPolicy,
    RuntimeSupervisorRequest,
    discover_runtime_supervisor_policy,
    runtime_supervisor_directory_identity,
    runtime_supervisor_file_identity,
    runtime_supervisor_request_id,
    runtime_supervisor_writable_identity,
)

_MAX_ELF_BYTES = 256 << 20
_MAX_PROBE_BYTES = 64 << 20
_MAX_ELF_PROGRAM_HEADERS = 128
_MAX_ELF_SECTIONS = 4096
_MAX_ELF_DYNAMIC_TAGS = 4096
_MAX_ELF_DYNAMIC_SYMBOLS = 65_536
_MAX_ELF_VERSION_REQUIREMENTS = 4096
_MAX_ELF_STRING_TABLE_BYTES = 4 << 20
_MAX_ELF_SYMBOL_NAME_BYTES = 1024
_MAX_ELF_NEEDED_LIBRARIES = 64
_MAX_STREAM_BYTES = 64 << 20
_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_BYTES = 64 << 10
_MAX_EVENTS = 20_000
_MAX_DURATION_SECONDS = 30.0
_MAX_EXACT_DURATION_SECONDS = 3.0
_MAX_THRESHOLD_NS = 1_000_000_000
DEFAULT_NATIVE_PTHREAD_PROBE_PATH = Path("/usr/lib/perflens/libperflens-pthread-probe.so")
_SUPPORTED_GLIBC_RUNTIMES = frozenset({"2.36", "2.41"})
_SUPPORTED_INTERPRETERS = frozenset(
    {
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    }
)
_REVIEWED_TARGET_NEEDED_LIBRARIES = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libatomic.so.1",
        "libc.so.6",
        "libdl.so.2",
        "libgcc_s.so.1",
        "libm.so.6",
        "libpthread.so.0",
        "librt.so.1",
        "libstdc++.so.6",
    }
)
_SESSION_ESCAPE_SYMBOLS = frozenset({"daemon", "setpgid", "setsid"})
_MEMFD_REQUIRED_SEALS = (
    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
)
_CONTAINER_TARGET_ID = re.compile(r"^container-target-[a-f0-9]{20}$")
_CONTAINER_RUN_ID = re.compile(r"^container-run-[a-f0-9]{20}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_GLIBC_VERSION = re.compile(r"^GLIBC_([0-9]+(?:\.[0-9]+){1,2})$")

NativeTargetScope = Literal["host_launched_workload", "managed_temporary_container"]
NativeLaunchAvailability = Literal["available", "partial", "unavailable"]
NativeLaunchBackend = Literal["host_launcher", "managed_docker"]
NativeTerminationReason = Literal["exited", "duration_limit", "identity_unavailable"]

_NATIVE_PROVENANCE_LIMITATIONS = (
    "The v0.4.0 Native probe does not capture call stacks or source attribution.",
    "Lock events and their PID/TID fields are self-observed by the in-process probe; "
    "the launcher cross-checks process identity through procfs, but event provenance "
    "is not independently kernel-authenticated.",
)
_NATIVE_RUNTIME_LIMITATIONS = (
    "Active launch accepts only the reviewed amd64 system runtime dependencies and "
    "rejects DT_RPATH, DT_RUNPATH, and dependency paths.",
    "Native launch coverage is partial: daemonizing or escaping the launcher's process "
    "session is unsupported; direct daemon, setsid, and setpgid imports are rejected, "
    "but indirect syscall, dlopen, or later exec escape cannot be prevented.",
)


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int


@dataclass(frozen=True, slots=True)
class NativePthreadProbePolicy:
    """Administrator/package-bound probe identity, never an Agent input."""

    path: Path
    sha256: str
    owner_uid: int = 0
    mode: int = 0o644

    def __post_init__(self) -> None:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise _native_error("Native pthread probe path must be absolute and non-symlinked")
        if _SHA256.fullmatch(self.sha256) is None:
            raise _native_error("Native pthread probe policy has an invalid digest")
        if isinstance(self.owner_uid, bool) or not 0 <= self.owner_uid <= (1 << 32) - 1:
            raise _native_error("Native pthread probe owner UID is invalid")
        if self.mode != 0o644:
            raise _native_error("Native pthread probe policy requires packaged mode 0644")


@dataclass(frozen=True, slots=True)
class NativePthreadProbeIdentity:
    path: Path
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class NativePthreadProbeDiscovery:
    availability: Literal["available", "unavailable"]
    policy: NativePthreadProbePolicy | None
    identity: NativePthreadProbeIdentity | None
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativePthreadTargetIdentity:
    path: Path
    project_relative_path: str
    identity_sha256: str
    binary_sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    interpreter: str
    runtime_glibc_version: str
    required_glibc_versions: tuple[str, ...]
    visible_lock_surfaces: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeManagedPthreadTarget:
    """Verified facts supplied by the managed-Docker identity layer.

    This description deliberately has no endpoint, Socket, CLI, host PID, host
    path, environment, mount, or arbitrary Docker option.
    """

    container_target_id: str
    container_run_id: str
    target_identity_sha256: str
    executable_path: str
    executable_sha256: str
    architecture: str
    libc_family: str
    glibc_version: str | None
    dynamically_linked: bool
    interpreter: str | None

    def __post_init__(self) -> None:
        if _CONTAINER_TARGET_ID.fullmatch(self.container_target_id) is None:
            raise _native_error("Managed Native target has an invalid ContainerTarget ID")
        if _CONTAINER_RUN_ID.fullmatch(self.container_run_id) is None:
            raise _native_error("Managed Native target has an invalid ContainerRun ID")
        if (
            _SHA256.fullmatch(self.target_identity_sha256) is None
            or _SHA256.fullmatch(self.executable_sha256) is None
        ):
            raise _native_error("Managed Native target has an invalid identity digest")
        path = PurePosixPath(self.executable_path)
        if (
            not self.executable_path.startswith("/")
            or "\x00" in self.executable_path
            or len(self.executable_path.encode("utf-8")) > 4096
            or str(path) != self.executable_path
            or ".." in path.parts
        ):
            raise _native_error("Managed Native executable path is not normalized")
        if self.architecture not in {"amd64", "x86_64"}:
            raise _native_error("Managed Native target architecture is unsupported")
        if self.libc_family not in {"glibc", "musl", "unknown"}:
            raise _native_error("Managed Native target libc family is invalid")
        dynamically_linked = cast(object, self.dynamically_linked)
        if not isinstance(dynamically_linked, bool):
            raise _native_error("Managed Native dynamic-link state is invalid")
        if self.glibc_version is not None:
            try:
                _version_tuple(self.glibc_version)
            except PerfLensError as exc:
                raise _native_error("Managed Native target glibc version is invalid") from exc
        if self.libc_family == "glibc" and self.glibc_version is None:
            raise _native_error("Managed glibc target must bind its runtime version")
        if self.interpreter is not None:
            interpreter = PurePosixPath(self.interpreter)
            if (
                not self.interpreter.startswith("/")
                or "\x00" in self.interpreter
                or len(self.interpreter.encode("utf-8")) > 4096
                or str(interpreter) != self.interpreter
                or ".." in interpreter.parts
            ):
                raise _native_error("Managed Native dynamic loader path is not normalized")


@dataclass(frozen=True, slots=True)
class NativeLaunchCapability:
    target_scope: NativeTargetScope
    launch_backend: NativeLaunchBackend
    availability: NativeLaunchAvailability
    target_identity_sha256: str | None
    target_label: str
    probe_sha256: str | None
    runtime_glibc_version: str | None
    supported_semantics: tuple[MeasurementSemantics, ...]
    supported_lock_surfaces: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeLaunchRequest:
    arguments: tuple[str, ...] = ()
    semantics: Literal["exact", "thresholded"] = "thresholded"
    threshold_ns: int | None = 1_000
    duration_seconds: float = 30.0
    max_events: int = _MAX_EVENTS

    def __post_init__(self) -> None:
        _validated_arguments(self.arguments)
        if self.semantics not in {"exact", "thresholded"}:
            raise _native_error("Native pthread measurement semantics are unsupported")
        duration = cast(object, self.duration_seconds)
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or not 0 < duration <= _MAX_DURATION_SECONDS
        ):
            raise _native_error("Native pthread launch duration is outside its fixed bound")
        if self.semantics == "exact":
            if self.threshold_ns is not None:
                raise _native_error("Exact Native pthread launch cannot set a threshold")
            if self.duration_seconds > _MAX_EXACT_DURATION_SECONDS:
                raise _native_error("Exact Native pthread launch exceeds three seconds")
        threshold = cast(object, self.threshold_ns)
        if self.semantics != "exact" and (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or not 1 <= threshold <= _MAX_THRESHOLD_NS
        ):
            raise _native_error("Thresholded Native pthread launch requires a bounded threshold")
        max_events = cast(object, self.max_events)
        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or not 1 <= max_events <= _MAX_EVENTS
        ):
            raise _native_error("Native pthread event limit exceeds its fixed bound")


@dataclass(frozen=True, slots=True)
class NativeLaunchResult:
    stream_path: Path
    stream_sha256: str
    stream_size: int
    target_identity_sha256: str
    target_pid: int
    target_uid: int
    target_start_ticks: int | None
    observed_tids: tuple[int, ...]
    started_at: str
    finished_at: str
    duration_seconds: float
    accounted_active_seconds: int
    exit_code: int | None
    termination_reason: NativeTerminationReason
    footer_observed: bool
    declared_event_count: int | None
    lost_event_count: int | None
    truncated: bool | None
    quality_status: Literal["partial"] = "partial"
    limitations: tuple[str, ...] = _NATIVE_RUNTIME_LIMITATIONS + _NATIVE_PROVENANCE_LIMITATIONS


class NativePthreadLauncher:
    """Launch a reviewed host workload as the current ordinary user."""

    def __init__(
        self,
        *,
        project_root: Path,
        private_output_root: Path,
        probe_policy: NativePthreadProbePolicy,
        invoking_uid: int | None = None,
        runtime_glibc_version: str | None = None,
        supervisor_client: RuntimeSupervisorClient | None = None,
    ) -> None:
        actual_uid = os.geteuid()
        if invoking_uid is not None and invoking_uid != actual_uid:
            raise _native_error("Native pthread launcher UID override is forbidden")
        self._invoking_uid = actual_uid
        if self._invoking_uid == 0:
            raise _native_error("Native pthread workload launcher must not run as root")
        self._project_directory = _inspect_directory_identity(
            project_root,
            owner_uid=self._invoking_uid,
            expected_mode=None,
            label="project root",
        )
        self._project_root = self._project_directory.path
        self._output_directory = _inspect_directory_identity(
            private_output_root,
            owner_uid=self._invoking_uid,
            expected_mode=0o700,
            label="private output root",
        )
        self._output_root = self._output_directory.path
        self._probe_policy = probe_policy
        self._probe = inspect_native_pthread_probe(probe_policy)
        self._runtime_glibc_version = _runtime_glibc_version(runtime_glibc_version)
        _require_active_launcher_kernel_support()
        if supervisor_client is None:
            discovery = discover_runtime_supervisor_policy()
            if discovery.policy is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "The fixed Runtime Lock supervisor is unavailable",
                    recoverable=True,
                    details={"limitations": discovery.limitations},
                )
            supervisor_client = RuntimeSupervisorClient(discovery.policy)
        self._supervisor = supervisor_client

    @property
    def probe_identity(self) -> NativePthreadProbeIdentity:
        return self._probe

    def inspect_target(self, executable: Path) -> NativePthreadTargetIdentity:
        return inspect_native_pthread_host_target(
            self._project_root,
            executable,
            invoking_uid=self._invoking_uid,
            runtime_glibc_version=self._runtime_glibc_version,
        )

    def capability(self, executable: Path) -> NativeLaunchCapability:
        target = self.inspect_target(executable)
        limitations: list[str] = [
            "Only dynamically linked glibc pthread mutex, rwlock, and condition "
            "surfaces are visible.",
            "Spin locks, inline/custom atomic locks, and uncontended paths outside "
            "the probe are invisible.",
            *_NATIVE_RUNTIME_LIMITATIONS,
            *_NATIVE_PROVENANCE_LIMITATIONS,
        ]
        availability: NativeLaunchAvailability = "available"
        if not target.visible_lock_surfaces:
            availability = "partial"
            limitations.append(
                "The target has no direct supported pthread import; dynamically "
                "loaded libraries may still be visible."
            )
        return NativeLaunchCapability(
            target_scope="host_launched_workload",
            launch_backend="host_launcher",
            availability=availability,
            target_identity_sha256=target.identity_sha256,
            target_label=target.project_relative_path,
            probe_sha256=self._probe.sha256,
            runtime_glibc_version=target.runtime_glibc_version,
            supported_semantics=("exact", "thresholded"),
            supported_lock_surfaces=target.visible_lock_surfaces,
            limitations=tuple(limitations),
        )

    def launch(
        self,
        executable: Path,
        request: NativeLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> NativeLaunchResult:
        """Run one workload without a shell and retain its bounded private stream."""

        if _SHA256.fullmatch(expected_target_identity_sha256) is None:
            raise _native_error("Native pthread expected target identity is invalid")
        target = self.inspect_target(executable)
        if target.identity_sha256 != expected_target_identity_sha256:
            raise _native_error("Native pthread executable differs from the authorized target")
        _assert_probe_current(self._probe_policy, self._probe)
        _assert_target_current(
            self._project_root,
            target,
            invoking_uid=self._invoking_uid,
            runtime_glibc_version=self._runtime_glibc_version,
        )
        snapshot_fd = probe_fd = output_fd = root_fd = project_fd = -1
        stream_created = False
        launch_succeeded = False
        stream_name = f"native-pthread-{os.urandom(10).hex()}.ndjson"
        stream_path = self._output_root / stream_name
        started_at = datetime.now(tz=UTC)
        try:
            snapshot_fd = _sealed_target_snapshot(target)
            probe_fd = _open_identity_fd(self._probe.path, self._probe)
            project_fd = _open_directory_identity_fd(self._project_directory)
            root_fd = _open_directory_identity_fd(self._output_directory)
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
            stream_created = True
            stream_path = self._output_root / stream_name
            supervisor_request = RuntimeSupervisorRequest(
                request_id=runtime_supervisor_request_id(),
                expected_parent_pid=os.getpid(),
                expected_supervisor_sha256=self._supervisor.policy.sha256,
                executable=runtime_supervisor_file_identity(snapshot_fd),
                working_directory=runtime_supervisor_directory_identity(project_fd),
                arguments=request.arguments,
                timeout_milliseconds=math.ceil(request.duration_seconds * 1_000),
                request=RuntimeSupervisorNativePthreadRequest(
                    probe=runtime_supervisor_file_identity(probe_fd),
                    output=runtime_supervisor_writable_identity(
                        output_fd,
                        maximum_size=_MAX_STREAM_BYTES,
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
                    "native_pthread_launcher",
                    "Native pthread private evidence exceeded 64 MiB",
                    recoverable=True,
                )
            if receipt.termination_reason not in {"exited", "timeout"}:
                raise _native_error(
                    "Runtime supervisor could not prove the Native workload lifecycle"
                )
            os.fsync(output_fd)
            os.close(output_fd)
            output_fd = -1
            os.fsync(root_fd)
            finished_at = started_at + timedelta(
                microseconds=(receipt.elapsed_monotonic_ns + 999) // 1_000
            )
            stream_sha256, stream_size, footer = _inspect_private_stream(
                stream_path,
                owner_uid=self._invoking_uid,
                expected_pid=receipt.workload_pid,
            )
            launch_succeeded = True
            return NativeLaunchResult(
                stream_path=stream_path,
                stream_sha256=stream_sha256,
                stream_size=stream_size,
                target_identity_sha256=target.identity_sha256,
                target_pid=receipt.workload_pid,
                target_uid=self._invoking_uid,
                target_start_ticks=receipt.workload_start_ticks,
                observed_tids=(receipt.workload_pid,),
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                duration_seconds=receipt.elapsed_monotonic_ns / 1_000_000_000,
                accounted_active_seconds=receipt.accounted_active_seconds,
                exit_code=receipt.exit_code,
                termination_reason=(
                    "duration_limit" if receipt.termination_reason == "timeout" else "exited"
                ),
                footer_observed=footer is not None,
                declared_event_count=(footer[0] if footer is not None else None),
                lost_event_count=(footer[1] if footer is not None else None),
                truncated=(footer[2] if footer is not None else None),
            )
        finally:
            for descriptor in (
                output_fd,
                snapshot_fd,
                probe_fd,
                project_fd,
                root_fd,
            ):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if stream_created and not launch_succeeded:
                with suppress(OSError, PerfLensError):
                    _remove_unreturned_private_stream(
                        self._output_directory,
                        stream_name,
                        owner_uid=self._invoking_uid,
                    )


def inspect_native_pthread_installation(
    probe_policy: NativePthreadProbePolicy | None,
    *,
    runtime_glibc_version: str | None = None,
    supervisor_policy: RuntimeSupervisorPolicy | None = None,
) -> NativeLaunchCapability:
    """Report wheel-only installations as unavailable without executing anything."""

    if probe_policy is None:
        return NativeLaunchCapability(
            target_scope="host_launched_workload",
            launch_backend="host_launcher",
            availability="unavailable",
            target_identity_sha256=None,
            target_label="native-pthread",
            probe_sha256=None,
            runtime_glibc_version=None,
            supported_semantics=(),
            supported_lock_surfaces=(),
            limitations=(
                "Active Native pthread instrumentation requires the main DEB packaged probe; "
                "this installation supports controlled import and analysis only.",
                *_NATIVE_PROVENANCE_LIMITATIONS,
            ),
        )
    try:
        runtime = _runtime_glibc_version(runtime_glibc_version)
        probe = inspect_native_pthread_probe(probe_policy)
        _require_active_launcher_kernel_support()
        effective_supervisor = supervisor_policy
        if effective_supervisor is None:
            effective_supervisor = discover_runtime_supervisor_policy().policy
        if effective_supervisor is None:
            raise _native_error("The fixed root-owned Runtime Lock supervisor is unavailable")
        RuntimeSupervisorClient(effective_supervisor)
    except PerfLensError as exc:
        return NativeLaunchCapability(
            target_scope="host_launched_workload",
            launch_backend="host_launcher",
            availability="unavailable",
            target_identity_sha256=None,
            target_label="native-pthread",
            probe_sha256=None,
            runtime_glibc_version=runtime_glibc_version,
            supported_semantics=(),
            supported_lock_surfaces=(),
            limitations=(
                f"Active Native pthread instrumentation is unavailable: {exc.message}",
                "Controlled Runtime Lock import and analysis remain available.",
                *_NATIVE_RUNTIME_LIMITATIONS,
                *_NATIVE_PROVENANCE_LIMITATIONS,
            ),
        )
    return NativeLaunchCapability(
        target_scope="host_launched_workload",
        launch_backend="host_launcher",
        availability="available",
        target_identity_sha256=None,
        target_label="native-pthread",
        probe_sha256=probe.sha256,
        runtime_glibc_version=runtime,
        supported_semantics=("exact", "thresholded"),
        supported_lock_surfaces=("condition", "mutex", "rwlock_read", "rwlock_write"),
        limitations=(
            "Targets are accepted only after per-workload ELF, owner, capability, and ABI checks.",
            *_NATIVE_RUNTIME_LIMITATIONS,
            *_NATIVE_PROVENANCE_LIMITATIONS,
        ),
    )


def inspect_managed_native_pthread_capability(
    target: NativeManagedPthreadTarget,
    *,
    probe_policy: NativePthreadProbePolicy | None,
) -> NativeLaunchCapability:
    """Describe one managed target for the typed Gate-based Docker launch path."""

    if probe_policy is None:
        return NativeLaunchCapability(
            target_scope="managed_temporary_container",
            launch_backend="managed_docker",
            availability="unavailable",
            target_identity_sha256=target.target_identity_sha256,
            target_label=target.executable_path,
            probe_sha256=None,
            runtime_glibc_version=target.glibc_version,
            supported_semantics=(),
            supported_lock_surfaces=(),
            limitations=(
                "The packaged Native pthread probe is unavailable.",
                "Controlled Runtime Lock import and deterministic analysis remain available.",
            ),
        )
    probe = inspect_native_pthread_probe(probe_policy)
    limitations = [
        "This compatibility inspection does not authorize or launch the described container; "
        "the parent Docker optimization Preview supplies that authority.",
        "Container identity, executable digest, namespace, and cgroup must be "
        "revalidated by the managed-Docker layer for every run.",
        "This Native adapter never receives the Docker Socket or arbitrary Docker arguments.",
        *_NATIVE_RUNTIME_LIMITATIONS,
        *_NATIVE_PROVENANCE_LIMITATIONS,
    ]
    compatible = True
    if not target.dynamically_linked:
        compatible = False
        limitations.append("Static pthread targets cannot be instrumented with LD_PRELOAD.")
    elif target.libc_family != "glibc":
        compatible = False
        limitations.append("Only glibc pthread targets are supported; musl is unsupported.")
    elif target.glibc_version not in _SUPPORTED_GLIBC_RUNTIMES:
        compatible = False
        limitations.append("The container glibc runtime is outside the 2.36/2.41 matrix.")
    elif target.interpreter not in _SUPPORTED_INTERPRETERS:
        compatible = False
        limitations.append("The container dynamic loader is outside the reviewed amd64 matrix.")
    return NativeLaunchCapability(
        target_scope="managed_temporary_container",
        launch_backend="managed_docker",
        availability=("available" if compatible else "unavailable"),
        target_identity_sha256=target.target_identity_sha256,
        target_label=target.executable_path,
        probe_sha256=probe.sha256,
        runtime_glibc_version=target.glibc_version,
        supported_semantics=(("exact", "thresholded") if compatible else ()),
        supported_lock_surfaces=(
            ("condition", "mutex", "rwlock_read", "rwlock_write")
            if compatible
            else ()
        ),
        limitations=tuple(limitations),
    )


def inspect_native_pthread_probe(
    policy: NativePthreadProbePolicy,
) -> NativePthreadProbeIdentity:
    return _inspect_native_pthread_probe_file(
        policy.path,
        expected_owner_uid=policy.owner_uid,
        expected_mode=policy.mode,
        expected_sha256=policy.sha256,
    )


def discover_native_pthread_probe_policy(
    path: Path = DEFAULT_NATIVE_PTHREAD_PROBE_PATH,
    *,
    expected_owner_uid: int = 0,
) -> NativePthreadProbeDiscovery:
    """Discover the package probe without a path-based pre-hash race."""

    try:
        identity = _inspect_native_pthread_probe_file(
            path,
            expected_owner_uid=expected_owner_uid,
            expected_mode=0o644,
            expected_sha256=None,
        )
        policy = NativePthreadProbePolicy(
            path=identity.path,
            sha256=identity.sha256,
            owner_uid=identity.owner_uid,
            mode=identity.mode,
        )
    except PerfLensError as exc:
        return NativePthreadProbeDiscovery(
            availability="unavailable",
            policy=None,
            identity=None,
            limitations=(str(exc),),
        )
    return NativePthreadProbeDiscovery(
        availability="available",
        policy=policy,
        identity=identity,
        limitations=(),
    )


def _inspect_native_pthread_probe_file(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_mode: int,
    expected_sha256: str | None,
) -> NativePthreadProbeIdentity:
    descriptor = -1
    try:
        if not path.is_absolute() or path.is_symlink():
            raise _native_error("Native pthread probe path must be absolute and non-symlinked")
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise _native_error("Native pthread probe path is not canonical")
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != expected_owner_uid
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or not 1 <= before.st_size <= _MAX_PROBE_BYTES
        ):
            raise _native_error("Native pthread probe owner, mode, links, or size are unsafe")
        _reject_file_capabilities(descriptor, "Native pthread probe")
        elf = _read_elf_metadata(descriptor, before.st_size, require_probe=True)
        if elf.interpreter is not None or elf.elf_type != "ET_DYN":
            raise _native_error("Native pthread probe is not an amd64 shared object")
        if elf.runtime_search_paths:
            raise _native_error("Native pthread probe has an unreviewed runtime search path")
        if elf.defined_dynamic_symbols != NATIVE_PTHREAD_PROBE_EXPORTS:
            raise _native_error("Native pthread probe exports differ from the reviewed ABI")
        if frozenset(elf.needed_libraries) != NATIVE_PTHREAD_PROBE_NEEDED_LIBRARIES:
            raise _native_error("Native pthread probe dependencies differ from the reviewed ABI")
        if (
            elf.probe_abi_version != NATIVE_PTHREAD_PROBE_ABI_VERSION
            or elf.probe_protocol_version != NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION
        ):
            raise _native_error("Native pthread probe ABI marker values are unsupported")
        digest = _hash_descriptor(descriptor, before)
        if expected_sha256 is not None and digest != expected_sha256:
            raise _native_error("Native pthread probe digest differs from the package policy")
        return NativePthreadProbeIdentity(
            path=resolved,
            sha256=digest,
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=before.st_uid,
            mode=stat.S_IMODE(before.st_mode),
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
        )
    except PerfLensError:
        raise
    except OSError as exc:
        raise _native_error("Native pthread probe cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def inspect_native_pthread_host_target(
    project_root: Path,
    executable: Path,
    *,
    invoking_uid: int | None = None,
    runtime_glibc_version: str | None = None,
) -> NativePthreadTargetIdentity:
    actual_uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != actual_uid:
        raise _native_error("Native pthread target UID override is forbidden")
    uid = actual_uid
    root = _private_directory(
        project_root,
        owner_uid=uid,
        expected_mode=None,
        label="project root",
    )
    candidate = executable if executable.is_absolute() else root / executable
    if candidate.is_symlink():
        raise _native_error("Native pthread executable must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise _native_error("Native pthread executable cannot be resolved safely") from exc
    if resolved != candidate or not resolved.is_relative_to(root):
        raise _native_error("Native pthread executable escapes the authorized project root")
    descriptor = -1
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != uid
            or before.st_mode & 0o022
            or not before.st_mode & 0o111
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or not 1 <= before.st_size <= _MAX_ELF_BYTES
        ):
            raise _native_error(
                "Native pthread executable owner, mode, links, size, or privilege bits are unsafe"
            )
        _reject_file_capabilities(descriptor, "Native pthread executable")
        elf = _read_elf_metadata(descriptor, before.st_size, require_probe=False)
        runtime = _runtime_glibc_version(runtime_glibc_version)
        _validate_target_elf(elf, runtime)
        digest = _hash_descriptor(descriptor, before)
        relative = resolved.relative_to(root).as_posix()
        identity_sha256 = hashlib.sha256(
            "\0".join(
                (
                    "perflens-native-pthread-target-v1",
                    digest,
                    relative,
                    str(before.st_dev),
                    str(before.st_ino),
                    runtime,
                    elf.interpreter or "",
                )
            ).encode()
        ).hexdigest()
        surfaces = native_pthread_visible_lock_kinds(elf.imported_dynamic_symbols)
        return NativePthreadTargetIdentity(
            path=resolved,
            project_relative_path=relative,
            identity_sha256=identity_sha256,
            binary_sha256=digest,
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=before.st_uid,
            mode=stat.S_IMODE(before.st_mode),
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
            interpreter=cast(str, elf.interpreter),
            runtime_glibc_version=runtime,
            required_glibc_versions=elf.glibc_versions,
            visible_lock_surfaces=surfaces,
        )
    except PerfLensError:
        raise
    except OSError as exc:
        raise _native_error("Native pthread executable cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _ElfMetadata:
    elf_type: str
    interpreter: str | None
    needed_libraries: tuple[str, ...]
    glibc_versions: tuple[str, ...]
    imported_dynamic_symbols: frozenset[str]
    runtime_search_paths: tuple[str, ...] = ()
    defined_dynamic_symbols: frozenset[str] = frozenset()
    probe_abi_version: int | None = None
    probe_protocol_version: str | None = None


class _InterpreterSegment(Protocol):
    def get_interp_name(self) -> str: ...


class _DynamicTag(Protocol):
    entry: Mapping[str, object]
    needed: str


class _DynamicSection(Protocol):
    def num_tags(self) -> int: ...

    def iter_tags(self) -> Iterator[_DynamicTag]: ...


class _VersionAuxiliary(Protocol):
    name: str


class _VersionNeedSection(Protocol):
    def iter_versions(
        self,
    ) -> Iterator[tuple[object, Iterable[_VersionAuxiliary]]]: ...


def _bounded_elf_string(value: str, *, label: str) -> str:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise _native_error(f"Native pthread ELF {label} is not valid UTF-8") from exc
    if not encoded or len(encoded) > _MAX_ELF_SYMBOL_NAME_BYTES or b"\x00" in encoded:
        raise _native_error(f"Native pthread ELF {label} exceeds its fixed bound")
    return value


def _validate_probe_wrapper_symbols(
    defined_symbols: Mapping[str, Any],
    *,
    executable_load_ranges: tuple[tuple[int, int], ...],
) -> None:
    wrapper_names = NATIVE_PTHREAD_PROBE_EXPORTS - NATIVE_PTHREAD_PROBE_MARKER_EXPORTS
    for wrapper_name in wrapper_names:
        symbol = defined_symbols.get(wrapper_name)
        if symbol is None:
            raise _native_error("Native pthread probe is missing a reviewed wrapper")
        info = symbol["st_info"]
        other = symbol["st_other"]
        address = int(symbol["st_value"])
        size_value = symbol["st_size"]
        size = int(size_value)
        address_limit = 1 << 64
        end = address + size
        if (
            info["type"] != "STT_FUNC"
            or info["bind"] != "STB_GLOBAL"
            or other["visibility"] != "STV_DEFAULT"
            or address <= 0
            or isinstance(size_value, bool)
            or size <= 0
            or address >= address_limit
            or end <= address
            or end > address_limit
            or not any(
                segment_start <= address and end <= segment_end
                for segment_start, segment_end in executable_load_ranges
            )
        ):
            raise _native_error(
                "Native pthread probe wrapper type, binding, visibility, or segment is unsafe"
            )


def _read_elf_metadata(descriptor: int, file_size: int, *, require_probe: bool) -> _ElfMetadata:
    try:
        if not 1 <= file_size <= _MAX_ELF_BYTES:
            raise _native_error("Native pthread ELF size is outside its fixed bound")
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            elf = ELFFile(handle)
            if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64":
                raise _native_error("Native pthread ELF is not little-endian amd64")
            program_header_count = elf.num_segments()
            section_count = elf.num_sections()
            if not 1 <= program_header_count <= _MAX_ELF_PROGRAM_HEADERS:
                raise _native_error("Native pthread ELF has too many program headers")
            if not 1 <= section_count <= _MAX_ELF_SECTIONS:
                raise _native_error("Native pthread ELF has too many sections")
            interpreter: str | None = None
            executable_load_ranges: list[tuple[int, int]] = []
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_INTERP":
                    interpreter = _bounded_elf_string(
                        cast(_InterpreterSegment, segment).get_interp_name(),
                        label="interpreter",
                    )
                if segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 0x1:
                    start = int(segment["p_vaddr"])
                    end = start + int(segment["p_memsz"])
                    if end <= start:
                        raise _native_error("Native pthread ELF has an invalid executable segment")
                    executable_load_ranges.append((start, end))
            for section_name in (".dynstr", ".shstrtab"):
                string_table = elf.get_section_by_name(section_name)
                if (
                    string_table is not None
                    and int(string_table["sh_size"]) > _MAX_ELF_STRING_TABLE_BYTES
                ):
                    raise _native_error("Native pthread ELF string table exceeds its fixed bound")
            needed: list[str] = []
            runtime_search_paths: list[str] = []
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                typed_dynamic = cast(_DynamicSection, dynamic)
                if typed_dynamic.num_tags() > _MAX_ELF_DYNAMIC_TAGS:
                    raise _native_error("Native pthread ELF has too many dynamic tags")
                for tag in typed_dynamic.iter_tags():
                    tag_name = tag.entry["d_tag"]
                    if tag_name == "DT_NEEDED":
                        needed.append(_bounded_elf_string(tag.needed, label="dependency"))
                        if len(needed) > _MAX_ELF_NEEDED_LIBRARIES:
                            raise _native_error("Native pthread ELF has too many dependencies")
                    elif tag_name in {"DT_RPATH", "DT_RUNPATH"}:
                        attribute = "rpath" if tag_name == "DT_RPATH" else "runpath"
                        value = getattr(tag, attribute, None)
                        if not isinstance(value, str):
                            raise _native_error(
                                "Native pthread target has a malformed runtime search path"
                            )
                        runtime_search_paths.append(
                            _bounded_elf_string(value, label="runtime search path")
                        )
            versions: set[str] = set()
            version_requirement_count = 0
            version_need = elf.get_section_by_name(".gnu.version_r")
            if version_need is not None:
                for _dependency, auxiliaries in cast(
                    _VersionNeedSection, version_need
                ).iter_versions():
                    for auxiliary in auxiliaries:
                        version_requirement_count += 1
                        if version_requirement_count > _MAX_ELF_VERSION_REQUIREMENTS:
                            raise _native_error(
                                "Native pthread ELF has too many version requirements"
                            )
                        version_name = _bounded_elf_string(
                            auxiliary.name,
                            label="version requirement",
                        )
                        match = _GLIBC_VERSION.fullmatch(version_name)
                        if match is not None:
                            versions.add(match.group(1))
            imported_symbols: set[str] = set()
            defined_symbols: dict[str, Any] = {}
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection) and section.name == ".dynsym":
                    if section.num_symbols() > _MAX_ELF_DYNAMIC_SYMBOLS:
                        raise _native_error("Native pthread ELF has too many dynamic symbols")
                    for symbol in section.iter_symbols():
                        if not symbol.name:
                            continue
                        symbol_name = _bounded_elf_string(
                            symbol.name,
                            label="dynamic symbol",
                        )
                        if symbol["st_shndx"] == "SHN_UNDEF":
                            imported_symbols.add(symbol_name)
                        else:
                            defined_symbols[symbol_name] = symbol
            probe_abi_version: int | None = None
            probe_protocol_version: str | None = None
            if require_probe:
                _validate_probe_wrapper_symbols(
                    defined_symbols,
                    executable_load_ranges=tuple(executable_load_ranges),
                )
                abi_symbol = defined_symbols.get("perflens_pthread_probe_abi_version")
                protocol_symbol = defined_symbols.get("perflens_pthread_probe_protocol_version")
                if abi_symbol is not None:
                    probe_abi_version = int.from_bytes(
                        _elf_symbol_bytes(elf, abi_symbol, 4),
                        byteorder="little",
                    )
                if protocol_symbol is not None:
                    raw_protocol = _elf_symbol_bytes(elf, protocol_symbol, 4)
                    if raw_protocol.endswith(b"\x00"):
                        probe_protocol_version = raw_protocol[:-1].decode("ascii", errors="strict")
            return _ElfMetadata(
                elf_type=elf["e_type"],
                interpreter=interpreter,
                needed_libraries=tuple(sorted(set(needed))),
                glibc_versions=tuple(sorted(versions, key=_version_tuple)),
                imported_dynamic_symbols=frozenset(imported_symbols),
                runtime_search_paths=tuple(sorted(set(runtime_search_paths))),
                defined_dynamic_symbols=frozenset(defined_symbols),
                probe_abi_version=probe_abi_version,
                probe_protocol_version=probe_protocol_version,
            )
    except PerfLensError:
        raise
    except Exception as exc:
        label = "probe" if require_probe else "target"
        raise _native_error(f"Native pthread {label} is not a supported ELF") from exc


def _elf_symbol_bytes(elf: ELFFile, symbol: Any, size: int) -> bytes:
    if int(symbol["st_size"]) < size:
        raise _native_error("Native pthread probe ABI marker has an invalid size")
    symbol_address = int(symbol["st_value"])
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        segment_address = int(segment["p_vaddr"])
        relative = symbol_address - segment_address
        if relative < 0 or relative + size > int(segment["p_filesz"]):
            continue
        position = elf.stream.tell()
        try:
            elf.stream.seek(int(segment["p_offset"]) + relative)
            data = elf.stream.read(size)
        finally:
            elf.stream.seek(position)
        if len(data) != size:
            break
        return data
    raise _native_error("Native pthread probe ABI marker is outside a loadable segment")


def _validate_target_elf(elf: _ElfMetadata, runtime_glibc_version: str) -> None:
    if elf.elf_type not in {"ET_DYN", "ET_EXEC"} or elf.interpreter is None:
        raise _native_error("Static pthread targets are unsupported")
    if "musl" in elf.interpreter or any("musl" in name for name in elf.needed_libraries):
        raise _native_error("musl pthread targets are unsupported")
    if elf.interpreter not in _SUPPORTED_INTERPRETERS:
        raise _native_error("Native pthread dynamic loader is outside the reviewed amd64 matrix")
    if "libc.so.6" not in elf.needed_libraries:
        raise _native_error("Native pthread target is not dynamically linked to glibc")
    if elf.runtime_search_paths:
        raise _native_error("Native pthread targets with DT_RPATH or DT_RUNPATH are unsupported")
    if any(
        "/" in library or PurePosixPath(library).is_absolute() for library in elf.needed_libraries
    ):
        raise _native_error("Native pthread target dependency paths are forbidden")
    unreviewed_libraries = set(elf.needed_libraries) - _REVIEWED_TARGET_NEEDED_LIBRARIES
    if unreviewed_libraries:
        raise _native_error("Native pthread target has a non-reviewed runtime dependency")
    if elf.imported_dynamic_symbols & _SESSION_ESCAPE_SYMBOLS:
        raise _native_error(
            "Native pthread targets that can escape the launch session are unsupported"
        )
    runtime_tuple = _version_tuple(runtime_glibc_version)
    if any(_version_tuple(version) > runtime_tuple for version in elf.glibc_versions):
        raise _native_error("Native pthread target requires a newer glibc ABI")


def _runtime_glibc_version(value: str | None) -> str:
    runtime = value
    if runtime is None:
        try:
            description = os.confstr("CS_GNU_LIBC_VERSION")
        except (OSError, ValueError):
            description = None
        if not description or not description.startswith("glibc "):
            raise _native_error("Host glibc runtime identity is unavailable")
        runtime = description.removeprefix("glibc ")
    if runtime not in _SUPPORTED_GLIBC_RUNTIMES:
        raise _native_error("Host glibc runtime is outside the supported 2.36/2.41 matrix")
    return runtime


def _require_active_launcher_kernel_support() -> None:
    if (
        not hasattr(os, "memfd_create")
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal")
        or not Path("/proc/self/fd").is_dir()
    ):
        raise _native_error("Host kernel or Python runtime lacks sealed memfd/pidfd launch support")


def _version_tuple(value: str) -> tuple[int, ...]:
    try:
        components = tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise _native_error("Native pthread glibc version is malformed") from exc
    if len(components) not in {2, 3}:
        raise _native_error("Native pthread glibc version is malformed")
    return components


def _private_directory(
    path: Path,
    *,
    owner_uid: int,
    expected_mode: int | None,
    label: str,
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _native_error(f"Native pthread {label} must be absolute and non-symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _native_error(f"Native pthread {label} cannot be resolved safely") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & 0o022
        or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
    ):
        raise _native_error(f"Native pthread {label} owner or mode is unsafe")
    return resolved


def _inspect_directory_identity(
    path: Path,
    *,
    owner_uid: int,
    expected_mode: int | None,
    label: str,
) -> _DirectoryIdentity:
    resolved = _private_directory(
        path,
        owner_uid=owner_uid,
        expected_mode=expected_mode,
        label=label,
    )
    metadata = resolved.stat(follow_symlinks=False)
    return _DirectoryIdentity(
        path=resolved,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _open_directory_identity_fd(identity: _DirectoryIdentity) -> int:
    descriptor = -1
    try:
        descriptor = os.open(
            identity.path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise _native_error("Native pthread launch directory cannot be opened safely") from exc
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    ) != (
        identity.device,
        identity.inode,
        identity.owner_uid,
        identity.mode,
    ):
        os.close(descriptor)
        raise _native_error("Native pthread launch directory identity changed")
    return descriptor


def _reject_file_capabilities(descriptor: int, label: str) -> None:
    try:
        capability = os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise _native_error(f"{label} file capabilities cannot be checked safely") from exc
    if capability:
        raise _native_error(f"{label} with file capabilities is unsupported")


def _hash_descriptor(descriptor: int, before: os.stat_result) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1 << 20):
        digest.update(chunk)
    after = os.fstat(descriptor)
    if _file_identity(before) != _file_identity(after):
        raise _native_error("Native pthread file changed while it was inspected")
    return digest.hexdigest()


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _assert_probe_current(
    policy: NativePthreadProbePolicy,
    expected: NativePthreadProbeIdentity,
) -> None:
    if inspect_native_pthread_probe(policy) != expected:
        raise _native_error("Native pthread probe changed after capability inspection")


def _assert_target_current(
    project_root: Path,
    expected: NativePthreadTargetIdentity,
    *,
    invoking_uid: int,
    runtime_glibc_version: str,
) -> None:
    current = inspect_native_pthread_host_target(
        project_root,
        expected.path,
        invoking_uid=invoking_uid,
        runtime_glibc_version=runtime_glibc_version,
    )
    if current != expected:
        raise _native_error("Native pthread executable changed after capability inspection")


def _open_identity_fd(
    path: Path,
    identity: NativePthreadProbeIdentity | NativePthreadTargetIdentity,
) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise _native_error("Native pthread launch input cannot be opened safely") from exc
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) != (
        identity.device,
        identity.inode,
        identity.owner_uid,
        identity.mode,
        1,
        identity.size,
        identity.modified_ns,
        identity.changed_ns,
    ):
        os.close(descriptor)
        raise _native_error("Native pthread launch input identity changed before exec")
    return descriptor


def _sealed_target_snapshot(
    expected: NativePthreadTargetIdentity,
) -> int:
    """Copy an authorized executable into an immutable, content-bound memfd."""

    _require_active_launcher_kernel_support()
    source_fd = snapshot_fd = -1
    try:
        source_fd = _open_identity_fd(expected.path, expected)
        source_before = os.fstat(source_fd)
        if _hash_descriptor(source_fd, source_before) != expected.binary_sha256:
            raise _native_error("Native pthread executable content changed before snapshot")
        snapshot_fd = os.memfd_create(
            "perflens-native-pthread-target",
            flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        os.lseek(source_fd, 0, os.SEEK_SET)
        copied_digest = hashlib.sha256()
        copied_size = 0
        while chunk := os.read(source_fd, 1 << 20):
            copied_digest.update(chunk)
            copied_size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_fd, view)
                if written <= 0:
                    raise _native_error("Native pthread executable snapshot write failed")
                view = view[written:]
        if copied_size != expected.size or copied_digest.hexdigest() != expected.binary_sha256:
            raise _native_error("Native pthread executable changed while snapshotting")
        if _file_identity(source_before) != _file_identity(os.fstat(source_fd)):
            raise _native_error("Native pthread executable changed while snapshotting")
        if _hash_descriptor(source_fd, source_before) != expected.binary_sha256:
            raise _native_error("Native pthread executable changed after snapshotting")
        path_check_fd = _open_identity_fd(expected.path, expected)
        os.close(path_check_fd)

        os.fchmod(snapshot_fd, 0o500)
        snapshot_before = os.fstat(snapshot_fd)
        if (
            snapshot_before.st_size != expected.size
            or _hash_descriptor(snapshot_fd, snapshot_before) != expected.binary_sha256
        ):
            raise _native_error("Native pthread executable snapshot digest is invalid")
        snapshot_elf = _read_elf_metadata(
            snapshot_fd,
            snapshot_before.st_size,
            require_probe=False,
        )
        _validate_target_elf(snapshot_elf, expected.runtime_glibc_version)
        if (
            snapshot_elf.interpreter != expected.interpreter
            or snapshot_elf.glibc_versions != expected.required_glibc_versions
            or native_pthread_visible_lock_kinds(snapshot_elf.imported_dynamic_symbols)
            != expected.visible_lock_surfaces
        ):
            raise _native_error("Native pthread executable snapshot ABI identity changed")
        fcntl.fcntl(snapshot_fd, fcntl.F_ADD_SEALS, _MEMFD_REQUIRED_SEALS)
        applied_seals = fcntl.fcntl(snapshot_fd, fcntl.F_GET_SEALS)
        if applied_seals & _MEMFD_REQUIRED_SEALS != _MEMFD_REQUIRED_SEALS:
            raise _native_error("Native pthread executable snapshot could not be sealed")
        os.lseek(snapshot_fd, 0, os.SEEK_SET)
        result = snapshot_fd
        snapshot_fd = -1
        return result
    except PerfLensError:
        raise
    except OSError as exc:
        raise _native_error("Native pthread executable cannot be snapshotted safely") from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if snapshot_fd >= 0:
            os.close(snapshot_fd)


def _validated_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
    value = cast(object, arguments)
    if not isinstance(value, tuple):
        raise _native_error("Native pthread workload arguments must be a fixed tuple")
    values = cast(tuple[object, ...], value)
    if len(values) > _MAX_ARGUMENTS:
        raise _native_error("Native pthread workload has too many arguments")
    total = 0
    validated: list[str] = []
    for item in values:
        if not isinstance(item, str) or "\x00" in item:
            raise _native_error("Native pthread workload argument is invalid")
        encoded = item.encode("utf-8")
        if len(encoded) > 4096:
            raise _native_error("Native pthread workload argument exceeds its bound")
        total += len(encoded) + 1
        validated.append(item)
    if total > _MAX_ARGUMENT_BYTES:
        raise _native_error("Native pthread workload argument vector exceeds its bound")
    return tuple(validated)


def _inspect_private_stream(
    path: Path,
    *,
    owner_uid: int,
    expected_pid: int,
) -> tuple[str, int, tuple[int, int, bool] | None]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != owner_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > _MAX_STREAM_BYTES
        ):
            raise _native_error("Native pthread private stream identity or size is unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, 1 << 20):
            raw.extend(chunk)
            if len(raw) > _MAX_STREAM_BYTES:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "native_pthread_launcher",
                    "Native pthread private stream exceeds 64 MiB",
                    recoverable=True,
                )
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise _native_error("Native pthread private stream changed while it was read")
    except PerfLensError:
        raise
    except OSError as exc:
        raise _native_error("Native pthread private stream cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    footer = _strict_footer(bytes(raw), expected_pid=expected_pid)
    return hashlib.sha256(raw).hexdigest(), len(raw), footer


def _remove_unreturned_private_stream(
    directory: _DirectoryIdentity,
    stream_name: str,
    *,
    owner_uid: int,
) -> None:
    """Remove only the launcher's own still-safe stream after receipt failure."""

    descriptor = _open_directory_identity_fd(directory)
    try:
        metadata = os.stat(stream_name, dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise _native_error("Native pthread unreturned stream identity is unsafe for cleanup")
        os.unlink(stream_name, dir_fd=descriptor)
    finally:
        os.close(descriptor)


def _strict_footer(raw: bytes, *, expected_pid: int) -> tuple[int, int, bool] | None:
    if not raw.endswith(b"\n"):
        return None
    lines = [line for line in raw.splitlines(keepends=True) if line.strip()]
    if not lines:
        return None
    return parse_native_pthread_probe_footer(
        lines[-1],
        expected_pid=expected_pid,
    )


def _native_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "native_pthread_launcher",
        message,
        recoverable=True,
    )
