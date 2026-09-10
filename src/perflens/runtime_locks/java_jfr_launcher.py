"""Unprivileged, startup-only launcher for executable-JAR JFR collection."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import math
import os
import signal
import stat
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, cast

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.linux_memfd import (
    F_ADD_SEALS,
    F_GET_SEALS,
    IMMUTABLE_MEMFD_SEALS,
)
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorJavaJfrPrintRequest,
    RuntimeSupervisorJavaJfrWorkloadRequest,
    RuntimeSupervisorRequest,
    discover_runtime_supervisor_policy,
    runtime_supervisor_directory_identity,
    runtime_supervisor_file_identity,
    runtime_supervisor_request_id,
    runtime_supervisor_writable_identity,
)

_MAX_JAR_BYTES = 256 << 20
_MAX_ARCHIVE_ENTRIES = 10_000
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 << 20
_MAX_MANIFEST_BYTES = 64 << 10
_MAX_JFR_BYTES = 64 << 20
_MAX_JSON_BYTES = 64 << 20
_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_BYTES = 64 << 10
_MAX_DURATION_SECONDS = 30.0
_MAX_NATIVE_LIBRARY_BYTES = 256 << 20
_MAX_NATIVE_LIBRARY_TOTAL_BYTES = 512 << 20
_MAX_NATIVE_LIBRARY_FILES = 256
_MAX_NATIVE_RELATIVE_PATH_BYTES = 1024
_MAX_RETAINED_DIRECTORIES = 64
_JAVA_PRIVATE_ROOT_PREFIX = ".runtime-lock-java-"
_JAVA_PRIVATE_RUN_PREFIX = "java-jfr-"
_JAVA_ARTIFACT_ROOT_LOCK_NAME = ".runtime-lock-java.lock"
_SUPPORTED_JDK_MAJORS = frozenset({17, 21, 25})
_PROFILE_THRESHOLDS_NS = {"balanced": 10_000_000, "deep": 1_000_000}
_FORBIDDEN_MANIFEST_KEYS = frozenset(
    {
        "add-exports",
        "add-opens",
        "agent-class",
        "class-path",
        "enable-native-access",
        "launcher-agent-class",
        "premain-class",
    }
)
_REQUIRED_SEALS = IMMUTABLE_MEMFD_SEALS

JavaJfrProfile = Literal["balanced", "deep"]
JavaJfrTerminationReason = Literal["exited", "duration_limit", "identity_unavailable"]

_JAVA_JFR_LIMITATIONS = (
    "Only startup-time executable-JAR JFR is supported; live attach, jcmd, agents, "
    "classpath, module-path, and arbitrary JVM flags are unavailable.",
    "Java launch coverage is partial: child processes that indirectly create a new "
    "session through application code may escape same-session cleanup and require review.",
    "JFR monitor and park events are runtime-observed thresholded evidence; owner and hold "
    "relationships are unavailable unless an event actually provides them.",
    "The private named .jfr path required by the JDK is continuously identity-checked, but "
    "collection assumes cooperative same-UID processes; hostile same-UID ABA replacement "
    "cannot be made impossible without a separate OS security identity.",
)


@dataclass(frozen=True, slots=True)
class JavaJfrFilePolicy:
    path: Path
    sha256: str
    owner_uid: int
    mode: int

    def __post_init__(self) -> None:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise _java_error("Java JFR policy path must be absolute and non-symlinked")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise _java_error("Java JFR policy digest is invalid")
        if isinstance(self.owner_uid, bool) or not 0 <= self.owner_uid <= (1 << 32) - 1:
            raise _java_error("Java JFR policy owner UID is invalid")
        if self.mode not in {0o555, 0o755, 0o644}:
            raise _java_error("Java JFR policy mode is unsupported")


@dataclass(frozen=True, slots=True)
class JavaJfrDirectoryPolicy:
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    def __post_init__(self) -> None:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise _java_error("Java JFR runtime directory must be absolute and non-symlinked")
        if self.mode not in {0o555, 0o755}:
            raise _java_error("Java JFR runtime directory mode is unsafe")
        if (
            min(
                self.device,
                self.inode,
                self.owner_uid,
                self.links,
                self.size,
                self.modified_ns,
                self.changed_ns,
            )
            < 0
        ):
            raise _java_error("Java JFR runtime directory identity is invalid")


@dataclass(frozen=True, slots=True)
class JavaJfrPayloadFilePolicy:
    path: Path
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int

    def __post_init__(self) -> None:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise _java_error("Java JFR runtime payload must be absolute and non-symlinked")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise _java_error("Java JFR runtime payload digest is invalid")
        if self.mode not in {0o444, 0o644}:
            raise _java_error("Java JFR runtime payload mode is unsafe")
        if (
            min(
                self.device,
                self.inode,
                self.owner_uid,
                self.size,
                self.modified_ns,
                self.changed_ns,
            )
            < 0
        ):
            raise _java_error("Java JFR runtime payload identity is invalid")


@dataclass(frozen=True, slots=True)
class JavaJfrNativeLibraryPolicy:
    relative_path: str
    named_path: Path
    resolved_path: Path
    source_kind: Literal["regular", "symlink"]
    link_target_sha256: str | None
    link_device: int | None
    link_inode: int | None
    link_owner_uid: int | None
    link_mode: int | None
    link_links: int | None
    link_size: int | None
    link_modified_ns: int | None
    link_changed_ns: int | None
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    def __post_init__(self) -> None:
        relative = PurePosixPath(self.relative_path)
        if (
            relative.is_absolute()
            or str(relative) != self.relative_path
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or len(self.relative_path.encode("utf-8")) > _MAX_NATIVE_RELATIVE_PATH_BYTES
        ):
            raise _java_error("Java JFR native library relative path is unsafe")
        if not self.named_path.is_absolute() or not self.resolved_path.is_absolute():
            raise _java_error("Java JFR native library private path is not absolute")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise _java_error("Java JFR native library digest is invalid")
        if (
            self.mode & 0o022
            or self.mode & 0o6000
            or not 0 < self.size <= _MAX_NATIVE_LIBRARY_BYTES
            or min(
                self.device,
                self.inode,
                self.owner_uid,
                self.links,
                self.modified_ns,
                self.changed_ns,
            )
            < 0
        ):
            raise _java_error("Java JFR native library identity is unsafe")
        link_values = (
            self.link_target_sha256,
            self.link_device,
            self.link_inode,
            self.link_owner_uid,
            self.link_mode,
            self.link_links,
            self.link_size,
            self.link_modified_ns,
            self.link_changed_ns,
        )
        if self.source_kind == "regular":
            if (
                any(item is not None for item in link_values)
                or self.named_path != self.resolved_path
            ):
                raise _java_error("Java JFR regular native library has symlink metadata")
        elif (
            any(item is None for item in link_values)
            or self.named_path == self.resolved_path
            or self.link_target_sha256 is None
            or len(self.link_target_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.link_target_sha256)
        ):
            raise _java_error("Java JFR native library symlink identity is incomplete")


@dataclass(frozen=True, slots=True)
class JavaJfrRuntimePayloadPolicy:
    jdk_root: JavaJfrDirectoryPolicy
    bin_directory: JavaJfrDirectoryPolicy
    lib_directory: JavaJfrDirectoryPolicy
    release_file: JavaJfrPayloadFilePolicy
    modules_file: JavaJfrPayloadFilePolicy
    native_libraries: tuple[JavaJfrNativeLibraryPolicy, ...]
    native_library_bytes: int
    native_library_manifest_sha256: str
    identity_sha256: str

    def __post_init__(self) -> None:
        if len(self.identity_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.identity_sha256
        ):
            raise _java_error("Java JFR runtime payload identity digest is invalid")
        if len(self.native_library_manifest_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.native_library_manifest_sha256
        ):
            raise _java_error("Java JFR native library manifest digest is invalid")
        root = self.jdk_root.path
        if (
            self.bin_directory.path != root / "bin"
            or self.lib_directory.path != root / "lib"
            or self.release_file.path != root / "release"
            or self.modules_file.path != root / "lib/modules"
        ):
            raise _java_error("Java JFR runtime payload layout is unsupported")
        if (
            not 0 < len(self.native_libraries) <= _MAX_NATIVE_LIBRARY_FILES
            or self.native_library_bytes != sum(item.size for item in self.native_libraries)
            or not 0 < self.native_library_bytes <= _MAX_NATIVE_LIBRARY_TOTAL_BYTES
        ):
            raise _java_error("Java JFR native library manifest exceeds its bound")
        relative_paths = tuple(item.relative_path for item in self.native_libraries)
        if (
            relative_paths != tuple(sorted(relative_paths, key=os.fsencode))
            or len(set(relative_paths)) != len(relative_paths)
            or not {"libjli.so", "server/libjvm.so"}.issubset(relative_paths)
        ):
            raise _java_error("Java JFR native library manifest layout is unsupported")
        for library in self.native_libraries:
            expected = self.lib_directory.path.joinpath(*PurePosixPath(library.relative_path).parts)
            if library.named_path != expected:
                raise _java_error("Java JFR native library escapes the JDK lib tree")
        if self.native_library_manifest_sha256 != _derive_native_library_policy_manifest_identity(
            self.native_libraries
        ):
            raise _java_error("Java JFR native library manifest identity differs from its files")
        if self.identity_sha256 != _derive_runtime_payload_policy_identity(self):
            raise _java_error("Java JFR runtime payload identity differs from its files")


@dataclass(frozen=True, slots=True)
class JavaJfrLaunchPolicy:
    java_tool: JavaJfrFilePolicy
    jfr_tool: JavaJfrFilePolicy
    jfc_profile: JavaJfrFilePolicy
    jdk_major: int
    profile: JavaJfrProfile
    runtime_payload: JavaJfrRuntimePayloadPolicy

    def __post_init__(self) -> None:
        if self.jdk_major not in _SUPPORTED_JDK_MAJORS:
            raise _java_error("Java JFR JDK major is outside the 17/21/25 matrix")
        if self.profile not in _PROFILE_THRESHOLDS_NS:
            raise _java_error("Java JFR profile is unsupported")
        if self.java_tool.path.name != "java" or self.jfr_tool.path.name != "jfr":
            raise _java_error("Java JFR tools must be the fixed java and jfr binaries")
        if self.java_tool.path.parent != self.jfr_tool.path.parent:
            raise _java_error("Java and jfr must come from the same JDK bin directory")
        if self.java_tool.path.parent != self.runtime_payload.bin_directory.path:
            raise _java_error("Java tools and runtime payload must come from the same JDK")
        if self.java_tool.mode not in {0o555, 0o755} or self.jfr_tool.mode not in {
            0o555,
            0o755,
        }:
            raise _java_error("Java JFR tools must use fixed executable modes")
        if self.jfc_profile.mode != 0o644:
            raise _java_error("Java JFR profile must use packaged mode 0644")


@dataclass(frozen=True, slots=True)
class JavaJfrFileIdentity:
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
class JavaExecutableJarIdentity:
    path: Path
    project_relative_path: str
    binary_sha256: str
    identity_sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    main_class: str


@dataclass(frozen=True, slots=True)
class JavaJfrLaunchRequest:
    arguments: tuple[str, ...] = ()
    duration_seconds: float = 30.0

    def __post_init__(self) -> None:
        _validate_arguments(self.arguments)
        duration = cast(object, self.duration_seconds)
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or not 0 < duration <= _MAX_DURATION_SECONDS
        ):
            raise _java_error("Java JFR launch duration is outside its fixed bound")


@dataclass(frozen=True, slots=True)
class JavaJfrJsonRunnerReceipt:
    jfr_tool_sha256: str
    jdk_major: int
    elapsed_monotonic_ns: int = 0
    accounted_active_seconds: int = 0


class JavaJfrJsonRunner(Protocol):
    def render_json(
        self,
        *,
        recording_directory_fd: int,
        recording_name: str,
        recording_fd: int,
        output_fd: int,
        jfr_tool: JavaJfrFileIdentity,
        jdk_major: int,
        max_output_bytes: int,
    ) -> JavaJfrJsonRunnerReceipt: ...


class SubprocessJavaJfrJsonRunner:
    """Render one recording with the already identity-pinned same-JDK jfr tool."""

    def __init__(self, supervisor_client: RuntimeSupervisorClient | None = None) -> None:
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

    def render_json(
        self,
        *,
        recording_directory_fd: int,
        recording_name: str,
        recording_fd: int,
        output_fd: int,
        jfr_tool: JavaJfrFileIdentity,
        jdk_major: int,
        max_output_bytes: int,
    ) -> JavaJfrJsonRunnerReceipt:
        if jdk_major not in _SUPPORTED_JDK_MAJORS or max_output_bytes != _MAX_JSON_BYTES:
            raise _java_error("Java JFR JSON runner policy is invalid")
        tool_fd = root_fd = -1
        try:
            tool_fd = _open_identity_fd(jfr_tool)
            root_fd = os.open("/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
            recording_before = os.fstat(recording_fd)
            recording_sha256 = _hash_fd(recording_fd, recording_before)
            os.ftruncate(output_fd, 0)
            os.lseek(output_fd, 0, os.SEEK_SET)
            request = RuntimeSupervisorRequest(
                request_id=runtime_supervisor_request_id(),
                expected_parent_pid=os.getpid(),
                expected_supervisor_sha256=self._supervisor.policy.sha256,
                executable=runtime_supervisor_file_identity(tool_fd),
                working_directory=runtime_supervisor_directory_identity(root_fd),
                arguments=(),
                timeout_milliseconds=30_000,
                request=RuntimeSupervisorJavaJfrPrintRequest(
                    recording_directory=runtime_supervisor_directory_identity(
                        recording_directory_fd
                    ),
                    recording_name=recording_name,
                    recording=runtime_supervisor_file_identity(recording_fd),
                    output=runtime_supervisor_writable_identity(
                        output_fd,
                        maximum_size=max_output_bytes,
                    ),
                ),
            )
            receipt = self._supervisor.execute(request)
            if receipt.terminating_signal == signal.SIGXFSZ:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "java_jfr_launcher",
                    "Java JFR JSON exceeds 64 MiB",
                    recoverable=True,
                )
            if receipt.termination_reason != "exited" or receipt.exit_code != 0:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "java_jfr_launcher",
                    "The fixed same-JDK jfr JSON conversion failed",
                    recoverable=True,
                )
            if os.fstat(output_fd).st_size > max_output_bytes:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "java_jfr_launcher",
                    "Java JFR JSON exceeds 64 MiB",
                    recoverable=True,
                )
            if _file_identity(recording_before) != _file_identity(os.fstat(recording_fd)):
                raise _java_error("Java JFR recording identity changed during JSON conversion")
            if _hash_fd(recording_fd, recording_before) != recording_sha256:
                raise _java_error("Java JFR recording content changed during JSON conversion")
            current_fd = _open_identity_fd(jfr_tool)
            os.close(current_fd)
            return JavaJfrJsonRunnerReceipt(
                jfr_tool.sha256,
                jdk_major,
                receipt.elapsed_monotonic_ns,
                receipt.accounted_active_seconds,
            )
        finally:
            for descriptor in (tool_fd, root_fd):
                if descriptor >= 0:
                    os.close(descriptor)


@dataclass(frozen=True, slots=True)
class JavaJfrLaunchResult:
    private_directory_path: Path
    private_directory_device: int
    private_directory_inode: int
    recording_path: Path
    recording_device: int
    recording_inode: int
    recording_sha256: str
    recording_size: int
    json_path: Path
    json_device: int
    json_inode: int
    json_sha256: str
    json_size: int
    target_identity_sha256: str
    jar_sha256: str
    arguments_sha256: str
    java_tool_sha256: str
    jfr_tool_sha256: str
    jfc_sha256: str
    runtime_payload_identity_sha256: str
    jdk_major: int
    profile: JavaJfrProfile
    threshold_ns: int
    target_pid: int
    target_uid: int
    target_start_ticks: int
    observed_tids: tuple[int, ...]
    started_at: str
    finished_at: str
    duration_seconds: float
    accounted_active_seconds: int
    exit_code: int | None
    termination_reason: JavaJfrTerminationReason
    quality_status: Literal["partial"] = "partial"
    limitations: tuple[str, ...] = _JAVA_JFR_LIMITATIONS


@dataclass(frozen=True, slots=True)
class JavaJfrRetainedEvidence:
    """Identity-bound private diagnostics retained after a conversion failure."""

    private_directory_path: Path
    private_directory_device: int
    private_directory_inode: int
    recording_path: Path
    recording_device: int
    recording_inode: int
    recording_sha256: str
    recording_size: int
    json_path: Path
    json_device: int
    json_inode: int
    json_sha256: str
    json_size: int


@dataclass(frozen=True, slots=True)
class JavaJfrRetentionInventory:
    """Identity-checked private diagnostics recovered after an MCP restart."""

    retained_evidence: tuple[JavaJfrRetainedEvidence, ...]
    retained_bytes: int
    private_root_count: int


@dataclass(slots=True)
class JavaJfrArtifactRootLease:
    """Process-local exclusive lease for Java JFR private evidence ownership."""

    artifact_root: Path
    artifact_root_device: int
    artifact_root_inode: int
    lock_device: int
    lock_inode: int
    owner_uid: int
    descriptor: int


@dataclass(slots=True)
class JavaJfrLaunchFailure(PerfLensError):
    """Bounded launch error whose private diagnostic identity stays process-local."""

    retained_evidence: JavaJfrRetainedEvidence | None = None
    accounted_active_seconds: int | None = None


type JavaJfrPrivateEvidence = JavaJfrLaunchResult | JavaJfrRetainedEvidence


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int


def inspect_java_jfr_tool_identity(policy: JavaJfrFilePolicy) -> JavaJfrFileIdentity:
    """Revalidate one authorized JFR executable before private Docker conversion."""

    return _inspect_policy_file(policy, executable=True, max_bytes=256 << 20)


def assert_java_jfr_launch_policy_current(policy: JavaJfrLaunchPolicy) -> None:
    """Reopen every file and directory bound by a Java launch Preview."""

    _inspect_policy_file(policy.java_tool, executable=True, max_bytes=256 << 20)
    _inspect_policy_file(policy.jfr_tool, executable=True, max_bytes=256 << 20)
    _inspect_policy_file(policy.jfc_profile, executable=False, max_bytes=1 << 20)
    for directory in (
        policy.runtime_payload.jdk_root,
        policy.runtime_payload.bin_directory,
        policy.runtime_payload.lib_directory,
    ):
        _inspect_runtime_directory(directory)
    _inspect_runtime_payload_file(policy.runtime_payload.release_file, max_bytes=1 << 20)
    _inspect_runtime_payload_file(policy.runtime_payload.modules_file, max_bytes=512 << 20)
    for library in policy.runtime_payload.native_libraries:
        _inspect_runtime_native_library(library)


class JavaJfrLauncher:
    """Launch one content-bound executable JAR with fixed startup JFR."""

    def __init__(
        self,
        *,
        project_root: Path,
        private_output_root: Path,
        policy: JavaJfrLaunchPolicy,
        json_runner: JavaJfrJsonRunner,
        invoking_uid: int | None = None,
        supervisor_client: RuntimeSupervisorClient | None = None,
    ) -> None:
        actual_uid = os.geteuid()
        if invoking_uid is not None and invoking_uid != actual_uid:
            raise _java_error("Java JFR launcher UID override is forbidden")
        if actual_uid == 0:
            raise _java_error("Java JFR workload launcher must not run as root")
        _require_kernel_support()
        self._uid = actual_uid
        self._project = _inspect_directory(project_root, actual_uid, None, "project root")
        self._output = _inspect_directory(private_output_root, actual_uid, 0o700, "output root")
        self._policy = policy
        self._java = _inspect_policy_file(policy.java_tool, executable=True, max_bytes=256 << 20)
        self._jfr = _inspect_policy_file(policy.jfr_tool, executable=True, max_bytes=256 << 20)
        self._jfc = _inspect_policy_file(policy.jfc_profile, executable=False, max_bytes=1 << 20)
        self._runtime_directories = tuple(
            _inspect_runtime_directory(item)
            for item in (
                policy.runtime_payload.jdk_root,
                policy.runtime_payload.bin_directory,
                policy.runtime_payload.lib_directory,
            )
        )
        self._runtime_payload_files = (
            _inspect_runtime_payload_file(
                policy.runtime_payload.release_file,
                max_bytes=1 << 20,
            ),
            _inspect_runtime_payload_file(
                policy.runtime_payload.modules_file,
                max_bytes=512 << 20,
            ),
        )
        self._runtime_native_libraries = tuple(
            _inspect_runtime_native_library(item)
            for item in policy.runtime_payload.native_libraries
        )
        _assert_runtime_payload_current(
            policy.runtime_payload,
            self._runtime_directories,
            self._runtime_payload_files,
            self._runtime_native_libraries,
        )
        self._json_runner = json_runner
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

    def inspect_target(self, executable_jar: Path) -> JavaExecutableJarIdentity:
        return inspect_executable_jar(
            self._project.path,
            executable_jar,
            invoking_uid=self._uid,
        )

    def launch(
        self,
        executable_jar: Path,
        request: JavaJfrLaunchRequest,
        *,
        expected_target_identity_sha256: str,
        expected_arguments_sha256: str,
    ) -> JavaJfrLaunchResult:
        target = self.inspect_target(executable_jar)
        if target.identity_sha256 != expected_target_identity_sha256:
            raise _java_error("Java JFR JAR differs from the authorized target")
        arguments_sha256 = java_jfr_arguments_sha256(request.arguments)
        if arguments_sha256 != expected_arguments_sha256:
            raise _java_error("Java JFR arguments differ from the authorized workload")
        _assert_policy_current(self._policy.java_tool, self._java, executable=True)
        _assert_policy_current(self._policy.jfr_tool, self._jfr, executable=True)
        _assert_policy_current(self._policy.jfc_profile, self._jfc, executable=False)
        _assert_runtime_payload_current(
            self._policy.runtime_payload,
            self._runtime_directories,
            self._runtime_payload_files,
            self._runtime_native_libraries,
        )
        snapshot_fd = java_fd = jfc_fd = recording_fd = json_fd = -1
        root_fd = run_fd = project_fd = -1
        created_names: list[str] = []
        launch_succeeded = False
        retain_bounded_conversion_failure = False
        token = os.urandom(10).hex()
        directory_name = f"java-jfr-{token}"
        recording_name = f"java-jfr-{token}.jfr"
        json_name = f"java-jfr-{token}.json"
        run_directory: _DirectoryIdentity | None = None
        workload_started_at: datetime | None = None
        workload_finished_at: datetime | None = None
        workload_receipt = None
        retained_failure: JavaJfrRetainedEvidence | None = None
        recording_sha256 = ""
        recording_size = 0
        try:
            snapshot_fd = _sealed_jar_snapshot(target)
            java_fd = _open_identity_fd(self._java)
            jfc_fd = _open_identity_fd(self._jfc)
            root_fd = _open_directory_fd(self._output)
            run_directory, run_fd = _create_private_directory(
                root_fd,
                self._output,
                directory_name,
                self._uid,
            )
            project_fd = _open_directory_fd(self._project)
            recording_fd = _create_private_file(run_fd, recording_name)
            created_names.append(recording_name)
            json_fd = _create_private_file(run_fd, json_name)
            created_names.append(json_name)
            workload_started_at = datetime.now(tz=UTC)
            supervisor_request = RuntimeSupervisorRequest(
                request_id=runtime_supervisor_request_id(),
                expected_parent_pid=os.getpid(),
                expected_supervisor_sha256=self._supervisor.policy.sha256,
                executable=runtime_supervisor_file_identity(java_fd),
                working_directory=runtime_supervisor_directory_identity(project_fd),
                arguments=request.arguments,
                timeout_milliseconds=math.ceil(request.duration_seconds * 1_000),
                request=RuntimeSupervisorJavaJfrWorkloadRequest(
                    jar=runtime_supervisor_file_identity(snapshot_fd),
                    profile=runtime_supervisor_file_identity(jfc_fd),
                    recording=runtime_supervisor_writable_identity(
                        recording_fd,
                        maximum_size=_MAX_JFR_BYTES,
                    ),
                ),
            )
            workload_receipt = self._supervisor.execute(supervisor_request)
            if workload_receipt.terminating_signal == signal.SIGXFSZ:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "java_jfr_launcher",
                    "Java JFR recording exceeds 64 MiB",
                    recoverable=True,
                )
            if workload_receipt.termination_reason not in {"exited", "timeout"}:
                raise _java_error("Runtime supervisor could not prove the Java workload lifecycle")
            workload_finished_at = workload_started_at + timedelta(
                microseconds=(workload_receipt.elapsed_monotonic_ns + 999) // 1_000
            )
            os.fsync(recording_fd)
            recording_sha256, recording_size = _inspect_recording_fd(recording_fd)
            retain_bounded_conversion_failure = True
            os.ftruncate(json_fd, 0)
            os.lseek(json_fd, 0, os.SEEK_SET)
            runner_directory_fd = os.dup(run_fd)
            runner_recording_fd = os.dup(recording_fd)
            runner_output_fd = os.dup(json_fd)
            try:
                receipt = self._json_runner.render_json(
                    recording_directory_fd=runner_directory_fd,
                    recording_name=recording_name,
                    recording_fd=runner_recording_fd,
                    output_fd=runner_output_fd,
                    jfr_tool=self._jfr,
                    jdk_major=self._policy.jdk_major,
                    max_output_bytes=_MAX_JSON_BYTES,
                )
            finally:
                os.close(runner_directory_fd)
                os.close(runner_recording_fd)
                os.close(runner_output_fd)
            if (
                receipt.jfr_tool_sha256 != self._jfr.sha256
                or receipt.jdk_major != self._policy.jdk_major
            ):
                raise _java_error("Java JFR JSON runner identity differs from the fixed JDK")
            _assert_policy_current(self._policy.java_tool, self._java, executable=True)
            _assert_policy_current(self._policy.jfr_tool, self._jfr, executable=True)
            _assert_policy_current(self._policy.jfc_profile, self._jfc, executable=False)
            _assert_runtime_payload_current(
                self._policy.runtime_payload,
                self._runtime_directories,
                self._runtime_payload_files,
                self._runtime_native_libraries,
            )
            os.fsync(json_fd)
            json_sha256, json_size = _inspect_json_fd(json_fd)
            assert workload_started_at is not None
            assert workload_finished_at is not None
            launch_succeeded = True
            return JavaJfrLaunchResult(
                private_directory_path=run_directory.path,
                private_directory_device=run_directory.device,
                private_directory_inode=run_directory.inode,
                recording_path=run_directory.path / recording_name,
                recording_device=os.fstat(recording_fd).st_dev,
                recording_inode=os.fstat(recording_fd).st_ino,
                recording_sha256=recording_sha256,
                recording_size=recording_size,
                json_path=run_directory.path / json_name,
                json_device=os.fstat(json_fd).st_dev,
                json_inode=os.fstat(json_fd).st_ino,
                json_sha256=json_sha256,
                json_size=json_size,
                target_identity_sha256=target.identity_sha256,
                jar_sha256=target.binary_sha256,
                arguments_sha256=arguments_sha256,
                java_tool_sha256=self._java.sha256,
                jfr_tool_sha256=self._jfr.sha256,
                jfc_sha256=self._jfc.sha256,
                runtime_payload_identity_sha256=(self._policy.runtime_payload.identity_sha256),
                jdk_major=self._policy.jdk_major,
                profile=self._policy.profile,
                threshold_ns=_PROFILE_THRESHOLDS_NS[self._policy.profile],
                target_pid=workload_receipt.workload_pid,
                target_uid=self._uid,
                target_start_ticks=workload_receipt.workload_start_ticks,
                observed_tids=(workload_receipt.workload_pid,),
                started_at=workload_started_at.isoformat(),
                finished_at=workload_finished_at.isoformat(),
                duration_seconds=workload_receipt.elapsed_monotonic_ns / 1_000_000_000,
                accounted_active_seconds=workload_receipt.accounted_active_seconds,
                exit_code=workload_receipt.exit_code,
                termination_reason=(
                    "duration_limit"
                    if workload_receipt.termination_reason == "timeout"
                    else "exited"
                ),
            )
        except Exception as exc:
            if (
                retain_bounded_conversion_failure
                and run_directory is not None
                and recording_sha256
                and _bounded_failure_outputs(recording_fd, json_fd)
            ):
                retained_failure = _retained_java_jfr_evidence(
                    run_directory=run_directory,
                    recording_path=run_directory.path / recording_name,
                    recording_fd=recording_fd,
                    recording_sha256=recording_sha256,
                    recording_size=recording_size,
                    json_path=run_directory.path / json_name,
                    json_fd=json_fd,
                    uid=self._uid,
                )
                raise _java_retained_error(
                    exc,
                    retained_failure,
                    accounted_active_seconds=(
                        workload_receipt.accounted_active_seconds
                        if workload_receipt is not None
                        else None
                    ),
                ) from exc
            raise
        finally:
            retain_failure_outputs = retained_failure is not None
            for descriptor in (
                snapshot_fd,
                java_fd,
                jfc_fd,
                recording_fd,
                json_fd,
                root_fd,
                run_fd,
                project_fd,
            ):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if (
                not launch_succeeded
                and created_names
                and run_directory is not None
                and not retain_failure_outputs
            ):
                with suppress(PerfLensError, OSError):
                    _remove_private_directory(run_directory, tuple(created_names), self._uid)


def inspect_executable_jar(
    project_root: Path,
    executable_jar: Path,
    *,
    invoking_uid: int | None = None,
) -> JavaExecutableJarIdentity:
    uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != uid:
        raise _java_error("Java JFR target UID override is forbidden")
    root = _inspect_directory(project_root, uid, None, "project root").path
    candidate = executable_jar if executable_jar.is_absolute() else root / executable_jar
    if candidate.is_symlink():
        raise _java_error("Java JFR executable JAR must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise _java_error("Java JFR executable JAR cannot be resolved safely") from exc
    if resolved != candidate or not resolved.is_relative_to(root):
        raise _java_error("Java JFR executable JAR escapes the project root")
    descriptor = -1
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        _assert_safe_regular(before, uid, max_bytes=_MAX_JAR_BYTES, executable=False)
        digest = _hash_fd(descriptor, before)
        main_class = _inspect_jar_manifest(descriptor, before.st_size)
        relative = resolved.relative_to(root).as_posix()
        identity = hashlib.sha256(
            "\0".join(
                (
                    "perflens-java-jfr-executable-jar-v1",
                    digest,
                    relative,
                    str(before.st_dev),
                    str(before.st_ino),
                    main_class,
                )
            ).encode()
        ).hexdigest()
        return JavaExecutableJarIdentity(
            path=resolved,
            project_relative_path=relative,
            binary_sha256=digest,
            identity_sha256=identity,
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=before.st_uid,
            mode=stat.S_IMODE(before.st_mode),
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
            main_class=main_class,
        )
    except PerfLensError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise _java_error("Java JFR executable JAR cannot be inspected safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def open_java_jfr_private_file(
    result: JavaJfrPrivateEvidence,
    kind: Literal["recording", "json"],
    *,
    invoking_uid: int | None = None,
) -> int:
    """Open one successful private artifact after revalidating its full identity and digest."""

    uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != uid:
        raise _java_error("Java JFR private evidence UID override is forbidden")
    directory = _result_directory_identity(result, uid)
    path = result.recording_path if kind == "recording" else result.json_path
    expected_device = result.recording_device if kind == "recording" else result.json_device
    expected_inode = result.recording_inode if kind == "recording" else result.json_inode
    expected_size = result.recording_size if kind == "recording" else result.json_size
    expected_sha256 = result.recording_sha256 if kind == "recording" else result.json_sha256
    descriptor = _open_result_file(
        directory,
        path,
        uid=uid,
        device=expected_device,
        inode=expected_inode,
        size=expected_size,
        sha256=expected_sha256,
    )
    return descriptor


def cleanup_java_jfr_launch_result(
    result: JavaJfrPrivateEvidence,
    *,
    invoking_uid: int | None = None,
) -> None:
    """Remove only the two still-identity-bound files returned by one successful launch."""

    uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != uid:
        raise _java_error("Java JFR private evidence UID override is forbidden")
    directory = _result_directory_identity(result, uid)
    descriptors: list[int] = []
    try:
        descriptors.append(open_java_jfr_private_file(result, "recording", invoking_uid=uid))
        descriptors.append(open_java_jfr_private_file(result, "json", invoking_uid=uid))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    if len(descriptors) != 2:
        raise _java_error("Java JFR private evidence could not be fully revalidated")
    _remove_private_directory(
        directory,
        (result.recording_path.name, result.json_path.name),
        uid,
    )


def acquire_java_jfr_artifact_root_lease(
    artifact_root: Path,
    *,
    invoking_uid: int | None = None,
) -> JavaJfrArtifactRootLease:
    """Exclusively serialize inventory and cleanup across MCP processes.

    The persistent lock file contains no data.  Kernel ``flock`` ownership is
    released automatically after a crash, allowing the next process to safely
    inventory bounded diagnostics that the previous process left behind.
    """

    uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != uid:
        raise _java_error("Java JFR artifact-root lease UID override is forbidden")
    root = _inspect_directory(artifact_root, uid, None, "artifact root")
    root_fd = _open_directory_fd(root)
    descriptor = -1
    locked = False
    try:
        try:
            descriptor = os.open(
                _JAVA_ARTIFACT_ROOT_LOCK_NAME,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_fd,
            )
            opened = os.fstat(descriptor)
            named = os.stat(
                _JAVA_ARTIFACT_ROOT_LOCK_NAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _java_error("Java JFR artifact-root lease cannot be opened safely") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or opened.st_dev != root.device
            or opened.st_dev != named.st_dev
            or opened.st_ino != named.st_ino
            or opened.st_uid != uid
            or named.st_uid != uid
            or opened.st_nlink != 1
            or named.st_nlink != 1
            or opened.st_size != 0
            or named.st_size != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(named.st_mode) != 0o600
            or opened.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise _java_error("Java JFR artifact-root lease identity is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise _java_error(
                "Another PerfLens Java JFR MCP process owns the private evidence lease"
            ) from exc
        except OSError as exc:
            raise _java_error("Java JFR artifact-root lease cannot be acquired") from exc
        current = os.fstat(descriptor)
        named_current = os.stat(
            _JAVA_ARTIFACT_ROOT_LOCK_NAME,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            current.st_dev != opened.st_dev
            or current.st_ino != opened.st_ino
            or current.st_uid != opened.st_uid
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
            or current.st_size != 0
            or named_current.st_dev != opened.st_dev
            or named_current.st_ino != opened.st_ino
            or named_current.st_uid != uid
            or stat.S_IMODE(named_current.st_mode) != 0o600
            or named_current.st_nlink != 1
            or named_current.st_size != 0
        ):
            raise _java_error("Java JFR artifact-root lease changed during acquisition")
        result = JavaJfrArtifactRootLease(
            artifact_root=root.path,
            artifact_root_device=root.device,
            artifact_root_inode=root.inode,
            lock_device=opened.st_dev,
            lock_inode=opened.st_ino,
            owner_uid=uid,
            descriptor=descriptor,
        )
        descriptor = -1
        return result
    finally:
        os.close(root_fd)
        if descriptor >= 0:
            if locked:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def release_java_jfr_artifact_root_lease(lease: JavaJfrArtifactRootLease) -> None:
    """Release one process-local Java JFR private-evidence lease."""

    descriptor = lease.descriptor
    if descriptor < 0:
        return
    lease.descriptor = -1
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev != lease.lock_device
            or metadata.st_ino != lease.lock_inode
            or metadata.st_uid != lease.owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise _java_error("Java JFR artifact-root lease identity changed")
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def inventory_java_jfr_retained_evidence(
    artifact_root: Path,
    *,
    max_retained_bytes: int,
    invoking_uid: int | None = None,
) -> JavaJfrRetentionInventory:
    """Recover and account identity-bound JFR diagnostics left by a prior process."""

    uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != uid:
        raise _java_error("Java JFR retained-evidence UID override is forbidden")
    if isinstance(max_retained_bytes, bool) or not 0 < max_retained_bytes <= 512 << 20:
        raise _java_retention_limit("Java JFR retained-evidence quota is invalid")
    parent = _inspect_directory(artifact_root, uid, None, "artifact root")
    parent_fd = _open_directory_fd(parent)
    retained: list[JavaJfrRetainedEvidence] = []
    retained_bytes = 0
    root_count = 0
    run_count = 0
    try:
        try:
            entries = os.scandir(parent_fd)
        except OSError as exc:
            raise _java_error("Java JFR retained roots cannot be inventoried safely") from exc
        with entries:
            for entry in entries:
                if not entry.name.startswith(_JAVA_PRIVATE_ROOT_PREFIX):
                    continue
                if not _is_java_private_root_name(entry.name):
                    raise _java_error("Java JFR artifact root contains a malformed private root")
                root_count += 1
                if root_count > _MAX_RETAINED_DIRECTORIES:
                    raise _java_retention_limit(
                        "Java JFR retained directory count exceeds its fixed bound"
                    )
                root, root_fd = _open_child_directory(
                    parent_fd,
                    parent,
                    entry.name,
                    owner_uid=uid,
                    expected_mode=0o700,
                    label="retained root",
                )
                try:
                    try:
                        run_entries = os.scandir(root_fd)
                    except OSError as exc:
                        raise _java_error(
                            "Java JFR retained root cannot be inventoried safely"
                        ) from exc
                    with run_entries:
                        for run_entry in run_entries:
                            run_count += 1
                            if run_count > _MAX_RETAINED_DIRECTORIES:
                                raise _java_retention_limit(
                                    "Java JFR retained directory count exceeds its fixed bound"
                                )
                            token = _java_private_run_token(run_entry.name)
                            if token is None:
                                raise _java_error(
                                    "Java JFR retained root contains an unexpected diagnostic entry"
                                )
                            run, run_fd = _open_child_directory(
                                root_fd,
                                root,
                                run_entry.name,
                                owner_uid=uid,
                                expected_mode=0o700,
                                label="retained run",
                            )
                            try:
                                evidence = _inventory_java_jfr_run(run, run_fd, token, uid)
                            finally:
                                os.close(run_fd)
                            retained_bytes += evidence.recording_size + evidence.json_size
                            if retained_bytes > max_retained_bytes:
                                raise _java_retention_limit(
                                    "Java JFR retained diagnostics exceed the private Session quota"
                                )
                            retained.append(evidence)
                finally:
                    os.close(root_fd)
    finally:
        os.close(parent_fd)
    return JavaJfrRetentionInventory(tuple(retained), retained_bytes, root_count)


def cleanup_java_jfr_empty_private_roots(
    artifact_root: Path,
    *,
    invoking_uid: int | None = None,
) -> None:
    """Remove only verified empty Java JFR roots after their runs were cleaned."""

    uid = os.geteuid()
    if invoking_uid is not None and invoking_uid != uid:
        raise _java_error("Java JFR retained-evidence UID override is forbidden")
    parent = _inspect_directory(artifact_root, uid, None, "artifact root")
    parent_fd = _open_directory_fd(parent)
    try:
        root_names: list[str] = []
        with os.scandir(parent_fd) as entries:
            for entry in entries:
                if not entry.name.startswith(_JAVA_PRIVATE_ROOT_PREFIX):
                    continue
                if not _is_java_private_root_name(entry.name):
                    raise _java_error("Java JFR artifact root contains a malformed private root")
                root_names.append(entry.name)
                if len(root_names) > _MAX_RETAINED_DIRECTORIES:
                    raise _java_retention_limit(
                        "Java JFR retained directory count exceeds its fixed bound"
                    )
        for root_name in root_names:
            root, root_fd = _open_child_directory(
                parent_fd,
                parent,
                root_name,
                owner_uid=uid,
                expected_mode=0o700,
                label="cleanup root",
            )
            try:
                with os.scandir(root_fd) as run_entries:
                    contains_runs = next(run_entries, None) is not None
                if contains_runs:
                    continue
            finally:
                os.close(root_fd)
            current = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                current.st_dev != root.device
                or current.st_ino != root.inode
                or current.st_uid != uid
                or not stat.S_ISDIR(current.st_mode)
                or stat.S_IMODE(current.st_mode) != 0o700
            ):
                raise _java_error("Java JFR empty private root identity changed")
            os.rmdir(root_name, dir_fd=parent_fd)
    except PerfLensError:
        raise
    except OSError as exc:
        raise _java_error("Java JFR empty private roots could not be cleaned safely") from exc
    finally:
        os.close(parent_fd)


def _inventory_java_jfr_run(
    run: _DirectoryIdentity,
    run_fd: int,
    token: str,
    uid: int,
) -> JavaJfrRetainedEvidence:
    recording_name = f"{_JAVA_PRIVATE_RUN_PREFIX}{token}.jfr"
    json_name = f"{_JAVA_PRIVATE_RUN_PREFIX}{token}.json"
    try:
        names: set[str] = set()
        with os.scandir(run_fd) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > 2:
                    break
    except OSError as exc:
        raise _java_error("Java JFR retained run cannot be inspected safely") from exc
    if names != {recording_name, json_name}:
        raise _java_error("Java JFR retained run has an unexpected file set")
    recording_fd = json_fd = -1
    try:
        recording_fd, recording = _open_retained_file(
            run_fd,
            recording_name,
            uid=uid,
            maximum=_MAX_JFR_BYTES,
            allow_empty=False,
        )
        recording_sha256, recording_size = _inspect_recording_fd(recording_fd)
        json_fd, rendered = _open_retained_file(
            run_fd,
            json_name,
            uid=uid,
            maximum=_MAX_JSON_BYTES,
            allow_empty=True,
        )
        json_sha256 = _hash_fd(json_fd, rendered)
        return JavaJfrRetainedEvidence(
            private_directory_path=run.path,
            private_directory_device=run.device,
            private_directory_inode=run.inode,
            recording_path=run.path / recording_name,
            recording_device=recording.st_dev,
            recording_inode=recording.st_ino,
            recording_sha256=recording_sha256,
            recording_size=recording_size,
            json_path=run.path / json_name,
            json_device=rendered.st_dev,
            json_inode=rendered.st_ino,
            json_sha256=json_sha256,
            json_size=rendered.st_size,
        )
    finally:
        if recording_fd >= 0:
            os.close(recording_fd)
        if json_fd >= 0:
            os.close(json_fd)


def _open_retained_file(
    directory_fd: int,
    name: str,
    *,
    uid: int,
    maximum: int,
    allow_empty: bool,
) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < (0 if allow_empty else 1)
            or metadata.st_size > maximum
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise _java_error("Java JFR retained diagnostic identity or size is unsafe")
        result = descriptor
        descriptor = -1
        return result, metadata
    except PerfLensError:
        raise
    except OSError as exc:
        raise _java_error("Java JFR retained diagnostic cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_child_directory(
    parent_fd: int,
    parent: _DirectoryIdentity,
    name: str,
    *,
    owner_uid: int,
    expected_mode: int,
    label: str,
) -> tuple[_DirectoryIdentity, int]:
    descriptor = -1
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise _java_error(f"Java JFR {label} cannot be opened safely") from exc
    if (
        named.st_dev != parent.device
        or opened.st_dev != named.st_dev
        or opened.st_ino != named.st_ino
        or opened.st_uid != owner_uid
        or named.st_uid != owner_uid
        or not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or stat.S_IMODE(named.st_mode) != expected_mode
    ):
        os.close(descriptor)
        raise _java_error(f"Java JFR {label} identity is unsafe")
    return (
        _DirectoryIdentity(
            parent.path / name,
            opened.st_dev,
            opened.st_ino,
            owner_uid,
            expected_mode,
        ),
        descriptor,
    )


def _is_java_private_root_name(name: str) -> bool:
    if not name.startswith(_JAVA_PRIVATE_ROOT_PREFIX):
        return False
    suffix = name.removeprefix(_JAVA_PRIVATE_ROOT_PREFIX)
    return len(suffix) == 8 and all(
        character in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in suffix
    )


def _java_private_run_token(name: str) -> str | None:
    if not name.startswith(_JAVA_PRIVATE_RUN_PREFIX):
        return None
    token = name.removeprefix(_JAVA_PRIVATE_RUN_PREFIX)
    if len(token) != 20 or any(character not in "0123456789abcdef" for character in token):
        return None
    return token


def _retained_java_jfr_evidence(
    *,
    run_directory: _DirectoryIdentity,
    recording_path: Path,
    recording_fd: int,
    recording_sha256: str,
    recording_size: int,
    json_path: Path,
    json_fd: int,
    uid: int,
) -> JavaJfrRetainedEvidence:
    recording = os.fstat(recording_fd)
    if (
        recording.st_dev != run_directory.device
        or recording.st_uid != uid
        or recording.st_size != recording_size
        or _hash_fd(recording_fd, recording) != recording_sha256
    ):
        raise _java_error("Java JFR retained recording identity changed")
    json_before = os.fstat(json_fd)
    json_mode = stat.S_IMODE(json_before.st_mode)
    if (
        not stat.S_ISREG(json_before.st_mode)
        or json_before.st_nlink != 1
        or json_before.st_uid != uid
        or json_mode != 0o600
        or not 0 <= json_before.st_size <= _MAX_JSON_BYTES
        or json_before.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise _java_error("Java JFR retained JSON identity is unsafe")
    json_sha256 = _hash_fd(json_fd, json_before)
    json_after = os.fstat(json_fd)
    if _file_identity(json_before) != _file_identity(json_after):
        raise _java_error("Java JFR retained JSON changed while it was hashed")
    return JavaJfrRetainedEvidence(
        private_directory_path=run_directory.path,
        private_directory_device=run_directory.device,
        private_directory_inode=run_directory.inode,
        recording_path=recording_path,
        recording_device=recording.st_dev,
        recording_inode=recording.st_ino,
        recording_sha256=recording_sha256,
        recording_size=recording_size,
        json_path=json_path,
        json_device=json_before.st_dev,
        json_inode=json_before.st_ino,
        json_sha256=json_sha256,
        json_size=json_before.st_size,
    )


def _java_retained_error(
    cause: Exception,
    retained: JavaJfrRetainedEvidence,
    *,
    accounted_active_seconds: int | None,
) -> JavaJfrLaunchFailure:
    if isinstance(cause, PerfLensError):
        return JavaJfrLaunchFailure(
            code=cause.code,
            stage=cause.stage,
            message=cause.message,
            recoverable=cause.recoverable,
            retryable=cause.retryable,
            details=dict(cause.details),
            suggested_actions=cause.suggested_actions,
            retained_evidence=retained,
            accounted_active_seconds=accounted_active_seconds,
        )
    return JavaJfrLaunchFailure(
        ErrorCode.EXTERNAL_TOOL_FAILED,
        "java_jfr_launcher",
        "The fixed same-JDK JFR conversion failed; bounded private diagnostics were retained",
        recoverable=True,
        retained_evidence=retained,
        accounted_active_seconds=accounted_active_seconds,
    )


def _java_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "java_jfr_launcher",
        message,
        recoverable=True,
    )


def _java_retention_limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "runtime_lock_collection",
        message,
        recoverable=True,
    )


def _require_kernel_support() -> None:
    if (
        not hasattr(os, "memfd_create")
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal")
        or not Path("/proc/self/fd").is_dir()
    ):
        raise _java_error("Host kernel lacks sealed memfd or pidfd launch support")


def _inspect_directory(
    path: Path,
    owner_uid: int,
    expected_mode: int | None,
    label: str,
) -> _DirectoryIdentity:
    if not path.is_absolute() or path.is_symlink():
        raise _java_error(f"Java JFR {label} must be absolute and non-symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _java_error(f"Java JFR {label} cannot be resolved safely") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or mode & 0o022
        or (expected_mode is not None and mode != expected_mode)
    ):
        raise _java_error(f"Java JFR {label} owner or mode is unsafe")
    return _DirectoryIdentity(resolved, metadata.st_dev, metadata.st_ino, owner_uid, mode)


def _open_directory_fd(identity: _DirectoryIdentity) -> int:
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
        raise _java_error("Java JFR launch directory cannot be opened safely") from exc
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    ) != (identity.device, identity.inode, identity.owner_uid, identity.mode):
        os.close(descriptor)
        raise _java_error("Java JFR launch directory identity changed")
    return descriptor


def _assert_safe_regular(
    metadata: os.stat_result,
    owner_uid: int,
    *,
    max_bytes: int,
    executable: bool,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    allowed_modes = {0o555, 0o755} if executable else {0o400, 0o440, 0o444, 0o600, 0o640, 0o644}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != owner_uid
        or mode not in allowed_modes
        or metadata.st_size <= 0
        or metadata.st_size > max_bytes
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise _java_error("Java JFR file owner, mode, type, or size is unsafe")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_fd(descriptor: int, before: os.stat_result) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1 << 20):
        digest.update(chunk)
    if _file_identity(before) != _file_identity(os.fstat(descriptor)):
        raise _java_error("Java JFR file changed while it was hashed")
    return digest.hexdigest()


def _reject_file_capabilities(descriptor: int, label: str) -> None:
    try:
        capability = os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise _java_error(f"Java JFR {label} capabilities cannot be checked") from exc
    if capability:
        raise _java_error(f"Java JFR {label} with file capabilities is unsupported")


def _inspect_policy_file(
    policy: JavaJfrFilePolicy,
    *,
    executable: bool,
    max_bytes: int,
) -> JavaJfrFileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            policy.path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        _assert_safe_regular(metadata, policy.owner_uid, max_bytes=max_bytes, executable=executable)
        if stat.S_IMODE(metadata.st_mode) != policy.mode:
            raise _java_error("Java JFR policy file mode differs from its binding")
        if executable:
            _reject_file_capabilities(descriptor, policy.path.name)
        digest = _hash_fd(descriptor, metadata)
        if digest != policy.sha256:
            raise _java_error("Java JFR policy file digest differs from its binding")
        return JavaJfrFileIdentity(
            policy.path,
            digest,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    except PerfLensError:
        raise
    except OSError as exc:
        raise _java_error("Java JFR policy file cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _assert_policy_current(
    policy: JavaJfrFilePolicy,
    expected: JavaJfrFileIdentity,
    *,
    executable: bool,
) -> None:
    maximum = 1 << 20 if not executable else 256 << 20
    if _inspect_policy_file(policy, executable=executable, max_bytes=maximum) != expected:
        raise _java_error("Java JFR policy file identity changed")


def _directory_policy_identity(policy: JavaJfrDirectoryPolicy) -> tuple[int, ...]:
    return (
        policy.device,
        policy.inode,
        policy.owner_uid,
        stat.S_IFDIR | policy.mode,
        policy.links,
        policy.size,
        policy.modified_ns,
        policy.changed_ns,
    )


def _inspect_runtime_directory(
    policy: JavaJfrDirectoryPolicy,
) -> JavaJfrDirectoryPolicy:
    descriptor = -1
    try:
        descriptor = os.open(
            policy.path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        descriptor_identity = os.fstat(descriptor)
        named_identity = policy.path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _java_error("Java JFR runtime directory cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    expected = _directory_policy_identity(policy)
    observed_descriptor = (
        descriptor_identity.st_dev,
        descriptor_identity.st_ino,
        descriptor_identity.st_uid,
        descriptor_identity.st_mode,
        descriptor_identity.st_nlink,
        descriptor_identity.st_size,
        descriptor_identity.st_mtime_ns,
        descriptor_identity.st_ctime_ns,
    )
    observed_named = (
        named_identity.st_dev,
        named_identity.st_ino,
        named_identity.st_uid,
        named_identity.st_mode,
        named_identity.st_nlink,
        named_identity.st_size,
        named_identity.st_mtime_ns,
        named_identity.st_ctime_ns,
    )
    if observed_descriptor != expected or observed_named != expected:
        raise _java_error("Java JFR runtime directory identity changed")
    return policy


def _inspect_runtime_payload_file(
    policy: JavaJfrPayloadFilePolicy,
    *,
    max_bytes: int,
) -> JavaJfrFileIdentity:
    try:
        identity = _inspect_policy_file(
            JavaJfrFilePolicy(
                path=policy.path,
                sha256=policy.sha256,
                owner_uid=policy.owner_uid,
                mode=policy.mode,
            ),
            executable=False,
            max_bytes=max_bytes,
        )
    except PerfLensError as exc:
        raise _java_error("Java JFR runtime payload file identity changed") from exc
    if (
        identity.device,
        identity.inode,
        identity.owner_uid,
        identity.mode,
        identity.size,
        identity.modified_ns,
        identity.changed_ns,
    ) != (
        policy.device,
        policy.inode,
        policy.owner_uid,
        policy.mode,
        policy.size,
        policy.modified_ns,
        policy.changed_ns,
    ):
        raise _java_error("Java JFR runtime payload file identity changed")
    return identity


def _derive_runtime_payload_policy_identity(
    policy: JavaJfrRuntimePayloadPolicy,
) -> str:
    material = ["perflens-java-jfr-runtime-payload-v2"]
    for directory in (
        policy.jdk_root,
        policy.bin_directory,
        policy.lib_directory,
    ):
        material.extend(
            (
                directory.path.name,
                str(directory.device),
                str(directory.inode),
                str(directory.owner_uid),
                str(directory.mode),
            )
        )
    for payload in (policy.release_file, policy.modules_file):
        material.extend(
            (
                payload.path.name,
                payload.sha256,
                str(payload.size),
                str(payload.owner_uid),
                str(payload.mode),
            )
        )
    material.extend(
        (
            policy.native_library_manifest_sha256,
            str(len(policy.native_libraries)),
            str(policy.native_library_bytes),
        )
    )
    return hashlib.sha256("\0".join(material).encode("utf-8")).hexdigest()


def _derive_native_library_policy_manifest_identity(
    native_libraries: tuple[JavaJfrNativeLibraryPolicy, ...],
) -> str:
    material = ["perflens-java-jfr-native-library-manifest-v1"]
    for library in native_libraries:
        material.extend(
            (
                library.relative_path,
                library.source_kind,
                library.link_target_sha256 or "",
                library.sha256,
                str(library.size),
                str(library.owner_uid),
                str(library.mode),
            )
        )
    return hashlib.sha256("\0".join(material).encode("utf-8")).hexdigest()


def _assert_runtime_payload_current(
    policy: JavaJfrRuntimePayloadPolicy,
    expected_directories: tuple[JavaJfrDirectoryPolicy, ...],
    expected_files: tuple[JavaJfrFileIdentity, JavaJfrFileIdentity],
    expected_native_libraries: tuple[JavaJfrFileIdentity, ...],
) -> None:
    current_directories = tuple(
        _inspect_runtime_directory(item)
        for item in (policy.jdk_root, policy.bin_directory, policy.lib_directory)
    )
    current_files = (
        _revalidate_runtime_payload_file(policy.release_file, expected_files[0]),
        _revalidate_runtime_payload_file(policy.modules_file, expected_files[1]),
    )
    current_native_libraries = tuple(
        _revalidate_runtime_native_library(item, expected)
        for item, expected in zip(
            policy.native_libraries,
            expected_native_libraries,
            strict=True,
        )
    )
    if (
        current_directories != expected_directories
        or current_files != expected_files
        or current_native_libraries != expected_native_libraries
    ):
        raise _java_error("Java JFR runtime payload identity changed")


def _inspect_runtime_native_library(
    policy: JavaJfrNativeLibraryPolicy,
) -> JavaJfrFileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            policy.resolved_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        _assert_native_library_metadata(policy, metadata)
        _reject_file_capabilities(descriptor, "native runtime library")
        digest = _hash_fd(descriptor, metadata)
        if digest != policy.sha256:
            raise _java_error("Java JFR native runtime library digest changed")
        _assert_native_library_named_identity(policy, metadata)
        return JavaJfrFileIdentity(
            policy.resolved_path,
            digest,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    except PerfLensError:
        raise
    except OSError as exc:
        raise _java_error("Java JFR native runtime library cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _revalidate_runtime_native_library(
    policy: JavaJfrNativeLibraryPolicy,
    expected: JavaJfrFileIdentity,
) -> JavaJfrFileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            policy.resolved_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        _assert_native_library_metadata(policy, metadata)
        _assert_native_library_named_identity(policy, metadata)
    except PerfLensError:
        raise
    except OSError as exc:
        raise _java_error("Java JFR native runtime library cannot be reopened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    observed = JavaJfrFileIdentity(
        policy.resolved_path,
        policy.sha256,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    if observed != expected:
        raise _java_error("Java JFR native runtime library identity changed")
    return expected


def _assert_native_library_metadata(
    policy: JavaJfrNativeLibraryPolicy,
    metadata: os.stat_result,
) -> None:
    observed = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    expected = (
        policy.device,
        policy.inode,
        policy.owner_uid,
        policy.mode,
        policy.links,
        policy.size,
        policy.modified_ns,
        policy.changed_ns,
    )
    if (
        observed != expected
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise _java_error("Java JFR native runtime library identity changed")


def _assert_native_library_named_identity(
    policy: JavaJfrNativeLibraryPolicy,
    target_metadata: os.stat_result,
) -> None:
    if policy.source_kind == "regular":
        named = policy.named_path.stat(follow_symlinks=False)
        if (
            named.st_dev,
            named.st_ino,
            named.st_uid,
            stat.S_IMODE(named.st_mode),
            named.st_nlink,
            named.st_size,
            named.st_mtime_ns,
            named.st_ctime_ns,
        ) != (
            target_metadata.st_dev,
            target_metadata.st_ino,
            target_metadata.st_uid,
            stat.S_IMODE(target_metadata.st_mode),
            target_metadata.st_nlink,
            target_metadata.st_size,
            target_metadata.st_mtime_ns,
            target_metadata.st_ctime_ns,
        ):
            raise _java_error("Java JFR native runtime library named identity changed")
        return
    link = policy.named_path.lstat()
    link_values = (
        policy.link_device,
        policy.link_inode,
        policy.link_owner_uid,
        policy.link_mode,
        policy.link_links,
        policy.link_size,
        policy.link_modified_ns,
        policy.link_changed_ns,
    )
    if any(item is None for item in link_values):
        raise _java_error("Java JFR native runtime library symlink identity is incomplete")
    observed_link = (
        link.st_dev,
        link.st_ino,
        link.st_uid,
        stat.S_IMODE(link.st_mode),
        link.st_nlink,
        link.st_size,
        link.st_mtime_ns,
        link.st_ctime_ns,
    )
    if observed_link != link_values:
        raise _java_error("Java JFR native runtime library symlink identity changed")
    target = os.readlink(policy.named_path)
    if (
        policy.link_target_sha256 is None
        or hashlib.sha256(os.fsencode(target)).hexdigest() != policy.link_target_sha256
        or policy.named_path.resolve(strict=True) != policy.resolved_path
    ):
        raise _java_error("Java JFR native runtime library symlink target changed")


def _revalidate_runtime_payload_file(
    policy: JavaJfrPayloadFilePolicy,
    expected: JavaJfrFileIdentity,
) -> JavaJfrFileIdentity:
    # The complete payload was hashed when the Launcher was constructed.  The
    # before/after checks compare both the open descriptor and named path,
    # including inode, size, mtime and ctime.  Rehashing the 100+ MiB modules
    # image around every workload would distort the Adapter overhead while a
    # trusted-owner in-place write necessarily changes ctime.
    descriptor = -1
    try:
        descriptor = os.open(
            policy.path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptor_metadata = os.fstat(descriptor)
        named_metadata = policy.path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _java_error("Java JFR runtime payload file cannot be reopened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    observed_descriptor = (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
        descriptor_metadata.st_uid,
        stat.S_IMODE(descriptor_metadata.st_mode),
        descriptor_metadata.st_nlink,
        descriptor_metadata.st_size,
        descriptor_metadata.st_mtime_ns,
        descriptor_metadata.st_ctime_ns,
    )
    observed_named = (
        named_metadata.st_dev,
        named_metadata.st_ino,
        named_metadata.st_uid,
        stat.S_IMODE(named_metadata.st_mode),
        named_metadata.st_nlink,
        named_metadata.st_size,
        named_metadata.st_mtime_ns,
        named_metadata.st_ctime_ns,
    )
    expected_metadata = (
        policy.device,
        policy.inode,
        policy.owner_uid,
        policy.mode,
        1,
        policy.size,
        policy.modified_ns,
        policy.changed_ns,
    )
    if (
        observed_descriptor != expected_metadata
        or observed_named != expected_metadata
        or expected.sha256 != policy.sha256
    ):
        raise _java_error("Java JFR runtime payload file identity changed")
    return expected


def _open_identity_fd(identity: JavaJfrFileIdentity) -> int:
    descriptor = os.open(
        identity.path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    metadata = os.fstat(descriptor)
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
        raise _java_error("Java JFR launch input identity changed")
    return descriptor


def _manifest_attributes(raw: bytes) -> dict[str, str]:
    if len(raw) > _MAX_MANIFEST_BYTES or b"\x00" in raw:
        raise _java_error("Java JFR JAR manifest exceeds its safe bound")
    try:
        text = raw.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise _java_error("Java JFR JAR manifest is not valid UTF-8") from exc
    logical: list[str] = []
    for line in text.split("\n"):
        if line.startswith(" "):
            if not logical:
                raise _java_error("Java JFR JAR manifest folding is invalid")
            logical[-1] += line[1:]
        elif line:
            logical.append(line)
    attributes: dict[str, str] = {}
    for line in logical:
        if ": " not in line:
            raise _java_error("Java JFR JAR manifest entry is malformed")
        key, value = line.split(": ", 1)
        normalized = key.casefold()
        if normalized in attributes:
            raise _java_error("Java JFR JAR manifest has duplicate attributes")
        attributes[normalized] = value
    return attributes


def _inspect_jar_manifest(descriptor: int, expected_size: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    with zipfile.ZipFile(f"/proc/self/fd/{descriptor}", "r") as archive:
        entries = archive.infolist()
        if len(entries) > _MAX_ARCHIVE_ENTRIES:
            raise _java_error("Java JFR JAR contains too many archive entries")
        total = 0
        manifests: list[zipfile.ZipInfo] = []
        for entry in entries:
            total += entry.file_size
            if total > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise _java_error("Java JFR JAR expands beyond its fixed bound")
            name = entry.filename
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or "\\" in name:
                raise _java_error("Java JFR JAR entry path is unsafe")
            archive_mode = (entry.external_attr >> 16) & 0xFFFF
            archive_type = stat.S_IFMT(archive_mode)
            if archive_type and archive_type not in {stat.S_IFREG, stat.S_IFDIR}:
                raise _java_error("Java JFR JAR contains a special archive entry")
            if name.casefold() == "meta-inf/manifest.mf":
                manifests.append(entry)
        if len(manifests) != 1:
            raise _java_error("Java JFR executable JAR must contain one manifest")
        manifest = manifests[0]
        if manifest.file_size > _MAX_MANIFEST_BYTES:
            raise _java_error("Java JFR JAR manifest exceeds its safe bound")
        attributes = _manifest_attributes(archive.read(manifest))
    if os.fstat(descriptor).st_size != expected_size:
        raise _java_error("Java JFR JAR changed during manifest inspection")
    forbidden = _FORBIDDEN_MANIFEST_KEYS & attributes.keys()
    if forbidden:
        raise _java_error("Java JFR JAR manifest requests classpath, agents, or JVM expansion")
    main_class = attributes.get("main-class", "").strip()
    if not main_class or any(character.isspace() for character in main_class):
        raise _java_error("Java JFR executable JAR Main-Class is unavailable")
    return main_class


def _open_target_identity_fd(target: JavaExecutableJarIdentity) -> int:
    descriptor = os.open(
        target.path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    metadata = os.fstat(descriptor)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) != (
        target.device,
        target.inode,
        target.owner_uid,
        1,
        target.size,
        target.modified_ns,
        target.changed_ns,
    ):
        os.close(descriptor)
        raise _java_error("Java JFR executable JAR identity changed")
    return descriptor


def _sealed_jar_snapshot(target: JavaExecutableJarIdentity) -> int:
    source_fd = snapshot_fd = -1
    try:
        source_fd = _open_target_identity_fd(target)
        source_before = os.fstat(source_fd)
        if _hash_fd(source_fd, source_before) != target.binary_sha256:
            raise _java_error("Java JFR executable JAR content changed before snapshot")
        snapshot_fd = os.memfd_create(
            "perflens-java-jfr-target",
            flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        os.lseek(source_fd, 0, os.SEEK_SET)
        copied = hashlib.sha256()
        size = 0
        while chunk := os.read(source_fd, 1 << 20):
            copied.update(chunk)
            size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_fd, view)
                if written <= 0:
                    raise _java_error("Java JFR JAR snapshot write failed")
                view = view[written:]
        if size != target.size or copied.hexdigest() != target.binary_sha256:
            raise _java_error("Java JFR executable JAR changed while snapshotting")
        if _file_identity(source_before) != _file_identity(os.fstat(source_fd)):
            raise _java_error("Java JFR executable JAR changed while snapshotting")
        if _hash_fd(source_fd, source_before) != target.binary_sha256:
            raise _java_error("Java JFR executable JAR changed after snapshotting")
        path_check = _open_target_identity_fd(target)
        os.close(path_check)
        os.fchmod(snapshot_fd, 0o400)
        snapshot_before = os.fstat(snapshot_fd)
        if _hash_fd(snapshot_fd, snapshot_before) != target.binary_sha256:
            raise _java_error("Java JFR JAR snapshot digest is invalid")
        if _inspect_jar_manifest(snapshot_fd, target.size) != target.main_class:
            raise _java_error("Java JFR JAR snapshot manifest changed")
        fcntl.fcntl(snapshot_fd, F_ADD_SEALS, _REQUIRED_SEALS)
        if fcntl.fcntl(snapshot_fd, F_GET_SEALS) & _REQUIRED_SEALS != _REQUIRED_SEALS:
            raise _java_error("Java JFR JAR snapshot could not be sealed")
        os.lseek(snapshot_fd, 0, os.SEEK_SET)
        result = snapshot_fd
        snapshot_fd = -1
        return result
    except PerfLensError:
        raise
    except OSError as exc:
        raise _java_error("Java JFR executable JAR cannot be snapshotted safely") from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if snapshot_fd >= 0:
            os.close(snapshot_fd)


def _validate_arguments(arguments: tuple[str, ...]) -> None:
    raw = cast(object, arguments)
    if not isinstance(raw, tuple):
        raise _java_error("Java JFR workload arguments must be a bounded tuple")
    values = cast(tuple[object, ...], raw)
    if len(values) > _MAX_ARGUMENTS:
        raise _java_error("Java JFR workload arguments must be a bounded tuple")
    total = 0
    for argument in values:
        if not isinstance(argument, str) or "\x00" in argument:
            raise _java_error("Java JFR workload argument is invalid")
        encoded = argument.encode("utf-8")
        if len(encoded) > 4096:
            raise _java_error("Java JFR workload argument exceeds its bound")
        total += len(encoded) + 1
    if total > _MAX_ARGUMENT_BYTES:
        raise _java_error("Java JFR workload argument vector exceeds its bound")


def java_jfr_arguments_sha256(arguments: tuple[str, ...]) -> str:
    """Return the canonical content binding for the fixed application argv."""

    _validate_arguments(arguments)
    return hashlib.sha256(b"\0".join(item.encode() for item in arguments)).hexdigest()


def _create_private_file(directory_fd: int, name: str) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise _java_error("Java JFR private evidence name is invalid")
    try:
        return os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise _java_error("Java JFR private evidence file cannot be created") from exc


def _create_private_directory(
    root_fd: int,
    root: _DirectoryIdentity,
    name: str,
    owner_uid: int,
) -> tuple[_DirectoryIdentity, int]:
    if "/" in name or name in {"", ".", ".."}:
        raise _java_error("Java JFR private directory name is invalid")
    descriptor = -1
    created: os.stat_result | None = None
    try:
        os.mkdir(name, 0o700, dir_fd=root_fd)
        created = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(created.st_mode)
            or created.st_dev != root.device
            or created.st_uid != owner_uid
            or stat.S_IMODE(created.st_mode) != 0o700
        ):
            _rollback_just_created_private_directory(root_fd, name, created, owner_uid)
            raise _java_error("Java JFR private directory identity is unsafe")
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
            dir_fd=root_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev != created.st_dev
            or metadata.st_ino != created.st_ino
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            descriptor = -1
            _rollback_just_created_private_directory(root_fd, name, created, owner_uid)
            raise _java_error("Java JFR private directory identity is unsafe")
    except PerfLensError:
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if created is not None:
            with suppress(OSError):
                _rollback_just_created_private_directory(root_fd, name, created, owner_uid)
        raise _java_error("Java JFR private directory cannot be created safely") from exc
    return (
        _DirectoryIdentity(
            root.path / name,
            metadata.st_dev,
            metadata.st_ino,
            owner_uid,
            0o700,
        ),
        descriptor,
    )


def _rollback_just_created_private_directory(
    root_fd: int,
    name: str,
    created: os.stat_result,
    owner_uid: int,
) -> None:
    """Remove only the still-identical empty directory created by this call."""

    current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    expected = (
        created.st_dev,
        created.st_ino,
        created.st_uid,
        created.st_mode,
        created.st_mtime_ns,
        created.st_ctime_ns,
    )
    observed = (
        current.st_dev,
        current.st_ino,
        current.st_uid,
        current.st_mode,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if (
        observed != expected
        or current.st_uid != owner_uid
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        return
    # rmdir is the final emptiness check.  It cannot remove a non-empty or
    # non-directory replacement and remains relative to the identity-pinned parent.
    os.rmdir(name, dir_fd=root_fd)


def _inspect_bounded_fd(
    descriptor: int,
    *,
    maximum: int,
    magic: bytes,
    label: str,
) -> tuple[str, int]:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise _java_error(f"Java JFR {label} identity or size is unsafe")
    os.lseek(descriptor, 0, os.SEEK_SET)
    prefix = os.read(descriptor, max(len(magic), 64))
    if not prefix.startswith(magic):
        raise _java_error(f"Java JFR {label} format is invalid")
    return _hash_fd(descriptor, before), before.st_size


def _inspect_recording_fd(descriptor: int) -> tuple[str, int]:
    return _inspect_bounded_fd(
        descriptor,
        maximum=_MAX_JFR_BYTES,
        magic=b"FLR\x00",
        label="recording",
    )


def _inspect_json_fd(descriptor: int) -> tuple[str, int]:
    before = os.fstat(descriptor)
    if before.st_size > _MAX_JSON_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "java_jfr_launcher",
            "Java JFR JSON exceeds 64 MiB",
            recoverable=True,
        )
    os.lseek(descriptor, 0, os.SEEK_SET)
    prefix = os.read(descriptor, 64).lstrip()
    if not prefix.startswith(b"{"):
        raise _java_error("Java JFR JSON format is invalid")
    return _inspect_bounded_fd(
        descriptor,
        maximum=_MAX_JSON_BYTES,
        magic=os.pread(descriptor, 1, 0),
        label="JSON",
    )


def _bounded_failure_outputs(recording_fd: int, json_fd: int) -> bool:
    try:
        recording = os.fstat(recording_fd)
        rendered = os.fstat(json_fd)
    except OSError:
        return False
    return (
        stat.S_ISREG(recording.st_mode)
        and stat.S_ISREG(rendered.st_mode)
        and recording.st_size <= _MAX_JFR_BYTES
        and rendered.st_size <= _MAX_JSON_BYTES
    )


def _result_directory_identity(result: JavaJfrPrivateEvidence, uid: int) -> _DirectoryIdentity:
    identity = _inspect_directory(result.private_directory_path, uid, 0o700, "result directory")
    if (identity.device, identity.inode) != (
        result.private_directory_device,
        result.private_directory_inode,
    ):
        raise _java_error("Java JFR result directory identity changed")
    return identity


def _open_result_file(
    directory: _DirectoryIdentity,
    path: Path,
    *,
    uid: int,
    device: int,
    inode: int,
    size: int,
    sha256: str,
) -> int:
    if path.parent != directory.path or path.name in {"", ".", ".."}:
        raise _java_error("Java JFR result path escapes its private directory")
    directory_fd = _open_directory_fd(directory)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_dev != device
            or metadata.st_ino != inode
            or metadata.st_size != size
            or _hash_fd(descriptor, metadata) != sha256
        ):
            raise _java_error("Java JFR result file identity or digest changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        result_fd = descriptor
        descriptor = -1
        return result_fd
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _remove_private_directory(
    directory: _DirectoryIdentity,
    names: tuple[str, ...],
    owner_uid: int,
) -> None:
    directory_fd = _open_directory_fd(directory)
    try:
        for name in names:
            descriptor = -1
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != owner_uid
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise _java_error("Java JFR private evidence identity changed before cleanup")
            except FileNotFoundError:
                continue
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            os.unlink(name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    parent = _inspect_directory(directory.path.parent, owner_uid, 0o700, "output root")
    parent_fd = _open_directory_fd(parent)
    try:
        metadata = os.stat(directory.path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            metadata.st_dev != directory.device
            or metadata.st_ino != directory.inode
            or metadata.st_uid != owner_uid
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _java_error("Java JFR private directory changed before cleanup")
        os.rmdir(directory.path.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
