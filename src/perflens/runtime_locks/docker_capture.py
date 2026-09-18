"""Safely capture fixed Runtime Lock outputs from one managed Docker scratch root.

This module deliberately stops at an unbound host-shaped Evidence Artifact.  The
caller must separately bind it to a verified ``ContainerTargetArtifact`` and
``ContainerRunArtifact`` before publishing it.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryFile
from typing import BinaryIO, Protocol, cast

from perflens.contracts.docker_build import (
    docker_runtime_lock_version_constraints,
    docker_runtime_lock_version_is_allowed,
)
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    derive_runtime_lock_adapter_execution_identity,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockEvidenceArtifact,
    RuntimeLockResourceLimits,
)
from perflens.docker.adapter import (
    CpythonDockerLaunch,
    GoPprofDockerLaunch,
    JavaJfrDockerLaunch,
    NativePthreadDockerLaunch,
    RuntimeLockDockerLaunch,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.cpython_converter import (
    convert_cpython_threading_stream,
    verify_cpython_threading_replay,
)
from perflens.runtime_locks.go_pprof_converter import (
    GoProfileKind,
    convert_go_pprof_raw,
    verify_go_pprof_replay,
)
from perflens.runtime_locks.go_pprof_launcher import (
    GoPprofRawResult,
    cleanup_go_pprof_raw_result,
    open_go_pprof_raw,
)
from perflens.runtime_locks.java_jfr_converter import (
    convert_java_jfr_json,
    verify_java_jfr_replay,
)
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrFileIdentity,
    JavaJfrJsonRunner,
)
from perflens.runtime_locks.native_pthread_converter import (
    convert_native_pthread_probe,
    replay_native_pthread_probe,
)

_NATIVE_OUTPUT = "runtime-lock-native.ndjson"
_CPYTHON_OUTPUT = "runtime-lock-cpython.ndjson"
_JAVA_OUTPUT = "runtime-lock.jfr"
_GO_OUTPUTS: dict[GoProfileKind, str] = {
    "mutex": "runtime-lock-mutex.pprof",
    "block": "runtime-lock-block.pprof",
}
_MAX_PRIVATE_SOURCE_BYTES = 64 << 20
_MAX_HEADER_BYTES = 65_536


class GoDockerPprofRenderer(Protocol):
    """The narrow existing ``GoPprofLauncher`` surface needed by Docker capture."""

    def render_pinned_raw(
        self,
        profile_fd: int,
        profile_kind: GoProfileKind,
    ) -> GoPprofRawResult: ...


@dataclass(frozen=True, slots=True)
class JavaDockerJfrAuthority:
    """Private path-bearing authority for one exact, already authorized JDK."""

    runner: JavaJfrJsonRunner
    jfr_tool: JavaJfrFileIdentity
    jdk_major: int


@dataclass(frozen=True, slots=True)
class GoDockerPprofAuthority:
    """Private fixed-tool authority for one selected Go profile."""

    renderer: GoDockerPprofRenderer
    profile_kind: GoProfileKind
    mutex_profile_fraction: int | None
    block_profile_rate_ns: int | None


@dataclass(frozen=True, slots=True)
class DockerRuntimeLockCapture:
    """A complete private conversion result ready for Docker identity binding."""

    evidence: RuntimeLockEvidenceArtifact
    execution_binding: RuntimeLockAdapterExecutionBinding
    runtime_characteristics: str
    replay_verified: bool
    adapter_id: str
    profile_kind: GoProfileKind | None
    private_source_sha256: str
    private_source_bytes: int
    converted_source_sha256: str
    converted_source_bytes: int
    normalized_source_sha256: str
    normalized_source_bytes: int
    converter_accounted_active_seconds: int


@dataclass(frozen=True, slots=True)
class _OpenedPrivateSource:
    descriptor: int
    root_descriptor: int
    name: str
    sha256: str
    size: int
    identity: tuple[int, int, int, int, int, int, int]


def capture_docker_runtime_lock_evidence(
    scratch_directory: Path,
    *,
    launch: RuntimeLockDockerLaunch,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    created_at: str,
    limits: RuntimeLockResourceLimits,
    scratch_owner_uid: int | None = None,
    source_owner_uid: int | None = None,
    go_profile_kind: GoProfileKind | None = None,
    java_authority: JavaDockerJfrAuthority | None = None,
    go_authority: GoDockerPprofAuthority | None = None,
) -> DockerRuntimeLockCapture:
    """Capture and deterministically replay one fixed private Docker output.

    Paths are selected solely from the typed launch.  The scratch directory and
    source file remain descriptor-pinned throughout conversion and replay.
    Java and Go require explicit private conversion authority because their
    binary inputs cannot be interpreted safely without an exact reviewed tool.
    """

    _validate_target(target_pid, target_uid, target_start_time_ticks)
    _validate_launch_binding(launch, execution_binding, go_profile_kind)
    source_name = _source_name(launch, go_profile_kind)
    source = _open_private_source(
        scratch_directory,
        source_name,
        root_owner_uid=(target_uid if scratch_owner_uid is None else scratch_owner_uid),
        source_owner_uid=(target_uid if source_owner_uid is None else source_owner_uid),
        maximum_bytes=min(limits.max_source_bytes, _MAX_PRIVATE_SOURCE_BYTES),
    )
    try:
        if isinstance(launch, NativePthreadDockerLaunch):
            header = _validate_private_header(
                source.descriptor,
                record_type="probe_header",
                semantics=launch.semantics,
                threshold_ns=launch.duration_threshold_ns,
                max_events=launch.max_events,
            )
            with _stream(source.descriptor) as stream:
                receipt = convert_native_pthread_probe(
                    stream,
                    limits=limits,
                    created_at=created_at,
                )
            runtime_characteristics = "native-pthread"
            actual_binding = bind_observed_runtime_execution(
                execution_binding,
                runtime_version=_header_text(header, "runtime_version"),
                runtime_characteristics=runtime_characteristics,
            )
            _validate_evidence_target(
                receipt.evidence, target_pid, target_uid, target_start_time_ticks
            )
            with _stream(source.descriptor) as stream:
                replay = replay_native_pthread_probe(receipt.evidence, stream)
            result = DockerRuntimeLockCapture(
                evidence=receipt.evidence,
                execution_binding=actual_binding,
                runtime_characteristics=runtime_characteristics,
                replay_verified=replay,
                adapter_id=execution_binding.adapter_id,
                profile_kind=None,
                private_source_sha256=source.sha256,
                private_source_bytes=source.size,
                converted_source_sha256=receipt.raw_source_sha256,
                converted_source_bytes=receipt.raw_source_bytes,
                normalized_source_sha256=receipt.normalized_source_sha256,
                normalized_source_bytes=receipt.normalized_source_bytes,
                converter_accounted_active_seconds=0,
            )
        elif isinstance(launch, CpythonDockerLaunch):
            header = _validate_private_header(
                source.descriptor,
                record_type="cpython_header",
                semantics=launch.semantics,
                threshold_ns=launch.duration_threshold_ns,
                max_events=launch.max_events,
            )
            runtime_characteristics = (
                "cpython-free-threaded" if header.get("free_threaded") is True else "cpython-gil"
            )
            actual_binding = bind_observed_runtime_execution(
                execution_binding,
                runtime_version=_header_text(header, "runtime_version"),
                runtime_characteristics=runtime_characteristics,
            )
            with _stream(source.descriptor) as stream:
                receipt = convert_cpython_threading_stream(
                    stream,
                    execution_binding=actual_binding,
                    limits=limits,
                    created_at=created_at,
                )
            _validate_evidence_target(
                receipt.evidence, target_pid, target_uid, target_start_time_ticks
            )
            with _stream(source.descriptor) as stream:
                replay = verify_cpython_threading_replay(
                    receipt,
                    stream,
                    execution_binding=actual_binding,
                )
            result = DockerRuntimeLockCapture(
                evidence=receipt.evidence,
                execution_binding=actual_binding,
                runtime_characteristics=runtime_characteristics,
                replay_verified=replay is not None,
                adapter_id=execution_binding.adapter_id,
                profile_kind=None,
                private_source_sha256=source.sha256,
                private_source_bytes=source.size,
                converted_source_sha256=receipt.raw_source_sha256,
                converted_source_bytes=receipt.raw_source_bytes,
                normalized_source_sha256=receipt.normalized_source_sha256,
                normalized_source_bytes=receipt.normalized_source_bytes,
                converter_accounted_active_seconds=0,
            )
        elif isinstance(launch, JavaJfrDockerLaunch):
            result = _capture_java(
                source,
                launch=launch,
                binding=execution_binding,
                authority=java_authority,
                target_pid=target_pid,
                target_uid=target_uid,
                target_start_time_ticks=target_start_time_ticks,
                created_at=created_at,
            )
        else:
            assert isinstance(launch, GoPprofDockerLaunch)
            result = _capture_go(
                source,
                binding=execution_binding,
                authority=go_authority,
                requested_profile_kind=go_profile_kind,
                target_pid=target_pid,
                target_uid=target_uid,
                target_start_time_ticks=target_start_time_ticks,
                limits=limits,
                created_at=created_at,
            )
        _assert_unchanged(source)
        if not result.replay_verified:
            raise _parse_error("Runtime Lock Docker conversion replay did not match")
        return result
    finally:
        os.close(source.descriptor)
        os.close(source.root_descriptor)


def _capture_java(
    source: _OpenedPrivateSource,
    *,
    launch: JavaJfrDockerLaunch,
    binding: RuntimeLockAdapterExecutionBinding,
    authority: JavaDockerJfrAuthority | None,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    created_at: str,
) -> DockerRuntimeLockCapture:
    if authority is None:
        raise _authority_error("Java Docker JFR conversion authority is unavailable")
    tools = {tool.name: tool for tool in binding.tools}
    try:
        major = int(binding.runtime_version.split(".", 1)[0])
    except ValueError:
        raise _authority_error("Java Runtime Lock binding version is malformed") from None
    if (
        authority.jdk_major != major
        or authority.jfr_tool.sha256 != tools["jfr"].binary_sha256
        or authority.jfr_tool.path.name != "jfr"
        or launch.profile != binding.profile
    ):
        raise _authority_error("Java Docker JFR authority differs from the authorized binding")
    with TemporaryFile(mode="w+b") as output:
        rendered = authority.runner.render_json(
            recording_directory_fd=source.root_descriptor,
            recording_name=source.name,
            recording_fd=source.descriptor,
            output_fd=output.fileno(),
            jfr_tool=authority.jfr_tool,
            jdk_major=authority.jdk_major,
            max_output_bytes=_MAX_PRIVATE_SOURCE_BYTES,
        )
        if (
            rendered.jfr_tool_sha256 != authority.jfr_tool.sha256
            or rendered.jdk_major != authority.jdk_major
        ):
            raise _authority_error("Java JFR renderer returned a different tool identity")
        output.seek(0)
        receipt = convert_java_jfr_json(
            output,
            execution_binding=binding,
            target_pid=target_pid,
            target_uid=target_uid,
            target_start_time_ticks=target_start_time_ticks,
            created_at=created_at,
            require_jvm_information=True,
        )
        assert receipt.evidence.source.runtime_version is not None
        runtime_characteristics = "jfr-jvm-information"
        actual_binding = bind_observed_runtime_execution(
            binding,
            runtime_version=receipt.evidence.source.runtime_version,
            runtime_characteristics=runtime_characteristics,
        )
        output.seek(0)
        replay = verify_java_jfr_replay(
            output,
            expected=receipt,
            execution_binding=binding,
            target_pid=target_pid,
            target_uid=target_uid,
            target_start_time_ticks=target_start_time_ticks,
            created_at=created_at,
            require_jvm_information=True,
        )
    return DockerRuntimeLockCapture(
        evidence=receipt.evidence,
        execution_binding=actual_binding,
        runtime_characteristics=runtime_characteristics,
        replay_verified=replay is not None,
        adapter_id=binding.adapter_id,
        profile_kind=None,
        private_source_sha256=source.sha256,
        private_source_bytes=source.size,
        converted_source_sha256=receipt.raw_source_sha256,
        converted_source_bytes=receipt.raw_source_bytes,
        normalized_source_sha256=receipt.normalized_source_sha256,
        normalized_source_bytes=receipt.normalized_source_bytes,
        converter_accounted_active_seconds=rendered.accounted_active_seconds,
    )


def _capture_go(
    source: _OpenedPrivateSource,
    *,
    binding: RuntimeLockAdapterExecutionBinding,
    authority: GoDockerPprofAuthority | None,
    requested_profile_kind: GoProfileKind | None,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    limits: RuntimeLockResourceLimits,
    created_at: str,
) -> DockerRuntimeLockCapture:
    if authority is None:
        raise _authority_error("Go Docker pprof conversion authority is unavailable")
    if requested_profile_kind is None or authority.profile_kind != requested_profile_kind:
        raise _authority_error("Go Docker pprof authority differs from the selected profile")
    raw: GoPprofRawResult | None = None
    raw_fd = -1
    try:
        raw = authority.renderer.render_pinned_raw(source.descriptor, authority.profile_kind)
        if raw.profile_kind != authority.profile_kind:
            raise _authority_error("Go pprof renderer returned a different profile kind")
        raw_fd = open_go_pprof_raw(raw)
        with _stream(raw_fd) as stream:
            receipt = convert_go_pprof_raw(
                stream,
                execution_binding=binding,
                profile_kind=authority.profile_kind,
                target_pid=target_pid,
                target_uid=target_uid,
                target_start_time_ticks=target_start_time_ticks,
                mutex_profile_fraction=authority.mutex_profile_fraction,
                block_profile_rate_ns=authority.block_profile_rate_ns,
                limits=limits,
                created_at=created_at,
            )
        with _stream(raw_fd) as stream:
            replay = verify_go_pprof_replay(
                stream,
                expected=receipt,
                execution_binding=binding,
                target_pid=target_pid,
                target_uid=target_uid,
                target_start_time_ticks=target_start_time_ticks,
                mutex_profile_fraction=authority.mutex_profile_fraction,
                block_profile_rate_ns=authority.block_profile_rate_ns,
            )
        return DockerRuntimeLockCapture(
            evidence=receipt.evidence,
            execution_binding=binding,
            runtime_characteristics="go-version-metadata",
            replay_verified=replay is not None,
            adapter_id=binding.adapter_id,
            profile_kind=authority.profile_kind,
            private_source_sha256=source.sha256,
            private_source_bytes=source.size,
            converted_source_sha256=receipt.raw_source_sha256,
            converted_source_bytes=receipt.raw_source_bytes,
            normalized_source_sha256=receipt.normalized_source_sha256,
            normalized_source_bytes=receipt.normalized_source_bytes,
            converter_accounted_active_seconds=raw.accounted_active_seconds,
        )
    finally:
        if raw_fd >= 0:
            os.close(raw_fd)
        if raw is not None:
            cleanup_go_pprof_raw_result(raw)


def _source_name(
    launch: RuntimeLockDockerLaunch,
    profile_kind: GoProfileKind | None,
) -> str:
    if isinstance(launch, NativePthreadDockerLaunch):
        if profile_kind is not None:
            raise _authority_error("Native Docker capture cannot select a Go profile")
        return _NATIVE_OUTPUT
    if isinstance(launch, CpythonDockerLaunch):
        if profile_kind is not None:
            raise _authority_error("CPython Docker capture cannot select a Go profile")
        return _CPYTHON_OUTPUT
    if isinstance(launch, JavaJfrDockerLaunch):
        if profile_kind is not None:
            raise _authority_error("Java Docker capture cannot select a Go profile")
        return _JAVA_OUTPUT
    if profile_kind is None or profile_kind not in launch.profile_kinds:
        raise _authority_error("Go Docker capture requires one authorized profile kind")
    return _GO_OUTPUTS[profile_kind]


def _validate_launch_binding(
    launch: RuntimeLockDockerLaunch,
    binding: RuntimeLockAdapterExecutionBinding,
    profile_kind: GoProfileKind | None,
) -> None:
    expected_adapter = {
        NativePthreadDockerLaunch: "native_pthread",
        CpythonDockerLaunch: "cpython_threading",
        JavaJfrDockerLaunch: "java_jfr",
        GoPprofDockerLaunch: "go_pprof",
    }[type(launch)]
    if binding.adapter_id != expected_adapter:
        raise _authority_error("Docker Runtime Lock launch and execution binding differ")
    if isinstance(launch, (NativePthreadDockerLaunch, CpythonDockerLaunch)):
        payload_sha256 = (
            launch.probe_sha256
            if isinstance(launch, NativePthreadDockerLaunch)
            else launch.bootstrap_sha256
        )
        if (
            binding.profile != launch.semantics
            or binding.measurement_semantics != launch.semantics
            or binding.duration_threshold_ns != launch.duration_threshold_ns
            or binding.configuration_sha256 != payload_sha256
            or binding.runtime_payload_identity_sha256 != payload_sha256
        ):
            raise _authority_error("Docker Runtime Lock controls differ from their binding")
    elif isinstance(launch, JavaJfrDockerLaunch):
        if (
            binding.profile != launch.profile
            or binding.configuration_sha256 != launch.configuration_sha256
            or binding.runtime_payload_identity_sha256 is None
        ):
            raise _authority_error("Docker JFR controls differ from their binding")
    else:
        if (
            profile_kind is None
            or profile_kind not in launch.profile_kinds
            or binding.profile != "mutex_and_block"
            or binding.measurement_semantics != "cumulative"
        ):
            raise _authority_error("Docker Go pprof controls differ from their binding")


def _open_private_source(
    root: Path,
    name: str,
    *,
    root_owner_uid: int,
    source_owner_uid: int,
    maximum_bytes: int,
) -> _OpenedPrivateSource:
    if not root.is_absolute() or root.is_symlink():
        raise _path_error("Runtime Lock Docker scratch directory path is unsafe")
    root_fd = file_fd = -1
    try:
        before_root = root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(before_root.st_mode)
            or before_root.st_uid != root_owner_uid
            or stat.S_IMODE(before_root.st_mode) != 0o733
            or root.resolve(strict=True) != root
        ):
            raise _path_error("Runtime Lock Docker scratch directory identity is unsafe")
        root_fd = os.open(
            root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        if _stat_identity(os.fstat(root_fd)) != _stat_identity(before_root):
            raise _path_error("Runtime Lock Docker scratch directory changed during open")
        file_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root_fd)
        metadata = os.fstat(file_fd)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != source_owner_uid
            or metadata.st_nlink != 1
            or mode != 0o644
            or mode & 0o6000
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise _path_error("Runtime Lock Docker private source identity is unsafe")
        digest = _hash_fd(file_fd, metadata.st_size)
        return _OpenedPrivateSource(
            descriptor=file_fd,
            root_descriptor=root_fd,
            name=name,
            sha256=digest,
            size=metadata.st_size,
            identity=_stat_identity(metadata),
        )
    except OSError as exc:
        if file_fd >= 0:
            os.close(file_fd)
        if root_fd >= 0:
            os.close(root_fd)
        raise _path_error("Runtime Lock Docker private source cannot be opened safely") from exc
    except Exception:
        if file_fd >= 0:
            os.close(file_fd)
        if root_fd >= 0:
            os.close(root_fd)
        raise


def _assert_unchanged(source: _OpenedPrivateSource) -> None:
    metadata = os.fstat(source.descriptor)
    if (
        _stat_identity(metadata) != source.identity
        or _hash_fd(source.descriptor, source.size) != source.sha256
    ):
        raise _path_error("Runtime Lock Docker private source changed during conversion")


def _hash_fd(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(descriptor, min(64 << 10, expected_size - offset), offset)
        if not chunk:
            raise _path_error("Runtime Lock Docker private source was truncated")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, expected_size):
        raise _path_error("Runtime Lock Docker private source grew during inspection")
    return digest.hexdigest()


def _stream(descriptor: int) -> BinaryIO:
    os.lseek(descriptor, 0, os.SEEK_SET)
    return os.fdopen(os.dup(descriptor), "rb", closefd=True)


def _validate_private_header(
    descriptor: int,
    *,
    record_type: str,
    semantics: str,
    threshold_ns: int | None,
    max_events: int,
) -> dict[str, object]:
    raw = os.pread(descriptor, _MAX_HEADER_BYTES + 2, 0)
    line, separator, _remaining = raw.partition(b"\n")
    if not separator or len(line) > _MAX_HEADER_BYTES:
        raise _parse_error("Runtime Lock Docker private header is incomplete or oversized")
    try:
        parsed = cast(object, json.loads(line))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _parse_error("Runtime Lock Docker private header is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise _parse_error("Runtime Lock Docker private header must be a JSON object")
    header = cast(dict[str, object], parsed)
    if (
        header.get("record_type") != record_type
        or header.get("semantics") != semantics
        or header.get("duration_threshold_ns") != threshold_ns
        or header.get("max_events") != max_events
    ):
        raise _authority_error("Runtime Lock private header differs from authorized controls")
    return header


def _header_text(header: dict[str, object], field: str) -> str:
    value = header.get(field)
    if not isinstance(value, str) or not value or len(value) > 128:
        raise _authority_error("Runtime Lock private header runtime identity is invalid")
    return value


def bind_observed_runtime_execution(
    authorized: RuntimeLockAdapterExecutionBinding,
    *,
    runtime_version: str,
    runtime_characteristics: str,
) -> RuntimeLockAdapterExecutionBinding:
    """Derive a path-free execution identity from target-emitted runtime facts."""

    try:
        constraint = docker_runtime_lock_version_constraints((authorized,))[0]
    except ValueError:
        # Import-only bindings can still be replayed by standalone deterministic
        # comparison tests, but cannot enter a Docker authorization scope.  Keep
        # their runtime identity literal rather than inventing a version matrix.
        allowed = runtime_version == authorized.runtime_version
    else:
        allowed = docker_runtime_lock_version_is_allowed(constraint, runtime_version)
    if not allowed:
        raise _authority_error("Container runtime version is outside the authorized matrix")
    metadata_sha256 = hashlib.sha256(
        (
            "perflens-docker-runtime-lock-execution-v1\0"
            f"{authorized.metadata_sha256}\0{runtime_version}\0{runtime_characteristics}"
        ).encode()
    ).hexdigest()
    identity = derive_runtime_lock_adapter_execution_identity(
        authorized.adapter_id,
        authorized.adapter_version,
        authorized.backend_id,
        runtime_version,
        authorized.profile,
        authorized.measurement_semantics,
        authorized.duration_threshold_ns,
        authorized.toolchain_identity_sha256,
        authorized.configuration_sha256,
        metadata_sha256,
        authorized.runtime_payload_identity_sha256,
    )
    return authorized.model_copy(
        update={
            "runtime_version": runtime_version,
            "metadata_sha256": metadata_sha256,
            "execution_identity_sha256": identity,
        }
    )


def _validate_evidence_target(
    evidence: RuntimeLockEvidenceArtifact,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
) -> None:
    if (
        evidence.schema_version != "1.1"
        or evidence.target.target_kind != "host"
        or evidence.target.target_pid != target_pid
        or evidence.target.target_uid != target_uid
        or evidence.target.target_start_time_ticks != target_start_time_ticks
    ):
        raise _authority_error("Runtime Lock private source differs from verified target identity")


def _validate_target(pid: int, uid: int, start_ticks: int) -> None:
    if (
        isinstance(pid, bool)
        or isinstance(uid, bool)
        or isinstance(start_ticks, bool)
        or pid <= 0
        or uid < 0
        or start_ticks <= 0
    ):
        raise _authority_error("Runtime Lock Docker target identity is invalid")


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_ctime_ns,
    )


def _path_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_docker_capture",
        message,
        recoverable=False,
    )


def _authority_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "runtime_lock_docker_capture",
        message,
        recoverable=False,
    )


def _parse_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "runtime_lock_docker_capture",
        message,
        recoverable=False,
    )
