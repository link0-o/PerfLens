from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Literal

import pytest

from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
)
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeLockResourceLimits
from perflens.docker.adapter import (
    CpythonDockerLaunch,
    GoPprofDockerLaunch,
    JavaJfrDockerLaunch,
    NativePthreadDockerLaunch,
    RuntimeLockDockerLaunch,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.docker_capture import (
    DockerRuntimeLockCapture,
    GoDockerPprofAuthority,
    JavaDockerJfrAuthority,
    bind_observed_runtime_execution,
    capture_docker_runtime_lock_evidence,
)
from perflens.runtime_locks.go_pprof_converter import GoProfileKind
from perflens.runtime_locks.go_pprof_launcher import GoPprofRawResult
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrFileIdentity,
    JavaJfrJsonRunnerReceipt,
)

CREATED_AT = "2026-08-31T00:00:00+00:00"
ZERO = "0" * 64


def _binding(
    adapter: Literal["native_pthread", "cpython_threading", "java_jfr", "go_pprof"],
    configuration_sha256: str,
) -> RuntimeLockAdapterExecutionBinding:
    if adapter == "native_pthread":
        tools: tuple[RuntimeLockAdapterToolBinding, ...] = ()
        values = (
            "native-pthread-adapter-v1",
            "ld-preload",
            "glibc-2.36-or-2.41",
            "exact",
            "exact",
            None,
            configuration_sha256,
        )
    elif adapter == "cpython_threading":
        tools = (
            RuntimeLockAdapterToolBinding(name="python", version="3.13.7", binary_sha256="1" * 64),
        )
        values = (
            "cpython-threading-adapter-v1",
            "threading-bootstrap",
            "3.13.7",
            "exact",
            "exact",
            None,
            configuration_sha256,
        )
    elif adapter == "java_jfr":
        tools = (
            RuntimeLockAdapterToolBinding(name="java", version="25.0.4.1", binary_sha256="3" * 64),
            RuntimeLockAdapterToolBinding(name="jfr", version="25.0.4.1", binary_sha256="4" * 64),
        )
        values = (
            "java-jfr-adapter-v1",
            "jfr",
            "25.0.4.1",
            "balanced",
            "thresholded",
            10_000_000,
            configuration_sha256,
        )
    else:
        tools = (
            RuntimeLockAdapterToolBinding(name="go", version="1.24.4", binary_sha256="5" * 64),
            RuntimeLockAdapterToolBinding(name="pprof", version="1.24.4", binary_sha256="6" * 64),
        )
        values = (
            "go-pprof-adapter-v1",
            "pprof",
            "1.24.4",
            "mutex_and_block",
            "cumulative",
            None,
            configuration_sha256,
        )
    adapter_version, backend, runtime, profile, semantics, threshold, configuration = values
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    payload = configuration if adapter != "go_pprof" else None
    identity = derive_runtime_lock_adapter_execution_identity(
        adapter,
        adapter_version,
        backend,
        runtime,
        profile,
        semantics,
        threshold,
        toolchain,
        configuration,
        "2" * 64,
        payload,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id=adapter,
        adapter_version=adapter_version,
        backend_id=backend,
        runtime_version=runtime,
        profile=profile,
        measurement_semantics=semantics,
        duration_threshold_ns=threshold,
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256=configuration,
        metadata_sha256="2" * 64,
        runtime_payload_identity_sha256=payload,
        execution_identity_sha256=identity,
    )


def _scratch(tmp_path: Path) -> Path:
    run_root = tmp_path / "run"
    run_root.mkdir(mode=0o700)
    root = run_root / "scratch"
    root.mkdir(mode=0o733)
    root.chmod(0o733)
    return root


def _write_private(root: Path, name: str, payload: bytes) -> Path:
    path = root / name
    path.write_bytes(payload)
    path.chmod(0o644)
    return path


def _capture(
    root: Path,
    launch: RuntimeLockDockerLaunch,
    binding: RuntimeLockAdapterExecutionBinding,
    *,
    target_pid: int = 4242,
    target_start_time_ticks: int = 77,
    go_profile_kind: GoProfileKind | None = None,
    java_authority: JavaDockerJfrAuthority | None = None,
    go_authority: GoDockerPprofAuthority | None = None,
) -> DockerRuntimeLockCapture:
    return capture_docker_runtime_lock_evidence(
        root,
        launch=launch,
        execution_binding=binding,
        target_pid=target_pid,
        target_uid=os.geteuid(),
        target_start_time_ticks=target_start_time_ticks,
        created_at=CREATED_AT,
        limits=RuntimeLockResourceLimits(max_input_records=20_000),
        go_profile_kind=go_profile_kind,
        java_authority=java_authority,
        go_authority=go_authority,
    )


def test_native_capture_is_replayed_and_keeps_container_binding_private(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    raw = (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes()
    records = [json.loads(line) for line in raw.splitlines()]
    records[0]["uid"] = os.geteuid()
    raw = b"".join(json.dumps(record, separators=(",", ":")).encode() + b"\n" for record in records)
    _write_private(root, "runtime-lock-native.ndjson", raw)
    payload_sha = "a" * 64
    launch = NativePthreadDockerLaunch(Path("/unused/probe"), payload_sha, "exact", None, 20)

    captured = _capture(root, launch, _binding("native_pthread", payload_sha))

    assert captured.replay_verified is True
    assert captured.private_source_sha256 == hashlib.sha256(raw).hexdigest()
    assert captured.private_source_bytes == len(raw)
    assert captured.evidence.schema_version == "1.1"
    assert captured.evidence.target.target_kind == "host"
    assert captured.evidence.target.container_reference is None
    assert captured.execution_binding.runtime_version == "glibc-2.41"
    assert captured.execution_binding.execution_identity_sha256 != (
        _binding("native_pthread", payload_sha).execution_identity_sha256
    )
    assert stat.S_IMODE(root.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(root.stat().st_mode) == 0o733
    assert stat.S_IMODE((root / "runtime-lock-native.ndjson").stat().st_mode) == 0o644


def test_cpython_capture_rejects_header_controls_outside_launch(tmp_path: Path) -> None:
    root = _scratch(tmp_path)
    raw = _cpython_empty_stream(os.geteuid(), max_events=19_999)
    _write_private(root, "runtime-lock-cpython.ndjson", raw)
    payload_sha = "b" * 64
    launch = CpythonDockerLaunch(Path("/unused/bootstrap"), payload_sha, "exact", None, 20_000)

    with pytest.raises(PerfLensError, match="authorized controls") as raised:
        _capture(
            root,
            launch,
            _binding("cpython_threading", payload_sha),
            target_pid=9000,
        )
    assert raised.value.code == ErrorCode.INVALID_INPUT


def test_cpython_capture_binds_the_target_emitted_runtime_and_threading_mode(
    tmp_path: Path,
) -> None:
    root = _scratch(tmp_path)
    raw = _cpython_empty_stream(os.geteuid(), max_events=20_000)
    _write_private(root, "runtime-lock-cpython.ndjson", raw)
    payload_sha = "b" * 64
    launch = CpythonDockerLaunch(Path("/unused/bootstrap"), payload_sha, "exact", None, 20_000)
    authorized = _binding("cpython_threading", payload_sha)

    captured = _capture(
        root,
        launch,
        authorized,
        target_pid=9000,
    )

    assert captured.execution_binding.runtime_version == "3.13.7"
    assert captured.evidence.source.runtime_version == "3.13.7"
    assert captured.execution_binding.metadata_sha256 != authorized.metadata_sha256


def test_private_source_symlink_non_exportable_and_writable_modes_are_rejected(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    raw = (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes()
    foreign = tmp_path / "foreign"
    foreign.write_bytes(raw)
    foreign.chmod(0o600)
    (root / "runtime-lock-native.ndjson").symlink_to(foreign)
    payload_sha = "a" * 64
    launch = NativePthreadDockerLaunch(Path("/unused/probe"), payload_sha, "exact", None, 20)

    with pytest.raises(PerfLensError) as raised:
        _capture(root, launch, _binding("native_pthread", payload_sha))
    assert raised.value.code == ErrorCode.PATH_SAFETY_VIOLATION

    (root / "runtime-lock-native.ndjson").unlink()
    path = _write_private(root, "runtime-lock-native.ndjson", raw)
    path.chmod(0o600)
    with pytest.raises(PerfLensError) as raised:
        _capture(root, launch, _binding("native_pthread", payload_sha))
    assert raised.value.code == ErrorCode.PATH_SAFETY_VIOLATION

    path.chmod(0o622)
    with pytest.raises(PerfLensError) as raised:
        _capture(root, launch, _binding("native_pthread", payload_sha))
    assert raised.value.code == ErrorCode.PATH_SAFETY_VIOLATION


def test_java_and_go_fail_closed_without_exact_conversion_authority(tmp_path: Path) -> None:
    root = _scratch(tmp_path)
    java_sha = "c" * 64
    _write_private(root, "runtime-lock.jfr", b"private-jfr")
    java = JavaJfrDockerLaunch(Path("/unused/runtime-lock.jfc"), java_sha, "balanced")
    with pytest.raises(PerfLensError, match="authority is unavailable"):
        _capture(root, java, _binding("java_jfr", java_sha), target_pid=9000)

    _write_private(root, "runtime-lock-mutex.pprof", b"private-pprof")
    go = GoPprofDockerLaunch(("mutex",))
    with pytest.raises(PerfLensError, match="authority is unavailable"):
        _capture(
            root,
            go,
            _binding("go_pprof", "d" * 64),
            target_pid=100,
            target_start_time_ticks=900,
            go_profile_kind="mutex",
        )


def test_java_capture_uses_bound_runner_and_replays(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock.jfr", b"private-jfr-recording")
    configuration = "c" * 64
    binding = _binding("java_jfr", configuration)
    fixture_payload = json.loads((fixture_root / "runtime_locks/jfr/jdk25-locks.json").read_bytes())
    fixture_payload["recording"]["events"].insert(
        0,
        {
            "type": "jdk.JVMInformation",
            "values": {
                "startTime": "2026-08-30T18:40:18.700000000+08:00",
                "jvmName": "OpenJDK 64-Bit Server VM",
                "jvmVersion": (
                    "OpenJDK 64-Bit Server VM (25.0.1+1) for linux-amd64 "
                    "JRE (25.0.1+1), built with gcc"
                ),
                "jvmArguments": None,
                "jvmFlags": None,
                "javaArguments": None,
                "jvmStartTime": "2026-08-30T18:40:18.600+08:00",
                "pid": 9000,
            },
        },
    )
    fixture = json.dumps(fixture_payload, separators=(",", ":")).encode()
    runner = _FakeJavaRunner(fixture, "4" * 64)
    tool = JavaJfrFileIdentity(
        path=Path("/fixed/jdk/bin/jfr"),
        sha256="4" * 64,
        device=1,
        inode=2,
        owner_uid=0,
        mode=0o755,
        size=1,
        modified_ns=1,
        changed_ns=1,
    )
    launch = JavaJfrDockerLaunch(Path("/unused/runtime-lock.jfc"), configuration, "balanced")

    captured = _capture(
        root,
        launch,
        binding,
        target_pid=9000,
        java_authority=JavaDockerJfrAuthority(runner, tool, 25),
    )

    assert captured.replay_verified is True
    assert captured.evidence.source.adapter_id == "java_jfr"
    assert captured.evidence.source.runtime_version == "25.0.1+1"
    assert captured.execution_binding.runtime_version == "25.0.1+1"
    assert captured.execution_binding.execution_identity_sha256 != (
        binding.execution_identity_sha256
    )
    assert captured.converted_source_sha256 == hashlib.sha256(fixture).hexdigest()
    assert captured.converter_accounted_active_seconds == 1
    replay_receipt = build_runtime_lock_source_replay_receipt(
        captured.evidence,
        origin_source_sha256=captured.private_source_sha256,
        origin_source_bytes=captured.private_source_bytes,
        normalized_source_sha256=captured.normalized_source_sha256,
        normalized_source_bytes=captured.normalized_source_bytes,
    )
    projected = replay_receipt.model_dump(mode="json")
    assert (
        replay_receipt.origin_source_sha256 == hashlib.sha256(b"private-jfr-recording").hexdigest()
    )
    assert replay_receipt.raw_source_sha256 == hashlib.sha256(fixture).hexdigest()
    assert not any("path" in key for key in projected)
    assert "private-jfr-recording" not in json.dumps(projected)


def test_java_capture_rejects_missing_or_foreign_target_jvm_identity(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock.jfr", b"private-jfr-recording")
    configuration = "c" * 64
    binding = _binding("java_jfr", configuration)
    payload = json.loads((fixture_root / "runtime_locks/jfr/jdk25-locks.json").read_bytes())
    runner = _FakeJavaRunner(
        json.dumps(payload, separators=(",", ":")).encode(),
        "4" * 64,
    )
    tool = JavaJfrFileIdentity(
        path=Path("/fixed/jdk/bin/jfr"),
        sha256="4" * 64,
        device=1,
        inode=2,
        owner_uid=0,
        mode=0o755,
        size=1,
        modified_ns=1,
        changed_ns=1,
    )
    launch = JavaJfrDockerLaunch(Path("/unused/runtime-lock.jfc"), configuration, "balanced")

    with pytest.raises(PerfLensError, match="lacks required JVMInformation"):
        _capture(
            root,
            launch,
            binding,
            target_pid=9000,
            java_authority=JavaDockerJfrAuthority(runner, tool, 25),
        )


@pytest.mark.parametrize(
    ("adapter", "runtime_version"),
    (
        ("native_pthread", "glibc-2.40"),
        ("cpython_threading", "3.11.9"),
        ("java_jfr", "21.0.8"),
        ("go_pprof", "1.25.0"),
    ),
)
def test_observed_container_runtime_must_match_the_authorized_matrix(
    adapter: Literal["native_pthread", "cpython_threading", "java_jfr", "go_pprof"],
    runtime_version: str,
) -> None:
    with pytest.raises(PerfLensError, match="outside the authorized matrix"):
        bind_observed_runtime_execution(
            _binding(adapter, "d" * 64),
            runtime_version=runtime_version,
            runtime_characteristics="test-runtime",
        )


def test_go_capture_uses_one_selected_profile_and_removes_private_raw(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock-mutex.pprof", b"private-protobuf")
    raw = (fixture_root / "runtime_locks/go/go1.24.4-mutex.raw").read_bytes()
    renderer = _FakeGoRenderer(tmp_path, raw)
    launch = GoPprofDockerLaunch(("mutex",))
    authority = GoDockerPprofAuthority(renderer, "mutex", 1, None)

    captured = _capture(
        root,
        launch,
        _binding("go_pprof", "d" * 64),
        target_pid=100,
        target_start_time_ticks=900,
        go_profile_kind="mutex",
        go_authority=authority,
    )

    assert captured.replay_verified is True
    assert captured.profile_kind == "mutex"
    assert captured.evidence.source.backend_id == "pprof-mutex"
    assert renderer.raw_path is not None and not renderer.raw_path.exists()


def test_go_capture_rejects_authority_for_a_different_profile(tmp_path: Path) -> None:
    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock-mutex.pprof", b"private-protobuf")
    renderer = _FakeGoRenderer(tmp_path, b"unused")
    launch = GoPprofDockerLaunch(("block", "mutex"))

    with pytest.raises(PerfLensError, match="differs from the selected profile"):
        _capture(
            root,
            launch,
            _binding("go_pprof", "d" * 64),
            target_pid=100,
            target_start_time_ticks=900,
            go_profile_kind="mutex",
            go_authority=GoDockerPprofAuthority(renderer, "block", None, 1),
        )


def _cpython_empty_stream(uid: int, *, max_events: int) -> bytes:
    records = (
        {
            "schema_version": "1.0",
            "record_type": "cpython_header",
            "protocol": "cpython_threading_probe",
            "protocol_version": "1.0",
            "runtime_version": "3.13.7",
            "free_threaded": False,
            "pid": 9000,
            "uid": uid,
            "target_start_time_ticks": 77,
            "semantics": "exact",
            "duration_threshold_ns": None,
            "max_events": max_events,
            "visible_lock_kinds": ["condition", "mutex", "recursive_mutex", "semaphore"],
        },
        {
            "schema_version": "1.0",
            "record_type": "cpython_footer",
            "protocol": "cpython_threading_probe",
            "pid": 9000,
            "sequence": 0,
            "declared_event_count": 0,
            "lost_event_count": 0,
            "truncated": False,
            "observed_target_tids": [9000],
        },
    )
    return b"".join(
        json.dumps(record, separators=(",", ":")).encode() + b"\n" for record in records
    )


class _FakeJavaRunner:
    def __init__(self, payload: bytes, tool_sha256: str) -> None:
        self._payload = payload
        self._tool_sha256 = tool_sha256

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
        assert recording_directory_fd >= 0
        assert recording_name == "runtime-lock.jfr"
        assert os.fstat(recording_fd).st_size > 0
        assert jfr_tool.sha256 == self._tool_sha256
        assert max_output_bytes == 64 << 20
        os.ftruncate(output_fd, 0)
        os.pwrite(output_fd, self._payload, 0)
        return JavaJfrJsonRunnerReceipt(
            self._tool_sha256,
            jdk_major,
            elapsed_monotonic_ns=1,
            accounted_active_seconds=1,
        )


class _FakeGoRenderer:
    def __init__(self, tmp_path: Path, payload: bytes) -> None:
        self._root = tmp_path / "go-private"
        self._root.mkdir(mode=0o700)
        self._payload = payload
        self.raw_path: Path | None = None

    def render_pinned_raw(self, profile_fd: int, profile_kind: GoProfileKind) -> GoPprofRawResult:
        assert os.fstat(profile_fd).st_size > 0
        path = self._root / f"profile.{profile_kind}.raw"
        path.write_bytes(self._payload)
        path.chmod(0o600)
        metadata = path.stat()
        self.raw_path = path
        return GoPprofRawResult(
            private_root=self._root,
            raw_path=path,
            raw_sha256=hashlib.sha256(self._payload).hexdigest(),
            raw_size=len(self._payload),
            raw_device=metadata.st_dev,
            raw_inode=metadata.st_ino,
            profile_kind="mutex",
            accounted_active_seconds=1,
        )
