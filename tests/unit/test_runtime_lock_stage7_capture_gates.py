from __future__ import annotations

# pyright: reportPrivateUsage=false
import json
import os
from pathlib import Path
from typing import BinaryIO, Literal

import pytest
from tests.unit.test_runtime_lock_docker_capture import (
    CREATED_AT,
    _binding,
    _capture,
    _FakeGoRenderer,
    _FakeJavaRunner,
    _scratch,
    _write_private,
)

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
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
from perflens.runtime_locks import docker_capture as capture_module
from perflens.runtime_locks.docker_capture import (
    GoDockerPprofAuthority,
    JavaDockerJfrAuthority,
    bind_observed_runtime_execution,
    capture_docker_runtime_lock_evidence,
)
from perflens.runtime_locks.go_pprof_converter import GoProfileKind
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrFileIdentity,
    JavaJfrJsonRunnerReceipt,
)


@pytest.mark.parametrize(
    ("pid", "uid", "start_ticks"),
    (
        (True, 1000, 1),
        (1, False, 1),
        (1, 1000, True),
        (0, 1000, 1),
        (1, -1, 1),
        (1, 1000, 0),
    ),
)
def test_capture_rejects_non_literal_or_out_of_range_target_identity(
    tmp_path: Path,
    pid: int,
    uid: int,
    start_ticks: int,
) -> None:
    launch = NativePthreadDockerLaunch(Path("/unused/probe"), "a" * 64, "exact", None, 20)

    with pytest.raises(PerfLensError, match="target identity is invalid") as raised:
        capture_docker_runtime_lock_evidence(
            tmp_path,
            launch=launch,
            execution_binding=_binding("native_pthread", "a" * 64),
            target_pid=pid,
            target_uid=uid,
            target_start_time_ticks=start_ticks,
            created_at=CREATED_AT,
            limits=RuntimeLockResourceLimits(),
        )

    assert raised.value.code == ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    ("launch", "profile"),
    (
        (NativePthreadDockerLaunch(Path("/p"), "a" * 64, "exact", None, 20), "mutex"),
        (CpythonDockerLaunch(Path("/p"), "b" * 64, "exact", None, 20), "mutex"),
        (JavaJfrDockerLaunch(Path("/p"), "c" * 64, "balanced"), "mutex"),
        (GoPprofDockerLaunch(("mutex",)), None),
        (GoPprofDockerLaunch(("mutex",)), "block"),
    ),
)
def test_capture_source_selection_rejects_foreign_or_missing_profile(
    launch: RuntimeLockDockerLaunch,
    profile: GoProfileKind | None,
) -> None:
    with pytest.raises(PerfLensError):
        capture_module._source_name(launch, profile)


@pytest.mark.parametrize(
    ("binding_adapter", "changed_field", "changed_value"),
    (
        ("cpython_threading", None, None),
        ("native_pthread", "profile", "thresholded"),
        ("native_pthread", "measurement_semantics", "thresholded"),
        ("native_pthread", "duration_threshold_ns", 1000),
        ("native_pthread", "configuration_sha256", "f" * 64),
        ("native_pthread", "runtime_payload_identity_sha256", "f" * 64),
    ),
)
def test_native_launch_must_equal_the_authorized_execution_binding(
    tmp_path: Path,
    binding_adapter: Literal["native_pthread", "cpython_threading"],
    changed_field: str | None,
    changed_value: object,
) -> None:
    launch = NativePthreadDockerLaunch(Path("/p"), "a" * 64, "exact", None, 20)
    binding = _binding(binding_adapter, "a" * 64)
    if changed_field is not None:
        binding = binding.model_copy(update={changed_field: changed_value})

    with pytest.raises(PerfLensError, match=r"launch and execution|controls differ"):
        _capture(tmp_path, launch, binding)


@pytest.mark.parametrize(
    ("adapter", "changed_field", "changed_value", "message"),
    (
        ("java_jfr", "profile", "deep", "JFR controls"),
        ("java_jfr", "configuration_sha256", "f" * 64, "JFR controls"),
        ("java_jfr", "runtime_payload_identity_sha256", None, "JFR controls"),
        ("go_pprof", "profile", "exact", "Go pprof controls"),
        ("go_pprof", "measurement_semantics", "sampled", "Go pprof controls"),
    ),
)
def test_java_and_go_launch_controls_are_content_bound(
    tmp_path: Path,
    adapter: Literal["java_jfr", "go_pprof"],
    changed_field: str,
    changed_value: object,
    message: str,
) -> None:
    if adapter == "java_jfr":
        launch: RuntimeLockDockerLaunch = JavaJfrDockerLaunch(Path("/p"), "c" * 64, "balanced")
        profile: GoProfileKind | None = None
    else:
        launch = GoPprofDockerLaunch(("mutex",))
        profile = "mutex"
    binding = _binding(adapter, "c" * 64).model_copy(update={changed_field: changed_value})

    with pytest.raises(PerfLensError, match=message):
        capture_docker_runtime_lock_evidence(
            tmp_path,
            launch=launch,
            execution_binding=binding,
            target_pid=1,
            target_uid=os.geteuid(),
            target_start_time_ticks=1,
            created_at=CREATED_AT,
            limits=RuntimeLockResourceLimits(),
            go_profile_kind=profile,
        )


@pytest.mark.parametrize("root_case", ("relative", "symlink", "file", "wrong_mode"))
def test_private_scratch_root_identity_fails_closed(tmp_path: Path, root_case: str) -> None:
    if root_case == "relative":
        root = Path("relative-scratch")
    elif root_case == "symlink":
        real = tmp_path / "real"
        real.mkdir(mode=0o733)
        root = tmp_path / "link"
        root.symlink_to(real, target_is_directory=True)
    elif root_case == "file":
        root = tmp_path / "file"
        root.write_bytes(b"not-a-directory")
    else:
        root = tmp_path / "wrong-mode"
        root.mkdir(mode=0o700)
    launch = NativePthreadDockerLaunch(Path("/p"), "a" * 64, "exact", None, 20)

    with pytest.raises(PerfLensError, match="scratch directory") as raised:
        _capture(root, launch, _binding("native_pthread", "a" * 64))

    assert raised.value.code == ErrorCode.PATH_SAFETY_VIOLATION


@pytest.mark.parametrize("source_case", ("missing", "directory", "hardlink", "empty", "oversized"))
def test_private_source_identity_fails_closed(tmp_path: Path, source_case: str) -> None:
    root = _scratch(tmp_path)
    source = root / "runtime-lock-native.ndjson"
    if source_case == "directory":
        source.mkdir(mode=0o755)
    elif source_case == "hardlink":
        source.write_bytes(b"x")
        source.chmod(0o644)
        os.link(source, root / "second-link")
    elif source_case == "empty":
        source.touch(mode=0o644)
    elif source_case == "oversized":
        with source.open("wb") as stream:
            stream.truncate(65 << 20)
        source.chmod(0o644)
    launch = NativePthreadDockerLaunch(Path("/p"), "a" * 64, "exact", None, 20)

    with pytest.raises(PerfLensError) as raised:
        _capture(root, launch, _binding("native_pthread", "a" * 64))

    assert raised.value.code == ErrorCode.PATH_SAFETY_VIOLATION


def test_private_root_and_source_owner_authorities_are_independent(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    raw = (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes()
    _write_private(root, "runtime-lock-native.ndjson", raw)
    launch = NativePthreadDockerLaunch(Path("/p"), "a" * 64, "exact", None, 20)
    binding = _binding("native_pthread", "a" * 64)

    with pytest.raises(PerfLensError, match="identity is unsafe"):
        capture_docker_runtime_lock_evidence(
            root,
            launch=launch,
            execution_binding=binding,
            target_pid=4242,
            target_uid=os.geteuid(),
            target_start_time_ticks=77,
            created_at=CREATED_AT,
            limits=RuntimeLockResourceLimits(),
            scratch_owner_uid=os.geteuid() + 1,
        )
    with pytest.raises(PerfLensError, match="identity is unsafe"):
        capture_docker_runtime_lock_evidence(
            root,
            launch=launch,
            execution_binding=binding,
            target_pid=4242,
            target_uid=os.geteuid(),
            target_start_time_ticks=77,
            created_at=CREATED_AT,
            limits=RuntimeLockResourceLimits(),
            source_owner_uid=os.geteuid() + 1,
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b"{}", "incomplete or oversized"),
        (b"{" + b"x" * 65_536 + b"}\n", "incomplete or oversized"),
        (b"not-json\n", "invalid JSON"),
        (b"[]\n", "JSON object"),
        (b'{"record_type":"other"}\n', "authorized controls"),
    ),
)
def test_private_header_is_bounded_typed_and_authorized(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    path = tmp_path / "header"
    path.write_bytes(payload)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(PerfLensError, match=message):
            capture_module._validate_private_header(
                descriptor,
                record_type="probe_header",
                semantics="exact",
                threshold_ns=None,
                max_events=20,
            )
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("value", (None, "", "x" * 129, 42))
def test_private_header_runtime_identity_is_bounded(value: object) -> None:
    with pytest.raises(PerfLensError, match="runtime identity is invalid"):
        capture_module._header_text({"runtime_version": value}, "runtime_version")


def test_private_source_hash_detects_truncation_and_growth(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"abc")
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(PerfLensError, match="truncated"):
            capture_module._hash_fd(descriptor, 4)
        with pytest.raises(PerfLensError, match="grew"):
            capture_module._hash_fd(descriptor, 2)
    finally:
        os.close(descriptor)


def test_private_source_change_after_descriptor_pin_is_rejected(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    path = _write_private(
        root,
        "runtime-lock-native.ndjson",
        (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes(),
    )
    source = capture_module._open_private_source(
        root,
        "runtime-lock-native.ndjson",
        root_owner_uid=os.geteuid(),
        source_owner_uid=os.geteuid(),
        maximum_bytes=64 << 20,
    )
    try:
        path.write_bytes(path.read_bytes() + b"\n")
        with pytest.raises(PerfLensError, match="changed during conversion"):
            capture_module._assert_unchanged(source)
    finally:
        os.close(source.descriptor)
        os.close(source.root_descriptor)


@pytest.mark.parametrize("uid_offset", (0, 1), ids=("same-uid", "cross-uid"))
def test_native_capture_rejects_private_target_mismatch_and_replay_failure(
    tmp_path: Path,
    fixture_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    uid_offset: int,
) -> None:
    root = _scratch(tmp_path)
    raw = (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes()
    records = [json.loads(line) for line in raw.splitlines()]
    records[0]["uid"] = os.geteuid() + uid_offset
    raw = b"".join(json.dumps(record).encode() + b"\n" for record in records)
    _write_private(root, "runtime-lock-native.ndjson", raw)
    launch = NativePthreadDockerLaunch(Path("/p"), "a" * 64, "exact", None, 20)
    binding = _binding("native_pthread", "a" * 64)

    with pytest.raises(PerfLensError, match="verified target identity"):
        _capture(root, launch, binding, target_pid=4243)

    replay_attempted = False

    def failed_replay(_expected: RuntimeLockEvidenceArtifact, _stream: BinaryIO) -> bool:
        nonlocal replay_attempted
        replay_attempted = True
        return False

    monkeypatch.setattr(capture_module, "replay_native_pthread_probe", failed_replay)
    if uid_offset:
        with pytest.raises(PerfLensError, match="verified target identity"):
            _capture(root, launch, binding)
        assert not replay_attempted
        return
    with pytest.raises(PerfLensError, match="replay did not match") as raised:
        _capture(root, launch, binding)
    assert raised.value.code == ErrorCode.PROFILE_PARSE_FAILED
    assert replay_attempted


def _java_tool() -> JavaJfrFileIdentity:
    return JavaJfrFileIdentity(
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


def test_java_capture_rejects_malformed_version_and_foreign_authority(tmp_path: Path) -> None:
    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock.jfr", b"private-jfr")
    launch = JavaJfrDockerLaunch(Path("/p"), "c" * 64, "balanced")
    binding = _binding("java_jfr", "c" * 64)
    runner = _FakeJavaRunner(b"{}", "4" * 64)

    with pytest.raises(PerfLensError, match="version is malformed"):
        _capture(
            root,
            launch,
            binding.model_copy(update={"runtime_version": "not-a-major"}),
            java_authority=JavaDockerJfrAuthority(runner, _java_tool(), 25),
        )

    with pytest.raises(PerfLensError, match="differs from the authorized binding"):
        _capture(
            root,
            launch,
            binding,
            java_authority=JavaDockerJfrAuthority(runner, _java_tool(), 21),
        )


def test_java_capture_rejects_renderer_tool_identity_replacement(tmp_path: Path) -> None:
    class ReplacedToolRunner(_FakeJavaRunner):
        def render_json(self, **kwargs: object) -> JavaJfrJsonRunnerReceipt:
            del kwargs
            return JavaJfrJsonRunnerReceipt(
                "f" * 64,
                25,
                elapsed_monotonic_ns=1,
                accounted_active_seconds=1,
            )

    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock.jfr", b"private-jfr")
    launch = JavaJfrDockerLaunch(Path("/p"), "c" * 64, "balanced")

    with pytest.raises(PerfLensError, match="different tool identity"):
        _capture(
            root,
            launch,
            _binding("java_jfr", "c" * 64),
            java_authority=JavaDockerJfrAuthority(
                ReplacedToolRunner(b"{}", "4" * 64),
                _java_tool(),
                25,
            ),
        )


def test_go_capture_rejects_renderer_profile_replacement(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    root = _scratch(tmp_path)
    _write_private(root, "runtime-lock-block.pprof", b"private-protobuf")
    raw = (fixture_root / "runtime_locks/go/go1.24.4-block.raw").read_bytes()
    renderer = _FakeGoRenderer(tmp_path, raw)
    launch = GoPprofDockerLaunch(("block",))

    with pytest.raises(PerfLensError, match="different profile kind"):
        _capture(
            root,
            launch,
            _binding("go_pprof", "d" * 64),
            target_pid=100,
            target_start_time_ticks=900,
            go_profile_kind="block",
            go_authority=GoDockerPprofAuthority(renderer, "block", None, 1),
        )

    assert renderer.raw_path is not None and not renderer.raw_path.exists()


def test_import_only_runtime_binding_uses_literal_fallback_matrix() -> None:
    tools = ()
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    identity = derive_runtime_lock_adapter_execution_identity(
        "generic_ndjson_import",
        "1",
        "ndjson",
        "custom-1",
        "exact",
        "exact",
        None,
        toolchain,
        "1" * 64,
        "2" * 64,
    )
    binding = RuntimeLockAdapterExecutionBinding(
        adapter_id="generic_ndjson_import",
        adapter_version="1",
        backend_id="ndjson",
        runtime_version="custom-1",
        profile="exact",
        measurement_semantics="exact",
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256="1" * 64,
        metadata_sha256="2" * 64,
        execution_identity_sha256=identity,
    )

    observed = bind_observed_runtime_execution(
        binding,
        runtime_version="custom-1",
        runtime_characteristics="generic-import",
    )
    assert observed.execution_identity_sha256 != binding.execution_identity_sha256

    with pytest.raises(PerfLensError, match="outside the authorized matrix"):
        bind_observed_runtime_execution(
            binding,
            runtime_version="custom-2",
            runtime_characteristics="generic-import",
        )
