from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    ContainerCgroupIdentity,
    ContainerNamespaceIdentity,
    ContainerTargetArtifact,
)
from perflens.docker.cgroup import (
    CgroupV2ResourceReader,
    build_container_resource_context,
)
from perflens.docker.identity import (
    KernelProcessIdentity,
    NamespaceIdentity,
    PrivateContainerInstance,
    ResolvedContainerTarget,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_SOURCE_COLLECTION_ID = "collection-" + "1" * 16
_SOURCE_OUTPUT_SHA256 = "2" * 64


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _write_cgroup(
    directory: Path,
    *,
    usage: int,
    user: int,
    system: int,
    periods: int,
    throttled: int,
    throttled_usec: int,
    memory_oom: int,
    read_bytes: int,
    write_bytes: int,
    pressure_total: int,
    cpu_max: str = "200000 100000",
    cpuset: str = "0-3",
    io_max: str = "8:0 rbps=1048576 wbps=max riops=1000 wiops=max",
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cpu.stat").write_text(
        f"usage_usec {usage}\n"
        f"user_usec {user}\n"
        f"system_usec {system}\n"
        f"nr_periods {periods}\n"
        f"nr_throttled {throttled}\n"
        f"throttled_usec {throttled_usec}\n",
        encoding="ascii",
    )
    (directory / "cpu.max").write_text(f"{cpu_max}\n", encoding="ascii")
    (directory / "cpuset.cpus.effective").write_text(f"{cpuset}\n", encoding="ascii")
    (directory / "memory.current").write_text("4096\n", encoding="ascii")
    (directory / "memory.max").write_text("1073741824\n", encoding="ascii")
    (directory / "memory.events").write_text(
        f"low 0\nhigh 0\nmax 0\noom {memory_oom}\noom_kill 0\n",
        encoding="ascii",
    )
    (directory / "memory.pressure").write_text(
        f"some avg10=0.00 avg60=0.00 avg300=0.00 total={pressure_total}\n"
        f"full avg10=0.00 avg60=0.00 avg300=0.00 total={pressure_total // 2}\n",
        encoding="ascii",
    )
    (directory / "io.stat").write_text(
        f"8:0 rbytes={read_bytes} wbytes={write_bytes} rios=2 wios=3 dbytes=0 dios=0\n",
        encoding="ascii",
    )
    (directory / "io.max").write_text(f"{io_max}\n", encoding="ascii")
    (directory / "io.pressure").write_text(
        f"some avg10=0.00 avg60=0.00 avg300=0.00 total={pressure_total * 2}\n"
        f"full avg10=0.00 avg60=0.00 avg300=0.00 total={pressure_total}\n",
        encoding="ascii",
    )
    (directory / "pids.current").write_text("2\n", encoding="ascii")
    (directory / "pids.max").write_text("64\n", encoding="ascii")


def _resolved_target(
    cgroup_root: Path,
    *,
    container_identity: str = "a" * 64,
) -> tuple[ResolvedContainerTarget, Path]:
    cgroup_directory = cgroup_root / "docker/test-container"
    cgroup_directory.mkdir(parents=True, exist_ok=True)
    inode = cgroup_directory.stat().st_ino
    cgroup_identity = _sha256_text(
        "cgroup-v2",
        container_identity,
        "/docker/test-container",
        str(inode),
    )
    artifact = ContainerTargetArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        target_id="container-target-" + "b" * 20,
        created_at="2026-08-21T00:00:00+00:00",
        target_kind="existing_container",
        container_identity_sha256=container_identity,
        image_identity_sha256="c" * 64,
        container_pid=12,
        host_pid=1002,
        host_uid=1000,
        host_start_time_ticks=9002,
        executable_name="worker",
        namespace=ContainerNamespaceIdentity(
            pid_namespace_inode=101,
            user_namespace_inode=102,
            mount_namespace_inode=103,
            cgroup_namespace_inode=104,
        ),
        cgroup=ContainerCgroupIdentity(
            version="v2",
            inode=inode,
            identity_sha256=cgroup_identity,
        ),
        uid_mapping="rootless_same_uid",
        adapter_recipe_id="local-docker-read-v1",
        adapter_sha256="d" * 64,
        identity_fingerprint="e" * 64,
        content_sha256="f" * 64,
    )
    kernel = KernelProcessIdentity(
        host_pid=1002,
        host_uid=1000,
        host_start_time_ticks=9002,
        container_pid=12,
        nspid=(1002, 12),
        executable_name="worker",
        namespace=NamespaceIdentity(pid=101, user=102, mount=103, cgroup=104),
        cgroup_relative_path="/docker/test-container",
        cgroup_inode=inode,
    )
    return (
        ResolvedContainerTarget(
            PrivateContainerInstance("1" * 64, "sha256:" + "c" * 64, 1001),
            kernel,
            artifact,
        ),
        cgroup_directory,
    )


def _initial_files(cgroup_directory: Path) -> None:
    _write_cgroup(
        cgroup_directory,
        usage=1000,
        user=700,
        system=300,
        periods=10,
        throttled=2,
        throttled_usec=100,
        memory_oom=0,
        read_bytes=100,
        write_bytes=200,
        pressure_total=20,
    )


def _later_files(cgroup_directory: Path, *, cpu_max: str = "200000 100000") -> None:
    _write_cgroup(
        cgroup_directory,
        usage=1600,
        user=1100,
        system=500,
        periods=16,
        throttled=3,
        throttled_usec=140,
        memory_oom=1,
        read_bytes=160,
        write_bytes=280,
        pressure_total=30,
        cpu_max=cpu_max,
    )


def test_cgroup_reader_and_delta_cover_bounded_container_resources(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    _later_files(directory)
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    context = build_container_resource_context(
        reader,
        before,
        after,
        source_collection_id=_SOURCE_COLLECTION_ID,
        source_output_sha256=_SOURCE_OUTPUT_SHA256,
        created_at=started + timedelta(seconds=2),
    )
    assert context.quality_status == "verified"
    assert context.scope == "entire_container_cgroup_v2"
    assert context.delta.cpu_usage_usec == 600
    assert context.delta.cpu_user_usec == 400
    assert context.delta.cpu_system_usec == 200
    assert context.delta.cpu_nr_throttled == 1
    assert context.delta.cpu_throttled_usec == 40
    assert context.delta.memory_event_deltas == (
        ("high", 0),
        ("low", 0),
        ("max", 0),
        ("oom", 1),
        ("oom_kill", 0),
    )
    assert context.delta.io_read_bytes == 60
    assert context.delta.io_write_bytes == 80
    assert context.before.io_limits[0].read_bps == 1_048_576
    assert context.before.io_limits[0].read_iops == 1_000
    assert context.before.io_limits[0].write_bps is None
    assert context.delta.memory_pressure_some_usec == 10
    assert context.delta.io_pressure_some_usec == 20
    assert context.source_collection_id == _SOURCE_COLLECTION_ID
    assert context.source_output_sha256 == _SOURCE_OUTPUT_SHA256
    assert context.content_sha256 == contract_content_sha256(
        context,
        exclude={"content_sha256"},
    )
    other_source = build_container_resource_context(
        reader,
        before,
        after,
        source_collection_id="collection-" + "3" * 16,
        source_output_sha256="4" * 64,
        created_at=started + timedelta(seconds=2),
    )
    assert other_source.resource_context_id != context.resource_context_id
    assert other_source.content_sha256 != context.content_sha256
    serialized = context.model_dump_json()
    assert "/docker/test-container" not in serialized
    assert "not exclusive measurements" in serialized


def test_missing_optional_pressure_and_io_are_explicitly_partial(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    for name in ("memory.pressure", "io.pressure", "io.stat", "io.max"):
        (directory / name).unlink()
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    _later_files(directory)
    for name in ("memory.pressure", "io.pressure", "io.stat", "io.max"):
        (directory / name).unlink()
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    context = build_container_resource_context(
        reader,
        before,
        after,
        source_collection_id=_SOURCE_COLLECTION_ID,
        source_output_sha256=_SOURCE_OUTPUT_SHA256,
    )
    assert context.quality_status == "partial"
    assert context.delta.memory_pressure_some_usec is None
    assert context.delta.io_pressure_some_usec is None
    assert context.delta.io_read_bytes == 0
    assert len(context.limitations) == 4


def test_io_limit_change_is_reported_as_partial_environment_drift(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    _later_files(directory)
    (directory / "io.max").write_text("8:0 rbps=524288\n", encoding="ascii")
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    context = build_container_resource_context(
        reader,
        before,
        after,
        source_collection_id=_SOURCE_COLLECTION_ID,
        source_output_sha256=_SOURCE_OUTPUT_SHA256,
    )
    assert context.quality_status == "partial"
    assert any("I/O limits changed" in value for value in context.limitations)


def test_resource_limit_change_is_reported_as_partial_environment_drift(
    tmp_path: Path,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    _later_files(directory, cpu_max="100000 100000")
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    context = build_container_resource_context(
        reader,
        before,
        after,
        source_collection_id=_SOURCE_COLLECTION_ID,
        source_output_sha256=_SOURCE_OUTPUT_SHA256,
    )
    assert context.quality_status == "partial"
    assert "CPU quota changed" in context.limitations[0]


def test_missing_optional_cpu_fields_are_partial_not_fabricated(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    (directory / "cpu.stat").write_text("usage_usec 1000\n", encoding="ascii")
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    (directory / "cpu.stat").write_text("usage_usec 1200\n", encoding="ascii")
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    context = build_container_resource_context(
        reader,
        before,
        after,
        source_collection_id=_SOURCE_COLLECTION_ID,
        source_output_sha256=_SOURCE_OUTPUT_SHA256,
        created_at=started + timedelta(seconds=2),
    )
    assert context.quality_status == "partial"
    assert context.delta.cpu_usage_usec == 200
    assert context.delta.cpu_user_usec is None
    assert any("user_usec" in limitation for limitation in context.limitations)


def test_snapshot_digest_and_target_binding_prevent_cross_container_mixup(
    tmp_path: Path,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    first_target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    first_reader = CgroupV2ResourceReader(first_target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = first_reader.capture(observed_at=started)
    _later_files(directory)
    after = first_reader.capture(observed_at=started + timedelta(seconds=1))

    tampered = replace(
        before,
        snapshot=before.snapshot.model_copy(update={"cpu_usage_usec": 999}),
    )
    with pytest.raises(PerfLensError) as captured:
        build_container_resource_context(
            first_reader,
            tampered,
            after,
            source_collection_id=_SOURCE_COLLECTION_ID,
            source_output_sha256=_SOURCE_OUTPUT_SHA256,
        )
    assert "digest" in captured.value.message

    second_target, _ = _resolved_target(
        cgroup_root,
        container_identity="9" * 64,
    )
    second_reader = CgroupV2ResourceReader(second_target, cgroup_root=cgroup_root)
    with pytest.raises(PerfLensError) as captured:
        build_container_resource_context(
            second_reader,
            before,
            after,
            source_collection_id=_SOURCE_COLLECTION_ID,
            source_output_sha256=_SOURCE_OUTPUT_SHA256,
        )
    assert "different Docker target" in captured.value.message


def test_decreasing_cumulative_counter_is_rejected(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _later_files(directory)
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    _initial_files(directory)
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    with pytest.raises(PerfLensError) as captured:
        build_container_resource_context(
            reader,
            before,
            after,
            source_collection_id=_SOURCE_COLLECTION_ID,
            source_output_sha256=_SOURCE_OUTPUT_SHA256,
        )
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert "decreased" in captured.value.message


def test_resource_context_rejects_naive_or_pre_observation_creation_time(
    tmp_path: Path,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    started = datetime(2026, 8, 21, tzinfo=UTC)
    before = reader.capture(observed_at=started)
    _later_files(directory)
    after = reader.capture(observed_at=started + timedelta(seconds=1))
    with pytest.raises(PerfLensError):
        build_container_resource_context(
            reader,
            before,
            after,
            source_collection_id=_SOURCE_COLLECTION_ID,
            source_output_sha256=_SOURCE_OUTPUT_SHA256,
            created_at=datetime(2026, 8, 21),
        )
    with pytest.raises(PerfLensError):
        build_container_resource_context(
            reader,
            before,
            after,
            source_collection_id=_SOURCE_COLLECTION_ID,
            source_output_sha256=_SOURCE_OUTPUT_SHA256,
            created_at=started,
        )


@pytest.mark.parametrize(
    ("file_name", "replacement"),
    (
        ("cpu.stat", "usage_usec 1\nusage_usec 2\n"),
        ("cpu.max", "max\n"),
        ("cpuset.cpus.effective", "3-1\n"),
        ("memory.current", "-1\n"),
        ("memory.events", "oom nope\n"),
        ("memory.pressure", "some total=nope\n"),
        ("io.stat", "8:0 rbytes=1\n8:0 rbytes=2\n"),
        ("io.max", "8:0 rbps=0\n"),
        ("io.max", "8:0 rbps=max\n8:0 wbps=1\n"),
        ("pids.max", "0\n"),
    ),
)
def test_malformed_cgroup_resources_fail_closed(
    tmp_path: Path,
    file_name: str,
    replacement: str,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    (directory / file_name).write_text(replacement, encoding="ascii")
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)
    with pytest.raises(PerfLensError) as captured:
        reader.capture()
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_cgroup_resource_symlink_oversize_and_directory_replacement_are_rejected(
    tmp_path: Path,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    reader = CgroupV2ResourceReader(target, cgroup_root=cgroup_root)

    (directory / "cpu.stat").unlink()
    (directory / "cpu.stat").symlink_to("memory.events")
    with pytest.raises(PerfLensError):
        reader.capture()

    (directory / "cpu.stat").unlink()
    (directory / "cpu.stat").write_text("x" * ((64 << 10) + 1), encoding="ascii")
    with pytest.raises(PerfLensError):
        reader.capture()

    replacement_parent = cgroup_root / "old"
    directory.rename(replacement_parent)
    _initial_files(directory)
    with pytest.raises(PerfLensError) as captured:
        reader.capture()
    assert "inode changed" in captured.value.message


def test_reader_rejects_public_private_cgroup_digest_mismatch(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    target, directory = _resolved_target(cgroup_root)
    _initial_files(directory)
    tampered = target.artifact.model_copy(
        update={"cgroup": target.artifact.cgroup.model_copy(update={"identity_sha256": "0" * 64})}
    )
    with pytest.raises(PerfLensError) as captured:
        CgroupV2ResourceReader(
            ResolvedContainerTarget(target.instance, target.kernel, tampered),
            cgroup_root=cgroup_root,
        )
    assert "digest" in captured.value.message
