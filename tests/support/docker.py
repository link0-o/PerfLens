from __future__ import annotations

import struct
from pathlib import Path

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    CgroupIoDeviceLimit,
    ContainerResourceContextArtifact,
    ContainerResourceDelta,
    ContainerResourceSnapshot,
    PressureSnapshot,
    derive_container_resource_context_id,
)


def write_self_contained_test_elf(path: Path, *, suffix: bytes = b"") -> Path:
    """Write the smallest ELF64 shape accepted by the Gate validator."""
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\x00" * 7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 120, 120, 4096)
    path.write_bytes(header + load + suffix)
    path.chmod(0o500)
    return path


def make_container_resource_context(
    *,
    container_identity_sha256: str = "5" * 64,
    source_collection_id: str = "collection-" + "1" * 16,
    source_output_sha256: str = "2" * 64,
) -> ContainerResourceContextArtifact:
    before = ContainerResourceSnapshot(
        observed_at="2026-08-21T00:00:00+00:00",
        cpu_usage_usec=1_000,
        cpu_user_usec=700,
        cpu_system_usec=300,
        cpu_nr_periods=10,
        cpu_nr_throttled=1,
        cpu_throttled_usec=50,
        cpu_period_usec=100_000,
        cpuset_cpus_effective="0-1",
        memory_current_bytes=1 << 20,
        memory_events=(("oom", 0),),
        memory_pressure=PressureSnapshot(some_total_us=10, full_total_us=0),
        io_pressure=PressureSnapshot(some_total_us=20, full_total_us=0),
        io_limits=(CgroupIoDeviceLimit(major=8, minor=0, read_bps=1 << 20),),
        pids_current=2,
    )
    after = before.model_copy(
        update={
            "observed_at": "2026-08-21T00:00:01+00:00",
            "cpu_usage_usec": 1_600,
            "cpu_user_usec": 1_100,
            "cpu_system_usec": 500,
            "cpu_nr_periods": 11,
            "cpu_nr_throttled": 2,
            "cpu_throttled_usec": 90,
            "memory_current_bytes": (1 << 20) + 4096,
            "memory_pressure": PressureSnapshot(some_total_us=13, full_total_us=0),
            "io_pressure": PressureSnapshot(some_total_us=25, full_total_us=0),
            "pids_current": 3,
        }
    )
    provisional = ContainerResourceContextArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        resource_context_id=derive_container_resource_context_id(
            container_identity_sha256=container_identity_sha256,
            cgroup_identity_sha256="7" * 64,
            source_collection_id=source_collection_id,
            source_output_sha256=source_output_sha256,
            before_observed_at=before.observed_at,
            after_observed_at=after.observed_at,
            created_at="2026-08-21T00:00:02+00:00",
        ),
        created_at="2026-08-21T00:00:02+00:00",
        container_identity_sha256=container_identity_sha256,
        cgroup_identity_sha256="7" * 64,
        source_collection_id=source_collection_id,
        source_output_sha256=source_output_sha256,
        before=before,
        after=after,
        delta=ContainerResourceDelta(
            cpu_usage_usec=600,
            cpu_user_usec=400,
            cpu_system_usec=200,
            cpu_nr_periods=1,
            cpu_nr_throttled=1,
            cpu_throttled_usec=40,
            memory_event_deltas=(("oom", 0),),
            io_read_bytes=0,
            io_write_bytes=0,
            io_read_ios=0,
            io_write_ios=0,
            memory_pressure_some_usec=3,
            memory_pressure_full_usec=0,
            io_pressure_some_usec=5,
            io_pressure_full_usec=0,
        ),
        quality_status="verified",
        allowed_conclusions=("Container-wide cgroup resource observations may be reported.",),
        forbidden_conclusions=(
            "Container counters are not exclusive measurements of the selected process.",
        ),
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
