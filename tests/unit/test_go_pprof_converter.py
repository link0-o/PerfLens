from __future__ import annotations

from io import BytesIO

import pytest

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockResourceLimits,
    RuntimeSampledContentionEvent,
)
from perflens.domain.errors import PerfLensError
from perflens.runtime_locks.go_pprof_converter import (
    convert_go_pprof_raw,
    verify_go_pprof_replay,
)

MUTEX_RAW = b"""PeriodType: contentions count
Period: 1
Time: 2026-08-31 00:00:00 +0000 UTC
Samples:
contentions/count delay/nanoseconds
          2    3000000: 1 2 
Locations
     1: 0x4cf558 M=1 sync.(*Mutex).Unlock /usr/lib/go/src/sync/mutex.go:65:0 s=64
             example/work.hot /private/project/work.go:19:0 s=11
     2: 0x43ccca M=1 runtime.main /usr/lib/go/src/runtime/proc.go:283:0 s=147
Mappings
1: 0x400000/0x4d0000/0x0 /private/build/workload deadbeef [FN]
"""

BLOCK_RAW = b"""PeriodType: contentions count
Period: 1
Samples:
contentions/count delay/nanoseconds
          1    2000000: 1 
Locations
     1: 0x40beb1 M=1 runtime.chanrecv1 /usr/lib/go/src/runtime/chan.go:506:0 s=505
Mappings
1: 0x400000/0x4d0000/0x0 /private/build/workload deadbeef [FN]
"""


def _binding() -> RuntimeLockAdapterExecutionBinding:
    tools = (
        RuntimeLockAdapterToolBinding(name="go", version="1.24.4", binary_sha256="1" * 64),
        RuntimeLockAdapterToolBinding(
            name="pprof", version="1.24.4", binary_sha256="2" * 64
        ),
    )
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    identity = derive_runtime_lock_adapter_execution_identity(
        "go_pprof",
        "go-pprof-adapter-v1",
        "pprof",
        "1.24.4",
        "mutex_and_block",
        "cumulative",
        None,
        toolchain,
        "2" * 64,
        "3" * 64,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="go_pprof",
        adapter_version="go-pprof-adapter-v1",
        backend_id="pprof",
        runtime_version="1.24.4",
        profile="mutex_and_block",
        measurement_semantics="cumulative",
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256="2" * 64,
        metadata_sha256="3" * 64,
        execution_identity_sha256=identity,
        limitations=("cumulative only",),
    )


def test_mutex_profile_is_partial_process_aggregate_and_path_private() -> None:
    receipt = convert_go_pprof_raw(
        BytesIO(MUTEX_RAW),
        execution_binding=_binding(),
        profile_kind="mutex",
        target_pid=100,
        target_uid=1000,
        target_start_time_ticks=900,
        mutex_profile_fraction=5,
        block_profile_rate_ns=None,
        created_at="2026-08-31T00:00:00+00:00",
    )
    evidence = receipt.evidence

    assert evidence.source.source_format == "pprof_text_v1"
    assert evidence.source.sampling_fraction == 5
    assert evidence.quality.status == "partial"
    assert evidence.execution_contexts[0].kind == "process_aggregate"
    event = evidence.events[0]
    assert isinstance(event, RuntimeSampledContentionEvent)
    assert event.observed_count == 2
    assert event.estimated_count is None
    assert event.lock_id is None
    assert all(
        frame.source_file is None or "/" not in frame.source_file
        for frame in evidence.stacks[0].frames
    )
    assert "/private/" not in evidence.model_dump_json()
    assert verify_go_pprof_replay(
        BytesIO(MUTEX_RAW),
        expected=receipt,
        execution_binding=_binding(),
        target_pid=100,
        target_uid=1000,
        target_start_time_ticks=900,
        mutex_profile_fraction=5,
        block_profile_rate_ns=None,
    ) is not None


def test_block_profile_keeps_independent_rate_and_channel_semantics() -> None:
    evidence = convert_go_pprof_raw(
        BytesIO(BLOCK_RAW),
        execution_binding=_binding(),
        profile_kind="block",
        target_pid=100,
        target_uid=1000,
        target_start_time_ticks=900,
        mutex_profile_fraction=None,
        block_profile_rate_ns=1_000,
    ).evidence

    assert evidence.source.block_profile_rate_ns == 1_000
    assert evidence.source.sampling_fraction is None
    event = evidence.events[0]
    assert isinstance(event, RuntimeSampledContentionEvent)
    assert event.lock_kind == "channel"
    assert event.estimated_count is None


@pytest.mark.parametrize(
    "raw",
    (
        MUTEX_RAW.replace(b"Period: 1", b"Period: 2"),
        MUTEX_RAW.replace(b"Locations", b"Locations\nLocations"),
        MUTEX_RAW.replace(b"3000000: 1 2", b"0: 1 2"),
        MUTEX_RAW.rstrip(b"\n"),
    ),
)
def test_raw_parser_rejects_format_drift_and_incomplete_profiles(raw: bytes) -> None:
    with pytest.raises(PerfLensError):
        convert_go_pprof_raw(
            BytesIO(raw),
            execution_binding=_binding(),
            profile_kind="mutex",
            target_pid=100,
            target_uid=1000,
            target_start_time_ticks=900,
            mutex_profile_fraction=1,
            block_profile_rate_ns=None,
        )


def test_raw_parser_rejects_oversized_numeric_fields() -> None:
    raw = MUTEX_RAW.replace(b"          2    3000000", b"          " + b"9" * 21 + b"    3000000")
    with pytest.raises(PerfLensError, match="malformed or oversized"):
        convert_go_pprof_raw(
            BytesIO(raw),
            execution_binding=_binding(),
            profile_kind="mutex",
            target_pid=100,
            target_uid=1000,
            target_start_time_ticks=900,
            mutex_profile_fraction=1,
            block_profile_rate_ns=None,
        )


def test_merged_locations_cannot_exceed_stack_depth() -> None:
    raw = b"""PeriodType: contentions count
Period: 1
Samples:
contentions/count delay/nanoseconds
          1    2000000: 1 2
Locations
     1: 0x40beb1 M=1 example.one /private/one.go:1:0 s=1
             example.one.inline /private/one.go:2:0 s=2
     2: 0x40beb2 M=1 example.two /private/two.go:2:0 s=2
             example.two.inline /private/two.go:3:0 s=3
Mappings
1: 0x400000/0x4d0000/0x0 /private/build/workload deadbeef [FN]
"""
    limits = RuntimeLockResourceLimits(max_stack_depth=2)
    with pytest.raises(PerfLensError, match="merged call path"):
        convert_go_pprof_raw(
            BytesIO(raw),
            execution_binding=_binding(),
            profile_kind="block",
            target_pid=100,
            target_uid=1000,
            target_start_time_ticks=900,
            mutex_profile_fraction=None,
            block_profile_rate_ns=1,
            limits=limits,
        )


def test_block_classifier_does_not_match_arbitrary_mutex_substrings() -> None:
    raw = BLOCK_RAW.replace(b"runtime.chanrecv1", b"example.MutexHelper")
    evidence = convert_go_pprof_raw(
        BytesIO(raw),
        execution_binding=_binding(),
        profile_kind="block",
        target_pid=100,
        target_uid=1000,
        target_start_time_ticks=900,
        mutex_profile_fraction=None,
        block_profile_rate_ns=1,
    ).evidence

    assert evidence.events[0].lock_kind == "unknown"
