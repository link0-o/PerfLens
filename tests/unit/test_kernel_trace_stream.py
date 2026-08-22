from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.domain.trace import (
    FutexEvent,
    ResourceLimits,
    SchedSwitchEvent,
    SchedWakeupEvent,
    TargetIdentity,
    TraceScope,
)
from perflens.profiles.kernel_trace_stream import FixedKernelTraceNdjsonAdapter


def _record(sequence: int, kind: str, **extra: object) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "sequence": sequence,
        "timestamp_ns": 1_000 + sequence * 10,
        "cpu": 2,
        "kind": kind,
        "target_tid": 321,
        **extra,
    }


def _write(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _adapter(
    path: Path,
    *,
    mode: str = "sched",
    lost: int = 0,
    truncated: bool = False,
):
    raw = path.read_bytes()
    return FixedKernelTraceNdjsonAdapter(
        target=TargetIdentity(pid=321, uid=os.getuid(), start_time_ticks=456),
        observed_target_tids=(321, 322),
        expected_input_owner_uid=os.getuid(),
        expected_input_owner_gid=os.getgid(),
        expected_input_mode=0o600,
        expected_input_sha256=hashlib.sha256(raw).hexdigest(),
        expected_input_bytes=len(raw),
        mode=mode,
        lost_event_count=lost,
        truncated=truncated,
        limits=ResourceLimits(max_events=100, max_input_lines=100),
    )


def test_parses_target_filtered_scheduler_and_merges_waker(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(
        trace,
        [
            _record(
                0,
                "sched_waking",
                related_target_tid=322,
                related_scope="target",
                target_cpu=2,
            ),
            _record(1, "sched_wakeup", target_cpu=2),
            _record(
                2,
                "sched_switch_out",
                related_scope="external_redacted",
                previous_state=1,
            ),
            _record(
                3,
                "sched_switch_both",
                related_target_tid=322,
                related_scope="target",
                previous_state=0,
            ),
        ],
    )

    result = _adapter(trace).parse(trace)

    assert result.statistics.input_event_count == 4
    assert result.statistics.emitted_event_count == 3
    assert result.statistics.provisional_enrichment_event_count == 1
    wakeup = result.events[0]
    assert isinstance(wakeup, SchedWakeupEvent)
    assert wakeup.waker_scope is TraceScope.TARGET
    assert wakeup.waker is not None and wakeup.waker.tid == 322
    switch = result.events[1]
    assert isinstance(switch, SchedSwitchEvent)
    assert switch.next_scope is TraceScope.FOREIGN


def test_truncation_and_loss_are_explicitly_partial(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(trace, [_record(0, "sched_wakeup", target_cpu=2)])

    result = _adapter(trace, lost=7, truncated=True).parse(trace)

    assert result.statistics.partial
    assert result.statistics.lost_event_count == 7
    assert result.statistics.diagnostic_count == 1


def test_parses_fixed_futex_operation_without_scheduler_metadata(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(
        trace,
        [
            _record(
                0,
                "futex_wait",
                lock_id="lock-aaaaaaaaaaaaaaaaaaaa",
                futex_operation="wait_bitset",
            )
        ],
    )

    result = _adapter(trace, mode="lock").parse(trace)

    assert result.statistics.malformed_event_count == 0
    assert len(result.events) == 1
    assert isinstance(result.events[0], FutexEvent)


def test_rejects_scheduler_relationship_metadata_on_futex_event(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(
        trace,
        [
            _record(
                0,
                "futex_wait",
                lock_id="lock-aaaaaaaaaaaaaaaaaaaa",
                futex_operation="wait_bitset",
                related_scope="external_redacted",
            )
        ],
    )

    result = _adapter(trace, mode="lock").parse(trace)

    assert not result.events
    assert result.statistics.malformed_event_count == 1


@pytest.mark.parametrize(
    "mutation",
    [
        {"foreign_pid": 999},
        {"object_address": "0xdeadbeef"},
        {"related_target_tid": 999, "related_scope": "target"},
    ],
)
def test_rejects_foreign_or_private_fields(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(trace, [_record(0, "sched_wakeup", target_cpu=2, **mutation)])

    result = _adapter(trace).parse(trace)

    assert not result.events
    assert result.statistics.malformed_event_count == 1


def test_rejects_symlink_and_group_writable_input(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(trace, [_record(0, "sched_wakeup", target_cpu=2)])
    symlink = tmp_path / "linked.ndjson"
    symlink.symlink_to(trace)
    with pytest.raises(PerfLensError):
        _adapter(trace).parse(symlink)
    trace.chmod(0o660)
    with pytest.raises(PerfLensError):
        _adapter(trace).parse(trace)


def test_rejects_content_replaced_after_expected_identity_was_bound(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write(trace, [_record(0, "sched_wakeup", target_cpu=2)])
    adapter = _adapter(trace)
    _write(trace, [_record(0, "sched_wakeup", target_cpu=3)])

    with pytest.raises(PerfLensError):
        adapter.parse(trace)
