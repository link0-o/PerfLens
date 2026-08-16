from __future__ import annotations

import os
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.trace import (
    EvidenceSemantics,
    FutexEvent,
    FutexOperation,
    LockAction,
    LockEvent,
    LockWaitOutcome,
    ResourceLimits,
    SchedMigrateEvent,
    SchedSwitchEvent,
    SchedWakeupEvent,
    TargetIdentity,
    TraceScope,
)
from perflens.profiles.trace_stream import (
    TRACE_PERF_SCRIPT_FIELDS,
    FixedTracePerfScriptAdapter,
)

TARGET = TargetIdentity(pid=4242, uid=1000, start_time_ticks=123456)
TARGET_TIDS = (4242, 4243)
LOCK_KEY = bytes.fromhex("00" * 32)


def _adapter(
    mode: str,
    *,
    limits: ResourceLimits | None = None,
    key: bytes = LOCK_KEY,
) -> FixedTracePerfScriptAdapter:
    return FixedTracePerfScriptAdapter(
        target=TARGET,
        observed_target_tids=TARGET_TIDS,
        expected_input_owner_uid=os.getuid(),
        expected_input_owner_gid=os.getgid(),
        expected_input_mode=0o600,
        mode=mode,
        limits=limits,
        lock_identity_key=key,
    )


def _private_fixture(fixture_root: Path, tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    destination.write_bytes((fixture_root / "trace_perf_script" / name).read_bytes())
    destination.chmod(0o600)
    return destination


def test_scheduler_stream_is_target_scoped_and_waking_only_enriches(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    result = _adapter("sched").parse(
        _private_fixture(fixture_root, tmp_path, "scheduler.perf-script")
    )

    assert [event.kind.value for event in result.events] == [
        "sched_switch",
        "sched_wakeup",
        "sched_wakeup",
        "sched_switch",
        "sched_migrate",
        "sched_switch",
    ]
    assert result.observed_target_tids == TARGET_TIDS
    first_switch = result.events[0]
    assert isinstance(first_switch, SchedSwitchEvent)
    assert first_switch.previous_scope is TraceScope.TARGET
    assert first_switch.next_scope is TraceScope.FOREIGN
    assert first_switch.next.pid is None
    assert first_switch.next.tid is None

    enriched = result.events[1]
    assert isinstance(enriched, SchedWakeupEvent)
    assert enriched.waker_scope is TraceScope.FOREIGN
    assert enriched.waker is not None
    assert enriched.waker.pid is None
    ambiguous = result.events[2]
    assert isinstance(ambiguous, SchedWakeupEvent)
    assert ambiguous.waker is None
    assert ambiguous.waker_scope is None
    migration = result.events[-2]
    assert isinstance(migration, SchedMigrateEvent)
    assert (migration.origin_cpu, migration.destination_cpu) == (3, 4)
    expanded_later = result.events[-1]
    assert isinstance(expanded_later, SchedSwitchEvent)
    assert expanded_later.previous_scope is TraceScope.TARGET
    assert expanded_later.next_scope is TraceScope.TARGET
    assert expanded_later.previous.tid == 4242
    assert expanded_later.next.tid == 4243

    stats = result.statistics
    assert stats.input_event_count == 12
    assert stats.emitted_event_count == 6
    assert stats.lost_event_count == 7
    assert stats.malformed_event_count == 1
    assert stats.foreign_event_dropped_count == 1
    assert stats.unsupported_event_count == 3
    assert stats.provisional_enrichment_event_count == 1
    assert stats.partial
    serialized = repr(result).encode("utf-8")
    for private_value in (
        b"foreign-worker",
        b"other-worker",
        b"evil",
        b"9777",
        b"9888",
    ):
        assert private_value not in serialized


def test_lock_stream_hashes_addresses_and_preserves_wait_end_outcomes(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    result = _adapter("lock").parse(
        _private_fixture(fixture_root, tmp_path, "lock.perf-script")
    )

    wait_ended = [
        event
        for event in result.events
        if isinstance(event, LockEvent) and event.action is LockAction.WAIT_ENDED
    ]
    assert [event.wait_outcome for event in wait_ended] == [
        LockWaitOutcome.ACQUIRED,
        LockWaitOutcome.INTERRUPTED,
        LockWaitOutcome.TIMED_OUT,
        LockWaitOutcome.FAILED,
        LockWaitOutcome.UNKNOWN,
    ]
    assert all(event.action is not LockAction.ACQUIRED for event in wait_ended[1:])
    assert wait_ended[-1].wait_outcome is LockWaitOutcome.UNKNOWN
    assert all(event.semantics is EvidenceSemantics.EXACT for event in wait_ended)
    first_lock_id = wait_ended[0].lock_id
    assert wait_ended[0].wait_outcome is LockWaitOutcome.ACQUIRED
    assert sum(
        isinstance(event, LockEvent)
        and event.action is LockAction.WAIT
        and event.lock_id == first_lock_id
        for event in result.events
    ) == 1
    assert sum(
        isinstance(event, LockEvent) and event.action is LockAction.WAIT
        for event in result.events
    ) == 2

    futex = [event for event in result.events if isinstance(event, FutexEvent)]
    assert [event.action.value for event in futex] == ["wait", "wake"]
    assert all(event.semantics is EvidenceSemantics.CANDIDATE for event in futex)
    lock_ids = {
        event.lock_id if isinstance(event, LockEvent) else event.futex_id
        for event in result.events
        if isinstance(event, (LockEvent, FutexEvent))
    }
    assert all(lock_id.startswith("lock-") and len(lock_id) == 25 for lock_id in lock_ids)

    serialized = repr(result).encode("utf-8")
    for private_value in (
        b"0xffff888001234000",
        b"0xffff888001234002",
        b"0x7fff12345000",
        b"0xdeadbeefcafefeed",
        b"9777",
        b"9888",
        b"legacy_mutex",
    ):
        assert private_value not in serialized

    stats = result.statistics
    assert stats.input_event_count == 16
    assert stats.emitted_event_count == 11
    assert stats.unsupported_event_count == 3
    assert stats.lock_phase_enrichment_event_count == 1
    assert stats.foreign_event_dropped_count == 1
    assert stats.partial


def test_lock_ids_are_stable_only_within_one_artifact(tmp_path: Path) -> None:
    transcript = tmp_path / "lock.perf-script"
    transcript.write_text(
        "4242/4243 [000] 1.000000001: lock:contention_begin: "
        "0x1234 (flags=MUTEX)\n"
        "4242/4243 [000] 1.000000002: lock:contention_end: "
        "0x1234 (ret=0)\n",
        encoding="ascii",
    )
    transcript.chmod(0o600)

    first = _adapter("lock", key=b"a" * 32).parse(transcript)
    second = _adapter("lock", key=b"b" * 32).parse(transcript)
    first_ids = [event.lock_id for event in first.events if isinstance(event, LockEvent)]
    second_ids = [event.lock_id for event in second.events if isinstance(event, LockEvent)]

    assert first_ids[0] == first_ids[1]
    assert second_ids[0] == second_ids[1]
    assert first_ids[0] != second_ids[0]


def test_audited_lock_phase_changes_merge_into_one_wait(tmp_path: Path) -> None:
    transcript = tmp_path / "lock-phases.perf-script"
    transcript.write_text(
        "4242/4243 [000] 1.000000001: lock:contention_begin: "
        "0x1234 (flags=SPIN)\n"
        "4242/4243 [000] 1.000000002: lock:contention_begin: "
        "0x1234 (flags=MUTEX)\n"
        "4242/4243 [000] 1.000000003: lock:contention_begin: "
        "0x1234 (flags=SPIN)\n"
        "4242/4243 [000] 1.000000004: lock:contention_end: "
        "0x1234 (ret=0)\n",
        encoding="ascii",
    )
    transcript.chmod(0o600)

    result = _adapter("lock").parse(transcript)

    assert [event.kind.value for event in result.events] == [
        "lock_wait",
        "lock_wait_ended",
    ]
    ended = result.events[-1]
    assert isinstance(ended, LockEvent)
    assert ended.wait_outcome is LockWaitOutcome.ACQUIRED
    assert result.statistics.lock_phase_enrichment_event_count == 2
    assert result.statistics.unsupported_event_count == 0
    assert not result.statistics.partial


def test_rejects_nonfixed_manifest_and_unsorted_target_tids() -> None:
    with pytest.raises(ValueError, match="fixed event-only manifest"):
        FixedTracePerfScriptAdapter(
            target=TARGET,
            observed_target_tids=TARGET_TIDS,
            expected_input_owner_uid=os.getuid(),
            expected_input_owner_gid=os.getgid(),
            expected_input_mode=0o600,
            mode="sched",
            manifest_fields="comm,pid,tid,cpu,time,event,trace",
        )
    with pytest.raises(ValueError, match="sorted unique"):
        FixedTracePerfScriptAdapter(
            target=TARGET,
            observed_target_tids=(4243, 4242),
            expected_input_owner_uid=os.getuid(),
            expected_input_owner_gid=os.getgid(),
            expected_input_mode=0o600,
            mode="sched",
            manifest_fields=TRACE_PERF_SCRIPT_FIELDS,
        )


def test_private_input_rejects_symlink_writable_file_and_owner_mismatch(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "secure.perf-script"
    transcript.write_text(
        "4242/4243 [000] 1.000000001: sched:sched_wakeup: "
        "comm=worker pid=4243 prio=120 target_cpu=0\n",
        encoding="ascii",
    )
    transcript.chmod(0o600)
    symlink = tmp_path / "trace-link.perf-script"
    symlink.symlink_to(transcript)

    with pytest.raises(PerfLensError) as linked:
        _adapter("sched").parse(symlink)
    assert linked.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    transcript.chmod(0o620)
    with pytest.raises(PerfLensError) as writable:
        _adapter("sched").parse(transcript)
    assert writable.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    transcript.chmod(0o600)
    wrong_owner = FixedTracePerfScriptAdapter(
        target=TARGET,
        observed_target_tids=TARGET_TIDS,
        expected_input_owner_uid=os.getuid() + 1,
        expected_input_owner_gid=os.getgid(),
        expected_input_mode=0o600,
        mode="sched",
    )
    with pytest.raises(PerfLensError) as owner:
        wrong_owner.parse(transcript)
    assert owner.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    wrong_group = FixedTracePerfScriptAdapter(
        target=TARGET,
        observed_target_tids=TARGET_TIDS,
        expected_input_owner_uid=os.getuid(),
        expected_input_owner_gid=os.getgid() + 1,
        expected_input_mode=0o600,
        mode="sched",
    )
    with pytest.raises(PerfLensError) as group:
        wrong_group.parse(transcript)
    assert group.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    transcript.chmod(0o640)
    group_private = FixedTracePerfScriptAdapter(
        target=TARGET,
        observed_target_tids=TARGET_TIDS,
        expected_input_owner_uid=os.getuid(),
        expected_input_owner_gid=os.getgid(),
        expected_input_mode=0o640,
        mode="sched",
    )
    assert len(group_private.parse(transcript).events) == 1


def test_futex_operation_subtypes_are_preserved(tmp_path: Path) -> None:
    transcript = tmp_path / "futex.perf-script"
    operations = (0, 9, 11, 1, 10, 3)
    transcript.write_text(
        "".join(
            f"4242/4243 [000] 1.{index:09d}: syscalls:sys_enter_futex: "
            f"__syscall_nr: 202, uaddr: 0x1234, op: 0x{operation:x}, val: 0x1\n"
            for index, operation in enumerate(operations, start=1)
        ),
        encoding="ascii",
    )
    transcript.chmod(0o600)

    result = _adapter("lock").parse(transcript)

    assert [event.operation for event in result.events if isinstance(event, FutexEvent)] == [
        FutexOperation.WAIT,
        FutexOperation.WAIT_BITSET,
        FutexOperation.WAIT_REQUEUE_PI,
        FutexOperation.WAKE,
        FutexOperation.WAKE_BITSET,
        FutexOperation.REQUEUE,
    ]


def test_prefixed_lost_record_is_counted_without_exporting_prefix_metadata(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "lost.perf-script"
    transcript.write_bytes(
        b"9777/9888 [006] 1.000000001: unknown: PERF_RECORD_LOST lost 9\n"
    )
    transcript.chmod(0o600)

    result = _adapter("sched").parse(transcript)

    assert result.events == ()
    assert result.statistics.lost_event_count == 9
    serialized = repr(result).encode("utf-8")
    assert b"9777" not in serialized
    assert b"9888" not in serialized


def test_lost_record_invalidates_pending_waker_and_lock_begin(tmp_path: Path) -> None:
    scheduler = tmp_path / "lost-sched.perf-script"
    scheduler.write_text(
        "9777/9888 [000] 1.000000001: sched:sched_waking: "
        "comm=worker pid=4243 prio=120 target_cpu=0\n"
        "PERF_RECORD_LOST lost 1\n"
        "9777/9888 [000] 1.000000002: sched:sched_wakeup: "
        "comm=worker pid=4243 prio=120 target_cpu=0\n",
        encoding="ascii",
    )
    scheduler.chmod(0o600)
    sched_result = _adapter("sched").parse(scheduler)
    wakeup = sched_result.events[0]
    assert isinstance(wakeup, SchedWakeupEvent)
    assert wakeup.waker is None
    assert sched_result.statistics.provisional_enrichment_event_count == 0
    assert sched_result.statistics.unsupported_event_count == 1

    lock = tmp_path / "lost-lock.perf-script"
    lock.write_text(
        "4242/4243 [000] 1.000000001: lock:contention_begin: "
        "0x1234 (flags=MUTEX)\n"
        "PERF_RECORD_LOST lost 1\n"
        "4242/4243 [000] 1.000000002: lock:contention_end: "
        "0x1234 (ret=0)\n",
        encoding="ascii",
    )
    lock.chmod(0o600)
    lock_result = _adapter("lock").parse(lock)
    ended = lock_result.events[-1]
    assert isinstance(ended, LockEvent)
    assert ended.wait_outcome is LockWaitOutcome.UNKNOWN


def test_overlong_lines_and_event_limits_are_bounded(tmp_path: Path) -> None:
    transcript = tmp_path / "bounded.perf-script"
    transcript.write_text(
        "x" * 140
        + "\n"
        + "4242/4243 [000] 1.000000001: sched:sched_wakeup: "
        + "comm=worker pid=4243 prio=120 target_cpu=0\n"
        + "4242/4243 [000] 1.000000002: sched:sched_wakeup: "
        + "comm=worker pid=4243 prio=120 target_cpu=0\n",
        encoding="ascii",
    )
    transcript.chmod(0o600)
    limits = ResourceLimits(max_line_chars=128, max_events=2)

    result = _adapter("sched", limits=limits).parse(transcript)

    assert len(result.events) == 1
    assert result.statistics.malformed_event_count == 1
    assert result.statistics.truncated_event_count == 1
    assert len(result.statistics.diagnostics) <= limits.max_warnings


def test_input_byte_and_line_limits_fail_closed(tmp_path: Path) -> None:
    transcript = tmp_path / "too-large.perf-script"
    transcript.write_text("\n" * 5, encoding="ascii")
    transcript.chmod(0o600)

    with pytest.raises(PerfLensError) as captured:
        _adapter("sched", limits=ResourceLimits(max_input_lines=2)).parse(transcript)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_identical_records_are_not_guessed_duplicate_but_out_of_order_is_visible(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "ordering.perf-script"
    first = (
        "4242/4243 [000] 2.000000000: sched:sched_wakeup: "
        "comm=worker pid=4243 prio=120 target_cpu=0\n"
    )
    transcript.write_text(
        first
        + first
        + "4242/4243 [000] 1.000000000: sched:sched_wakeup: "
        + "comm=worker pid=4243 prio=120 target_cpu=0\n",
        encoding="ascii",
    )
    transcript.chmod(0o600)

    result = _adapter("sched").parse(transcript)

    assert len(result.events) == 2
    assert result.statistics.duplicate_event_count == 0
    assert result.statistics.out_of_order_event_count == 1


def test_comm_with_fake_labels_is_rejected_without_echoing_source(tmp_path: Path) -> None:
    transcript = tmp_path / "ambiguous.perf-script"
    transcript.write_bytes(
        b"4242/4243 [000] 1.000000000: sched:sched_switch: "
        b"prev_comm=x prev_pid=9 prev_pid=4243 prev_prio=120 prev_state=S ==> "
        b"next_comm=foreign-secret next_pid=9888 next_prio=120\n"
    )
    transcript.chmod(0o600)

    result = _adapter("sched").parse(transcript)

    assert result.events == ()
    assert result.statistics.malformed_event_count == 1
    assert b"foreign-secret" not in repr(result).encode("utf-8")
    assert b"9888" not in repr(result).encode("utf-8")
