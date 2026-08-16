from __future__ import annotations

import pytest

from perflens.domain.trace import (
    EvidenceSemantics,
    LockAction,
    LockEvent,
    SchedMigrateEvent,
    SchedSwitchEvent,
    SchedWakeupEvent,
    TargetIdentity,
    TaskIdentity,
    TraceEvent,
    TraceScope,
    WakeupSource,
)
from perflens.domain.trace_analysis import (
    AnalysisLimits,
    IncompleteReason,
    IntervalCompleteness,
    WaitCategory,
    analyze_scheduler_and_off_cpu,
    nearest_rank_percentile,
)

TARGET = TargetIdentity(pid=1200, uid=1000, start_time_ticks=900)
TARGET_TASK = TaskIdentity(pid=1200, tid=1201)
FOREIGN_TASK = TaskIdentity.external_redacted()


def _switch_in(event_id: str, sequence: int, timestamp_ns: int, *, cpu: int = 0):
    return SchedSwitchEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        cpu=cpu,
        previous=FOREIGN_TASK,
        previous_scope=TraceScope.FOREIGN,
        next=TARGET_TASK,
        next_scope=TraceScope.TARGET,
        previous_state="running",
    )


def _switch_out(event_id: str, sequence: int, timestamp_ns: int, *, cpu: int = 0):
    return SchedSwitchEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        cpu=cpu,
        previous=TARGET_TASK,
        previous_scope=TraceScope.TARGET,
        next=FOREIGN_TASK,
        next_scope=TraceScope.FOREIGN,
        previous_state="interruptible_sleep",
    )


def _wakeup(event_id: str, sequence: int, timestamp_ns: int):
    return SchedWakeupEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        woken=TARGET_TASK,
        woken_scope=TraceScope.TARGET,
        waker=FOREIGN_TASK,
        waker_scope=TraceScope.FOREIGN,
        source=WakeupSource.WAKEUP,
    )


def _complete_cycle() -> tuple[TraceEvent, ...]:
    return (
        _switch_in("in-1", 1, 10, cpu=0),
        _switch_out("out-1", 2, 20, cpu=0),
        _wakeup("wake-1", 3, 50),
        _switch_in("in-2", 4, 70, cpu=1),
        _switch_out("out-2", 5, 100, cpu=1),
    )


def test_explicit_migration_is_counted_once_and_not_duplicated_by_switch_in() -> None:
    events = (
        _switch_out("out", 1, 10, cpu=1),
        SchedMigrateEvent(
            event_id="migrate",
            sequence=2,
            timestamp_ns=20,
            target=TARGET,
            semantics=EvidenceSemantics.EXACT,
            task=TARGET_TASK,
            task_scope=TraceScope.TARGET,
            origin_cpu=1,
            destination_cpu=2,
        ),
        _wakeup("wake", 3, 30),
        _switch_in("in", 4, 40, cpu=2),
    )

    scheduler, _off_cpu = analyze_scheduler_and_off_cpu(events)

    assert scheduler.threads[0].migration_count == 1
    assert "migrate" in scheduler.event_accounting.consumed.ids


def test_scheduler_and_off_cpu_measure_only_complete_target_intervals() -> None:
    scheduler, off_cpu = analyze_scheduler_and_off_cpu(_complete_cycle())

    assert scheduler.target == TARGET
    assert len(scheduler.threads) == 1
    thread = scheduler.threads[0]
    assert thread.tid == TARGET_TASK.tid
    assert thread.switch_in_count == 2
    assert thread.switch_out_count == 2
    assert thread.migration_count == 1
    assert thread.runtime.sample_count == 2
    assert thread.runtime.total_ns == 40
    assert thread.runtime.minimum_ns == 10
    assert thread.runtime.mean_ns == 20
    assert thread.runtime.p50_ns == 10
    assert thread.runtime.p95_ns == 30
    assert thread.runnable_latency.sample_count == 1
    assert thread.runnable_latency.total_ns == 20

    assert off_cpu.complete_interval_count == 1
    assert off_cpu.incomplete_interval_count == 2
    assert off_cpu.split_complete_interval_count == 1
    complete = next(
        interval
        for interval in off_cpu.worst_intervals
        if interval.completeness is IntervalCompleteness.COMPLETE
    )
    assert complete.tid == TARGET_TASK.tid
    assert complete.total_duration_ns == 50
    assert complete.blocked_duration_ns == 30
    assert complete.runnable_duration_ns == 20
    assert complete.wakeup_event_ids == ("wake-1",)
    assert complete.candidate_wait_category is WaitCategory.SLEEP
    assert complete.switch_out_stack == ()
    assert complete.waker_target_tid is None
    assert off_cpu.threads[0].off_cpu.total_ns == 50
    assert off_cpu.threads[0].blocked.total_ns == 30
    assert off_cpu.threads[0].runnable.total_ns == 20
    assert tuple(
        (row.category, row.interval_count)
        for row in off_cpu.threads[0].candidate_categories
    ) == ((WaitCategory.SLEEP, 1),)

    accounting = scheduler.event_accounting
    assert accounting.observed_event_count == 5
    assert accounting.consumed.ids == ("in-1", "out-1", "wake-1", "in-2", "out-2")
    assert accounting.unpaired.total_count == 0
    assert accounting.ignored.total_count == 0


def test_missing_wakeup_keeps_wait_split_unknown() -> None:
    events = (
        _switch_out("out", 1, 10),
        _switch_in("in", 2, 40),
    )

    scheduler, off_cpu = analyze_scheduler_and_off_cpu(events)

    assert scheduler.runnable_latency_interval_count == 0
    missing = next(
        interval
        for interval in off_cpu.worst_intervals
        if interval.incomplete_reason is IncompleteReason.MISSING_WAKEUP
    )
    assert missing.completeness is IntervalCompleteness.COMPLETE
    assert not missing.split_complete
    assert missing.total_duration_ns == 30
    assert missing.wakeup_timestamp_ns is None
    assert missing.blocked_duration_ns is None
    assert missing.runnable_duration_ns is None
    assert missing.unknown_duration_ns == 30
    assert off_cpu.total_complete_interval_count == 1
    assert off_cpu.split_complete_interval_count == 0
    assert off_cpu.threads[0].off_cpu.total_ns == 30
    assert off_cpu.threads[0].unknown.total_ns == 30


def test_duplicate_wakeup_does_not_choose_a_latency_or_wait_split() -> None:
    events = (
        _switch_out("out", 1, 10),
        _wakeup("wake-1", 2, 20),
        _wakeup("wake-2", 3, 21),
        _switch_in("in", 4, 30),
    )

    scheduler, off_cpu = analyze_scheduler_and_off_cpu(events)

    assert scheduler.runnable_latency_interval_count == 0
    duplicate = next(
        interval
        for interval in off_cpu.worst_intervals
        if interval.incomplete_reason is IncompleteReason.DUPLICATE_WAKEUP
    )
    assert duplicate.total_duration_ns == 20
    assert duplicate.wakeup_timestamp_ns is None
    assert duplicate.blocked_duration_ns is None
    assert duplicate.runnable_duration_ns is None
    assert duplicate.unknown_duration_ns == 20
    assert duplicate.wakeup_event_ids == ("wake-1", "wake-2")
    assert {warning.code for warning in scheduler.event_accounting.warnings} >= {
        "duplicate_wakeup"
    }


def test_trace_end_boundary_is_incomplete_but_preserves_directly_measured_prefix() -> None:
    events = (
        _switch_out("out", 1, 10),
        _wakeup("wake", 2, 25),
    )

    _, off_cpu = analyze_scheduler_and_off_cpu(events)

    interval = off_cpu.worst_intervals[0]
    assert interval.incomplete_reason is IncompleteReason.TRACE_END_BOUNDARY
    assert interval.total_duration_ns is None
    assert interval.blocked_duration_ns is None
    assert interval.observed_blocked_prefix_ns == 15
    assert interval.runnable_duration_ns is None
    assert interval.switch_in_timestamp_ns is None


def test_foreign_identity_is_not_exposed_in_analysis_results() -> None:
    lock = LockEvent(
        event_id="lock",
        sequence=6,
        timestamp_ns=110,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=TraceScope.TARGET,
        action=LockAction.WAIT,
        lock_id="lock-sha256-1234",
        owner=FOREIGN_TASK,
        owner_scope=TraceScope.FOREIGN,
    )
    scheduler, off_cpu = analyze_scheduler_and_off_cpu((*_complete_cycle(), lock))

    assert scheduler.event_accounting.ignored.ids == ("lock",)
    assert off_cpu.event_accounting.ignored.ids == ("lock",)
    assert "2200" not in repr(scheduler)
    assert "2201" not in repr(scheduler)
    assert "2200" not in repr(off_cpu)
    assert "2201" not in repr(off_cpu)


def test_sequence_validation_rejects_time_reversal_before_analysis() -> None:
    events = (
        _switch_out("out", 1, 20),
        _wakeup("wake", 2, 19),
    )

    with pytest.raises(ValueError, match="must not move backwards"):
        analyze_scheduler_and_off_cpu(events)


def test_nearest_rank_percentiles_are_fixed_and_deterministic() -> None:
    values = (4, 1, 3, 2)

    assert nearest_rank_percentile(values, 50) == 2
    assert nearest_rank_percentile(values, 95) == 4
    assert nearest_rank_percentile(values, 99) == 4
    with pytest.raises(ValueError, match="at least one"):
        nearest_rank_percentile((), 50)
    with pytest.raises(ValueError, match=r"1\.\.100"):
        nearest_rank_percentile(values, 0)


def test_worst_intervals_and_event_ledgers_are_bounded() -> None:
    scheduler, off_cpu = analyze_scheduler_and_off_cpu(
        _complete_cycle(),
        limits=AnalysisLimits(max_worst_intervals=1, max_event_ids=1),
    )

    assert len(scheduler.worst_runtime_intervals) == 1
    assert scheduler.worst_runtime_intervals[0].duration_ns == 30
    assert len(scheduler.worst_runnable_latencies) == 1
    assert len(off_cpu.worst_intervals) == 1
    assert scheduler.event_accounting.consumed.total_count == 5
    assert len(scheduler.event_accounting.consumed.ids) == 1
    assert scheduler.event_accounting.consumed.truncated
    assert scheduler.event_accounting.unpaired.total_count == 0
    assert not scheduler.event_accounting.unpaired.truncated


def test_analysis_interval_limit_fails_closed() -> None:
    with pytest.raises(ValueError, match="max_intervals"):
        analyze_scheduler_and_off_cpu(
            _complete_cycle(),
            limits=AnalysisLimits(max_intervals=1),
        )


def test_duplicate_switch_in_is_never_paired_as_runtime() -> None:
    events = (
        _switch_in("in-1", 1, 10),
        _switch_in("in-2", 2, 20),
        _switch_out("out", 3, 30),
    )

    scheduler, _ = analyze_scheduler_and_off_cpu(events)

    assert scheduler.runtime_interval_count == 0
    assert "in-1" in scheduler.event_accounting.unpaired.ids
    assert "in-2" in scheduler.event_accounting.unpaired.ids
    assert "out" in scheduler.event_accounting.unpaired.ids


def test_overlapping_switch_out_preserves_only_directly_observed_prefix() -> None:
    events = (
        _switch_out("out-1", 1, 10),
        _wakeup("wake", 2, 20),
        _switch_out("out-2", 3, 30),
    )

    _, off_cpu = analyze_scheduler_and_off_cpu(events)

    overlap = next(
        interval
        for interval in off_cpu.worst_intervals
        if interval.incomplete_reason is IncompleteReason.OVERLAPPING_SWITCH_OUT
    )
    assert overlap.switch_out_timestamp_ns == 10
    assert overlap.wakeup_timestamp_ns == 20
    assert overlap.blocked_duration_ns is None
    assert overlap.observed_blocked_prefix_ns == 10
    assert overlap.total_duration_ns is None
    assert overlap.runnable_duration_ns is None
    assert overlap.wakeup_event_ids == ("wake",)
