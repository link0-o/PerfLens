from __future__ import annotations

from dataclasses import replace

import pytest

from perflens.domain.trace import (
    EvidenceSemantics,
    FutexAction,
    FutexEvent,
    LockAction,
    LockEvent,
    LockWaitOutcome,
    ResourceLimits,
    SchedMigrateEvent,
    SchedSwitchEvent,
    SchedWakeupEvent,
    TargetIdentity,
    TaskIdentity,
    TraceScope,
    WakeupSource,
    validate_trace_event,
    validate_trace_sequence,
)

TARGET = TargetIdentity(pid=1200, uid=1000, start_time_ticks=400)
TARGET_TASK = TaskIdentity(pid=1200, tid=1201)
FOREIGN_TASK = TaskIdentity.external_redacted()


def _switch(*, event_id: str = "event-1", sequence: int = 1, timestamp_ns: int = 10):
    return SchedSwitchEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        cpu=2,
        stack=("worker", "schedule"),
        previous=TARGET_TASK,
        previous_scope=TraceScope.TARGET,
        next=FOREIGN_TASK,
        next_scope=TraceScope.FOREIGN,
        previous_state="S",
    )


def _wakeup(*, event_id: str = "event-2", sequence: int = 2, timestamp_ns: int = 20):
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
        source=WakeupSource.WAKING,
    )


def _migrate(*, event_id: str = "event-4", sequence: int = 4, timestamp_ns: int = 40):
    return SchedMigrateEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=TraceScope.TARGET,
        origin_cpu=2,
        destination_cpu=3,
    )


def _futex(*, event_id: str = "event-3", sequence: int = 3, timestamp_ns: int = 30):
    return FutexEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=EvidenceSemantics.CANDIDATE,
        task=TARGET_TASK,
        task_scope=TraceScope.TARGET,
        action=FutexAction.WAIT,
        futex_id="futex-sha256-1234",
    )


def test_valid_trace_sequence_reports_bounded_quality_diagnostics() -> None:
    events = (_switch(), _wakeup(), _futex())

    stats = validate_trace_sequence(
        events,
        expected_target=TARGET,
        input_line_count=7,
        output_bytes=512,
    )

    assert stats.event_count == 3
    assert stats.input_line_count == 7
    assert stats.output_bytes == 512
    assert stats.first_timestamp_ns == 10
    assert stats.last_timestamp_ns == 30
    assert stats.unique_tid_count == 1
    assert stats.unique_lock_count == 1
    assert stats.exact_event_count == 2
    assert stats.candidate_event_count == 1
    assert stats.target_scope_event_count == 3
    assert stats.foreign_scope_event_count == 2
    assert stats.warning_count == 2
    assert [warning.code for warning in stats.warnings] == [
        "candidate_evidence_present",
        "foreign_scope_present",
    ]
    assert not stats.warnings_truncated


@pytest.mark.parametrize(
    ("events", "message"),
    [
        ((_switch(), _wakeup(event_id="event-1")), "duplicate trace event_id"),
        ((_switch(sequence=2), _wakeup(sequence=2)), "strictly increasing"),
        ((_switch(timestamp_ns=20), _wakeup(timestamp_ns=19)), "must not move backwards"),
        (
            (
                _switch(),
                replace(
                    _wakeup(),
                    target=TargetIdentity(pid=1200, uid=1000, start_time_ticks=401),
                ),
            ),
            "target identity changed",
        ),
    ],
)
def test_trace_sequence_rejects_identity_and_ordering_errors(
    events: tuple[SchedSwitchEvent | SchedWakeupEvent, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_trace_sequence(events)


def test_scopes_must_match_the_bound_target_identity() -> None:
    invalid = replace(_switch(), previous_scope=TraceScope.FOREIGN)

    with pytest.raises(ValueError, match="already be redacted"):
        validate_trace_event(invalid)


def test_waker_identity_and_scope_are_an_atomic_pair() -> None:
    invalid = replace(_wakeup(), waker_scope=None)

    with pytest.raises(ValueError, match="both be present"):
        validate_trace_event(invalid)


def test_sched_migrate_is_exact_target_scoped_and_changes_cpu() -> None:
    validate_trace_event(_migrate())

    with pytest.raises(ValueError, match="must differ"):
        validate_trace_event(replace(_migrate(), destination_cpu=2))
    with pytest.raises(ValueError, match="already be redacted"):
        validate_trace_event(
            replace(
                _migrate(),
                task=TaskIdentity(pid=2200, tid=2201),
                task_scope=TraceScope.FOREIGN,
            )
        )


@pytest.mark.parametrize(
    ("event", "message"),
    [
        (replace(_switch(), timestamp_ns=-1), "timestamp_ns"),
        (
            replace(_switch(), previous=TaskIdentity(pid=1200, tid=0)),
            "previous.tid",
        ),
        (replace(_switch(), stack=("valid", "bad\nframe")), "control character"),
    ],
)
def test_trace_event_rejects_invalid_scalars(
    event: SchedSwitchEvent,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_trace_event(event)


def test_futex_evidence_cannot_claim_exact_high_level_lock_semantics() -> None:
    invalid = replace(_futex(), semantics=EvidenceSemantics.EXACT)

    with pytest.raises(ValueError, match="must remain candidate"):
        validate_trace_event(invalid)


def test_lock_owner_and_acquire_release_semantics_are_not_fabricated() -> None:
    acquired = LockEvent(
        event_id="lock-1",
        sequence=1,
        timestamp_ns=1,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=TraceScope.TARGET,
        action=LockAction.ACQUIRED,
        lock_id="lock-sha256-1234",
        owner=FOREIGN_TASK,
        owner_scope=TraceScope.FOREIGN,
    )

    with pytest.raises(ValueError, match="only for lock wait"):
        validate_trace_event(acquired)

    with pytest.raises(ValueError, match="must be exact"):
        validate_trace_event(
            replace(acquired, owner=None, owner_scope=None, semantics=EvidenceSemantics.CANDIDATE)
        )

    with pytest.raises(ValueError, match="wait_outcome is required"):
        validate_trace_event(
            replace(acquired, action=LockAction.WAIT_ENDED, owner=None, owner_scope=None)
        )

    wait_ended = replace(
        acquired,
        action=LockAction.WAIT_ENDED,
        owner=None,
        owner_scope=None,
        wait_outcome=LockWaitOutcome.TIMED_OUT,
    )
    validate_trace_event(wait_ended)
    with pytest.raises(ValueError, match="required only"):
        validate_trace_event(replace(wait_ended, action=LockAction.RELEASED))


def test_foreign_task_identity_must_be_redacted_before_domain_validation() -> None:
    event = replace(
        _switch(),
        previous=TaskIdentity(pid=2200, tid=2201),
        previous_scope=TraceScope.FOREIGN,
    )

    with pytest.raises(ValueError, match="already be redacted"):
        validate_trace_event(event)


def test_resource_limits_reject_non_positive_values() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        ResourceLimits(max_warnings=0)


def test_sequence_enforces_event_tid_lock_line_stack_and_output_bounds() -> None:
    with pytest.raises(ValueError, match="max_events"):
        validate_trace_sequence((_switch(), _wakeup()), limits=ResourceLimits(max_events=1))
    second_target = replace(
        _switch(),
        next=TaskIdentity(pid=1200, tid=1202),
        next_scope=TraceScope.TARGET,
    )
    with pytest.raises(ValueError, match="max_unique_tids"):
        validate_trace_sequence((second_target,), limits=ResourceLimits(max_unique_tids=1))
    with pytest.raises(ValueError, match="max_unique_locks"):
        validate_trace_sequence(
            (
                _futex(),
                replace(_futex(), event_id="event-4", sequence=4, futex_id="futex-other"),
            ),
            limits=ResourceLimits(max_unique_locks=1),
        )
    with pytest.raises(ValueError, match="max_input_lines"):
        validate_trace_sequence((), input_line_count=2, limits=ResourceLimits(max_input_lines=1))
    with pytest.raises(ValueError, match="max_output_bytes"):
        validate_trace_sequence((), output_bytes=2, limits=ResourceLimits(max_output_bytes=1))
    with pytest.raises(ValueError, match="max_stack_depth"):
        validate_trace_event(
            replace(_switch(), stack=("one", "two")),
            limits=ResourceLimits(max_stack_depth=1),
        )


def test_diagnostics_are_bounded_even_when_multiple_warnings_apply() -> None:
    stats = validate_trace_sequence(
        (_futex(),),
        limits=ResourceLimits(max_warnings=1),
    )

    # This event has candidate semantics, but no foreign task metadata.
    assert stats.warning_count == 1
    assert len(stats.warnings) == 1
    assert not stats.warnings_truncated

    stats = validate_trace_sequence(
        (_switch(), _futex()),
        limits=ResourceLimits(max_warnings=1),
    )
    assert stats.warning_count == 2
    assert len(stats.warnings) == 1
    assert stats.warnings_truncated
