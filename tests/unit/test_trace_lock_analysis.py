from __future__ import annotations

import pytest

from perflens.domain.trace import (
    EvidenceSemantics,
    FutexAction,
    FutexEvent,
    LockAction,
    LockEvent,
    LockWaitOutcome,
    SchedSwitchEvent,
    TargetIdentity,
    TaskIdentity,
    TraceEvent,
    TraceScope,
)
from perflens.domain.trace_lock_analysis import (
    CandidateAction,
    LockAnalysisLimits,
    LockPairingPhase,
    LockPairingReason,
    LockQualityStatus,
    OwnerEvidence,
    analyze_locks,
)

TARGET = TargetIdentity(pid=1200, uid=1000, start_time_ticks=900)
WAITER = TaskIdentity(pid=1200, tid=1201)
TARGET_OWNER = TaskIdentity(pid=1200, tid=1202)
FOREIGN_OWNER = TaskIdentity.external_redacted()
LOCK_ID = "lock-sha256-1234"


def _lock(
    event_id: str,
    sequence: int,
    timestamp_ns: int,
    action: LockAction,
    *,
    semantics: EvidenceSemantics = EvidenceSemantics.EXACT,
    owner: TaskIdentity | None = None,
    owner_scope: TraceScope | None = None,
    lock_id: str = LOCK_ID,
    stack: tuple[str, ...] = ("worker", "mutex"),
    wait_outcome: LockWaitOutcome | None = None,
) -> LockEvent:
    return LockEvent(
        event_id=event_id,
        sequence=sequence,
        timestamp_ns=timestamp_ns,
        target=TARGET,
        semantics=semantics,
        task=WAITER,
        task_scope=TraceScope.TARGET,
        action=action,
        lock_id=lock_id,
        wait_outcome=wait_outcome,
        owner=owner,
        owner_scope=owner_scope,
        stack=stack,
    )


def _exact_cycle() -> tuple[TraceEvent, ...]:
    return (
        _lock(
            "wait",
            1,
            10,
            LockAction.WAIT,
            owner=TARGET_OWNER,
            owner_scope=TraceScope.TARGET,
        ),
        _lock("acquire", 2, 30, LockAction.ACQUIRED),
        _lock("release", 3, 80, LockAction.RELEASED),
    )


def test_exact_wait_and_hold_are_independently_paired_and_conserved() -> None:
    analysis = analyze_locks(_exact_cycle())

    assert analysis.quality_status is LockQualityStatus.COMPLETE
    assert analysis.exact_wait.sample_count == 1
    assert analysis.exact_wait.total_ns == 20
    assert analysis.exact_hold.sample_count == 1
    assert analysis.exact_hold.total_ns == 50
    assert analysis.exact_wait_interval_count == 1
    assert analysis.exact_hold_interval_count == 1
    assert analysis.worst_wait_intervals[0].owner_evidence is OwnerEvidence.TARGET
    assert analysis.worst_wait_intervals[0].owner_tid == TARGET_OWNER.tid
    assert analysis.worst_hold_intervals[0].duration_ns == 50
    assert analysis.event_accounting.consumed.total_count == 3
    assert analysis.event_accounting.unpaired.total_count == 0
    assert analysis.projection_conservation_passed
    assert tuple((row.outcome, row.count) for row in analysis.wait_outcomes) == (
        (LockWaitOutcome.ACQUIRED, 1),
    )

    for rows in (analysis.locks, analysis.threads, analysis.paths):
        assert sum(row.exact_wait.total_ns for row in rows) == analysis.exact_wait.total_ns
        assert sum(row.exact_hold.total_ns for row in rows) == analysis.exact_hold.total_ns
        assert sum(row.candidate_event_count for row in rows) == 0


def test_foreign_owner_is_redacted_not_guessed() -> None:
    events = (
        _lock(
            "wait",
            1,
            10,
            LockAction.WAIT,
            owner=FOREIGN_OWNER,
            owner_scope=TraceScope.FOREIGN,
        ),
        _lock("acquire", 2, 20, LockAction.ACQUIRED),
        _lock("release", 3, 30, LockAction.RELEASED),
    )

    analysis = analyze_locks(events)

    wait = analysis.worst_wait_intervals[0]
    assert wait.owner_evidence is OwnerEvidence.FOREIGN_REDACTED
    assert wait.owner_tid is None
    assert "2200" not in repr(analysis)
    assert "2201" not in repr(analysis)


def test_missing_release_never_reports_hold_duration() -> None:
    events = (
        _lock("wait", 1, 10, LockAction.WAIT),
        _lock("acquire", 2, 30, LockAction.ACQUIRED),
    )

    analysis = analyze_locks(events)

    assert analysis.exact_wait.total_ns == 20
    assert analysis.exact_hold.sample_count == 0
    assert analysis.exact_hold.total_ns == 0
    assert analysis.quality_status is LockQualityStatus.PARTIAL
    assert any(
        issue.phase is LockPairingPhase.HOLD
        and issue.reason is LockPairingReason.TRACE_END_BOUNDARY
        for issue in analysis.incomplete_pairings
    )
    assert "acquire" in analysis.event_accounting.consumed.ids


def test_unsuccessful_wait_end_keeps_exact_duration_without_fabricating_hold() -> None:
    events = (
        _lock("wait", 1, 10, LockAction.WAIT),
        _lock(
            "interrupted",
            2,
            35,
            LockAction.WAIT_ENDED,
            wait_outcome=LockWaitOutcome.INTERRUPTED,
        ),
    )

    analysis = analyze_locks(events)

    assert analysis.exact_wait.total_ns == 25
    assert analysis.exact_hold.sample_count == 0
    assert analysis.worst_wait_intervals[0].outcome is LockWaitOutcome.INTERRUPTED
    assert tuple((row.outcome, row.count) for row in analysis.wait_outcomes) == (
        (LockWaitOutcome.INTERRUPTED, 1),
    )
    assert analysis.event_accounting.consumed.ids == ("wait", "interrupted")
    assert analysis.quality_status is LockQualityStatus.COMPLETE


def test_unknown_wait_end_outcome_is_partial_but_never_acquired() -> None:
    events = (
        _lock("wait", 1, 10, LockAction.WAIT),
        _lock(
            "unknown-end",
            2,
            30,
            LockAction.WAIT_ENDED,
            wait_outcome=LockWaitOutcome.UNKNOWN,
        ),
    )

    analysis = analyze_locks(events)

    assert analysis.exact_wait.total_ns == 20
    assert analysis.exact_hold.sample_count == 0
    assert analysis.quality_status is LockQualityStatus.PARTIAL


def test_release_without_acquire_is_partial_and_has_no_hold_time() -> None:
    analysis = analyze_locks((_lock("release", 1, 20, LockAction.RELEASED),))

    assert analysis.exact_hold.sample_count == 0
    assert analysis.incomplete_pairing_count == 1
    assert analysis.incomplete_pairings[0].reason is LockPairingReason.RELEASE_WITHOUT_ACQUIRE
    assert analysis.event_accounting.unpaired.ids == ("release",)


def test_duplicate_wait_does_not_choose_one_for_exact_contention() -> None:
    events = (
        _lock("wait-1", 1, 10, LockAction.WAIT),
        _lock("wait-2", 2, 11, LockAction.WAIT),
        _lock("acquire", 3, 30, LockAction.ACQUIRED),
        _lock("release", 4, 40, LockAction.RELEASED),
    )

    analysis = analyze_locks(events)

    assert analysis.exact_wait.sample_count == 0
    assert analysis.exact_hold.total_ns == 10
    assert analysis.incomplete_pairings[0].reason is LockPairingReason.DUPLICATE_WAIT
    assert set(analysis.event_accounting.unpaired.ids) == {"wait-1", "wait-2"}
    assert analysis.event_accounting.consumed.ids == ("acquire", "release")


def test_futex_and_candidate_waits_never_mix_with_exact_contention() -> None:
    futex_wait = FutexEvent(
        event_id="futex-wait",
        sequence=1,
        timestamp_ns=10,
        target=TARGET,
        semantics=EvidenceSemantics.CANDIDATE,
        task=WAITER,
        task_scope=TraceScope.TARGET,
        action=FutexAction.WAIT,
        futex_id="futex-stable-id",
        stack=("pthread_mutex_lock",),
    )
    futex_wake = FutexEvent(
        event_id="futex-wake",
        sequence=2,
        timestamp_ns=20,
        target=TARGET,
        semantics=EvidenceSemantics.CANDIDATE,
        task=WAITER,
        task_scope=TraceScope.TARGET,
        action=FutexAction.WAKE,
        futex_id="futex-stable-id",
        wake_count=1,
    )
    candidate_lock = _lock(
        "candidate-lock",
        3,
        30,
        LockAction.WAIT,
        semantics=EvidenceSemantics.CANDIDATE,
    )

    analysis = analyze_locks((futex_wait, futex_wake, candidate_lock))

    assert analysis.quality_status is LockQualityStatus.PARTIAL
    assert analysis.candidate_event_count == 3
    assert analysis.candidate_wait_event_count == 2
    assert analysis.candidate_wake_event_count == 1
    assert analysis.exact_wait.sample_count == 0
    assert analysis.exact_hold.sample_count == 0
    assert {item.action for item in analysis.candidate_observations} == {
        CandidateAction.WAIT,
        CandidateAction.WAKE,
    }
    assert all(
        item.source == "user_lock_wait_candidate"
        for item in analysis.candidate_observations
    )
    assert {item.lock_id for item in analysis.candidate_observations} == {
        "futex-stable-id",
        LOCK_ID,
    }
    assert analysis.event_accounting.consumed.total_count == 3
    assert analysis.event_accounting.unpaired.total_count == 0


def test_empty_call_path_has_an_explicit_unresolved_projection() -> None:
    candidate = _lock(
        "candidate",
        1,
        10,
        LockAction.WAIT,
        semantics=EvidenceSemantics.CANDIDATE,
        stack=(),
    )

    analysis = analyze_locks((candidate,))

    assert len(analysis.paths) == 1
    assert analysis.paths[0].path == ()
    assert not analysis.paths[0].path_resolved
    assert analysis.paths[0].candidate_wait_count == 1


def test_overlapping_acquire_is_isolated_and_never_starts_a_guessed_hold() -> None:
    events = (
        _lock("acquire-1", 1, 10, LockAction.ACQUIRED),
        _lock("acquire-2", 2, 20, LockAction.ACQUIRED),
        _lock("release", 3, 30, LockAction.RELEASED),
    )

    analysis = analyze_locks(events)

    assert analysis.exact_hold.sample_count == 0
    assert analysis.quality_status is LockQualityStatus.PARTIAL
    assert any(
        issue.reason is LockPairingReason.OVERLAPPING_ACQUIRE
        for issue in analysis.incomplete_pairings
    )
    assert set(analysis.event_accounting.unpaired.ids) == {
        "acquire-1",
        "acquire-2",
        "release",
    }


def test_scheduler_events_are_ignored_and_not_projected() -> None:
    sched = SchedSwitchEvent(
        event_id="sched",
        sequence=1,
        timestamp_ns=1,
        target=TARGET,
        semantics=EvidenceSemantics.EXACT,
        previous=WAITER,
        previous_scope=TraceScope.TARGET,
        next=FOREIGN_OWNER,
        next_scope=TraceScope.FOREIGN,
        previous_state="S",
    )
    events = (
        sched,
        _lock("wait", 2, 11, LockAction.WAIT),
        _lock("acquire", 3, 31, LockAction.ACQUIRED),
        _lock("release", 4, 81, LockAction.RELEASED),
    )

    analysis = analyze_locks(events)

    assert analysis.event_accounting.ignored.ids == ("sched",)
    assert analysis.event_accounting.observed_event_count == 4


def test_worst_diagnostics_candidates_and_ledgers_are_bounded() -> None:
    analysis = analyze_locks(
        _exact_cycle(),
        limits=LockAnalysisLimits(max_worst_intervals=1, max_event_ids=1),
    )

    assert len(analysis.worst_wait_intervals) == 1
    assert len(analysis.worst_hold_intervals) == 1
    assert analysis.event_accounting.consumed.total_count == 3
    assert len(analysis.event_accounting.consumed.ids) == 1
    assert analysis.event_accounting.consumed.truncated

    candidates = tuple(
        _lock(
            f"candidate-{index}",
            index,
            index,
            LockAction.WAIT,
            semantics=EvidenceSemantics.CANDIDATE,
        )
        for index in range(1, 4)
    )
    analysis = analyze_locks(
        candidates,
        limits=LockAnalysisLimits(max_candidate_observations=1),
    )
    assert analysis.candidate_event_count == 3
    assert len(analysis.candidate_observations) == 1
    assert analysis.candidate_observations_truncated


def test_interval_and_projection_limits_fail_closed() -> None:
    with pytest.raises(ValueError, match="max_intervals"):
        analyze_locks(_exact_cycle(), limits=LockAnalysisLimits(max_intervals=1))
    with pytest.raises(ValueError, match="max_projection_rows"):
        analyze_locks(_exact_cycle(), limits=LockAnalysisLimits(max_projection_rows=2))
