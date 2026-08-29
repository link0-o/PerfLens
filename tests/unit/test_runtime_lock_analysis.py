from __future__ import annotations

from dataclasses import replace

import pytest

from perflens.domain.runtime_lock_analysis import (
    RuntimeCallPathProjection,
    RuntimeContextKind,
    RuntimeContextProjection,
    RuntimeEventKind,
    RuntimeExecutionContext,
    RuntimeLockEvent,
    RuntimeLockKindProjection,
    RuntimeMeasurementSemantics,
    RuntimeOutcomeProjection,
    RuntimePairingReason,
    analyze_runtime_lock_events,
    duration_distribution,
    nearest_rank_percentile,
    replay_runtime_lock_events,
)

THREAD_1 = RuntimeExecutionContext(
    kind=RuntimeContextKind.OS_THREAD,
    context_id="runtime-context-a",
    target_tid=101,
)
THREAD_2 = RuntimeExecutionContext(
    kind=RuntimeContextKind.JAVA_VIRTUAL_THREAD,
    context_id="runtime-context-b",
)


def _event(
    event_id: str,
    event_index: int,
    timestamp_ns: int,
    event_kind: RuntimeEventKind,
    *,
    context: RuntimeExecutionContext = THREAD_1,
    semantics: RuntimeMeasurementSemantics = RuntimeMeasurementSemantics.EXACT,
    lock_id: str | None = "runtime-lock-a",
    lock_kind: str = "mutex",
    stack_id: str | None = "runtime-stack-a",
    owner_context: RuntimeExecutionContext | None = None,
    wait_begin_event_id: str | None = None,
    wait_end_event_id: str | None = None,
    acquire_event_id: str | None = None,
    duration_ns: int | None = None,
    hold_duration_ns: int | None = None,
    outcome: str | None = None,
    parked_context: RuntimeExecutionContext | None = None,
    observed_count: int | None = None,
    estimated_count: float | None = None,
    cumulative_wait_ns: int | None = None,
) -> RuntimeLockEvent:
    return RuntimeLockEvent(
        event_id=event_id,
        event_index=event_index,
        timestamp_ns=timestamp_ns,
        context=context,
        event_kind=event_kind,
        measurement_semantics=semantics,
        lock_id=lock_id,
        lock_kind=lock_kind,
        stack_id=stack_id,
        owner_context=owner_context,
        wait_begin_event_id=wait_begin_event_id,
        wait_end_event_id=wait_end_event_id,
        acquire_event_id=acquire_event_id,
        duration_ns=duration_ns,
        hold_duration_ns=hold_duration_ns,
        outcome=outcome,
        parked_context=parked_context,
        observed_count=observed_count,
        estimated_count=estimated_count,
        cumulative_wait_ns=cumulative_wait_ns,
    )


def _exact_cycle(
    *,
    index_offset: int = 0,
    timestamp_offset: int = 0,
    context: RuntimeExecutionContext = THREAD_1,
    lock_id: str = "runtime-lock-a",
    stack_id: str = "runtime-stack-a",
) -> tuple[RuntimeLockEvent, ...]:
    prefix = f"{index_offset}-"
    wait = _event(
        f"{prefix}wait",
        index_offset,
        timestamp_offset + 10,
        RuntimeEventKind.WAIT_BEGIN,
        context=context,
        lock_id=lock_id,
        stack_id=stack_id,
        owner_context=THREAD_2,
    )
    acquire = _event(
        f"{prefix}acquire",
        index_offset + 1,
        timestamp_offset + 30,
        RuntimeEventKind.ACQUIRE,
        context=context,
        lock_id=lock_id,
        stack_id=stack_id,
    )
    release = _event(
        f"{prefix}release",
        index_offset + 2,
        timestamp_offset + 80,
        RuntimeEventKind.RELEASE,
        context=context,
        lock_id=lock_id,
        stack_id=stack_id,
        acquire_event_id=acquire.event_id,
        hold_duration_ns=50,
    )
    return wait, acquire, release


def test_integer_nearest_rank_distribution_has_no_float_interpolation() -> None:
    values = (1, 2, 3, 4, 100)

    assert nearest_rank_percentile(values, 0) == 1
    assert nearest_rank_percentile(values, 50) == 3
    assert nearest_rank_percentile(values, 95) == 100
    assert duration_distribution(values).mean_ns == 22
    assert duration_distribution(()).maximum_ns == 0


def test_exact_wait_acquire_release_replay_and_all_projections_are_conserved() -> None:
    analysis = analyze_runtime_lock_events(_exact_cycle(), max_exported_rows=10)

    assert analysis.replay.consumed_event_ids == ("0-wait", "0-acquire", "0-release")
    assert not analysis.replay.unpaired_event_ids
    assert analysis.totals.exact_waits.sample_count == 1
    assert analysis.totals.exact_waits.total_ns == 20
    assert analysis.totals.exact_holds.total_ns == 50
    assert analysis.totals.owner_observed_count == 1
    assert analysis.locks.omission.omitted_row_count == 0
    assert analysis.contexts.omission.omitted_row_count == 0
    assert analysis.call_paths.omission.omitted_row_count == 0
    assert analysis.outcomes.omission.omitted_row_count == 0
    assert analysis.lock_kinds.omission.omitted_row_count == 0


def test_explicit_wait_end_requires_matching_identity_time_and_duration() -> None:
    begin = _event("wait", 0, 10, RuntimeEventKind.WAIT_BEGIN)
    bad_end = _event(
        "end",
        1,
        40,
        RuntimeEventKind.WAIT_END,
        wait_begin_event_id="wait",
        duration_ns=29,
        outcome="acquired",
    )

    replay = replay_runtime_lock_events((begin, bad_end))

    assert not replay.waits
    assert replay.unpaired_event_ids == ("wait", "end")
    assert replay.issues[0].reason is RuntimePairingReason.WAIT_DURATION_MISMATCH

    mismatched = replace(bad_end, duration_ns=30, lock_id="runtime-lock-b")
    replay = replay_runtime_lock_events((begin, mismatched))
    assert replay.issues[0].reason is RuntimePairingReason.WAIT_IDENTITY_MISMATCH


def test_invalid_duplicate_wait_begin_cannot_be_resurrected_by_explicit_reference() -> None:
    first = _event("first", 0, 10, RuntimeEventKind.WAIT_BEGIN)
    duplicate = _event("duplicate", 1, 20, RuntimeEventKind.WAIT_BEGIN)
    end = _event(
        "end",
        2,
        30,
        RuntimeEventKind.WAIT_END,
        wait_begin_event_id="first",
        duration_ns=20,
        outcome="acquired",
    )

    replay = replay_runtime_lock_events((first, duplicate, end))

    assert not replay.waits
    assert not replay.consumed_event_ids
    assert replay.unpaired_event_ids == ("first", "duplicate", "end")
    assert [issue.reason for issue in replay.issues] == [
        RuntimePairingReason.DUPLICATE_WAIT_BEGIN,
        RuntimePairingReason.REUSED_WAIT_BEGIN,
    ]


def test_wait_end_acquire_reference_is_validated_without_double_counting_wait() -> None:
    begin = _event("wait", 0, 10, RuntimeEventKind.WAIT_BEGIN)
    end = _event(
        "end",
        1,
        30,
        RuntimeEventKind.WAIT_END,
        wait_begin_event_id="wait",
        duration_ns=20,
        outcome="acquired",
    )
    acquire = _event(
        "acquire",
        2,
        31,
        RuntimeEventKind.ACQUIRE,
        wait_end_event_id="end",
    )
    release = _event(
        "release",
        3,
        41,
        RuntimeEventKind.RELEASE,
        acquire_event_id="acquire",
        hold_duration_ns=10,
    )

    analysis = analyze_runtime_lock_events((begin, end, acquire, release), max_exported_rows=10)

    assert analysis.totals.exact_waits.sample_count == 1
    assert analysis.totals.exact_waits.total_ns == 20
    assert analysis.totals.exact_holds.total_ns == 10
    assert analysis.replay.consumed_event_ids == ("wait", "end", "acquire", "release")


def test_thresholded_single_event_duration_is_not_promoted_to_exact() -> None:
    event = _event(
        "jfr-enter",
        0,
        100,
        RuntimeEventKind.WAIT_END,
        semantics=RuntimeMeasurementSemantics.THRESHOLDED,
        duration_ns=12_000_000,
        outcome="acquired",
    )

    analysis = analyze_runtime_lock_events((event,), max_exported_rows=10)

    assert analysis.totals.exact_waits.sample_count == 0
    assert analysis.totals.thresholded_waits.sample_count == 1
    assert analysis.totals.thresholded_waits.total_ns == 12_000_000
    assert analysis.replay.consumed_event_ids == ("jfr-enter",)


@pytest.mark.parametrize(
    ("semantics", "sampled", "cumulative"),
    [
        (RuntimeMeasurementSemantics.SAMPLED, 7, 0),
        (RuntimeMeasurementSemantics.CUMULATIVE, 0, 7),
    ],
)
def test_profile_observation_count_and_wait_weight_remain_separate(
    semantics: RuntimeMeasurementSemantics,
    sampled: int,
    cumulative: int,
) -> None:
    profile = _event(
        "profile",
        0,
        0,
        RuntimeEventKind.SAMPLED_CONTENTION,
        context=RuntimeExecutionContext(
            kind=RuntimeContextKind.PROCESS_AGGREGATE,
            context_id="process",
        ),
        semantics=semantics,
        lock_id=None,
        stack_id="runtime-stack-profile",
        observed_count=7,
        estimated_count=70.5 if semantics is RuntimeMeasurementSemantics.SAMPLED else None,
        cumulative_wait_ns=900,
    )

    analysis = analyze_runtime_lock_events((profile,), max_exported_rows=10)

    assert analysis.totals.sampled_observation_count == sampled
    assert analysis.totals.cumulative_observation_count == cumulative
    assert analysis.totals.observed_or_estimated_wait_ns == 900
    assert analysis.totals.exact_waits.sample_count == 0
    assert len(analysis.outcomes.rows) == 1
    outcome = analysis.outcomes.rows[0]
    assert isinstance(outcome, RuntimeOutcomeProjection)
    assert outcome.outcome == "unknown"
    context_row = analysis.contexts.rows[0]
    path_row = analysis.call_paths.rows[0]
    kind_row = analysis.lock_kinds.rows[0]
    assert isinstance(context_row, RuntimeContextProjection)
    assert isinstance(path_row, RuntimeCallPathProjection)
    assert isinstance(kind_row, RuntimeLockKindProjection)
    assert context_row.lock_count is None
    assert path_row.lock_count is None
    assert outcome.lock_count is None
    assert kind_row.lock_count is None


def test_park_unpark_is_attributed_to_parked_context_not_unparker() -> None:
    parked = _event(
        "park",
        0,
        20,
        RuntimeEventKind.PARK,
        context=THREAD_1,
        lock_kind="park",
    )
    unpark = _event(
        "unpark",
        1,
        55,
        RuntimeEventKind.UNPARK,
        context=THREAD_2,
        lock_kind="park",
        parked_context=THREAD_1,
    )

    analysis = analyze_runtime_lock_events((parked, unpark), max_exported_rows=10)

    assert analysis.replay.waits[0].context == THREAD_1
    assert analysis.replay.waits[0].outcome == "unparked"
    assert analysis.replay.waits[0].duration_ns == 35
    assert len(analysis.contexts.rows) == 1


def test_missing_pairs_and_mixed_semantics_never_produce_invented_durations() -> None:
    acquire = _event("acquire", 0, 1, RuntimeEventKind.ACQUIRE)

    replay = replay_runtime_lock_events((acquire,))

    assert not replay.waits
    assert not replay.holds
    assert replay.unpaired_event_ids == ("acquire",)
    assert replay.issues[0].reason is RuntimePairingReason.TRACE_END_BOUNDARY

    sampled = _event(
        "sample",
        1,
        2,
        RuntimeEventKind.SAMPLED_CONTENTION,
        semantics=RuntimeMeasurementSemantics.SAMPLED,
        observed_count=1,
        cumulative_wait_ns=2,
    )
    with pytest.raises(ValueError, match="one measurement semantics"):
        replay_runtime_lock_events((acquire, sampled))


def test_release_without_source_duration_consumes_pair_but_never_invents_hold() -> None:
    acquire = _event("acquire", 0, 10, RuntimeEventKind.ACQUIRE)
    release = _event("release", 1, 50, RuntimeEventKind.RELEASE)

    analysis = analyze_runtime_lock_events((acquire, release), max_exported_rows=10)

    assert analysis.replay.consumed_event_ids == ("acquire", "release")
    assert not analysis.replay.issues
    assert analysis.totals.exact_holds.sample_count == 0
    assert analysis.totals.exact_holds.total_ns == 0


def test_recursive_mutex_acquires_use_lifo_holds_and_conserve_both_levels() -> None:
    outer = _event(
        "outer-acquire",
        0,
        10,
        RuntimeEventKind.ACQUIRE,
        lock_kind="recursive_mutex",
    )
    inner = _event(
        "inner-acquire",
        1,
        20,
        RuntimeEventKind.ACQUIRE,
        lock_kind="recursive_mutex",
    )
    inner_release = _event(
        "inner-release",
        2,
        30,
        RuntimeEventKind.RELEASE,
        lock_kind="recursive_mutex",
        acquire_event_id="inner-acquire",
        hold_duration_ns=10,
    )
    outer_release = _event(
        "outer-release",
        3,
        40,
        RuntimeEventKind.RELEASE,
        lock_kind="recursive_mutex",
        acquire_event_id="outer-acquire",
        hold_duration_ns=30,
    )

    analysis = analyze_runtime_lock_events(
        (outer, inner, inner_release, outer_release), max_exported_rows=10
    )

    assert not analysis.replay.issues
    assert analysis.replay.consumed_event_ids == (
        "outer-acquire",
        "inner-acquire",
        "inner-release",
        "outer-release",
    )
    assert analysis.totals.exact_holds.sample_count == 2
    assert analysis.totals.exact_holds.total_ns == 40
    assert analysis.totals.exact_holds.p50_ns == 10
    assert analysis.totals.exact_holds.p95_ns == 30


def test_projection_truncation_conserves_omitted_count_and_nanoseconds() -> None:
    events = (
        *_exact_cycle(),
        *_exact_cycle(
            index_offset=3,
            timestamp_offset=100,
            context=THREAD_2,
            lock_id="runtime-lock-b",
            stack_id="runtime-stack-b",
        ),
    )

    analysis = analyze_runtime_lock_events(events, max_exported_rows=1)

    assert analysis.totals.observation_count == 2
    assert analysis.totals.total_wait_ns == 40
    assert analysis.totals.exact_holds.total_ns == 100
    for page in (analysis.locks, analysis.contexts, analysis.call_paths):
        assert page.omission.total_row_count == 2
        assert page.omission.exported_row_count == 1
        assert page.omission.omitted_row_count == 1
        assert page.omission.omitted_observation_count == 1
        assert page.omission.omitted_wait_ns == 20
        assert page.omission.omitted_hold_count == 1
        assert page.omission.omitted_hold_ns == 50


def test_runtime_event_rejects_cross_kind_fields_and_non_finite_estimates() -> None:
    with pytest.raises(ValueError, match="another event kind"):
        _event(
            "bad",
            0,
            0,
            RuntimeEventKind.ACQUIRE,
            duration_ns=1,
        )
    with pytest.raises(ValueError, match="finite and positive"):
        _event(
            "bad-profile",
            0,
            0,
            RuntimeEventKind.SAMPLED_CONTENTION,
            semantics=RuntimeMeasurementSemantics.SAMPLED,
            observed_count=1,
            estimated_count=float("inf"),
            cumulative_wait_ns=1,
        )
