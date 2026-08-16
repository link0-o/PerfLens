"""Conservative deterministic lock analysis over normalized trace evidence.

Exact wait and hold intervals are paired independently.  Futex evidence remains a generic
``user_lock_wait_candidate`` and is never mixed into exact contention or hold-time aggregates.
The analyzer does not decode stable anonymous lock IDs or disclose foreign owner identities.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import islice

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
    TraceEvent,
    TraceScope,
    validate_trace_sequence,
)
from perflens.domain.trace_analysis import (
    AnalysisWarning,
    DurationDistribution,
    EventAccounting,
    EventIdLedger,
    event_id_ledger_sha256,
    nearest_rank_percentile,
)


class LockQualityStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class OwnerEvidence(StrEnum):
    TARGET = "target"
    FOREIGN_REDACTED = "foreign_redacted"
    UNAVAILABLE = "unavailable"


class CandidateAction(StrEnum):
    WAIT = "wait"
    WAKE = "wake"


class LockPairingPhase(StrEnum):
    WAIT = "wait"
    HOLD = "hold"


class LockPairingReason(StrEnum):
    TRACE_START_BOUNDARY = "trace_start_boundary"
    TRACE_END_BOUNDARY = "trace_end_boundary"
    DUPLICATE_WAIT = "duplicate_wait"
    OVERLAPPING_ACQUIRE = "overlapping_acquire"
    RELEASE_WITHOUT_ACQUIRE = "release_without_acquire"


@dataclass(frozen=True, slots=True)
class LockAnalysisLimits:
    max_intervals: int = 100_000
    max_worst_intervals: int = 100
    max_incomplete_intervals: int = 100
    max_candidate_observations: int = 1_000
    max_projection_rows: int = 65_536
    max_event_ids: int = 1_000
    max_warnings: int = 100

    def __post_init__(self) -> None:
        if any(
            value < 1
            for value in (
                self.max_intervals,
                self.max_worst_intervals,
                self.max_incomplete_intervals,
                self.max_candidate_observations,
                self.max_projection_rows,
                self.max_event_ids,
                self.max_warnings,
            )
        ):
            raise ValueError("LockAnalysisLimits values must be positive")


@dataclass(frozen=True, slots=True)
class ExactLockWaitInterval:
    tid: int
    lock_id: str
    wait_timestamp_ns: int
    wait_end_timestamp_ns: int
    duration_ns: int
    wait_event_id: str
    wait_end_event_id: str
    outcome: LockWaitOutcome
    owner_evidence: OwnerEvidence
    owner_tid: int | None
    path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExactLockHoldInterval:
    tid: int
    lock_id: str
    acquired_timestamp_ns: int
    released_timestamp_ns: int
    duration_ns: int
    acquired_event_id: str
    released_event_id: str
    path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UserLockWaitCandidate:
    tid: int
    lock_id: str
    timestamp_ns: int
    action: CandidateAction
    event_id: str
    path: tuple[str, ...]
    source: str = "user_lock_wait_candidate"


@dataclass(frozen=True, slots=True)
class LockPairingIssue:
    tid: int
    lock_id: str
    phase: LockPairingPhase
    reason: LockPairingReason
    event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LockWaitOutcomeCount:
    outcome: LockWaitOutcome
    count: int


@dataclass(frozen=True, slots=True)
class LockAggregate:
    lock_id: str
    exact_wait: DurationDistribution
    exact_hold: DurationDistribution
    wait_outcomes: tuple[LockWaitOutcomeCount, ...]
    candidate_wait_count: int
    candidate_wake_count: int

    @property
    def candidate_event_count(self) -> int:
        return self.candidate_wait_count + self.candidate_wake_count


@dataclass(frozen=True, slots=True)
class LockThreadAggregate:
    tid: int
    exact_wait: DurationDistribution
    exact_hold: DurationDistribution
    wait_outcomes: tuple[LockWaitOutcomeCount, ...]
    candidate_wait_count: int
    candidate_wake_count: int

    @property
    def candidate_event_count(self) -> int:
        return self.candidate_wait_count + self.candidate_wake_count


@dataclass(frozen=True, slots=True)
class LockPathAggregate:
    path: tuple[str, ...]
    path_resolved: bool
    exact_wait: DurationDistribution
    exact_hold: DurationDistribution
    wait_outcomes: tuple[LockWaitOutcomeCount, ...]
    candidate_wait_count: int
    candidate_wake_count: int

    @property
    def candidate_event_count(self) -> int:
        return self.candidate_wait_count + self.candidate_wake_count


@dataclass(frozen=True, slots=True)
class LockAnalysis:
    target: TargetIdentity | None
    quality_status: LockQualityStatus
    exact_wait: DurationDistribution
    exact_hold: DurationDistribution
    exact_wait_interval_count: int
    exact_hold_interval_count: int
    wait_outcomes: tuple[LockWaitOutcomeCount, ...]
    candidate_wait_event_count: int
    candidate_wake_event_count: int
    incomplete_pairing_count: int
    locks: tuple[LockAggregate, ...]
    threads: tuple[LockThreadAggregate, ...]
    paths: tuple[LockPathAggregate, ...]
    worst_wait_intervals: tuple[ExactLockWaitInterval, ...]
    worst_hold_intervals: tuple[ExactLockHoldInterval, ...]
    incomplete_pairings: tuple[LockPairingIssue, ...]
    incomplete_pairings_truncated: bool
    candidate_observations: tuple[UserLockWaitCandidate, ...]
    candidate_observations_truncated: bool
    event_accounting: EventAccounting
    projection_conservation_passed: bool

    @property
    def candidate_event_count(self) -> int:
        return self.candidate_wait_event_count + self.candidate_wake_event_count


def _new_int_list() -> list[int]:
    return []


def _new_outcome_counts() -> dict[LockWaitOutcome, int]:
    return {}


@dataclass(slots=True)
class _ProjectionValues:
    waits: list[int] = field(default_factory=_new_int_list)
    holds: list[int] = field(default_factory=_new_int_list)
    wait_outcomes: dict[LockWaitOutcome, int] = field(default_factory=_new_outcome_counts)
    candidate_wait_count: int = 0
    candidate_wake_count: int = 0


def _outcome_counts(values: _ProjectionValues) -> tuple[LockWaitOutcomeCount, ...]:
    return tuple(
        LockWaitOutcomeCount(outcome=outcome, count=count)
        for outcome, count in sorted(values.wait_outcomes.items(), key=lambda item: item[0].value)
    )


class _EventStatus(StrEnum):
    OBSERVED = "observed"
    CONSUMED = "consumed"
    UNPAIRED = "unpaired"
    IGNORED = "ignored"


class _AccountingBuilder:
    __slots__ = ("_limits", "_order", "_status", "_warning_count", "_warnings")

    def __init__(self, limits: LockAnalysisLimits) -> None:
        self._limits = limits
        self._order: list[str] = []
        self._status: dict[str, _EventStatus] = {}
        self._warning_count = 0
        self._warnings: list[AnalysisWarning] = []

    def observe(self, event_id: str, *, ignored: bool) -> None:
        self._order.append(event_id)
        self._status[event_id] = _EventStatus.IGNORED if ignored else _EventStatus.OBSERVED

    def consume(self, *event_ids: str) -> None:
        for event_id in event_ids:
            if self._status[event_id] is not _EventStatus.IGNORED:
                self._status[event_id] = _EventStatus.CONSUMED

    def unpaired(self, *event_ids: str) -> None:
        for event_id in event_ids:
            if self._status[event_id] is _EventStatus.OBSERVED:
                self._status[event_id] = _EventStatus.UNPAIRED

    def warn(
        self,
        code: str,
        message: str,
        *,
        event_id: str | None,
        tid: int,
    ) -> None:
        self._warning_count += 1
        if len(self._warnings) < self._limits.max_warnings:
            self._warnings.append(
                AnalysisWarning(code=code, message=message, event_id=event_id, tid=tid)
            )

    def finish(self) -> EventAccounting:
        for event_id, status in tuple(self._status.items()):
            if status is _EventStatus.OBSERVED:
                self._status[event_id] = _EventStatus.UNPAIRED

        def event_ids(status: _EventStatus) -> EventIdLedger:
            total_count = sum(
                self._status[event_id] is status for event_id in self._order
            )
            sample = tuple(
                islice(
                    (
                        event_id
                        for event_id in self._order
                        if self._status[event_id] is status
                    ),
                    self._limits.max_event_ids,
                )
            )
            return EventIdLedger(
                total_count=total_count,
                ids=sample,
                all_event_ids_sha256=event_id_ledger_sha256(
                    event_id
                    for event_id in self._order
                    if self._status[event_id] is status
                ),
                truncated=total_count > len(sample),
            )

        accounting = EventAccounting(
            observed_event_count=len(self._order),
            consumed=event_ids(_EventStatus.CONSUMED),
            unpaired=event_ids(_EventStatus.UNPAIRED),
            ignored=event_ids(_EventStatus.IGNORED),
            warning_count=self._warning_count,
            warnings=tuple(self._warnings),
            warnings_truncated=self._warning_count > len(self._warnings),
        )
        categorized = (
            accounting.consumed.total_count
            + accounting.unpaired.total_count
            + accounting.ignored.total_count
        )
        if categorized != accounting.observed_event_count:
            raise ValueError("lock event accounting is not conserved")
        return accounting


def _distribution(values: Sequence[int]) -> DurationDistribution:
    if not values:
        return DurationDistribution(
            sample_count=0,
            total_ns=0,
            minimum_ns=0,
            mean_ns=0,
            p50_ns=None,
            p95_ns=None,
            p99_ns=None,
            max_ns=None,
        )
    total = sum(values)
    return DurationDistribution(
        sample_count=len(values),
        total_ns=total,
        minimum_ns=min(values),
        mean_ns=total // len(values),
        p50_ns=nearest_rank_percentile(values, 50),
        p95_ns=nearest_rank_percentile(values, 95),
        p99_ns=nearest_rank_percentile(values, 99),
        max_ns=max(values),
    )


def _owner(event: LockEvent) -> tuple[OwnerEvidence, int | None]:
    if event.owner is None or event.owner_scope is None:
        return OwnerEvidence.UNAVAILABLE, None
    if event.owner_scope is TraceScope.TARGET:
        if event.owner.tid is None:
            raise ValueError("target lock owner identity was redacted")
        return OwnerEvidence.TARGET, event.owner.tid
    return OwnerEvidence.FOREIGN_REDACTED, None


def _candidate_from_futex(event: FutexEvent) -> UserLockWaitCandidate:
    if event.task.tid is None:
        raise ValueError("target futex task identity was redacted")
    return UserLockWaitCandidate(
        tid=event.task.tid,
        lock_id=event.futex_id,
        timestamp_ns=event.timestamp_ns,
        action=CandidateAction.WAIT if event.action is FutexAction.WAIT else CandidateAction.WAKE,
        event_id=event.event_id,
        path=event.stack,
    )


def _candidate_from_lock(event: LockEvent) -> UserLockWaitCandidate:
    if event.task.tid is None:
        raise ValueError("target lock task identity was redacted")
    return UserLockWaitCandidate(
        tid=event.task.tid,
        lock_id=event.lock_id,
        timestamp_ns=event.timestamp_ns,
        action=CandidateAction.WAIT,
        event_id=event.event_id,
        path=event.stack,
    )


def analyze_locks(
    events: Sequence[TraceEvent],
    *,
    limits: LockAnalysisLimits | None = None,
    resource_limits: ResourceLimits | None = None,
) -> LockAnalysis:
    """Pair exact lock evidence and separately retain generic user-lock candidates."""

    active_limits = limits or LockAnalysisLimits()
    validation = validate_trace_sequence(events, limits=resource_limits or ResourceLimits())
    target = events[0].target if events else None
    accounting_builder = _AccountingBuilder(active_limits)
    pending_waits: dict[tuple[int, str], list[LockEvent]] = {}
    active_holds: dict[tuple[int, str], LockEvent] = {}
    wait_intervals: list[ExactLockWaitInterval] = []
    hold_intervals: list[ExactLockHoldInterval] = []
    incomplete: list[LockPairingIssue] = []
    incomplete_count = 0
    candidates: list[UserLockWaitCandidate] = []
    candidate_wait_count = 0
    candidate_wake_count = 0
    interval_count = 0
    lock_values: dict[str, _ProjectionValues] = {}
    thread_values: dict[int, _ProjectionValues] = {}
    path_values: dict[tuple[str, ...], _ProjectionValues] = {}

    def reserve_interval() -> None:
        nonlocal interval_count
        interval_count += 1
        if interval_count > active_limits.max_intervals:
            raise ValueError("lock analysis interval count exceeds max_intervals")

    def projection[Key](
        table: dict[Key, _ProjectionValues],
        key: Key,
    ) -> _ProjectionValues:
        current = table.get(key)
        if current is None:
            current = _ProjectionValues()
            table[key] = current
        return current

    def add_projection_wait(
        lock_id: str,
        tid: int,
        path: tuple[str, ...],
        value: int,
        outcome: LockWaitOutcome,
    ) -> None:
        for current in (
            projection(lock_values, lock_id),
            projection(thread_values, tid),
            projection(path_values, path),
        ):
            current.waits.append(value)
            current.wait_outcomes[outcome] = current.wait_outcomes.get(outcome, 0) + 1

    def add_projection_hold(lock_id: str, tid: int, path: tuple[str, ...], value: int) -> None:
        projection(lock_values, lock_id).holds.append(value)
        projection(thread_values, tid).holds.append(value)
        projection(path_values, path).holds.append(value)

    def add_projection_candidate(candidate: UserLockWaitCandidate) -> None:
        projections = (
            projection(lock_values, candidate.lock_id),
            projection(thread_values, candidate.tid),
            projection(path_values, candidate.path),
        )
        for current in projections:
            if candidate.action is CandidateAction.WAIT:
                current.candidate_wait_count += 1
            else:
                current.candidate_wake_count += 1

    def add_incomplete(
        *,
        tid: int,
        lock_id: str,
        phase: LockPairingPhase,
        reason: LockPairingReason,
        event_ids: tuple[str, ...],
    ) -> None:
        nonlocal incomplete_count
        incomplete_count += 1
        if len(incomplete) < active_limits.max_incomplete_intervals:
            incomplete.append(
                LockPairingIssue(
                    tid=tid,
                    lock_id=lock_id,
                    phase=phase,
                    reason=reason,
                    event_ids=event_ids,
                )
            )

    def add_candidate(candidate: UserLockWaitCandidate) -> None:
        nonlocal candidate_wait_count, candidate_wake_count
        if candidate.action is CandidateAction.WAIT:
            candidate_wait_count += 1
        else:
            candidate_wake_count += 1
        if len(candidates) < active_limits.max_candidate_observations:
            candidates.append(candidate)
        add_projection_candidate(candidate)
        accounting_builder.consume(candidate.event_id)

    for event in events:
        ignored = isinstance(event, (SchedSwitchEvent, SchedWakeupEvent, SchedMigrateEvent))
        accounting_builder.observe(event.event_id, ignored=ignored)
        if ignored:
            continue
        if isinstance(event, FutexEvent):
            add_candidate(_candidate_from_futex(event))
            continue
        if event.task.tid is None:
            raise ValueError("target lock task identity was redacted")
        if event.action is LockAction.WAIT:
            if event.semantics is EvidenceSemantics.CANDIDATE:
                add_candidate(_candidate_from_lock(event))
                continue
            key = (event.task.tid, event.lock_id)
            waits = pending_waits.setdefault(key, [])
            waits.append(event)
            if len(waits) > 1:
                accounting_builder.unpaired(*(wait.event_id for wait in waits))
                accounting_builder.warn(
                    "duplicate_lock_wait",
                    "multiple exact waits precede one acquire; wait duration is ambiguous",
                    event_id=event.event_id,
                    tid=event.task.tid,
                )
            continue

        key = (event.task.tid, event.lock_id)
        if event.action in {LockAction.ACQUIRED, LockAction.WAIT_ENDED}:
            outcome = (
                LockWaitOutcome.ACQUIRED
                if event.action is LockAction.ACQUIRED
                else event.wait_outcome
            )
            if outcome is None:
                raise ValueError("lock wait-ended event omits its outcome")
            waits = pending_waits.pop(key, [])
            if len(waits) == 1:
                wait = waits[0]
                duration = event.timestamp_ns - wait.timestamp_ns
                reserve_interval()
                owner_evidence, owner_tid = _owner(wait)
                wait_intervals.append(
                    ExactLockWaitInterval(
                        tid=event.task.tid,
                        lock_id=event.lock_id,
                        wait_timestamp_ns=wait.timestamp_ns,
                        wait_end_timestamp_ns=event.timestamp_ns,
                        duration_ns=duration,
                        wait_event_id=wait.event_id,
                        wait_end_event_id=event.event_id,
                        outcome=outcome,
                        owner_evidence=owner_evidence,
                        owner_tid=owner_tid,
                        path=wait.stack,
                    )
                )
                add_projection_wait(
                    event.lock_id,
                    event.task.tid,
                    wait.stack,
                    duration,
                    outcome,
                )
                accounting_builder.consume(wait.event_id, event.event_id)
            elif len(waits) > 1:
                ids = (*(wait.event_id for wait in waits), event.event_id)
                accounting_builder.unpaired(*ids)
                add_incomplete(
                    tid=event.task.tid,
                    lock_id=event.lock_id,
                    phase=LockPairingPhase.WAIT,
                    reason=LockPairingReason.DUPLICATE_WAIT,
                    event_ids=ids,
                )
            else:
                accounting_builder.unpaired(event.event_id)
                add_incomplete(
                    tid=event.task.tid,
                    lock_id=event.lock_id,
                    phase=LockPairingPhase.WAIT,
                    reason=LockPairingReason.TRACE_START_BOUNDARY,
                    event_ids=(event.event_id,),
                )

            if outcome is not LockWaitOutcome.ACQUIRED:
                continue

            previous_acquire = active_holds.pop(key, None)
            if previous_acquire is not None:
                accounting_builder.unpaired(previous_acquire.event_id, event.event_id)
                add_incomplete(
                    tid=event.task.tid,
                    lock_id=event.lock_id,
                    phase=LockPairingPhase.HOLD,
                    reason=LockPairingReason.OVERLAPPING_ACQUIRE,
                    event_ids=(previous_acquire.event_id, event.event_id),
                )
                accounting_builder.warn(
                    "overlapping_lock_acquire",
                    "a second acquire arrived before the prior hold was released",
                    event_id=event.event_id,
                    tid=event.task.tid,
                )
            else:
                active_holds[key] = event
            continue

        acquire = active_holds.pop(key, None)
        if acquire is None:
            accounting_builder.unpaired(event.event_id)
            add_incomplete(
                tid=event.task.tid,
                lock_id=event.lock_id,
                phase=LockPairingPhase.HOLD,
                reason=LockPairingReason.RELEASE_WITHOUT_ACQUIRE,
                event_ids=(event.event_id,),
            )
            accounting_builder.warn(
                "release_without_acquire",
                "release has no matching acquire; hold duration is unavailable",
                event_id=event.event_id,
                tid=event.task.tid,
            )
            continue
        duration = event.timestamp_ns - acquire.timestamp_ns
        reserve_interval()
        hold_intervals.append(
            ExactLockHoldInterval(
                tid=event.task.tid,
                lock_id=event.lock_id,
                acquired_timestamp_ns=acquire.timestamp_ns,
                released_timestamp_ns=event.timestamp_ns,
                duration_ns=duration,
                acquired_event_id=acquire.event_id,
                released_event_id=event.event_id,
                path=acquire.stack,
            )
        )
        add_projection_hold(event.lock_id, event.task.tid, acquire.stack, duration)
        accounting_builder.consume(acquire.event_id, event.event_id)

    for (tid, lock_id), waits in sorted(pending_waits.items()):
        ids = tuple(wait.event_id for wait in waits)
        accounting_builder.unpaired(*ids)
        add_incomplete(
            tid=tid,
            lock_id=lock_id,
            phase=LockPairingPhase.WAIT,
            reason=(
                LockPairingReason.DUPLICATE_WAIT
                if len(waits) > 1
                else LockPairingReason.TRACE_END_BOUNDARY
            ),
            event_ids=ids,
        )
        accounting_builder.warn(
            "unclosed_lock_wait",
            "exact wait did not reach an acquire before the trace ended",
            event_id=ids[0],
            tid=tid,
        )

    for (tid, lock_id), acquire in sorted(active_holds.items()):
        accounting_builder.unpaired(acquire.event_id)
        add_incomplete(
            tid=tid,
            lock_id=lock_id,
            phase=LockPairingPhase.HOLD,
            reason=LockPairingReason.TRACE_END_BOUNDARY,
            event_ids=(acquire.event_id,),
        )
        accounting_builder.warn(
            "unclosed_lock_hold",
            "acquire did not reach a release; hold duration is unavailable",
            event_id=acquire.event_id,
            tid=tid,
        )

    projection_row_count = len(lock_values) + len(thread_values) + len(path_values)
    if projection_row_count > active_limits.max_projection_rows:
        raise ValueError("lock projection rows exceed max_projection_rows")

    locks = tuple(
        LockAggregate(
            lock_id=lock_id,
            exact_wait=_distribution(values.waits),
            exact_hold=_distribution(values.holds),
            wait_outcomes=_outcome_counts(values),
            candidate_wait_count=values.candidate_wait_count,
            candidate_wake_count=values.candidate_wake_count,
        )
        for lock_id, values in sorted(lock_values.items())
    )
    threads = tuple(
        LockThreadAggregate(
            tid=tid,
            exact_wait=_distribution(values.waits),
            exact_hold=_distribution(values.holds),
            wait_outcomes=_outcome_counts(values),
            candidate_wait_count=values.candidate_wait_count,
            candidate_wake_count=values.candidate_wake_count,
        )
        for tid, values in sorted(thread_values.items())
    )
    paths = tuple(
        LockPathAggregate(
            path=path,
            path_resolved=bool(path),
            exact_wait=_distribution(values.waits),
            exact_hold=_distribution(values.holds),
            wait_outcomes=_outcome_counts(values),
            candidate_wait_count=values.candidate_wait_count,
            candidate_wake_count=values.candidate_wake_count,
        )
        for path, values in sorted(path_values.items())
    )
    exact_wait = _distribution([interval.duration_ns for interval in wait_intervals])
    exact_hold = _distribution([interval.duration_ns for interval in hold_intervals])
    expected = (
        exact_wait.sample_count,
        exact_wait.total_ns,
        exact_hold.sample_count,
        exact_hold.total_ns,
        candidate_wait_count,
        candidate_wake_count,
    )

    def projection_totals(
        rows: Sequence[LockAggregate | LockThreadAggregate | LockPathAggregate],
    ) -> tuple[int, int, int, int, int, int]:
        return (
            sum(row.exact_wait.sample_count for row in rows),
            sum(row.exact_wait.total_ns for row in rows),
            sum(row.exact_hold.sample_count for row in rows),
            sum(row.exact_hold.total_ns for row in rows),
            sum(row.candidate_wait_count for row in rows),
            sum(row.candidate_wake_count for row in rows),
        )

    if any(projection_totals(rows) != expected for rows in (locks, threads, paths)):
        raise ValueError("lock/TID/path projections are not conserved")
    global_outcomes = {
        outcome: sum(interval.outcome is outcome for interval in wait_intervals)
        for outcome in LockWaitOutcome
    }
    for rows in (locks, threads, paths):
        for outcome, count in global_outcomes.items():
            projected = sum(
                item.count
                for row in rows
                for item in row.wait_outcomes
                if item.outcome is outcome
            )
            if projected != count:
                raise ValueError("lock wait outcomes are not conserved")
    accounting = accounting_builder.finish()
    if accounting.observed_event_count != validation.event_count:
        raise ValueError("lock analysis event accounting is not conserved")

    worst_waits = sorted(
        wait_intervals,
        key=lambda interval: (
            -interval.duration_ns,
            interval.lock_id,
            interval.tid,
            interval.wait_event_id,
        ),
    )
    worst_holds = sorted(
        hold_intervals,
        key=lambda interval: (
            -interval.duration_ns,
            interval.lock_id,
            interval.tid,
            interval.acquired_event_id,
        ),
    )
    quality_status = (
        LockQualityStatus.PARTIAL
        if (
            incomplete_count
            or candidate_wait_count
            or candidate_wake_count
            or global_outcomes[LockWaitOutcome.UNKNOWN]
        )
        else LockQualityStatus.COMPLETE
    )
    return LockAnalysis(
        target=target,
        quality_status=quality_status,
        exact_wait=exact_wait,
        exact_hold=exact_hold,
        exact_wait_interval_count=len(wait_intervals),
        exact_hold_interval_count=len(hold_intervals),
        wait_outcomes=tuple(
            LockWaitOutcomeCount(outcome=outcome, count=count)
            for outcome, count in sorted(global_outcomes.items(), key=lambda item: item[0].value)
            if count
        ),
        candidate_wait_event_count=candidate_wait_count,
        candidate_wake_event_count=candidate_wake_count,
        incomplete_pairing_count=incomplete_count,
        locks=locks,
        threads=threads,
        paths=paths,
        worst_wait_intervals=tuple(worst_waits[: active_limits.max_worst_intervals]),
        worst_hold_intervals=tuple(worst_holds[: active_limits.max_worst_intervals]),
        incomplete_pairings=tuple(incomplete),
        incomplete_pairings_truncated=incomplete_count > len(incomplete),
        candidate_observations=tuple(candidates),
        candidate_observations_truncated=(
            candidate_wait_count + candidate_wake_count > len(candidates)
        ),
        event_accounting=accounting,
        projection_conservation_passed=True,
    )
