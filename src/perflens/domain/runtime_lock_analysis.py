"""Pure deterministic analysis for normalized user-space runtime lock evidence.

This module deliberately has no dependency on Pydantic, the CLI, MCP, or any runtime
adapter.  Adapters normalize their public contract into :class:`RuntimeLockEvent` values;
the application layer then projects the result back into a versioned public artifact.

The state machine is conservative.  Exact durations derived from event pairs are accepted
only when identity, context, lock, ordering, and source-reported duration agree.  Thresholded
single-event durations and sampled/cumulative profiles remain separate measurement classes and
are never promoted to exact counts.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from math import ceil, isfinite


class RuntimeMeasurementSemantics(StrEnum):
    EXACT = "exact"
    THRESHOLDED = "thresholded"
    SAMPLED = "sampled"
    CUMULATIVE = "cumulative"


class RuntimeEventKind(StrEnum):
    WAIT_BEGIN = "wait_begin"
    WAIT_END = "wait_end"
    ACQUIRE = "acquire"
    RELEASE = "release"
    PARK = "park"
    UNPARK = "unpark"
    SAMPLED_CONTENTION = "sampled_contention"


class RuntimeContextKind(StrEnum):
    OS_THREAD = "os_thread"
    JAVA_PLATFORM_THREAD = "java_platform_thread"
    JAVA_VIRTUAL_THREAD = "java_virtual_thread"
    GO_GOROUTINE = "go_goroutine"
    PROCESS_AGGREGATE = "process_aggregate"


@dataclass(frozen=True, slots=True, order=True)
class RuntimeExecutionContext:
    """Opaque execution identity safe to expose within one evidence artifact."""

    kind: RuntimeContextKind
    context_id: str
    target_tid: int | None = None

    def __post_init__(self) -> None:
        if not self.context_id or len(self.context_id) > 256:
            raise ValueError("runtime execution context requires a bounded identity")
        if self.target_tid is not None and self.target_tid <= 0:
            raise ValueError("runtime target TID must be positive")
        if self.kind is RuntimeContextKind.OS_THREAD and self.target_tid is None:
            raise ValueError("OS-thread runtime context requires a target TID")
        if self.kind is RuntimeContextKind.PROCESS_AGGREGATE and self.target_tid is not None:
            raise ValueError("process aggregate runtime context cannot claim a target TID")
        if (
            self.kind
            in {
                RuntimeContextKind.JAVA_VIRTUAL_THREAD,
                RuntimeContextKind.GO_GOROUTINE,
            }
            and self.target_tid is not None
        ):
            raise ValueError("virtual-thread and goroutine contexts cannot claim an OS TID")


@dataclass(frozen=True, slots=True)
class RuntimeLockEvent:
    """Adapter-independent normalized runtime event.

    Optional fields are interpreted only by the event kind that owns them.  The application
    conversion is responsible for rejecting unknown public fields; this class independently
    rejects contradictory or unsafe normalized values before replay.
    """

    event_id: str
    event_index: int
    timestamp_ns: int
    context: RuntimeExecutionContext
    event_kind: RuntimeEventKind
    measurement_semantics: RuntimeMeasurementSemantics
    lock_kind: str
    lock_id: str | None = None
    stack_id: str | None = None
    owner_context: RuntimeExecutionContext | None = None
    wait_begin_event_id: str | None = None
    wait_end_event_id: str | None = None
    acquire_event_id: str | None = None
    duration_ns: int | None = None
    hold_duration_ns: int | None = None
    outcome: str | None = None
    parked_context: RuntimeExecutionContext | None = None
    observed_count: int | None = None
    estimated_count: float | None = None
    cumulative_wait_ns: int | None = None

    def __post_init__(self) -> None:
        if not self.event_id or len(self.event_id) > 256:
            raise ValueError("runtime event requires a bounded identity")
        if self.event_index < 0 or self.timestamp_ns < 0:
            raise ValueError("runtime event index and timestamp must be non-negative")
        if not self.lock_kind or len(self.lock_kind) > 128:
            raise ValueError("runtime event requires a bounded lock kind")
        if self.lock_id is not None and (not self.lock_id or len(self.lock_id) > 256):
            raise ValueError("runtime lock identity must be bounded")
        if self.stack_id is not None and (not self.stack_id or len(self.stack_id) > 256):
            raise ValueError("runtime stack identity must be bounded")
        for value, label in (
            (self.duration_ns, "wait duration"),
            (self.hold_duration_ns, "hold duration"),
            (self.cumulative_wait_ns, "cumulative wait"),
        ):
            if value is not None and value < 0:
                raise ValueError(f"runtime {label} must be non-negative")
        if self.observed_count is not None and self.observed_count <= 0:
            raise ValueError("runtime observed count must be positive")
        if self.estimated_count is not None and (
            not isfinite(self.estimated_count) or self.estimated_count <= 0
        ):
            raise ValueError("runtime estimated count must be finite and positive")

        if self.event_kind is RuntimeEventKind.WAIT_BEGIN:
            self._reject_fields(
                "wait_begin",
                self.wait_begin_event_id,
                self.wait_end_event_id,
                self.acquire_event_id,
                self.duration_ns,
                self.hold_duration_ns,
                self.outcome,
                self.parked_context,
                self.observed_count,
                self.estimated_count,
                self.cumulative_wait_ns,
            )
        elif self.event_kind is RuntimeEventKind.WAIT_END:
            if self.duration_ns is None or self.outcome is None:
                raise ValueError("runtime wait_end requires duration and outcome")
            self._reject_fields(
                "wait_end",
                self.acquire_event_id,
                self.wait_end_event_id,
                self.hold_duration_ns,
                self.parked_context,
                self.observed_count,
                self.estimated_count,
                self.cumulative_wait_ns,
            )
        elif self.event_kind is RuntimeEventKind.ACQUIRE:
            self._reject_fields(
                "acquire",
                self.wait_begin_event_id,
                self.acquire_event_id,
                self.duration_ns,
                self.hold_duration_ns,
                self.outcome,
                self.owner_context,
                self.parked_context,
                self.observed_count,
                self.estimated_count,
                self.cumulative_wait_ns,
            )
        elif self.event_kind is RuntimeEventKind.RELEASE:
            if (self.acquire_event_id is None) != (self.hold_duration_ns is None):
                raise ValueError("runtime release acquire identity and duration must be paired")
            self._reject_fields(
                "release",
                self.wait_begin_event_id,
                self.wait_end_event_id,
                self.duration_ns,
                self.outcome,
                self.owner_context,
                self.parked_context,
                self.observed_count,
                self.estimated_count,
                self.cumulative_wait_ns,
            )
        elif self.event_kind is RuntimeEventKind.PARK:
            self._reject_fields(
                "park",
                self.wait_begin_event_id,
                self.wait_end_event_id,
                self.acquire_event_id,
                self.duration_ns,
                self.hold_duration_ns,
                self.outcome,
                self.owner_context,
                self.parked_context,
                self.observed_count,
                self.estimated_count,
                self.cumulative_wait_ns,
            )
        elif self.event_kind is RuntimeEventKind.UNPARK:
            self._reject_fields(
                "unpark",
                self.wait_begin_event_id,
                self.wait_end_event_id,
                self.acquire_event_id,
                self.duration_ns,
                self.hold_duration_ns,
                self.outcome,
                self.owner_context,
                self.observed_count,
                self.estimated_count,
                self.cumulative_wait_ns,
            )
        else:
            if self.measurement_semantics not in {
                RuntimeMeasurementSemantics.SAMPLED,
                RuntimeMeasurementSemantics.CUMULATIVE,
            }:
                raise ValueError("profile contention requires sampled/cumulative semantics")
            if self.observed_count is None or self.cumulative_wait_ns is None:
                raise ValueError("profile contention requires observed count and wait weight")
            self._reject_fields(
                "sampled_contention",
                self.wait_begin_event_id,
                self.wait_end_event_id,
                self.acquire_event_id,
                self.duration_ns,
                self.hold_duration_ns,
                self.outcome,
                self.owner_context,
                self.parked_context,
            )

    @staticmethod
    def _reject_fields(label: str, *values: object | None) -> None:
        if any(value is not None for value in values):
            raise ValueError(f"runtime {label} carries fields owned by another event kind")


@dataclass(frozen=True, slots=True)
class RuntimeDurationDistribution:
    sample_count: int
    total_ns: int
    minimum_ns: int
    mean_ns: int
    p50_ns: int
    p95_ns: int
    p99_ns: int
    maximum_ns: int


def nearest_rank_percentile(values: Sequence[int], percentile: int) -> int:
    """Return an integer nearest-rank percentile without floating-point interpolation."""

    if not values:
        return 0
    if percentile < 0 or percentile > 100:
        raise ValueError("runtime percentile must be between zero and one hundred")
    ordered = sorted(values)
    if percentile == 0:
        return ordered[0]
    rank = ceil(percentile * len(ordered) / 100)
    return ordered[rank - 1]


def duration_distribution(values: Sequence[int]) -> RuntimeDurationDistribution:
    if not values:
        return RuntimeDurationDistribution(0, 0, 0, 0, 0, 0, 0, 0)
    if any(value < 0 for value in values):
        raise ValueError("runtime duration distributions cannot contain negative values")
    total = sum(values)
    return RuntimeDurationDistribution(
        sample_count=len(values),
        total_ns=total,
        minimum_ns=min(values),
        mean_ns=total // len(values),
        p50_ns=nearest_rank_percentile(values, 50),
        p95_ns=nearest_rank_percentile(values, 95),
        p99_ns=nearest_rank_percentile(values, 99),
        maximum_ns=max(values),
    )


class RuntimePairingPhase(StrEnum):
    WAIT = "wait"
    HOLD = "hold"
    PARK = "park"


class RuntimePairingReason(StrEnum):
    DUPLICATE_WAIT_BEGIN = "duplicate_wait_begin"
    UNKNOWN_WAIT_BEGIN = "unknown_wait_begin"
    WAIT_IDENTITY_MISMATCH = "wait_identity_mismatch"
    WAIT_DURATION_MISMATCH = "wait_duration_mismatch"
    WAIT_END_WITHOUT_BEGIN = "wait_end_without_begin"
    ACQUIRE_WITHOUT_WAIT = "acquire_without_wait"
    DUPLICATE_ACQUIRE = "duplicate_acquire"
    UNKNOWN_ACQUIRE = "unknown_acquire"
    HOLD_IDENTITY_MISMATCH = "hold_identity_mismatch"
    HOLD_DURATION_MISMATCH = "hold_duration_mismatch"
    RELEASE_WITHOUT_ACQUIRE = "release_without_acquire"
    NON_LIFO_RELEASE = "non_lifo_release"
    REUSED_WAIT_BEGIN = "reused_wait_begin"
    REUSED_WAIT_END = "reused_wait_end"
    REUSED_ACQUIRE = "reused_acquire"
    UNPARK_WITHOUT_PARK = "unpark_without_park"
    TRACE_END_BOUNDARY = "trace_end_boundary"


@dataclass(frozen=True, slots=True)
class RuntimePairingIssue:
    phase: RuntimePairingPhase
    reason: RuntimePairingReason
    event_ids: tuple[str, ...]
    context: RuntimeExecutionContext
    lock_id: str | None
    lock_kind: str


@dataclass(frozen=True, slots=True)
class RuntimeWaitObservation:
    context: RuntimeExecutionContext
    lock_id: str | None
    lock_kind: str
    stack_id: str | None
    semantics: RuntimeMeasurementSemantics
    duration_ns: int
    outcome: str
    owner_observed: bool
    event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuntimeHoldObservation:
    context: RuntimeExecutionContext
    lock_id: str | None
    lock_kind: str
    stack_id: str | None
    duration_ns: int
    event_ids: tuple[str, str]


@dataclass(frozen=True, slots=True)
class RuntimeProfileObservation:
    context: RuntimeExecutionContext
    lock_id: str | None
    lock_kind: str
    stack_id: str | None
    semantics: RuntimeMeasurementSemantics
    observed_count: int
    estimated_count: float | None
    cumulative_wait_ns: int
    event_id: str


@dataclass(frozen=True, slots=True)
class RuntimeReplay:
    semantics: RuntimeMeasurementSemantics | None
    waits: tuple[RuntimeWaitObservation, ...]
    holds: tuple[RuntimeHoldObservation, ...]
    profiles: tuple[RuntimeProfileObservation, ...]
    issues: tuple[RuntimePairingIssue, ...]
    consumed_event_ids: tuple[str, ...]
    unpaired_event_ids: tuple[str, ...]
    ignored_event_ids: tuple[str, ...]

    @property
    def observed_event_count(self) -> int:
        return (
            len(self.consumed_event_ids)
            + len(self.unpaired_event_ids)
            + len(self.ignored_event_ids)
        )


@dataclass(slots=True)
class _Status:
    used: bool = False
    invalid: bool = False


def _same_subject(left: RuntimeLockEvent, right: RuntimeLockEvent) -> bool:
    return (
        left.context == right.context
        and left.lock_id == right.lock_id
        and left.lock_kind == right.lock_kind
        and left.measurement_semantics == right.measurement_semantics
    )


def _duration_matches(start: RuntimeLockEvent, end: RuntimeLockEvent, duration_ns: int) -> bool:
    return end.timestamp_ns >= start.timestamp_ns and (
        end.timestamp_ns - start.timestamp_ns == duration_ns
    )


def replay_runtime_lock_events(events: Sequence[RuntimeLockEvent]) -> RuntimeReplay:
    """Validate canonical order and conservatively replay all supported pairings."""

    _validate_sequence(events)
    semantics = events[0].measurement_semantics if events else None
    statuses = {event.event_id: _Status() for event in events}
    by_id = {event.event_id: event for event in events}
    pending_waits: dict[tuple[RuntimeExecutionContext, str | None, str], RuntimeLockEvent] = {}
    active_acquires: dict[
        tuple[RuntimeExecutionContext, str | None, str], list[RuntimeLockEvent]
    ] = {}
    pending_parks: dict[tuple[RuntimeExecutionContext, str | None, str], RuntimeLockEvent] = {}
    waits: list[RuntimeWaitObservation] = []
    holds: list[RuntimeHoldObservation] = []
    profiles: list[RuntimeProfileObservation] = []
    issues: list[RuntimePairingIssue] = []
    paired_wait_begins: set[str] = set()
    linked_wait_ends: set[str] = set()
    released_acquires: set[str] = set()

    def key(event: RuntimeLockEvent) -> tuple[RuntimeExecutionContext, str | None, str]:
        return event.context, event.lock_id, event.lock_kind

    def mark_used(*paired: RuntimeLockEvent) -> None:
        for item in paired:
            statuses[item.event_id].used = True

    def issue(
        phase: RuntimePairingPhase,
        reason: RuntimePairingReason,
        subject: RuntimeLockEvent,
        *related: RuntimeLockEvent,
    ) -> None:
        implicated = (subject, *related)
        for item in implicated:
            statuses[item.event_id].invalid = True
        issues.append(
            RuntimePairingIssue(
                phase=phase,
                reason=reason,
                event_ids=tuple(item.event_id for item in implicated),
                context=subject.context,
                lock_id=subject.lock_id,
                lock_kind=subject.lock_kind,
            )
        )

    def record_wait(
        start: RuntimeLockEvent,
        end: RuntimeLockEvent,
        *,
        duration_ns: int,
        outcome: str,
        context: RuntimeExecutionContext | None = None,
    ) -> None:
        waits.append(
            RuntimeWaitObservation(
                context=context or start.context,
                lock_id=start.lock_id,
                lock_kind=start.lock_kind,
                stack_id=end.stack_id or start.stack_id,
                semantics=start.measurement_semantics,
                duration_ns=duration_ns,
                outcome=outcome,
                owner_observed=(start.owner_context is not None or end.owner_context is not None),
                event_ids=(start.event_id, end.event_id),
            )
        )
        if start.event_kind is RuntimeEventKind.WAIT_BEGIN:
            paired_wait_begins.add(start.event_id)
        mark_used(start, end)

    for event in events:
        subject_key = key(event)
        if event.event_kind is RuntimeEventKind.WAIT_BEGIN:
            previous = pending_waits.get(subject_key)
            if previous is not None:
                issue(
                    RuntimePairingPhase.WAIT,
                    RuntimePairingReason.DUPLICATE_WAIT_BEGIN,
                    previous,
                    event,
                )
                pending_waits.pop(subject_key)
            else:
                pending_waits[subject_key] = event
            continue

        if event.event_kind is RuntimeEventKind.WAIT_END:
            assert event.duration_ns is not None
            assert event.outcome is not None
            start: RuntimeLockEvent | None = None
            if event.wait_begin_event_id is not None:
                referenced = by_id.get(event.wait_begin_event_id)
                if referenced is None or referenced.event_kind is not RuntimeEventKind.WAIT_BEGIN:
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.UNKNOWN_WAIT_BEGIN,
                        event,
                    )
                    continue
                if referenced.event_id in paired_wait_begins:
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.REUSED_WAIT_BEGIN,
                        event,
                        referenced,
                    )
                    continue
                if statuses[referenced.event_id].invalid:
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.REUSED_WAIT_BEGIN,
                        event,
                        referenced,
                    )
                    continue
                if not _same_subject(referenced, event):
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.WAIT_IDENTITY_MISMATCH,
                        event,
                        referenced,
                    )
                    pending_waits.pop(key(referenced), None)
                    continue
                start = referenced
            else:
                start = pending_waits.get(subject_key)

            # Thresholded tools such as JFR can legitimately provide a complete duration
            # without exposing a separate begin event.  Exact evidence cannot.
            if start is None:
                if event.measurement_semantics is RuntimeMeasurementSemantics.THRESHOLDED:
                    waits.append(
                        RuntimeWaitObservation(
                            context=event.context,
                            lock_id=event.lock_id,
                            lock_kind=event.lock_kind,
                            stack_id=event.stack_id,
                            semantics=event.measurement_semantics,
                            duration_ns=event.duration_ns,
                            outcome=event.outcome,
                            owner_observed=event.owner_context is not None,
                            event_ids=(event.event_id,),
                        )
                    )
                    mark_used(event)
                else:
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.WAIT_END_WITHOUT_BEGIN,
                        event,
                    )
                continue
            pending_waits.pop(key(start), None)
            if not _duration_matches(start, event, event.duration_ns):
                issue(
                    RuntimePairingPhase.WAIT,
                    RuntimePairingReason.WAIT_DURATION_MISMATCH,
                    event,
                    start,
                )
                continue
            record_wait(start, event, duration_ns=event.duration_ns, outcome=event.outcome)
            continue

        if event.event_kind is RuntimeEventKind.ACQUIRE:
            if event.wait_end_event_id is not None:
                referenced_end = by_id.get(event.wait_end_event_id)
                if (
                    referenced_end is None
                    or referenced_end.event_kind is not RuntimeEventKind.WAIT_END
                    or referenced_end.outcome != "acquired"
                ):
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.UNKNOWN_WAIT_BEGIN,
                        event,
                    )
                    continue
                if referenced_end.event_id in linked_wait_ends:
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.REUSED_WAIT_END,
                        event,
                        referenced_end,
                    )
                    continue
                if statuses[referenced_end.event_id].invalid:
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.REUSED_WAIT_END,
                        event,
                        referenced_end,
                    )
                    continue
                if (
                    not _same_subject(referenced_end, event)
                    or referenced_end.timestamp_ns > event.timestamp_ns
                ):
                    issue(
                        RuntimePairingPhase.WAIT,
                        RuntimePairingReason.WAIT_IDENTITY_MISMATCH,
                        event,
                        referenced_end,
                    )
                    continue
                mark_used(referenced_end, event)
                linked_wait_ends.add(referenced_end.event_id)
            start = pending_waits.pop(subject_key, None)
            if start is not None:
                record_wait(
                    start,
                    event,
                    duration_ns=event.timestamp_ns - start.timestamp_ns,
                    outcome="acquired",
                )
            elif event.measurement_semantics is RuntimeMeasurementSemantics.EXACT:
                # A visible uncontended acquire is valid fast-path evidence.  It becomes
                # consumed once paired with release; until then it remains conservatively
                # unpaired rather than fabricating a zero wait.
                pass
            active = active_acquires.setdefault(subject_key, [])
            if active and event.lock_kind != "recursive_mutex":
                previous = active.pop()
                issue(
                    RuntimePairingPhase.HOLD,
                    RuntimePairingReason.DUPLICATE_ACQUIRE,
                    previous,
                    event,
                )
                if not active:
                    active_acquires.pop(subject_key, None)
            else:
                active.append(event)
            continue

        if event.event_kind is RuntimeEventKind.RELEASE:
            acquire: RuntimeLockEvent | None
            if event.acquire_event_id is not None:
                referenced = by_id.get(event.acquire_event_id)
                if referenced is None or referenced.event_kind is not RuntimeEventKind.ACQUIRE:
                    issue(
                        RuntimePairingPhase.HOLD,
                        RuntimePairingReason.UNKNOWN_ACQUIRE,
                        event,
                    )
                    continue
                if referenced.event_id in released_acquires:
                    issue(
                        RuntimePairingPhase.HOLD,
                        RuntimePairingReason.REUSED_ACQUIRE,
                        event,
                        referenced,
                    )
                    continue
                if statuses[referenced.event_id].invalid:
                    issue(
                        RuntimePairingPhase.HOLD,
                        RuntimePairingReason.REUSED_ACQUIRE,
                        event,
                        referenced,
                    )
                    continue
                if not _same_subject(referenced, event):
                    issue(
                        RuntimePairingPhase.HOLD,
                        RuntimePairingReason.HOLD_IDENTITY_MISMATCH,
                        event,
                        referenced,
                    )
                    active_acquires.pop(key(referenced), None)
                    continue
                acquire = referenced
            else:
                active = active_acquires.get(subject_key, [])
                acquire = active[-1] if active else None
            if acquire is None:
                issue(
                    RuntimePairingPhase.HOLD,
                    RuntimePairingReason.RELEASE_WITHOUT_ACQUIRE,
                    event,
                )
                continue
            active = active_acquires.get(key(acquire), [])
            if not active or acquire not in active:
                issue(
                    RuntimePairingPhase.HOLD,
                    RuntimePairingReason.REUSED_ACQUIRE,
                    event,
                    acquire,
                )
                continue
            if active[-1] is not acquire:
                issue(
                    RuntimePairingPhase.HOLD,
                    RuntimePairingReason.NON_LIFO_RELEASE,
                    event,
                    acquire,
                )
                active_acquires.pop(key(acquire), None)
                continue
            active.pop()
            if not active:
                active_acquires.pop(key(acquire), None)
            released_acquires.add(acquire.event_id)
            duration_ns = event.hold_duration_ns
            if duration_ns is None:
                # A complete acquire/release pair is useful accounting, but timestamps alone
                # are not source-observed hold evidence.  Never manufacture a hold duration.
                mark_used(acquire, event)
                continue
            if not _duration_matches(acquire, event, duration_ns):
                issue(
                    RuntimePairingPhase.HOLD,
                    RuntimePairingReason.HOLD_DURATION_MISMATCH,
                    event,
                    acquire,
                )
                continue
            if event.measurement_semantics is RuntimeMeasurementSemantics.EXACT:
                holds.append(
                    RuntimeHoldObservation(
                        context=event.context,
                        lock_id=event.lock_id,
                        lock_kind=event.lock_kind,
                        stack_id=event.stack_id or acquire.stack_id,
                        duration_ns=duration_ns,
                        event_ids=(acquire.event_id, event.event_id),
                    )
                )
            mark_used(acquire, event)
            continue

        if event.event_kind is RuntimeEventKind.PARK:
            previous = pending_parks.get(subject_key)
            if previous is not None:
                issue(
                    RuntimePairingPhase.PARK,
                    RuntimePairingReason.DUPLICATE_WAIT_BEGIN,
                    previous,
                    event,
                )
                pending_parks.pop(subject_key)
            else:
                pending_parks[subject_key] = event
            continue

        if event.event_kind is RuntimeEventKind.UNPARK:
            if event.parked_context is None:
                issue(
                    RuntimePairingPhase.PARK,
                    RuntimePairingReason.UNPARK_WITHOUT_PARK,
                    event,
                )
                continue
            park_key = event.parked_context, event.lock_id, event.lock_kind
            park = pending_parks.pop(park_key, None)
            if park is None or statuses[park.event_id].invalid:
                issue(
                    RuntimePairingPhase.PARK,
                    RuntimePairingReason.UNPARK_WITHOUT_PARK,
                    event,
                    *((park,) if park is not None else ()),
                )
                continue
            record_wait(
                park,
                event,
                duration_ns=event.timestamp_ns - park.timestamp_ns,
                outcome="unparked",
                context=park.context,
            )
            continue

        assert event.event_kind is RuntimeEventKind.SAMPLED_CONTENTION
        assert event.observed_count is not None
        assert event.cumulative_wait_ns is not None
        profiles.append(
            RuntimeProfileObservation(
                context=event.context,
                lock_id=event.lock_id,
                lock_kind=event.lock_kind,
                stack_id=event.stack_id,
                semantics=event.measurement_semantics,
                observed_count=event.observed_count,
                estimated_count=event.estimated_count,
                cumulative_wait_ns=event.cumulative_wait_ns,
                event_id=event.event_id,
            )
        )
        mark_used(event)

    for pending, phase in (
        (pending_waits.values(), RuntimePairingPhase.WAIT),
        (
            (event for active in active_acquires.values() for event in active),
            RuntimePairingPhase.HOLD,
        ),
        (pending_parks.values(), RuntimePairingPhase.PARK),
    ):
        for event in pending:
            issue(phase, RuntimePairingReason.TRACE_END_BOUNDARY, event)

    consumed: list[str] = []
    unpaired: list[str] = []
    ignored: list[str] = []
    for event in events:
        status = statuses[event.event_id]
        if status.used:
            consumed.append(event.event_id)
        elif status.invalid:
            unpaired.append(event.event_id)
        else:
            # No supported runtime event is silently discarded.  Keeping this branch makes
            # disposition conservation explicit if new event kinds are added later.
            ignored.append(event.event_id)
    return RuntimeReplay(
        semantics=semantics,
        waits=tuple(waits),
        holds=tuple(holds),
        profiles=tuple(profiles),
        issues=tuple(issues),
        consumed_event_ids=tuple(consumed),
        unpaired_event_ids=tuple(unpaired),
        ignored_event_ids=tuple(ignored),
    )


def _validate_sequence(events: Sequence[RuntimeLockEvent]) -> None:
    event_ids = tuple(event.event_id for event in events)
    if len(set(event_ids)) != len(event_ids):
        raise ValueError("runtime event IDs must be unique")
    if tuple(event.event_index for event in events) != tuple(range(len(events))):
        raise ValueError("runtime event indexes must be contiguous")
    ordering = tuple((event.timestamp_ns, event.event_index) for event in events)
    if ordering != tuple(sorted(ordering)):
        raise ValueError("runtime events must use canonical timestamp/index order")
    semantics = {event.measurement_semantics for event in events}
    if len(semantics) > 1:
        raise ValueError("one runtime evidence stream must use one measurement semantics")


@dataclass(frozen=True, slots=True)
class RuntimeProjectionMetrics:
    exact_waits: RuntimeDurationDistribution
    thresholded_waits: RuntimeDurationDistribution
    sampled_observation_count: int
    cumulative_observation_count: int
    observed_or_estimated_wait_ns: int
    exact_holds: RuntimeDurationDistribution
    owner_observed_count: int

    @property
    def observation_count(self) -> int:
        return (
            self.exact_waits.sample_count
            + self.thresholded_waits.sample_count
            + self.sampled_observation_count
            + self.cumulative_observation_count
        )

    @property
    def total_wait_ns(self) -> int:
        return self.observed_or_estimated_wait_ns


@dataclass(frozen=True, slots=True)
class RuntimeLockProjection:
    lock_id: str | None
    lock_kind: str
    metrics: RuntimeProjectionMetrics
    waiter_context_count: int
    top_stack_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuntimeContextProjection:
    context: RuntimeExecutionContext
    metrics: RuntimeProjectionMetrics
    lock_count: int | None


@dataclass(frozen=True, slots=True)
class RuntimeCallPathProjection:
    stack_id: str | None
    metrics: RuntimeProjectionMetrics
    lock_count: int | None
    execution_context_count: int


@dataclass(frozen=True, slots=True)
class RuntimeOutcomeProjection:
    outcome: str
    metrics: RuntimeProjectionMetrics
    lock_count: int | None
    execution_context_count: int


@dataclass(frozen=True, slots=True)
class RuntimeLockKindProjection:
    lock_kind: str
    metrics: RuntimeProjectionMetrics
    lock_count: int | None
    execution_context_count: int


@dataclass(frozen=True, slots=True)
class RuntimeProjectionOmission:
    total_row_count: int
    exported_row_count: int
    omitted_row_count: int
    omitted_exact_wait_count: int
    omitted_exact_wait_ns: int
    omitted_thresholded_wait_count: int
    omitted_thresholded_wait_ns: int
    omitted_sampled_observation_count: int
    omitted_cumulative_observation_count: int
    omitted_observed_or_estimated_wait_ns: int
    omitted_observation_count: int
    omitted_wait_ns: int
    omitted_hold_count: int
    omitted_hold_ns: int
    omitted_owner_observed_count: int

    def __post_init__(self) -> None:
        if self.total_row_count != self.exported_row_count + self.omitted_row_count:
            raise ValueError("runtime projection row counts are not conserved")
        if self.omitted_observation_count != (
            self.omitted_exact_wait_count
            + self.omitted_thresholded_wait_count
            + self.omitted_sampled_observation_count
            + self.omitted_cumulative_observation_count
        ):
            raise ValueError("runtime omitted semantic observation counts are not conserved")
        if self.omitted_wait_ns != self.omitted_observed_or_estimated_wait_ns:
            raise ValueError("runtime omitted semantic wait weights are not conserved")


@dataclass(frozen=True, slots=True)
class RuntimeProjectionPage:
    rows: tuple[object, ...]
    omission: RuntimeProjectionOmission


@dataclass(frozen=True, slots=True)
class RuntimeLockAnalysis:
    replay: RuntimeReplay
    totals: RuntimeProjectionMetrics
    locks: RuntimeProjectionPage
    contexts: RuntimeProjectionPage
    call_paths: RuntimeProjectionPage
    outcomes: RuntimeProjectionPage
    lock_kinds: RuntimeProjectionPage


def _new_int_list() -> list[int]:
    return []


@dataclass(slots=True)
class _Accumulator:
    exact_wait_ns: list[int] = field(default_factory=_new_int_list)
    thresholded_wait_ns: list[int] = field(default_factory=_new_int_list)
    sampled_observation_count: int = 0
    cumulative_observation_count: int = 0
    observed_or_estimated_wait_ns: int = 0
    exact_hold_ns: list[int] = field(default_factory=_new_int_list)
    owner_observed_count: int = 0

    def metrics(self) -> RuntimeProjectionMetrics:
        return RuntimeProjectionMetrics(
            exact_waits=duration_distribution(self.exact_wait_ns),
            thresholded_waits=duration_distribution(self.thresholded_wait_ns),
            sampled_observation_count=self.sampled_observation_count,
            cumulative_observation_count=self.cumulative_observation_count,
            observed_or_estimated_wait_ns=self.observed_or_estimated_wait_ns,
            exact_holds=duration_distribution(self.exact_hold_ns),
            owner_observed_count=self.owner_observed_count,
        )


def _accumulate_wait(accumulator: _Accumulator, observation: RuntimeWaitObservation) -> None:
    if observation.semantics is RuntimeMeasurementSemantics.EXACT:
        accumulator.exact_wait_ns.append(observation.duration_ns)
    elif observation.semantics is RuntimeMeasurementSemantics.THRESHOLDED:
        accumulator.thresholded_wait_ns.append(observation.duration_ns)
    else:
        raise ValueError("paired runtime wait carried profile measurement semantics")
    accumulator.observed_or_estimated_wait_ns += observation.duration_ns
    if observation.owner_observed:
        accumulator.owner_observed_count += 1


def _accumulate_profile(accumulator: _Accumulator, observation: RuntimeProfileObservation) -> None:
    if observation.semantics is RuntimeMeasurementSemantics.SAMPLED:
        accumulator.sampled_observation_count += observation.observed_count
    elif observation.semantics is RuntimeMeasurementSemantics.CUMULATIVE:
        accumulator.cumulative_observation_count += observation.observed_count
    else:
        raise ValueError("profile runtime observation carried event measurement semantics")
    accumulator.observed_or_estimated_wait_ns += observation.cumulative_wait_ns


def _sort_key(metrics: RuntimeProjectionMetrics, identity: str) -> tuple[int, int, int, str]:
    return (
        -metrics.total_wait_ns,
        -metrics.exact_holds.total_ns,
        -metrics.observation_count,
        identity,
    )


def _known_lock_count(values: set[tuple[str | None, str]]) -> int | None:
    """Return no cardinality when any contributing observation hid its lock identity."""

    return None if any(lock_id is None for lock_id, _kind in values) else len(values)


def _page[TProjection](
    rows: Sequence[TProjection],
    *,
    limit: int,
    metrics: Callable[[TProjection], RuntimeProjectionMetrics],
) -> RuntimeProjectionPage:
    if limit < 1:
        raise ValueError("runtime projection export limit must be positive")
    exported = tuple(rows[:limit])
    omitted = rows[limit:]
    omission = RuntimeProjectionOmission(
        total_row_count=len(rows),
        exported_row_count=len(exported),
        omitted_row_count=len(omitted),
        omitted_exact_wait_count=sum(metrics(row).exact_waits.sample_count for row in omitted),
        omitted_exact_wait_ns=sum(metrics(row).exact_waits.total_ns for row in omitted),
        omitted_thresholded_wait_count=sum(
            metrics(row).thresholded_waits.sample_count for row in omitted
        ),
        omitted_thresholded_wait_ns=sum(metrics(row).thresholded_waits.total_ns for row in omitted),
        omitted_sampled_observation_count=sum(
            metrics(row).sampled_observation_count for row in omitted
        ),
        omitted_cumulative_observation_count=sum(
            metrics(row).cumulative_observation_count for row in omitted
        ),
        omitted_observed_or_estimated_wait_ns=sum(
            metrics(row).observed_or_estimated_wait_ns for row in omitted
        ),
        omitted_observation_count=sum(metrics(row).observation_count for row in omitted),
        omitted_wait_ns=sum(metrics(row).total_wait_ns for row in omitted),
        omitted_hold_count=sum(metrics(row).exact_holds.sample_count for row in omitted),
        omitted_hold_ns=sum(metrics(row).exact_holds.total_ns for row in omitted),
        omitted_owner_observed_count=sum(metrics(row).owner_observed_count for row in omitted),
    )
    return RuntimeProjectionPage(rows=exported, omission=omission)


def analyze_runtime_lock_events(
    events: Sequence[RuntimeLockEvent],
    *,
    max_exported_rows: int,
    max_top_stack_ids: int = 10,
) -> RuntimeLockAnalysis:
    """Replay events and build five independently conserved deterministic projections."""

    if max_top_stack_ids < 1:
        raise ValueError("runtime top-stack limit must be positive")
    replay = replay_runtime_lock_events(events)
    totals = _Accumulator()
    by_lock: dict[tuple[str | None, str], _Accumulator] = defaultdict(_Accumulator)
    lock_contexts: dict[tuple[str | None, str], set[RuntimeExecutionContext]] = defaultdict(set)
    lock_stacks: dict[tuple[str | None, str], dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    by_context: dict[RuntimeExecutionContext, _Accumulator] = defaultdict(_Accumulator)
    context_locks: dict[RuntimeExecutionContext, set[tuple[str | None, str]]] = defaultdict(set)
    by_path: dict[str | None, _Accumulator] = defaultdict(_Accumulator)
    path_locks: dict[str | None, set[tuple[str | None, str]]] = defaultdict(set)
    path_contexts: dict[str | None, set[RuntimeExecutionContext]] = defaultdict(set)
    by_outcome: dict[str, _Accumulator] = defaultdict(_Accumulator)
    outcome_locks: dict[str, set[tuple[str | None, str]]] = defaultdict(set)
    outcome_contexts: dict[str, set[RuntimeExecutionContext]] = defaultdict(set)
    by_kind: dict[str, _Accumulator] = defaultdict(_Accumulator)
    kind_locks: dict[str, set[tuple[str | None, str]]] = defaultdict(set)
    kind_contexts: dict[str, set[RuntimeExecutionContext]] = defaultdict(set)

    for observation in replay.waits:
        lock_key = observation.lock_id, observation.lock_kind
        targets = (
            totals,
            by_lock[lock_key],
            by_context[observation.context],
            by_path[observation.stack_id],
            by_outcome[observation.outcome],
            by_kind[observation.lock_kind],
        )
        for target in targets:
            _accumulate_wait(target, observation)
        lock_contexts[lock_key].add(observation.context)
        context_locks[observation.context].add(lock_key)
        path_locks[observation.stack_id].add(lock_key)
        path_contexts[observation.stack_id].add(observation.context)
        outcome_locks[observation.outcome].add(lock_key)
        outcome_contexts[observation.outcome].add(observation.context)
        kind_locks[observation.lock_kind].add(lock_key)
        kind_contexts[observation.lock_kind].add(observation.context)
        if observation.stack_id is not None:
            lock_stacks[lock_key][observation.stack_id] += observation.duration_ns

    for observation in replay.holds:
        lock_key = observation.lock_id, observation.lock_kind
        targets = (
            totals,
            by_lock[lock_key],
            by_context[observation.context],
            by_path[observation.stack_id],
            by_outcome["acquired"],
            by_kind[observation.lock_kind],
        )
        for target in targets:
            target.exact_hold_ns.append(observation.duration_ns)
        context_locks[observation.context].add(lock_key)
        path_locks[observation.stack_id].add(lock_key)
        path_contexts[observation.stack_id].add(observation.context)
        outcome_locks["acquired"].add(lock_key)
        outcome_contexts["acquired"].add(observation.context)
        kind_locks[observation.lock_kind].add(lock_key)
        kind_contexts[observation.lock_kind].add(observation.context)
        if observation.stack_id is not None:
            lock_stacks[lock_key][observation.stack_id] += observation.duration_ns

    for observation in replay.profiles:
        lock_key = observation.lock_id, observation.lock_kind
        targets = (
            totals,
            by_lock[lock_key],
            by_context[observation.context],
            by_path[observation.stack_id],
            by_outcome["unknown"],
            by_kind[observation.lock_kind],
        )
        for target in targets:
            _accumulate_profile(target, observation)
        lock_contexts[lock_key].add(observation.context)
        context_locks[observation.context].add(lock_key)
        path_locks[observation.stack_id].add(lock_key)
        path_contexts[observation.stack_id].add(observation.context)
        outcome_locks["unknown"].add(lock_key)
        outcome_contexts["unknown"].add(observation.context)
        kind_locks[observation.lock_kind].add(lock_key)
        kind_contexts[observation.lock_kind].add(observation.context)
        if observation.stack_id is not None:
            lock_stacks[lock_key][observation.stack_id] += observation.cumulative_wait_ns

    locks = [
        RuntimeLockProjection(
            lock_id=lock_id,
            lock_kind=lock_kind,
            metrics=accumulator.metrics(),
            waiter_context_count=len(lock_contexts[(lock_id, lock_kind)]),
            top_stack_ids=tuple(
                stack_id
                for stack_id, _weight in sorted(
                    lock_stacks[(lock_id, lock_kind)].items(),
                    key=lambda item: (-item[1], item[0]),
                )[:max_top_stack_ids]
            ),
        )
        for (lock_id, lock_kind), accumulator in by_lock.items()
    ]
    locks.sort(
        key=lambda row: _sort_key(row.metrics, f"{row.lock_id or '~aggregate'}\0{row.lock_kind}")
    )
    contexts = [
        RuntimeContextProjection(
            context=context,
            metrics=accumulator.metrics(),
            lock_count=_known_lock_count(context_locks[context]),
        )
        for context, accumulator in by_context.items()
    ]
    contexts.sort(
        key=lambda row: _sort_key(
            row.metrics,
            f"{row.context.kind.value}\0{row.context.context_id}\0{row.context.target_tid or 0}",
        )
    )
    paths = [
        RuntimeCallPathProjection(
            stack_id=stack_id,
            metrics=accumulator.metrics(),
            lock_count=_known_lock_count(path_locks[stack_id]),
            execution_context_count=len(path_contexts[stack_id]),
        )
        for stack_id, accumulator in by_path.items()
    ]
    paths.sort(key=lambda row: _sort_key(row.metrics, row.stack_id or "~unknown"))
    outcomes = [
        RuntimeOutcomeProjection(
            outcome=outcome,
            metrics=accumulator.metrics(),
            lock_count=_known_lock_count(outcome_locks[outcome]),
            execution_context_count=len(outcome_contexts[outcome]),
        )
        for outcome, accumulator in by_outcome.items()
    ]
    outcomes.sort(key=lambda row: _sort_key(row.metrics, row.outcome))
    kinds = [
        RuntimeLockKindProjection(
            lock_kind=lock_kind,
            metrics=accumulator.metrics(),
            lock_count=_known_lock_count(kind_locks[lock_kind]),
            execution_context_count=len(kind_contexts[lock_kind]),
        )
        for lock_kind, accumulator in by_kind.items()
    ]
    kinds.sort(key=lambda row: _sort_key(row.metrics, row.lock_kind))

    analysis = RuntimeLockAnalysis(
        replay=replay,
        totals=totals.metrics(),
        locks=_page(locks, limit=max_exported_rows, metrics=lambda row: row.metrics),
        contexts=_page(contexts, limit=max_exported_rows, metrics=lambda row: row.metrics),
        call_paths=_page(paths, limit=max_exported_rows, metrics=lambda row: row.metrics),
        outcomes=_page(outcomes, limit=max_exported_rows, metrics=lambda row: row.metrics),
        lock_kinds=_page(kinds, limit=max_exported_rows, metrics=lambda row: row.metrics),
    )
    validate_runtime_projection_conservation(analysis)
    return analysis


def validate_runtime_projection_conservation(analysis: RuntimeLockAnalysis) -> None:
    """Independently assert every exported+omitted projection equals global totals."""

    expected = _metric_ledger(analysis.totals)
    for name, page in (
        ("lock", analysis.locks),
        ("context", analysis.contexts),
        ("call path", analysis.call_paths),
        ("lock kind", analysis.lock_kinds),
    ):
        rows = tuple(page.rows)
        actual = _sum_metric_ledgers(_metric_ledger(_projection_metrics(row)) for row in rows)
        omission = page.omission
        actual = (
            actual[0] + omission.omitted_observation_count,
            actual[1] + omission.omitted_wait_ns,
            actual[2] + omission.omitted_hold_count,
            actual[3] + omission.omitted_hold_ns,
        )
        if actual != expected:
            raise ValueError(f"runtime {name} projection weights are not conserved")

    # Holds follow successful acquisition; profiles lack a source outcome and are projected
    # under ``unknown``.  This keeps the outcome projection complete without inventing success.
    outcome_expected = expected
    outcome_actual = _sum_metric_ledgers(
        _metric_ledger(_projection_metrics(row)) for row in analysis.outcomes.rows
    )
    outcome_actual = (
        outcome_actual[0] + analysis.outcomes.omission.omitted_observation_count,
        outcome_actual[1] + analysis.outcomes.omission.omitted_wait_ns,
        outcome_actual[2] + analysis.outcomes.omission.omitted_hold_count,
        outcome_actual[3] + analysis.outcomes.omission.omitted_hold_ns,
    )
    if outcome_actual != outcome_expected:
        raise ValueError("runtime outcome projection weights are not conserved")


def _projection_metrics(row: object) -> RuntimeProjectionMetrics:
    value = getattr(row, "metrics", None)
    if not isinstance(value, RuntimeProjectionMetrics):
        raise TypeError("runtime projection row does not expose deterministic metrics")
    return value


def _metric_ledger(metrics: RuntimeProjectionMetrics) -> tuple[int, int, int, int]:
    return (
        metrics.observation_count,
        metrics.total_wait_ns,
        metrics.exact_holds.sample_count,
        metrics.exact_holds.total_ns,
    )


def _sum_metric_ledgers(
    ledgers: Iterable[tuple[int, int, int, int]],
) -> tuple[int, int, int, int]:
    observation_count = wait_ns = hold_count = hold_ns = 0
    for ledger in ledgers:
        observation_count += ledger[0]
        wait_ns += ledger[1]
        hold_count += ledger[2]
        hold_ns += ledger[3]
    return observation_count, wait_ns, hold_count, hold_ns
