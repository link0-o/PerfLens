"""Deterministic scheduler and off-CPU analysis over normalized trace events.

The state machine is intentionally conservative: trace boundaries, duplicate wakeups, and
missing transitions produce incomplete intervals instead of guessed latency or wait categories.
Foreign task identities are used only to recognize target transitions and are never copied into
analysis results.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import islice

from perflens.domain.trace import (
    FutexEvent,
    LockEvent,
    ResourceLimits,
    SchedMigrateEvent,
    SchedSwitchEvent,
    SchedWakeupEvent,
    TargetIdentity,
    TraceEvent,
    TraceScope,
    validate_trace_sequence,
)


class IntervalCompleteness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class IncompleteReason(StrEnum):
    TRACE_START_BOUNDARY = "trace_start_boundary"
    TRACE_END_BOUNDARY = "trace_end_boundary"
    MISSING_WAKEUP = "missing_wakeup"
    DUPLICATE_WAKEUP = "duplicate_wakeup"
    OVERLAPPING_SWITCH_OUT = "overlapping_switch_out"
    DUPLICATE_SWITCH_IN = "duplicate_switch_in"


class WaitCategory(StrEnum):
    """Conservative candidate category; it is never a confirmed root cause."""

    SLEEP = "sleep"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    max_intervals: int = 100_000
    max_worst_intervals: int = 100
    max_event_ids: int = 1_000
    max_warnings: int = 100

    def __post_init__(self) -> None:
        if any(
            value < 1
            for value in (
                self.max_intervals,
                self.max_worst_intervals,
                self.max_event_ids,
                self.max_warnings,
            )
        ):
            raise ValueError("trace AnalysisLimits values must be positive")


@dataclass(frozen=True, slots=True)
class DurationDistribution:
    sample_count: int
    total_ns: int
    minimum_ns: int
    mean_ns: int
    p50_ns: int | None
    p95_ns: int | None
    p99_ns: int | None
    max_ns: int | None


@dataclass(frozen=True, slots=True)
class RuntimeInterval:
    tid: int
    switch_in_timestamp_ns: int
    switch_out_timestamp_ns: int
    duration_ns: int
    switch_in_event_id: str
    switch_out_event_id: str


@dataclass(frozen=True, slots=True)
class RunnableLatencyInterval:
    tid: int
    wakeup_timestamp_ns: int
    switch_in_timestamp_ns: int
    duration_ns: int
    wakeup_event_id: str
    switch_in_event_id: str
    waker_target_tid: int | None


@dataclass(frozen=True, slots=True)
class OffCpuInterval:
    tid: int
    switch_out_timestamp_ns: int | None
    wakeup_timestamp_ns: int | None
    switch_in_timestamp_ns: int | None
    total_duration_ns: int | None
    blocked_duration_ns: int | None
    runnable_duration_ns: int | None
    unknown_duration_ns: int | None
    observed_blocked_prefix_ns: int | None
    observed_runnable_suffix_ns: int | None
    previous_state: str | None
    candidate_wait_category: WaitCategory
    switch_out_stack: tuple[str, ...]
    waker_target_tid: int | None
    completeness: IntervalCompleteness
    split_complete: bool
    incomplete_reason: IncompleteReason | None
    switch_out_event_id: str | None
    wakeup_event_ids: tuple[str, ...]
    switch_in_event_id: str | None


@dataclass(frozen=True, slots=True)
class SchedulerThreadSummary:
    tid: int
    switch_in_count: int
    switch_out_count: int
    migration_count: int
    incomplete_transition_count: int
    runtime: DurationDistribution
    runnable_latency: DurationDistribution


@dataclass(frozen=True, slots=True)
class OffCpuThreadSummary:
    tid: int
    total_complete_interval_count: int
    split_complete_interval_count: int
    total_incomplete_interval_count: int
    off_cpu: DurationDistribution
    blocked: DurationDistribution
    runnable: DurationDistribution
    unknown: DurationDistribution
    candidate_categories: tuple[WaitCategoryCount, ...]

    @property
    def complete_interval_count(self) -> int:
        return self.total_complete_interval_count

    @property
    def incomplete_interval_count(self) -> int:
        return self.total_incomplete_interval_count


@dataclass(frozen=True, slots=True)
class EventIdLedger:
    total_count: int
    ids: tuple[str, ...]
    all_event_ids_sha256: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class WaitCategoryCount:
    category: WaitCategory
    interval_count: int


@dataclass(frozen=True, slots=True)
class AnalysisWarning:
    code: str
    message: str
    event_id: str | None = None
    tid: int | None = None


@dataclass(frozen=True, slots=True)
class EventAccounting:
    observed_event_count: int
    consumed: EventIdLedger
    unpaired: EventIdLedger
    ignored: EventIdLedger
    warning_count: int
    warnings: tuple[AnalysisWarning, ...]
    warnings_truncated: bool


@dataclass(frozen=True, slots=True)
class SchedulerAnalysis:
    target: TargetIdentity | None
    threads: tuple[SchedulerThreadSummary, ...]
    worst_runtime_intervals: tuple[RuntimeInterval, ...]
    worst_runnable_latencies: tuple[RunnableLatencyInterval, ...]
    runtime_interval_count: int
    runnable_latency_interval_count: int
    event_accounting: EventAccounting


@dataclass(frozen=True, slots=True)
class OffCpuAnalysis:
    target: TargetIdentity | None
    threads: tuple[OffCpuThreadSummary, ...]
    worst_intervals: tuple[OffCpuInterval, ...]
    interval_count: int
    total_complete_interval_count: int
    split_complete_interval_count: int
    total_incomplete_interval_count: int
    event_accounting: EventAccounting

    @property
    def complete_interval_count(self) -> int:
        return self.total_complete_interval_count

    @property
    def incomplete_interval_count(self) -> int:
        return self.total_incomplete_interval_count


@dataclass(slots=True)
class _RunState:
    timestamp_ns: int
    event_id: str
    cpu: int | None


@dataclass(slots=True)
class _Wakeup:
    timestamp_ns: int
    event_id: str
    waker_target_tid: int | None


@dataclass(slots=True)
class _OffCpuState:
    timestamp_ns: int
    event_id: str
    previous_state: str
    stack: tuple[str, ...]


def _new_int_list() -> list[int]:
    return []


def _new_category_counts() -> dict[WaitCategory, int]:
    return {}


@dataclass(slots=True)
class _ThreadAccumulator:
    switch_in_count: int = 0
    switch_out_count: int = 0
    migration_count: int = 0
    incomplete_transition_count: int = 0
    total_complete_off_cpu_count: int = 0
    split_complete_off_cpu_count: int = 0
    total_incomplete_off_cpu_count: int = 0
    runtime_ns: list[int] = field(default_factory=_new_int_list)
    runnable_latency_ns: list[int] = field(default_factory=_new_int_list)
    off_cpu_ns: list[int] = field(default_factory=_new_int_list)
    blocked_ns: list[int] = field(default_factory=_new_int_list)
    off_cpu_runnable_ns: list[int] = field(default_factory=_new_int_list)
    unknown_off_cpu_ns: list[int] = field(default_factory=_new_int_list)
    candidate_categories: dict[WaitCategory, int] = field(
        default_factory=_new_category_counts
    )


class _EventStatus(StrEnum):
    OBSERVED = "observed"
    CONSUMED = "consumed"
    UNPAIRED = "unpaired"
    IGNORED = "ignored"


class _EventAccountingBuilder:
    __slots__ = ("_limits", "_order", "_status", "_warning_count", "_warnings")

    def __init__(self, limits: AnalysisLimits) -> None:
        self._limits = limits
        self._order: list[str] = []
        self._status: dict[str, _EventStatus] = {}
        self._warning_count = 0
        self._warnings: list[AnalysisWarning] = []

    def observe(self, event_id: str, *, ignored: bool = False) -> None:
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
        event_id: str | None = None,
        tid: int | None = None,
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

        def build(status: _EventStatus) -> EventIdLedger:
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

        return EventAccounting(
            observed_event_count=len(self._order),
            consumed=build(_EventStatus.CONSUMED),
            unpaired=build(_EventStatus.UNPAIRED),
            ignored=build(_EventStatus.IGNORED),
            warning_count=self._warning_count,
            warnings=tuple(self._warnings),
            warnings_truncated=self._warning_count > len(self._warnings),
        )


def nearest_rank_percentile(values: Sequence[int], percentile: int) -> int:
    """Return the deterministic nearest-rank percentile for non-negative durations."""

    if not values:
        raise ValueError("nearest-rank percentile requires at least one value")
    if percentile < 1 or percentile > 100:
        raise ValueError("percentile must be in the inclusive range 1..100")
    if any(value < 0 for value in values):
        raise ValueError("duration values must be non-negative")
    ordered = sorted(values)
    rank = (percentile * len(ordered) + 99) // 100
    return ordered[rank - 1]


def event_id_ledger_sha256(event_ids: Iterable[str]) -> str:
    """Hash the complete ordered ledger without retaining another unbounded ID copy."""

    digest = hashlib.sha256()
    for event_id in event_ids:
        encoded = event_id.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


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


def _off_cpu_sort_key(interval: OffCpuInterval) -> tuple[int, int, int, str]:
    duration = -1 if interval.total_duration_ns is None else interval.total_duration_ns
    start = -1 if interval.switch_out_timestamp_ns is None else interval.switch_out_timestamp_ns
    event_id = interval.switch_out_event_id or interval.switch_in_event_id or ""
    return (-duration, interval.tid, start, event_id)


def _target_tid(task_tid: int | None) -> int:
    """Narrow a task TID after the domain validator established target scope."""

    if task_tid is None:
        raise ValueError("target-scoped scheduler event contains a redacted task")
    return task_tid


def _candidate_wait_category(previous_state: str | None) -> WaitCategory:
    if previous_state in {"interruptible_sleep", "parked", "stopped", "S"}:
        return WaitCategory.SLEEP
    return WaitCategory.UNKNOWN


@dataclass(frozen=True, slots=True)
class _TemporalResult:
    scheduler: SchedulerAnalysis
    off_cpu: OffCpuAnalysis


def _analyze_temporal(
    events: Sequence[TraceEvent],
    *,
    limits: AnalysisLimits,
    resource_limits: ResourceLimits,
) -> _TemporalResult:
    validation = validate_trace_sequence(events, limits=resource_limits)
    target = events[0].target if events else None
    accounting_builder = _EventAccountingBuilder(limits)
    run_states: dict[int, _RunState] = {}
    off_states: dict[int, _OffCpuState] = {}
    wakeups: dict[int, list[_Wakeup]] = {}
    last_run_cpu: dict[int, int] = {}
    thread_accumulators: dict[int, _ThreadAccumulator] = {}
    runtime_intervals: list[RuntimeInterval] = []
    runnable_intervals: list[RunnableLatencyInterval] = []
    off_cpu_intervals: list[OffCpuInterval] = []
    interval_count = 0

    def accumulator(tid: int) -> _ThreadAccumulator:
        current = thread_accumulators.get(tid)
        if current is None:
            current = _ThreadAccumulator()
            thread_accumulators[tid] = current
        return current

    def reserve_interval() -> None:
        nonlocal interval_count
        interval_count += 1
        if interval_count > limits.max_intervals:
            raise ValueError("trace analysis interval count exceeds max_intervals")

    def append_incomplete(
        *,
        tid: int,
        reason: IncompleteReason,
        switch_out: _OffCpuState | None,
        pending_wakeups: Sequence[_Wakeup],
        switch_in: SchedSwitchEvent | None,
    ) -> None:
        reserve_interval()
        start_ns = None if switch_out is None else switch_out.timestamp_ns
        end_ns = None if switch_in is None else switch_in.timestamp_ns
        total_ns = None if start_ns is None or end_ns is None else end_ns - start_ns
        wakeup_ns = pending_wakeups[0].timestamp_ns if len(pending_wakeups) == 1 else None
        waker_target_tid = (
            pending_wakeups[0].waker_target_tid if len(pending_wakeups) == 1 else None
        )
        total_complete = total_ns is not None
        unknown_ns = total_ns if total_complete else None
        observed_blocked_prefix = (
            wakeup_ns - start_ns
            if start_ns is not None and wakeup_ns is not None and end_ns is None
            else None
        )
        observed_runnable_suffix = (
            end_ns - wakeup_ns
            if start_ns is None and wakeup_ns is not None and end_ns is not None
            else None
        )
        off_cpu_intervals.append(
            OffCpuInterval(
                tid=tid,
                switch_out_timestamp_ns=start_ns,
                wakeup_timestamp_ns=wakeup_ns,
                switch_in_timestamp_ns=end_ns,
                total_duration_ns=total_ns,
                blocked_duration_ns=None,
                runnable_duration_ns=None,
                unknown_duration_ns=unknown_ns,
                observed_blocked_prefix_ns=observed_blocked_prefix,
                observed_runnable_suffix_ns=observed_runnable_suffix,
                previous_state=None if switch_out is None else switch_out.previous_state,
                candidate_wait_category=_candidate_wait_category(
                    None if switch_out is None else switch_out.previous_state
                ),
                switch_out_stack=() if switch_out is None else switch_out.stack,
                waker_target_tid=waker_target_tid,
                completeness=(
                    IntervalCompleteness.COMPLETE
                    if total_complete
                    else IntervalCompleteness.INCOMPLETE
                ),
                split_complete=False,
                incomplete_reason=reason,
                switch_out_event_id=None if switch_out is None else switch_out.event_id,
                wakeup_event_ids=tuple(wakeup.event_id for wakeup in pending_wakeups),
                switch_in_event_id=None if switch_in is None else switch_in.event_id,
            )
        )
        current = accumulator(tid)
        if total_ns is not None:
            current.total_complete_off_cpu_count += 1
            current.off_cpu_ns.append(total_ns)
            current.unknown_off_cpu_ns.append(total_ns)
            category = _candidate_wait_category(
                None if switch_out is None else switch_out.previous_state
            )
            current.candidate_categories[category] = (
                current.candidate_categories.get(category, 0) + 1
            )
            if switch_out is not None and switch_in is not None:
                accounting_builder.consume(switch_out.event_id, switch_in.event_id)
        else:
            current.total_incomplete_off_cpu_count += 1

    def handle_switch_out(event: SchedSwitchEvent) -> None:
        tid = _target_tid(event.previous.tid)
        current = accumulator(tid)
        current.switch_out_count += 1
        run_state = run_states.pop(tid, None)
        if run_state is None:
            current.incomplete_transition_count += 1
            accounting_builder.unpaired(event.event_id)
            accounting_builder.warn(
                "switch_out_without_switch_in",
                "switch-out has no matching switch-in inside the trace",
                event_id=event.event_id,
                tid=tid,
            )
        else:
            duration = event.timestamp_ns - run_state.timestamp_ns
            reserve_interval()
            runtime_intervals.append(
                RuntimeInterval(
                    tid=tid,
                    switch_in_timestamp_ns=run_state.timestamp_ns,
                    switch_out_timestamp_ns=event.timestamp_ns,
                    duration_ns=duration,
                    switch_in_event_id=run_state.event_id,
                    switch_out_event_id=event.event_id,
                )
            )
            current.runtime_ns.append(duration)
            accounting_builder.consume(run_state.event_id, event.event_id)
            if event.cpu is not None:
                last_run_cpu[tid] = event.cpu

        previous_off = off_states.pop(tid, None)
        stale_wakeups = wakeups.pop(tid, [])
        if previous_off is not None:
            current.incomplete_transition_count += 1
            accounting_builder.unpaired(
                previous_off.event_id,
                event.event_id,
                *(wakeup.event_id for wakeup in stale_wakeups),
            )
            append_incomplete(
                tid=tid,
                reason=IncompleteReason.OVERLAPPING_SWITCH_OUT,
                switch_out=previous_off,
                pending_wakeups=stale_wakeups,
                switch_in=None,
            )
            accounting_builder.warn(
                "overlapping_switch_out",
                "a second switch-out arrived before the prior off-CPU interval closed",
                event_id=event.event_id,
                tid=tid,
            )
        elif stale_wakeups:
            accounting_builder.unpaired(*(wakeup.event_id for wakeup in stale_wakeups))
            accounting_builder.warn(
                "wakeup_while_running",
                "wakeup observed before a matching target switch-out",
                event_id=stale_wakeups[0].event_id,
                tid=tid,
            )
        off_states[tid] = _OffCpuState(
            timestamp_ns=event.timestamp_ns,
            event_id=event.event_id,
            previous_state=event.previous_state,
            stack=event.stack,
        )

    def handle_wakeup(event: SchedWakeupEvent) -> None:
        tid = _target_tid(event.woken.tid)
        accumulator(tid)
        waker_target_tid = (
            event.waker.tid
            if event.waker is not None
            and event.waker_scope is TraceScope.TARGET
            and event.waker.tid is not None
            else None
        )
        wakeups.setdefault(tid, []).append(
            _Wakeup(
                timestamp_ns=event.timestamp_ns,
                event_id=event.event_id,
                waker_target_tid=waker_target_tid,
            )
        )

    def handle_switch_in(event: SchedSwitchEvent) -> None:
        tid = _target_tid(event.next.tid)
        current = accumulator(tid)
        current.switch_in_count += 1
        existing_run = run_states.pop(tid, None)
        if existing_run is not None:
            current.incomplete_transition_count += 1
            accounting_builder.unpaired(existing_run.event_id, event.event_id)
            accounting_builder.warn(
                "duplicate_switch_in",
                "switch-in arrived while the target task was already considered running",
                event_id=event.event_id,
                tid=tid,
            )
            # Neither switch-in is a safe runtime start after a duplicate transition.  Keep the
            # subsequent switch-out unpaired rather than selecting the later event heuristically.
            return

        if event.cpu is not None:
            previous_cpu = last_run_cpu.get(tid)
            if previous_cpu is not None and previous_cpu != event.cpu:
                current.migration_count += 1
        run_states[tid] = _RunState(
            timestamp_ns=event.timestamp_ns,
            event_id=event.event_id,
            cpu=event.cpu,
        )

        pending_wakeups = wakeups.pop(tid, [])
        off_state = off_states.pop(tid, None)
        if len(pending_wakeups) == 1:
            wakeup = pending_wakeups[0]
            reserve_interval()
            latency = event.timestamp_ns - wakeup.timestamp_ns
            runnable_intervals.append(
                RunnableLatencyInterval(
                    tid=tid,
                    wakeup_timestamp_ns=wakeup.timestamp_ns,
                    switch_in_timestamp_ns=event.timestamp_ns,
                    duration_ns=latency,
                    wakeup_event_id=wakeup.event_id,
                    switch_in_event_id=event.event_id,
                    waker_target_tid=wakeup.waker_target_tid,
                )
            )
            current.runnable_latency_ns.append(latency)
            accounting_builder.consume(wakeup.event_id, event.event_id)
        elif len(pending_wakeups) > 1:
            current.incomplete_transition_count += 1
            accounting_builder.unpaired(
                event.event_id,
                *(wakeup.event_id for wakeup in pending_wakeups),
            )
            accounting_builder.warn(
                "duplicate_wakeup",
                "multiple wakeups precede one switch-in; runnable latency is ambiguous",
                event_id=pending_wakeups[0].event_id,
                tid=tid,
            )

        if off_state is None:
            current.incomplete_transition_count += 1
            accounting_builder.unpaired(
                event.event_id,
                *(wakeup.event_id for wakeup in pending_wakeups),
            )
            append_incomplete(
                tid=tid,
                reason=IncompleteReason.TRACE_START_BOUNDARY,
                switch_out=None,
                pending_wakeups=pending_wakeups,
                switch_in=event,
            )
            return

        if not pending_wakeups:
            current.incomplete_transition_count += 1
            accounting_builder.unpaired(off_state.event_id, event.event_id)
            append_incomplete(
                tid=tid,
                reason=IncompleteReason.MISSING_WAKEUP,
                switch_out=off_state,
                pending_wakeups=(),
                switch_in=event,
            )
            accounting_builder.warn(
                "missing_wakeup",
                "off-CPU interval has no wakeup; blocked/runnable split is unknown",
                event_id=event.event_id,
                tid=tid,
            )
            return

        if len(pending_wakeups) > 1:
            accounting_builder.unpaired(
                off_state.event_id,
                event.event_id,
                *(wakeup.event_id for wakeup in pending_wakeups),
            )
            append_incomplete(
                tid=tid,
                reason=IncompleteReason.DUPLICATE_WAKEUP,
                switch_out=off_state,
                pending_wakeups=pending_wakeups,
                switch_in=event,
            )
            return

        wakeup = pending_wakeups[0]
        total = event.timestamp_ns - off_state.timestamp_ns
        blocked = wakeup.timestamp_ns - off_state.timestamp_ns
        runnable = event.timestamp_ns - wakeup.timestamp_ns
        reserve_interval()
        off_cpu_intervals.append(
            OffCpuInterval(
                tid=tid,
                switch_out_timestamp_ns=off_state.timestamp_ns,
                wakeup_timestamp_ns=wakeup.timestamp_ns,
                switch_in_timestamp_ns=event.timestamp_ns,
                total_duration_ns=total,
                blocked_duration_ns=blocked,
                runnable_duration_ns=runnable,
                unknown_duration_ns=0,
                observed_blocked_prefix_ns=None,
                observed_runnable_suffix_ns=None,
                previous_state=off_state.previous_state,
                candidate_wait_category=_candidate_wait_category(
                    off_state.previous_state
                ),
                switch_out_stack=off_state.stack,
                waker_target_tid=wakeup.waker_target_tid,
                completeness=IntervalCompleteness.COMPLETE,
                split_complete=True,
                incomplete_reason=None,
                switch_out_event_id=off_state.event_id,
                wakeup_event_ids=(wakeup.event_id,),
                switch_in_event_id=event.event_id,
            )
        )
        current.total_complete_off_cpu_count += 1
        current.split_complete_off_cpu_count += 1
        current.off_cpu_ns.append(total)
        current.blocked_ns.append(blocked)
        current.off_cpu_runnable_ns.append(runnable)
        category = _candidate_wait_category(off_state.previous_state)
        current.candidate_categories[category] = (
            current.candidate_categories.get(category, 0) + 1
        )
        accounting_builder.consume(off_state.event_id, wakeup.event_id, event.event_id)

    def handle_migrate(event: SchedMigrateEvent) -> None:
        tid = _target_tid(event.task.tid)
        current = accumulator(tid)
        current.migration_count += 1
        # An explicit migration is authoritative.  Remember its destination so the subsequent
        # switch-in CPU transition validates continuity rather than double-counting it.
        last_run_cpu[tid] = event.destination_cpu
        accounting_builder.consume(event.event_id)

    for event in events:
        ignored = isinstance(event, (LockEvent, FutexEvent))
        accounting_builder.observe(event.event_id, ignored=ignored)
        if ignored:
            continue
        if isinstance(event, SchedWakeupEvent):
            handle_wakeup(event)
            continue
        if isinstance(event, SchedMigrateEvent):
            handle_migrate(event)
            continue
        if event.previous_scope is TraceScope.TARGET:
            handle_switch_out(event)
        if event.next_scope is TraceScope.TARGET:
            handle_switch_in(event)

    for tid, run_state in run_states.items():
        current = accumulator(tid)
        current.incomplete_transition_count += 1
        accounting_builder.unpaired(run_state.event_id)
        accounting_builder.warn(
            "trace_ended_while_running",
            "target task remained running at the trace boundary",
            event_id=run_state.event_id,
            tid=tid,
        )

    pending_tids = set(off_states) | set(wakeups)
    for tid in sorted(pending_tids):
        current = accumulator(tid)
        current.incomplete_transition_count += 1
        off_state = off_states.get(tid)
        pending_wakeups = wakeups.get(tid, [])
        event_ids = [wakeup.event_id for wakeup in pending_wakeups]
        if off_state is not None:
            event_ids.append(off_state.event_id)
        accounting_builder.unpaired(*event_ids)
        append_incomplete(
            tid=tid,
            reason=IncompleteReason.TRACE_END_BOUNDARY,
            switch_out=off_state,
            pending_wakeups=pending_wakeups,
            switch_in=None,
        )
        accounting_builder.warn(
            "trace_end_boundary",
            "off-CPU state did not reach a switch-in before the trace ended",
            event_id=event_ids[0] if event_ids else None,
            tid=tid,
        )

    accounting = accounting_builder.finish()
    scheduler_threads = tuple(
        SchedulerThreadSummary(
            tid=tid,
            switch_in_count=current.switch_in_count,
            switch_out_count=current.switch_out_count,
            migration_count=current.migration_count,
            incomplete_transition_count=current.incomplete_transition_count,
            runtime=_distribution(current.runtime_ns),
            runnable_latency=_distribution(current.runnable_latency_ns),
        )
        for tid, current in sorted(thread_accumulators.items())
    )
    off_cpu_threads = tuple(
        OffCpuThreadSummary(
            tid=tid,
            total_complete_interval_count=current.total_complete_off_cpu_count,
            split_complete_interval_count=current.split_complete_off_cpu_count,
            total_incomplete_interval_count=current.total_incomplete_off_cpu_count,
            off_cpu=_distribution(current.off_cpu_ns),
            blocked=_distribution(current.blocked_ns),
            runnable=_distribution(current.off_cpu_runnable_ns),
            unknown=_distribution(current.unknown_off_cpu_ns),
            candidate_categories=tuple(
                WaitCategoryCount(category=category, interval_count=count)
                for category, count in sorted(
                    current.candidate_categories.items(), key=lambda item: item[0].value
                )
            ),
        )
        for tid, current in sorted(thread_accumulators.items())
    )
    sorted_runtime = sorted(
        runtime_intervals,
        key=lambda interval: (
            -interval.duration_ns,
            interval.tid,
            interval.switch_in_timestamp_ns,
            interval.switch_in_event_id,
        ),
    )
    sorted_runnable = sorted(
        runnable_intervals,
        key=lambda interval: (
            -interval.duration_ns,
            interval.tid,
            interval.wakeup_timestamp_ns,
            interval.wakeup_event_id,
        ),
    )
    sorted_off_cpu = sorted(off_cpu_intervals, key=_off_cpu_sort_key)
    scheduler = SchedulerAnalysis(
        target=target,
        threads=scheduler_threads,
        worst_runtime_intervals=tuple(sorted_runtime[: limits.max_worst_intervals]),
        worst_runnable_latencies=tuple(sorted_runnable[: limits.max_worst_intervals]),
        runtime_interval_count=len(runtime_intervals),
        runnable_latency_interval_count=len(runnable_intervals),
        event_accounting=accounting,
    )
    total_complete_off_cpu = sum(
        interval.completeness is IntervalCompleteness.COMPLETE for interval in off_cpu_intervals
    )
    split_complete_off_cpu = sum(interval.split_complete for interval in off_cpu_intervals)
    off_cpu = OffCpuAnalysis(
        target=target,
        threads=off_cpu_threads,
        worst_intervals=tuple(sorted_off_cpu[: limits.max_worst_intervals]),
        interval_count=len(off_cpu_intervals),
        total_complete_interval_count=total_complete_off_cpu,
        split_complete_interval_count=split_complete_off_cpu,
        total_incomplete_interval_count=len(off_cpu_intervals) - total_complete_off_cpu,
        event_accounting=accounting,
    )
    if validation.event_count != accounting.observed_event_count:
        raise ValueError("trace analysis event accounting is not conserved")
    return _TemporalResult(scheduler=scheduler, off_cpu=off_cpu)


def analyze_scheduler_and_off_cpu(
    events: Sequence[TraceEvent],
    *,
    limits: AnalysisLimits | None = None,
    resource_limits: ResourceLimits | None = None,
) -> tuple[SchedulerAnalysis, OffCpuAnalysis]:
    """Analyze target scheduler and off-CPU state without exposing foreign identities."""

    result = _analyze_temporal(
        events,
        limits=limits or AnalysisLimits(),
        resource_limits=resource_limits or ResourceLimits(),
    )
    return result.scheduler, result.off_cpu


def analyze_scheduler(
    events: Sequence[TraceEvent],
    *,
    limits: AnalysisLimits | None = None,
    resource_limits: ResourceLimits | None = None,
) -> SchedulerAnalysis:
    return analyze_scheduler_and_off_cpu(
        events,
        limits=limits,
        resource_limits=resource_limits,
    )[0]


def analyze_off_cpu(
    events: Sequence[TraceEvent],
    *,
    limits: AnalysisLimits | None = None,
    resource_limits: ResourceLimits | None = None,
) -> OffCpuAnalysis:
    return analyze_scheduler_and_off_cpu(
        events,
        limits=limits,
        resource_limits=resource_limits,
    )[1]
