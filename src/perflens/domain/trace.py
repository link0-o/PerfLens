"""Bounded, tool-independent trace events used by deterministic analyzers.

This module deliberately contains no Pydantic, CLI, or external-tool types.  It is the
normalization boundary between trace adapters and the sched/off-CPU/lock analyzers.  In
particular, a futex event is only evidence of a possible user-space wait; it is not evidence of
a particular language runtime lock.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import cast


class TraceEventKind(StrEnum):
    SCHED_SWITCH = "sched_switch"
    SCHED_WAKEUP = "sched_wakeup"
    SCHED_MIGRATE = "sched_migrate"
    LOCK_WAIT = "lock_wait"
    LOCK_ACQUIRED = "lock_acquired"
    LOCK_WAIT_ENDED = "lock_wait_ended"
    LOCK_RELEASED = "lock_released"
    FUTEX_WAIT = "futex_wait"
    FUTEX_WAKE = "futex_wake"


class TraceScope(StrEnum):
    """Whether a task belongs to the explicitly authorized target process."""

    TARGET = "target"
    FOREIGN = "foreign"


class EvidenceSemantics(StrEnum):
    """How strongly an event supports the operation represented by its kind."""

    EXACT = "exact"
    CANDIDATE = "candidate"


class WakeupSource(StrEnum):
    WAKEUP = "wakeup"
    WAKEUP_NEW = "wakeup_new"
    WAKING = "waking"


class LockAction(StrEnum):
    WAIT = "wait"
    ACQUIRED = "acquired"
    WAIT_ENDED = "wait_ended"
    RELEASED = "released"


class LockWaitOutcome(StrEnum):
    ACQUIRED = "acquired"
    TIMED_OUT = "timed_out"
    INTERRUPTED = "interrupted"
    FAILED = "failed"
    UNKNOWN = "unknown"


class FutexAction(StrEnum):
    WAIT = "wait"
    WAKE = "wake"


class FutexOperation(StrEnum):
    """Normalized Linux futex command, without private flag bits or raw addresses."""

    WAIT = "wait"
    WAIT_BITSET = "wait_bitset"
    WAIT_REQUEUE_PI = "wait_requeue_pi"
    WAKE = "wake"
    WAKE_BITSET = "wake_bitset"
    REQUEUE = "requeue"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    """Identity bound to the collection plan, including PID-reuse protection."""

    pid: int
    uid: int
    start_time_ticks: int


@dataclass(frozen=True, slots=True)
class TaskIdentity:
    """A target task identity, or an already-redacted external task marker.

    Adapters may need a foreign PID/TID briefly while deciding whether a kernel event involves
    the authorized target.  Those identifiers must be discarded before constructing this IR.
    A foreign task is therefore represented by ``pid=None, tid=None`` rather than by a stable
    identifier that could leak through diagnostics or accidental serialization.
    """

    pid: int | None
    tid: int | None

    def __post_init__(self) -> None:
        if (self.pid is None) is not (self.tid is None):
            raise ValueError("redacted task PID and TID must either both be absent or present")

    @classmethod
    def external_redacted(cls) -> TaskIdentity:
        return cls(pid=None, tid=None)


@dataclass(frozen=True, slots=True, kw_only=True)
class TraceEventBase:
    event_id: str
    sequence: int
    timestamp_ns: int
    target: TargetIdentity
    semantics: EvidenceSemantics
    cpu: int | None = None
    stack: tuple[str, ...] = ()

    @property
    def kind(self) -> TraceEventKind:
        raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class SchedSwitchEvent(TraceEventBase):
    """One sched_switch with independently scoped previous and next tasks."""

    previous: TaskIdentity
    previous_scope: TraceScope
    next: TaskIdentity
    next_scope: TraceScope
    previous_state: str

    @property
    def kind(self) -> TraceEventKind:
        return TraceEventKind.SCHED_SWITCH


@dataclass(frozen=True, slots=True, kw_only=True)
class SchedWakeupEvent(TraceEventBase):
    """A sched_wakeup/sched_waking observation for the authorized target."""

    woken: TaskIdentity
    woken_scope: TraceScope
    source: WakeupSource
    waker: TaskIdentity | None = None
    waker_scope: TraceScope | None = None

    @property
    def kind(self) -> TraceEventKind:
        return TraceEventKind.SCHED_WAKEUP


@dataclass(frozen=True, slots=True, kw_only=True)
class SchedMigrateEvent(TraceEventBase):
    """One exact target-task CPU migration reported by the kernel backend."""

    task: TaskIdentity
    task_scope: TraceScope
    origin_cpu: int
    destination_cpu: int

    @property
    def kind(self) -> TraceEventKind:
        return TraceEventKind.SCHED_MIGRATE


@dataclass(frozen=True, slots=True, kw_only=True)
class LockEvent(TraceEventBase):
    """Kernel-lock evidence or a generic, explicitly labelled lock candidate."""

    task: TaskIdentity
    task_scope: TraceScope
    action: LockAction
    lock_id: str
    wait_outcome: LockWaitOutcome | None = None
    owner: TaskIdentity | None = None
    owner_scope: TraceScope | None = None

    @property
    def kind(self) -> TraceEventKind:
        return {
            LockAction.WAIT: TraceEventKind.LOCK_WAIT,
            LockAction.ACQUIRED: TraceEventKind.LOCK_ACQUIRED,
            LockAction.WAIT_ENDED: TraceEventKind.LOCK_WAIT_ENDED,
            LockAction.RELEASED: TraceEventKind.LOCK_RELEASED,
        }[self.action]


@dataclass(frozen=True, slots=True, kw_only=True)
class FutexEvent(TraceEventBase):
    """A futex wait/wake candidate, never a confirmed high-level lock event."""

    task: TaskIdentity
    task_scope: TraceScope
    action: FutexAction
    futex_id: str
    operation: FutexOperation = FutexOperation.UNKNOWN
    wake_count: int | None = None

    @property
    def kind(self) -> TraceEventKind:
        return {
            FutexAction.WAIT: TraceEventKind.FUTEX_WAIT,
            FutexAction.WAKE: TraceEventKind.FUTEX_WAKE,
        }[self.action]


type TraceEvent = (
    SchedSwitchEvent | SchedWakeupEvent | SchedMigrateEvent | LockEvent | FutexEvent
)


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    # Trace evidence is materially denser than on-CPU samples.  Keep the in-memory normalized
    # boundary well below the 64 MiB private raw ceiling so a malicious or noisy trace cannot
    # turn a bounded file into millions of Python objects.
    max_events: int = 100_000
    max_input_lines: int = 1_000_000
    max_line_chars: int = 64 << 10
    max_stack_depth: int = 127
    max_unique_tids: int = 65_536
    max_unique_locks: int = 100_000
    max_warnings: int = 100
    max_output_bytes: int = 64 << 20

    def __post_init__(self) -> None:
        if any(
            value < 1
            for value in (
                self.max_events,
                self.max_input_lines,
                self.max_line_chars,
                self.max_stack_depth,
                self.max_unique_tids,
                self.max_unique_locks,
                self.max_warnings,
                self.max_output_bytes,
            )
        ):
            raise ValueError("trace ResourceLimits values must be positive")


@dataclass(frozen=True, slots=True)
class TraceValidationWarning:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class TraceValidationStats:
    event_count: int
    input_line_count: int
    output_bytes: int
    first_timestamp_ns: int | None
    last_timestamp_ns: int | None
    unique_tid_count: int
    unique_lock_count: int
    exact_event_count: int
    candidate_event_count: int
    target_scope_event_count: int
    foreign_scope_event_count: int
    warning_count: int
    warnings: tuple[TraceValidationWarning, ...]
    warnings_truncated: bool


def _require_plain_int(value: object, *, field_name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field_name} must be an integer >= {minimum}")
    return value


def _validate_target(target: TargetIdentity) -> None:
    _require_plain_int(target.pid, field_name="target.pid", minimum=1)
    _require_plain_int(target.uid, field_name="target.uid", minimum=0)
    _require_plain_int(
        target.start_time_ticks,
        field_name="target.start_time_ticks",
        minimum=1,
    )


def _validate_task(task: TaskIdentity, *, field_name: str) -> None:
    if task.pid is None or task.tid is None:
        raise ValueError(f"{field_name} target identity must not be redacted")
    _require_plain_int(task.pid, field_name=f"{field_name}.pid", minimum=1)
    _require_plain_int(task.tid, field_name=f"{field_name}.tid", minimum=1)


def _validate_scoped_task(
    task: TaskIdentity,
    scope: TraceScope,
    target: TargetIdentity,
    *,
    field_name: str,
) -> None:
    if scope is TraceScope.TARGET:
        _validate_task(task, field_name=field_name)
        if task.pid != target.pid:
            raise ValueError(f"{field_name} is marked target but has a foreign pid")
        return
    if task.pid is not None or task.tid is not None:
        raise ValueError(f"{field_name} foreign identity must already be redacted")


def _validate_bounded_text(value: object, *, field_name: str, limits: ResourceLimits) -> str:
    if not isinstance(value, str) or not value or len(value) > limits.max_line_chars:
        raise ValueError(f"{field_name} must be non-empty and within max_line_chars")
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise ValueError(f"{field_name} contains a forbidden control character")
    return value


def _validate_stack(value: object, *, limits: ResourceLimits) -> None:
    if not isinstance(value, tuple):
        raise ValueError("stack must be an immutable tuple")
    frames = cast(tuple[object, ...], value)
    if len(frames) > limits.max_stack_depth:
        raise ValueError("stack exceeds max_stack_depth")
    for index, frame in enumerate(frames):
        _validate_bounded_text(frame, field_name=f"stack[{index}]", limits=limits)


def _validate_common(event: TraceEventBase, limits: ResourceLimits) -> None:
    _validate_bounded_text(event.event_id, field_name="event_id", limits=limits)
    _require_plain_int(event.sequence, field_name="sequence", minimum=0)
    _require_plain_int(event.timestamp_ns, field_name="timestamp_ns", minimum=0)
    _validate_target(event.target)
    if event.cpu is not None:
        _require_plain_int(event.cpu, field_name="cpu", minimum=0)
    _validate_stack(event.stack, limits=limits)


def validate_trace_event(event: TraceEventBase, limits: ResourceLimits | None = None) -> None:
    """Validate one normalized event without trusting its originating adapter."""

    active_limits = limits or ResourceLimits()
    _validate_common(event, active_limits)

    if isinstance(event, SchedSwitchEvent):
        if event.semantics is not EvidenceSemantics.EXACT:
            raise ValueError("sched_switch evidence semantics must be exact")
        _validate_scoped_task(
            event.previous,
            event.previous_scope,
            event.target,
            field_name="previous",
        )
        _validate_scoped_task(event.next, event.next_scope, event.target, field_name="next")
        if (
            event.previous_scope is not TraceScope.TARGET
            and event.next_scope is not TraceScope.TARGET
        ):
            raise ValueError("sched_switch must involve the authorized target")
        _validate_bounded_text(
            event.previous_state,
            field_name="previous_state",
            limits=active_limits,
        )
        return

    if isinstance(event, SchedWakeupEvent):
        if event.semantics is not EvidenceSemantics.EXACT:
            raise ValueError("sched_wakeup evidence semantics must be exact")
        _validate_scoped_task(event.woken, event.woken_scope, event.target, field_name="woken")
        if event.woken_scope is not TraceScope.TARGET:
            raise ValueError("sched_wakeup must identify an authorized target task")
        if (event.waker is None) is not (event.waker_scope is None):
            raise ValueError("waker and waker_scope must either both be present or both be absent")
        if event.waker is not None and event.waker_scope is not None:
            _validate_scoped_task(
                event.waker,
                event.waker_scope,
                event.target,
                field_name="waker",
            )
        return

    if isinstance(event, SchedMigrateEvent):
        if event.semantics is not EvidenceSemantics.EXACT:
            raise ValueError("sched_migrate evidence semantics must be exact")
        _validate_scoped_task(event.task, event.task_scope, event.target, field_name="task")
        if event.task_scope is not TraceScope.TARGET:
            raise ValueError("sched_migrate task must belong to the authorized target")
        _require_plain_int(event.origin_cpu, field_name="origin_cpu", minimum=0)
        _require_plain_int(event.destination_cpu, field_name="destination_cpu", minimum=0)
        if event.origin_cpu == event.destination_cpu:
            raise ValueError("sched_migrate origin and destination CPUs must differ")
        return

    if isinstance(event, LockEvent):
        _validate_scoped_task(event.task, event.task_scope, event.target, field_name="task")
        if event.task_scope is not TraceScope.TARGET:
            raise ValueError("lock event task must belong to the authorized target")
        _validate_bounded_text(event.lock_id, field_name="lock_id", limits=active_limits)
        if (event.owner is None) is not (event.owner_scope is None):
            raise ValueError("owner and owner_scope must either both be present or both be absent")
        if event.action is not LockAction.WAIT and event.owner is not None:
            raise ValueError("owner metadata is valid only for lock wait evidence")
        if (event.action is LockAction.WAIT_ENDED) != (event.wait_outcome is not None):
            raise ValueError("wait_outcome is required only for lock wait-ended evidence")
        if (
            event.action in (
                LockAction.ACQUIRED,
                LockAction.WAIT_ENDED,
                LockAction.RELEASED,
            )
            and event.semantics is not EvidenceSemantics.EXACT
        ):
            raise ValueError("lock acquire/release evidence semantics must be exact")
        if event.owner is not None and event.owner_scope is not None:
            _validate_scoped_task(
                event.owner,
                event.owner_scope,
                event.target,
                field_name="owner",
            )
        return

    if isinstance(event, FutexEvent):
        _validate_scoped_task(event.task, event.task_scope, event.target, field_name="task")
        if event.task_scope is not TraceScope.TARGET:
            raise ValueError("futex event task must belong to the authorized target")
        if event.semantics is not EvidenceSemantics.CANDIDATE:
            raise ValueError("futex evidence must remain candidate semantics")
        wait_operations = {
            FutexOperation.WAIT,
            FutexOperation.WAIT_BITSET,
            FutexOperation.WAIT_REQUEUE_PI,
            FutexOperation.UNKNOWN,
        }
        wake_operations = {
            FutexOperation.WAKE,
            FutexOperation.WAKE_BITSET,
            FutexOperation.REQUEUE,
            FutexOperation.UNKNOWN,
        }
        if event.action is FutexAction.WAIT and event.operation not in wait_operations:
            raise ValueError("futex wait action contradicts its normalized operation")
        if event.action is FutexAction.WAKE and event.operation not in wake_operations:
            raise ValueError("futex wake action contradicts its normalized operation")
        _validate_bounded_text(event.futex_id, field_name="futex_id", limits=active_limits)
        if event.action is FutexAction.WAIT and event.wake_count is not None:
            raise ValueError("wake_count is invalid for futex wait evidence")
        if event.wake_count is not None:
            _require_plain_int(event.wake_count, field_name="wake_count", minimum=0)
        return

    raise ValueError(f"unsupported normalized trace event type: {type(event).__name__}")


def _tasks_for_event(event: TraceEvent) -> tuple[tuple[TaskIdentity, TraceScope], ...]:
    if isinstance(event, SchedSwitchEvent):
        return ((event.previous, event.previous_scope), (event.next, event.next_scope))
    if isinstance(event, SchedWakeupEvent):
        tasks = [(event.woken, event.woken_scope)]
        if event.waker is not None and event.waker_scope is not None:
            tasks.append((event.waker, event.waker_scope))
        return tuple(tasks)
    if isinstance(event, SchedMigrateEvent):
        return ((event.task, event.task_scope),)
    if isinstance(event, LockEvent):
        tasks = [(event.task, event.task_scope)]
        if event.owner is not None and event.owner_scope is not None:
            tasks.append((event.owner, event.owner_scope))
        return tuple(tasks)
    return ((event.task, event.task_scope),)


def validate_trace_sequence(
    events: Iterable[TraceEvent],
    *,
    expected_target: TargetIdentity | None = None,
    input_line_count: int | None = None,
    output_bytes: int | None = None,
    limits: ResourceLimits | None = None,
) -> TraceValidationStats:
    """Validate ordering, identity, semantics, and resource bounds for a trace stream."""

    active_limits = limits or ResourceLimits()
    if expected_target is not None:
        _validate_target(expected_target)
    if input_line_count is not None:
        _require_plain_int(input_line_count, field_name="input_line_count", minimum=0)
        if input_line_count > active_limits.max_input_lines:
            raise ValueError("input_line_count exceeds max_input_lines")
    observed_output_bytes = 0 if output_bytes is None else _require_plain_int(
        output_bytes,
        field_name="output_bytes",
        minimum=0,
    )
    if observed_output_bytes > active_limits.max_output_bytes:
        raise ValueError("output_bytes exceeds max_output_bytes")

    event_ids: set[str] = set()
    tids: set[int] = set()
    lock_ids: set[str] = set()
    event_count = 0
    exact_count = 0
    candidate_count = 0
    target_scope_count = 0
    foreign_scope_count = 0
    first_timestamp: int | None = None
    last_timestamp: int | None = None
    previous_sequence: int | None = None
    target = expected_target

    for event in events:
        event_count += 1
        if event_count > active_limits.max_events:
            raise ValueError("trace event count exceeds max_events")
        validate_trace_event(event, active_limits)
        if event.event_id in event_ids:
            raise ValueError("duplicate trace event_id")
        event_ids.add(event.event_id)
        if previous_sequence is not None and event.sequence <= previous_sequence:
            raise ValueError("trace sequence must be strictly increasing")
        previous_sequence = event.sequence
        if last_timestamp is not None and event.timestamp_ns < last_timestamp:
            raise ValueError("trace timestamps must not move backwards")
        if first_timestamp is None:
            first_timestamp = event.timestamp_ns
        last_timestamp = event.timestamp_ns

        if target is None:
            target = event.target
        elif event.target != target:
            raise ValueError("trace target identity changed within the sequence")

        if event.semantics is EvidenceSemantics.EXACT:
            exact_count += 1
        else:
            candidate_count += 1
        scoped_tasks = _tasks_for_event(event)
        if any(scope is TraceScope.TARGET for _, scope in scoped_tasks):
            target_scope_count += 1
        if any(scope is TraceScope.FOREIGN for _, scope in scoped_tasks):
            foreign_scope_count += 1
        tids.update(
            task.tid
            for task, scope in scoped_tasks
            if scope is TraceScope.TARGET and task.tid is not None
        )
        if len(tids) > active_limits.max_unique_tids:
            raise ValueError("trace TID cardinality exceeds max_unique_tids")
        if isinstance(event, LockEvent):
            lock_ids.add(event.lock_id)
        elif isinstance(event, FutexEvent):
            lock_ids.add(event.futex_id)
        if len(lock_ids) > active_limits.max_unique_locks:
            raise ValueError("trace lock cardinality exceeds max_unique_locks")

    warnings: list[TraceValidationWarning] = []
    warning_count = 0

    def add_warning(code: str, message: str) -> None:
        nonlocal warning_count
        warning_count += 1
        if len(warnings) < active_limits.max_warnings:
            warnings.append(TraceValidationWarning(code=code, message=message))

    if candidate_count:
        add_warning(
            "candidate_evidence_present",
            "candidate events cannot establish a specific high-level lock or root cause",
        )
    if foreign_scope_count:
        add_warning(
            "foreign_scope_present",
            "foreign task metadata requires privacy filtering before publication",
        )

    observed_line_count = event_count if input_line_count is None else input_line_count
    return TraceValidationStats(
        event_count=event_count,
        input_line_count=observed_line_count,
        output_bytes=observed_output_bytes,
        first_timestamp_ns=first_timestamp,
        last_timestamp_ns=last_timestamp,
        unique_tid_count=len(tids),
        unique_lock_count=len(lock_ids),
        exact_event_count=exact_count,
        candidate_event_count=candidate_count,
        target_scope_event_count=target_scope_count,
        foreign_scope_event_count=foreign_scope_count,
        warning_count=warning_count,
        warnings=tuple(warnings),
        warnings_truncated=warning_count > len(warnings),
    )
