"""Strict streaming adapter for the private target-filtered kernel Trace format."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.trace import (
    EvidenceSemantics,
    FutexAction,
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
    TaskIdentity,
    TraceEvent,
    TraceScope,
    WakeupSource,
    validate_trace_sequence,
)
from perflens.profiles.trace_stream import (
    TraceParseDiagnostic,
    TraceParseStatistics,
    TraceStreamParseResult,
)

KERNEL_TRACE_STREAM_PARSER_VERSION = "target-filtered-kernel-ndjson-v1"

_COMMON: set[str] = {
    "schema_version",
    "sequence",
    "timestamp_ns",
    "cpu",
    "kind",
    "target_tid",
}
_OPTIONAL: set[str] = {
    "related_target_tid",
    "related_scope",
    "previous_state",
    "target_cpu",
    "origin_cpu",
    "destination_cpu",
    "lock_id",
    "lock_flags",
    "wait_result",
    "futex_operation",
}
_KINDS: set[str] = {
    "sched_switch_out",
    "sched_switch_in",
    "sched_switch_both",
    "sched_waking",
    "sched_wakeup",
    "sched_wakeup_new",
    "sched_migrate",
    "lock_wait",
    "lock_wait_ended",
    "futex_wait",
    "futex_wake",
}
_KIND_FIELDS: dict[str, set[str]] = {
    "sched_switch_out": {"related_target_tid", "related_scope", "previous_state"},
    "sched_switch_in": {"related_target_tid", "related_scope"},
    "sched_switch_both": {"related_target_tid", "related_scope", "previous_state"},
    "sched_waking": {"related_target_tid", "related_scope", "target_cpu"},
    "sched_wakeup": {"target_cpu"},
    "sched_wakeup_new": {"target_cpu"},
    "sched_migrate": {"origin_cpu", "destination_cpu"},
    "lock_wait": {"lock_id", "lock_flags"},
    "lock_wait_ended": {"lock_id", "wait_result"},
    "futex_wait": {"lock_id", "futex_operation"},
    "futex_wake": {"lock_id", "futex_operation"},
}
_FUTEX_OPERATIONS = {item.value: item for item in FutexOperation}


class FixedKernelTraceNdjsonAdapter:
    """Convert Helper-produced typed records into privacy-safe domain events.

    File identity, event shape, target membership, ordering and resource limits are independently
    revalidated.  The adapter never accepts a raw PID/comm/address field.
    """

    def __init__(
        self,
        *,
        target: TargetIdentity,
        observed_target_tids: tuple[int, ...],
        expected_input_owner_uid: int,
        expected_input_owner_gid: int,
        expected_input_mode: int,
        mode: str,
        lost_event_count: int,
        truncated: bool,
        limits: ResourceLimits | None = None,
    ) -> None:
        if mode not in {"sched", "off_cpu", "lock"}:
            raise ValueError("kernel trace mode must be sched, off_cpu, or lock")
        if (
            not observed_target_tids
            or tuple(sorted(set(observed_target_tids))) != observed_target_tids
            or any(isinstance(tid, bool) or tid <= 0 for tid in observed_target_tids)
        ):
            raise ValueError("observed target TIDs must be sorted unique positive integers")
        if expected_input_owner_uid < 0 or expected_input_owner_gid < 0:
            raise ValueError("expected kernel trace owner identity must be non-negative")
        if expected_input_mode not in {0o600, 0o640}:
            raise ValueError("expected kernel trace mode must be exactly 0600 or 0640")
        if isinstance(lost_event_count, bool) or lost_event_count < 0:
            raise ValueError("lost_event_count must be a non-negative integer")
        self._target = target
        self._target_tids = frozenset(observed_target_tids)
        self._observed_target_tids = observed_target_tids
        self._owner_uid = expected_input_owner_uid
        self._owner_gid = expected_input_owner_gid
        self._input_mode = expected_input_mode
        self._mode = mode
        self._lost_event_count = lost_event_count
        self._truncated = truncated
        self._limits = limits or ResourceLimits()

    def parse(self, path: Path) -> TraceStreamParseResult:
        descriptor = _open_safe_input(
            path,
            expected_uid=self._owner_uid,
            expected_gid=self._owner_gid,
            expected_mode=self._input_mode,
            max_bytes=self._limits.max_output_bytes,
        )
        state = _KernelParserState(
            target=self._target,
            target_tids=self._target_tids,
            mode=self._mode,
            limits=self._limits,
            lost_event_count=self._lost_event_count,
            truncated=self._truncated,
        )
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as source:
                descriptor = -1
                while True:
                    line = source.readline(self._limits.max_line_chars + 1)
                    if not line:
                        break
                    state.consume(line)
        except PerfLensError:
            raise
        except OSError as exc:
            raise _invalid("Kernel trace input could not be read") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        result = state.finish(self._observed_target_tids)
        validate_trace_sequence(
            result.events,
            expected_target=self._target,
            input_line_count=result.statistics.input_line_count,
            output_bytes=result.statistics.input_bytes,
            limits=self._limits,
        )
        return result


class _KernelParserState:
    def __init__(
        self,
        *,
        target: TargetIdentity,
        target_tids: frozenset[int],
        mode: str,
        limits: ResourceLimits,
        lost_event_count: int,
        truncated: bool,
    ) -> None:
        self.target = target
        self.target_tids = target_tids
        self.mode = mode
        self.limits = limits
        self.events: list[TraceEvent] = []
        self.input_bytes = 0
        self.input_lines = 0
        self.input_events = 0
        self.malformed = 0
        self.unsupported = 0
        self.out_of_order = 0
        self.diagnostic_count = 0
        self.diagnostics: list[TraceParseDiagnostic] = []
        self.provisional_count = 0
        self.pending_wakers: dict[int, tuple[int, TaskIdentity | None, TraceScope | None]] = {}
        self.last_timestamp: int | None = None
        self.lost_event_count = lost_event_count
        self.truncated_count = 0
        if truncated:
            self._diagnose(
                "HELPER_OUTPUT_TRUNCATED",
                "Kernel trace reached the private output bound",
            )

    def consume(self, raw_line: bytes) -> None:
        self.input_lines += 1
        self.input_bytes += len(raw_line)
        if self.input_lines > self.limits.max_input_lines:
            raise _limit("Kernel trace exceeds the configured line limit")
        if self.input_bytes > self.limits.max_output_bytes:
            raise _limit("Kernel trace exceeds the configured byte limit")
        self.input_events += 1
        if self.input_events > self.limits.max_events:
            raise _limit("Kernel trace exceeds the configured event limit")
        if len(raw_line) > self.limits.max_line_chars or not raw_line.endswith(b"\n"):
            self.malformed += 1
            self._diagnose("INVALID_LINE", "Kernel trace record violates the line boundary")
            return
        try:
            raw = json.loads(
                raw_line,
                object_pairs_hook=_without_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.malformed += 1
            self._diagnose("INVALID_JSON", "Kernel trace record is not strict JSON")
            return
        if not isinstance(raw, dict):
            self.malformed += 1
            self._diagnose("INVALID_FIELDS", "Kernel trace record has missing or unknown fields")
            return
        raw_object = cast(dict[str, Any], raw)
        if not _COMMON.issubset(raw_object) or not set(raw_object).issubset(
            _COMMON | _OPTIONAL
        ):
            self.malformed += 1
            self._diagnose("INVALID_FIELDS", "Kernel trace record has missing or unknown fields")
            return
        try:
            self._consume_record(raw_object)
        except (KeyError, TypeError, ValueError):
            self.malformed += 1
            self._diagnose("INVALID_RECORD", "Kernel trace record failed typed validation")

    def _consume_record(self, raw: dict[str, Any]) -> None:
        if raw["schema_version"] != "1.0" or raw["kind"] not in _KINDS:
            raise ValueError("unsupported schema or event kind")
        kind = cast(str, raw["kind"])
        if not set(raw).issubset(_COMMON | _KIND_FIELDS[kind]):
            raise ValueError("event fields do not match their fixed kind")
        sequence = _plain_int(raw["sequence"], minimum=0)
        timestamp = _plain_int(raw["timestamp_ns"], minimum=0)
        cpu = _plain_int(raw["cpu"], minimum=0)
        tid = _plain_int(raw["target_tid"], minimum=1)
        if sequence != self.input_events - 1 or tid not in self.target_tids:
            raise ValueError("sequence or target TID is outside the authenticated scope")
        if self.last_timestamp is not None and timestamp < self.last_timestamp:
            self.out_of_order += 1
            self._diagnose("OUT_OF_ORDER_EVENT", "Kernel trace record is out of order")
            return
        self.last_timestamp = timestamp
        if self.mode in {"sched", "off_cpu"} and not kind.startswith("sched_"):
            raise ValueError("non-scheduler event in scheduler trace")
        if self.mode == "lock" and kind.startswith("sched_"):
            raise ValueError("scheduler event in lock trace")
        converter = self._converter(kind)
        event = converter(raw, sequence, timestamp, cpu, tid)
        if event is not None:
            self.events.append(event)

    def _converter(
        self,
        kind: str,
    ) -> Callable[[dict[str, Any], int, int, int, int], TraceEvent | None]:
        if kind.startswith("sched_switch_"):
            return self._switch
        if kind in {"sched_waking", "sched_wakeup", "sched_wakeup_new"}:
            return self._wakeup
        if kind == "sched_migrate":
            return self._migrate
        if kind in {"lock_wait", "lock_wait_ended"}:
            return self._lock
        return self._futex

    def _switch(
        self, raw: dict[str, Any], sequence: int, timestamp: int, cpu: int, tid: int
    ) -> TraceEvent:
        kind = cast(str, raw["kind"])
        related = raw.get("related_target_tid")
        if related is not None:
            related = _plain_int(related, minimum=1)
            if related not in self.target_tids:
                raise ValueError("related TID escaped target scope")
        scope = raw.get("related_scope")
        if scope not in {"target", "external_redacted"}:
            raise ValueError("switch relation is absent or unsafe")
        target_task = TaskIdentity(pid=self.target.pid, tid=tid)
        related_task = (
            TaskIdentity(pid=self.target.pid, tid=related)
            if related is not None
            else TaskIdentity.external_redacted()
        )
        related_scope = TraceScope.TARGET if related is not None else TraceScope.FOREIGN
        if kind == "sched_switch_out":
            previous, previous_scope = target_task, TraceScope.TARGET
            next_task, next_scope = related_task, related_scope
        elif kind == "sched_switch_in":
            previous, previous_scope = related_task, related_scope
            next_task, next_scope = target_task, TraceScope.TARGET
        else:
            if related is None:
                raise ValueError("target-to-target switch lacks related TID")
            previous, previous_scope = target_task, TraceScope.TARGET
            next_task, next_scope = related_task, TraceScope.TARGET
        state = _task_state(raw.get("previous_state")) if kind != "sched_switch_in" else "unknown"
        return SchedSwitchEvent(
            event_id=_event_id(sequence, timestamp, kind),
            sequence=len(self.events),
            timestamp_ns=timestamp,
            cpu=cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            previous=previous,
            previous_scope=previous_scope,
            next=next_task,
            next_scope=next_scope,
            previous_state=state,
        )

    def _wakeup(
        self, raw: dict[str, Any], sequence: int, timestamp: int, cpu: int, tid: int
    ) -> TraceEvent | None:
        kind = cast(str, raw["kind"])
        related = raw.get("related_target_tid")
        scope = raw.get("related_scope")
        waker: TaskIdentity | None = None
        waker_scope: TraceScope | None = None
        if related is not None:
            related = _plain_int(related, minimum=1)
            if related not in self.target_tids or scope != "target":
                raise ValueError("waker escaped target scope")
            waker = TaskIdentity(pid=self.target.pid, tid=related)
            waker_scope = TraceScope.TARGET
        elif scope == "external_redacted":
            waker = TaskIdentity.external_redacted()
            waker_scope = TraceScope.FOREIGN
        elif scope is not None:
            raise ValueError("waker relation is unsafe")
        if kind == "sched_waking":
            pending = self.pending_wakers.get(tid)
            count = 1 if pending is None else pending[0] + 1
            self.pending_wakers[tid] = (count, waker, waker_scope)
            return None
        pending = self.pending_wakers.pop(tid, None)
        if pending is not None and pending[0] == 1:
            self.provisional_count += 1
            waker, waker_scope = pending[1], pending[2]
        elif pending is not None:
            self.unsupported += pending[0]
            self._diagnose(
                "AMBIGUOUS_WAKER", "Multiple waking records prevented exact waker enrichment"
            )
            waker, waker_scope = None, None
        return SchedWakeupEvent(
            event_id=_event_id(sequence, timestamp, kind),
            sequence=len(self.events),
            timestamp_ns=timestamp,
            cpu=cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            woken=TaskIdentity(pid=self.target.pid, tid=tid),
            woken_scope=TraceScope.TARGET,
            source=(WakeupSource.WAKEUP_NEW if kind.endswith("_new") else WakeupSource.WAKEUP),
            waker=waker,
            waker_scope=waker_scope,
        )

    def _migrate(
        self, raw: dict[str, Any], sequence: int, timestamp: int, cpu: int, tid: int
    ) -> TraceEvent:
        origin = _plain_int(raw.get("origin_cpu"), minimum=0)
        destination = _plain_int(raw.get("destination_cpu"), minimum=0)
        return SchedMigrateEvent(
            event_id=_event_id(sequence, timestamp, "sched_migrate"),
            sequence=len(self.events),
            timestamp_ns=timestamp,
            cpu=cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            task=TaskIdentity(pid=self.target.pid, tid=tid),
            task_scope=TraceScope.TARGET,
            origin_cpu=origin,
            destination_cpu=destination,
        )

    def _lock(
        self, raw: dict[str, Any], sequence: int, timestamp: int, cpu: int, tid: int
    ) -> TraceEvent:
        lock_id = _lock_id(raw.get("lock_id"))
        kind = cast(str, raw["kind"])
        if kind == "lock_wait":
            action, outcome = LockAction.WAIT, None
            _plain_int(raw.get("lock_flags"), minimum=0)
        else:
            action = LockAction.WAIT_ENDED
            outcome = _wait_outcome(_plain_int(raw.get("wait_result")))
        return LockEvent(
            event_id=_event_id(sequence, timestamp, kind),
            sequence=len(self.events),
            timestamp_ns=timestamp,
            cpu=cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            task=TaskIdentity(pid=self.target.pid, tid=tid),
            task_scope=TraceScope.TARGET,
            action=action,
            lock_id=lock_id,
            wait_outcome=outcome,
        )

    def _futex(
        self, raw: dict[str, Any], sequence: int, timestamp: int, cpu: int, tid: int
    ) -> TraceEvent:
        kind = cast(str, raw["kind"])
        operation_raw = raw.get("futex_operation")
        if operation_raw not in _FUTEX_OPERATIONS:
            raise ValueError("futex operation is not allowlisted")
        action = FutexAction.WAIT if kind == "futex_wait" else FutexAction.WAKE
        return FutexEvent(
            event_id=_event_id(sequence, timestamp, kind),
            sequence=len(self.events),
            timestamp_ns=timestamp,
            cpu=cpu,
            target=self.target,
            semantics=EvidenceSemantics.CANDIDATE,
            task=TaskIdentity(pid=self.target.pid, tid=tid),
            task_scope=TraceScope.TARGET,
            action=action,
            futex_id=_lock_id(raw.get("lock_id")),
            operation=_FUTEX_OPERATIONS[cast(str, operation_raw)],
        )

    def finish(self, observed_target_tids: tuple[int, ...]) -> TraceStreamParseResult:
        unpaired = sum(item[0] for item in self.pending_wakers.values())
        if unpaired:
            self.unsupported += unpaired
            self._diagnose("UNPAIRED_WAKING", "Waking enrichment lacked a successful wakeup")
        diagnostics = tuple(self.diagnostics)
        statistics = TraceParseStatistics(
            input_bytes=self.input_bytes,
            input_line_count=self.input_lines,
            input_event_count=self.input_events,
            emitted_event_count=len(self.events),
            lost_event_count=self.lost_event_count,
            malformed_event_count=self.malformed,
            duplicate_event_count=0,
            out_of_order_event_count=self.out_of_order,
            unsupported_event_count=self.unsupported,
            truncated_event_count=self.truncated_count,
            foreign_event_dropped_count=0,
            provisional_enrichment_event_count=self.provisional_count,
            lock_phase_enrichment_event_count=0,
            diagnostic_count=self.diagnostic_count,
            diagnostics=diagnostics,
            diagnostics_truncated=self.diagnostic_count > len(diagnostics),
        )
        return TraceStreamParseResult(
            events=tuple(self.events),
            observed_target_tids=observed_target_tids,
            statistics=statistics,
        )

    def _diagnose(self, code: str, message: str) -> None:
        self.diagnostic_count += 1
        if len(self.diagnostics) < self.limits.max_warnings:
            self.diagnostics.append(
                TraceParseDiagnostic(
                    code=code,
                    line_number=self.input_lines,
                    message=message,
                )
            )


def _open_safe_input(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    max_bytes: int,
) -> int:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_size <= 0
            or metadata.st_size > max_bytes
        ):
            raise OSError("unsafe private kernel trace")
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "kernel_trace_input",
            "Kernel trace input failed the private-file safety check",
            recoverable=True,
        ) from exc


def _without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate kernel trace field")
        result[key] = value
    return result


def _plain_int(value: Any, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("kernel trace integer field has the wrong type")
    if minimum is not None and value < minimum:
        raise ValueError("kernel trace integer field is below its bound")
    return value


def _lock_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 25 or not value.startswith("lock-"):
        raise ValueError("kernel trace lock identity is malformed")
    if any(character not in "0123456789abcdef" for character in value[5:]):
        raise ValueError("kernel trace lock identity is malformed")
    return value


def _task_state(value: Any) -> str:
    state = _plain_int(value, minimum=0)
    return {
        0: "running",
        1: "interruptible_sleep",
        2: "uninterruptible_sleep",
        4: "stopped",
        8: "traced",
        16: "dead",
        32: "dead",
        64: "parked",
        1024: "idle",
    }.get(state, "unknown")


def _wait_outcome(result: int) -> LockWaitOutcome:
    return {
        0: LockWaitOutcome.ACQUIRED,
        -4: LockWaitOutcome.INTERRUPTED,
        -35: LockWaitOutcome.FAILED,
        -110: LockWaitOutcome.TIMED_OUT,
    }.get(result, LockWaitOutcome.FAILED)


def _event_id(sequence: int, timestamp: int, kind: str) -> str:
    digest = hashlib.sha256(f"{sequence}:{timestamp}:{kind}".encode("ascii")).hexdigest()
    return f"event-{digest[:24]}"


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.INVALID_INPUT, "kernel_trace_input", message, recoverable=True)


def _limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "kernel_trace_input",
        message,
        recoverable=True,
    )
