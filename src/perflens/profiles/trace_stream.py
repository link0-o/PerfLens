"""Bounded parser for PerfLens' fixed, event-only ``perf script`` recipe.

This adapter consumes text produced by an external ``perf script`` process.  It never reads
``perf.data`` itself.  The caller is responsible for verifying the converter executable and
manifest before handing the private text stream to this parser.

Only target-scoped normalized domain events leave this module.  In particular, command names,
foreign process identifiers, and raw lock addresses are discarded while parsing and are never
included in diagnostics.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

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

TRACE_PERF_SCRIPT_FIELDS = "trace:pid,tid,cpu,time,event,trace"
TRACE_PERF_SCRIPT_LOCALE = "C"
TRACE_STREAM_PARSER_VERSION = "trace-perf-script-v1"
TRACE_PERF_SCRIPT_RECIPE = (
    "script",
    "--force",
    "--ns",
    "--show-lost-events",
    "-F",
    TRACE_PERF_SCRIPT_FIELDS,
    "-i",
    "<private-input>",
)

_HEADER_SLASH = re.compile(
    rb"^\s*(?P<pid>[0-9]+)/(?P<tid>[0-9]+)\s+\[(?P<cpu>[0-9]+)\]\s+"
    rb"(?P<seconds>[0-9]+)\.(?P<fraction>[0-9]{9}):\s+"
    rb"(?P<group>[a-z0-9_]+):(?P<event>[a-z0-9_]+):(?:\s*(?P<payload>.*))?$"
)
_HEADER_SPLIT = re.compile(
    rb"^\s*(?P<pid>[0-9]+)\s+(?P<tid>[0-9]+)\s+\[(?P<cpu>[0-9]+)\]\s+"
    rb"(?P<seconds>[0-9]+)\.(?P<fraction>[0-9]{9}):\s+"
    rb"(?P<group>[a-z0-9_]+):(?P<event>[a-z0-9_]+):(?:\s*(?P<payload>.*))?$"
)
_LOST_RECORD = re.compile(
    rb"^\s*(?:(?:[0-9]+/[0-9]+|[0-9]+\s+[0-9]+)\s+\[[0-9]+\]\s+"
    rb"[0-9]+\.[0-9]{9}:\s+(?:\S+:\s+)?)?"
    rb"PERF_RECORD_LOST\s+lost\s+(?P<count>[0-9]+)\s*$"
)
_SCHED_SWITCH = re.compile(
    rb"^prev_comm=(?P<prev_comm>.{0,16}) prev_pid=(?P<prev_tid>[0-9]+) "
    rb"prev_prio=(?P<prev_prio>-?[0-9]+) prev_state=(?P<prev_state>\S+) ==\> "
    rb"next_comm=(?P<next_comm>.{0,16}) next_pid=(?P<next_tid>[0-9]+) "
    rb"next_prio=(?P<next_prio>-?[0-9]+)$"
)
_SCHED_WAKEUP = re.compile(
    rb"^comm=(?P<comm>.{0,16}) pid=(?P<tid>[0-9]+) "
    rb"prio=(?P<prio>-?[0-9]+) target_cpu=(?P<target_cpu>[0-9]+)$"
)
_SCHED_MIGRATE = re.compile(
    rb"^comm=(?P<comm>.{0,16}) pid=(?P<tid>[0-9]+) "
    rb"prio=(?P<prio>-?[0-9]+) orig_cpu=(?P<origin>[0-9]+) "
    rb"dest_cpu=(?P<destination>[0-9]+)$"
)
_FIELD = re.compile(
    rb"(?:^|[\s,])(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:)\s*"
    rb"(?P<value>[^\s,]+)"
)
_ADDRESS = re.compile(rb"^(?:0x)?[0-9a-fA-F]{1,16}$")
_INTEGER = re.compile(rb"^-?(?:0x[0-9a-fA-F]+|[0-9]+)$")
_MODERN_LOCK_BEGIN = re.compile(
    rb"^(?P<address>(?:0x)?[0-9a-fA-F]{1,16}) "
    rb"\(flags=(?P<flags>[A-Z0-9_|]+)\)$"
)
_MODERN_LOCK_END = re.compile(
    rb"^(?P<address>(?:0x)?[0-9a-fA-F]{1,16}) \(ret=(?P<ret>-?[0-9]+)\)$"
)
_LEGACY_LOCK = re.compile(
    rb"^(?P<address>(?:0x)?[0-9a-fA-F]{1,16}) (?P<name>[^\x00\r\n]+)$"
)

_SCHED_EVENTS = {
    ("sched", "sched_switch"),
    ("sched", "sched_waking"),
    ("sched", "sched_wakeup"),
    ("sched", "sched_wakeup_new"),
    ("sched", "sched_migrate_task"),
}
_LOCK_EVENTS = {
    ("lock", "contention_begin"),
    ("lock", "contention_end"),
    ("lock", "lock_acquire"),
    ("lock", "lock_acquired"),
    ("lock", "lock_contended"),
    ("lock", "lock_release"),
    ("syscalls", "sys_enter_futex"),
    ("syscalls", "sys_exit_futex"),
}
_KNOWN_LOCK_FLAGS = frozenset({b"0", b"SPIN", b"READ", b"WRITE", b"RT", b"PERCPU", b"MUTEX"})
_FUTEX_COMMAND_MASK = 0x7F
_FUTEX_WAIT = 0
_FUTEX_WAKE = 1
_FUTEX_REQUEUE = 3
_FUTEX_WAIT_BITSET = 9
_FUTEX_WAKE_BITSET = 10
_FUTEX_WAIT_REQUEUE_PI = 11


@dataclass(frozen=True, slots=True)
class TraceParseDiagnostic:
    """A bounded diagnostic which deliberately contains no source text."""

    code: str
    line_number: int
    message: str


@dataclass(frozen=True, slots=True)
class TraceParseStatistics:
    input_bytes: int
    input_line_count: int
    input_event_count: int
    emitted_event_count: int
    lost_event_count: int
    malformed_event_count: int
    duplicate_event_count: int
    out_of_order_event_count: int
    unsupported_event_count: int
    truncated_event_count: int
    foreign_event_dropped_count: int
    provisional_enrichment_event_count: int
    lock_phase_enrichment_event_count: int
    diagnostic_count: int
    diagnostics: tuple[TraceParseDiagnostic, ...]
    diagnostics_truncated: bool

    def __post_init__(self) -> None:
        classified = (
            self.emitted_event_count
            + self.malformed_event_count
            + self.duplicate_event_count
            + self.out_of_order_event_count
            + self.unsupported_event_count
            + self.truncated_event_count
            + self.foreign_event_dropped_count
            + self.provisional_enrichment_event_count
            + self.lock_phase_enrichment_event_count
        )
        if classified != self.input_event_count:
            raise ValueError("trace parser input event counts are not conserved")
        if self.diagnostic_count < len(self.diagnostics):
            raise ValueError("trace diagnostic sample exceeds diagnostic count")
        if self.diagnostics_truncated != (self.diagnostic_count > len(self.diagnostics)):
            raise ValueError("trace diagnostic truncation flag is inconsistent")

    @property
    def partial(self) -> bool:
        return any(
            (
                int(self.emitted_event_count == 0),
                self.lost_event_count,
                self.malformed_event_count,
                self.duplicate_event_count,
                self.out_of_order_event_count,
                self.unsupported_event_count,
                self.truncated_event_count,
                self.foreign_event_dropped_count,
                self.diagnostic_count,
                int(self.diagnostics_truncated),
            )
        )


@dataclass(frozen=True, slots=True)
class TraceStreamParseResult:
    events: tuple[TraceEvent, ...]
    observed_target_tids: tuple[int, ...]
    statistics: TraceParseStatistics


@dataclass(frozen=True, slots=True)
class _Header:
    pid: int
    tid: int
    cpu: int
    timestamp_ns: int
    group: str
    event: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class _ProvisionalWaker:
    task: TaskIdentity
    scope: TraceScope


@dataclass(slots=True)
class _PendingWakers:
    count: int
    first: _ProvisionalWaker


class FixedTracePerfScriptAdapter:
    """Parse one immutable fixed-recipe trace transcript.

    ``observed_target_tids`` must come from the backend's authenticated target observation, not
    from untrusted trace payload fields.  A fresh lock-identity key is generated for every
    adapter instance so hashed lock IDs cannot be correlated across artifacts.
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
        limits: ResourceLimits | None = None,
        lock_identity_key: bytes | None = None,
        manifest_fields: str = TRACE_PERF_SCRIPT_FIELDS,
        locale: str = TRACE_PERF_SCRIPT_LOCALE,
        manifest_recipe: tuple[str, ...] = TRACE_PERF_SCRIPT_RECIPE,
    ) -> None:
        if mode not in {"sched", "off_cpu", "lock"}:
            raise ValueError("trace mode must be sched, off_cpu, or lock")
        if (
            manifest_fields != TRACE_PERF_SCRIPT_FIELDS
            or locale != TRACE_PERF_SCRIPT_LOCALE
            or manifest_recipe != TRACE_PERF_SCRIPT_RECIPE
        ):
            raise ValueError("trace parser requires the fixed event-only manifest and C locale")
        if not observed_target_tids:
            raise ValueError("observed_target_tids must not be empty")
        if isinstance(expected_input_owner_uid, bool) or expected_input_owner_uid < 0:
            raise ValueError("expected_input_owner_uid must be a non-negative integer")
        if isinstance(expected_input_owner_gid, bool) or expected_input_owner_gid < 0:
            raise ValueError("expected_input_owner_gid must be a non-negative integer")
        if expected_input_mode not in {0o600, 0o640}:
            raise ValueError("expected_input_mode must be exactly 0600 or 0640")
        if (
            any(isinstance(tid, bool) or tid <= 0 for tid in observed_target_tids)
            or tuple(sorted(set(observed_target_tids))) != observed_target_tids
        ):
            raise ValueError("observed_target_tids must be sorted unique positive integers")
        key = lock_identity_key if lock_identity_key is not None else secrets.token_bytes(32)
        if len(key) < 16:
            raise ValueError("lock identity key must contain at least 128 bits")
        self._target = target
        self._target_tids = frozenset(observed_target_tids)
        self._mode = mode
        self._limits = limits or ResourceLimits()
        self._lock_identity_key = key
        self._expected_input_owner_uid = expected_input_owner_uid
        self._expected_input_owner_gid = expected_input_owner_gid
        self._expected_input_mode = expected_input_mode

    def parse(self, path: Path) -> TraceStreamParseResult:
        state = _ParserState(
            target=self._target,
            target_tids=self._target_tids,
            mode=self._mode,
            limits=self._limits,
            lock_identity_key=self._lock_identity_key,
        )
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            source_stat = os.fstat(descriptor)
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "trace_input",
                "Trace transcript failed the private-file safety check",
                recoverable=True,
            ) from error
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_nlink != 1
            or source_stat.st_uid != self._expected_input_owner_uid
            or source_stat.st_gid != self._expected_input_owner_gid
            or stat.S_IMODE(source_stat.st_mode) != self._expected_input_mode
        ):
            os.close(descriptor)
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "trace_input",
                "Trace transcript failed the private-file safety check",
                recoverable=True,
            )
        source_size = source_stat.st_size
        if source_size > self._limits.max_output_bytes:
            os.close(descriptor)
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "trace_input",
                "Trace transcript exceeds the configured byte limit",
                recoverable=True,
                details={
                    "actual_bytes": source_size,
                    "max_input_bytes": self._limits.max_output_bytes,
                },
            )
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as source:
                descriptor = -1
                while True:
                    raw_line = source.readline(self._limits.max_line_chars + 1)
                    if raw_line == b"":
                        break
                    state.consume_line(raw_line, source)
        except PerfLensError:
            raise
        except OSError as error:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "trace_input",
                "Trace transcript could not be read",
                recoverable=True,
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return state.finish()


class _ParserState:
    def __init__(
        self,
        *,
        target: TargetIdentity,
        target_tids: frozenset[int],
        mode: str,
        limits: ResourceLimits,
        lock_identity_key: bytes,
    ) -> None:
        self.target = target
        self.target_tids = target_tids
        self.mode = mode
        self.limits = limits
        self.lock_identity_key = lock_identity_key
        self.events: list[TraceEvent] = []
        self.observed_tids: set[int] = set()
        self.diagnostics: list[TraceParseDiagnostic] = []
        self.diagnostic_count = 0
        self.input_bytes = 0
        self.input_lines = 0
        self.input_events = 0
        self.lost_events = 0
        self.malformed = 0
        self.duplicates = 0
        self.out_of_order = 0
        self.unsupported = 0
        self.truncated = 0
        self.foreign = 0
        self.provisional = 0
        self.lock_phase_enrichment = 0
        self.last_timestamp_ns: int | None = None
        self.provisional_wakers: dict[int, _PendingWakers] = {}
        self.audited_contentions: dict[tuple[int, str], bytes | None] = {}

    def consume_line(self, raw_line: bytes, source: BinaryIO) -> None:
        self.input_lines += 1
        if self.input_lines > self.limits.max_input_lines:
            raise self._limit_error("Trace transcript exceeds the configured line limit")
        self.input_bytes += len(raw_line)
        if self.input_bytes > self.limits.max_output_bytes:
            raise self._limit_error("Trace transcript exceeds the configured byte limit")
        if len(raw_line) > self.limits.max_line_chars:
            if not raw_line.endswith(b"\n"):
                while True:
                    remainder = source.readline(self.limits.max_line_chars + 1)
                    if not remainder:
                        break
                    self.input_bytes += len(remainder)
                    if self.input_bytes > self.limits.max_output_bytes:
                        raise self._limit_error(
                            "Trace transcript exceeds the configured byte limit"
                        )
                    if remainder.endswith(b"\n"):
                        break
            self.input_events += 1
            self.malformed += 1
            self._diagnose("LINE_TOO_LONG", "Trace event line exceeds the fixed byte limit")
            return
        line = raw_line.rstrip(b"\r\n")
        if not line.strip():
            return
        if b"\x00" in line:
            self.input_events += 1
            self.malformed += 1
            self._diagnose("CONTROL_CHARACTER", "Trace event contains a forbidden byte")
            return
        lost = _LOST_RECORD.fullmatch(line)
        if lost is not None:
            self.lost_events += int(lost.group("count"))
            self._discard_provisional_wakers(
                "LOST_PROVISIONAL_WAKER",
                "Lost kernel events invalidated pending sched_waking enrichment",
            )
            # A missing contention record makes a later successful end ambiguous.  Preserve
            # already-emitted waits, but do not let the end claim an audited acquire outcome.
            self.audited_contentions.clear()
            self._diagnose("KERNEL_EVENTS_LOST", "The kernel reported lost trace events")
            return

        self.input_events += 1
        if self.input_events > self.limits.max_events:
            self.truncated += 1
            self._diagnose("INPUT_EVENT_LIMIT", "Trace input event limit was reached")
            return
        header = self._parse_header(line)
        if header is None:
            self.malformed += 1
            code = "MALFORMED_LOST_RECORD" if b"PERF_RECORD_LOST" in line else "MALFORMED_EVENT"
            self._diagnose(code, "Trace event does not match the fixed event-only format")
            return

        # This fixed text format has no stable kernel record sequence number.  Two byte-identical
        # lines can therefore be distinct legitimate events.  Duplicate state transitions are
        # classified later by deterministic analyzers; the parser must not invent a duplicate.
        if self.last_timestamp_ns is not None and header.timestamp_ns < self.last_timestamp_ns:
            self.out_of_order += 1
            self._diagnose("OUT_OF_ORDER_EVENT", "Out-of-order trace event was discarded")
            return
        self.last_timestamp_ns = header.timestamp_ns

        event_key = (header.group, header.event)
        allowed = _SCHED_EVENTS if self.mode in {"sched", "off_cpu"} else _LOCK_EVENTS
        if event_key not in allowed:
            self.unsupported += 1
            self._diagnose("UNSUPPORTED_EVENT", "Trace event is outside the fixed mode allowlist")
            return
        if len(self.events) >= self.limits.max_events:
            self.truncated += 1
            self._diagnose("EVENT_LIMIT", "Normalized trace event limit was reached")
            return

        event = self._convert(header)
        if event is not None:
            self.events.append(event)

    def _parse_header(self, line: bytes) -> _Header | None:
        match = _HEADER_SLASH.fullmatch(line) or _HEADER_SPLIT.fullmatch(line)
        if match is None:
            return None
        return _Header(
            pid=int(match.group("pid")),
            tid=int(match.group("tid")),
            cpu=int(match.group("cpu")),
            timestamp_ns=(
                int(match.group("seconds")) * 1_000_000_000 + int(match.group("fraction"))
            ),
            group=match.group("group").decode("ascii"),
            event=match.group("event").decode("ascii"),
            payload=match.group("payload") or b"",
        )

    def _convert(self, header: _Header) -> TraceEvent | None:
        if header.group == "sched":
            return self._convert_sched(header)
        if header.group == "lock":
            return self._convert_lock(header)
        return self._convert_futex(header)

    def _convert_sched(self, header: _Header) -> TraceEvent | None:
        if header.event == "sched_switch":
            return self._convert_sched_switch(header)
        if header.event in {"sched_waking", "sched_wakeup", "sched_wakeup_new"}:
            return self._convert_sched_wakeup(header)
        return self._convert_sched_migrate(header)

    def _convert_sched_switch(self, header: _Header) -> TraceEvent | None:
        if any(
            header.payload.count(label) != 1
            for label in (
                b"prev_pid=",
                b" prev_prio=",
                b" prev_state=",
                b" next_pid=",
                b" next_prio=",
            )
        ):
            return self._malformed_payload("AMBIGUOUS_SCHED_SWITCH")
        match = _SCHED_SWITCH.fullmatch(header.payload)
        if match is None:
            return self._malformed_payload("MALFORMED_SCHED_SWITCH")
        previous_tid = int(match.group("prev_tid"))
        next_tid = int(match.group("next_tid"))
        previous, previous_scope = self._scoped_payload_task(previous_tid)
        next_task, next_scope = self._scoped_payload_task(next_tid)
        if previous_scope is TraceScope.FOREIGN and next_scope is TraceScope.FOREIGN:
            self.foreign += 1
            return None
        previous_state = self._normalize_sched_state(match.group("prev_state"))
        event = SchedSwitchEvent(
            event_id=self._event_id(header, "sched-switch"),
            sequence=len(self.events),
            timestamp_ns=header.timestamp_ns,
            cpu=header.cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            previous=previous,
            previous_scope=previous_scope,
            next=next_task,
            next_scope=next_scope,
            previous_state=previous_state,
        )
        self._observe_target_tasks(previous, previous_scope, next_task, next_scope)
        return event

    def _convert_sched_wakeup(self, header: _Header) -> TraceEvent | None:
        if any(
            header.payload.count(label) != 1
            for label in (b" pid=", b" prio=", b" target_cpu=")
        ):
            return self._malformed_payload("AMBIGUOUS_SCHED_WAKEUP")
        match = _SCHED_WAKEUP.fullmatch(header.payload)
        if match is None:
            return self._malformed_payload("MALFORMED_SCHED_WAKEUP")
        woken_tid = int(match.group("tid"))
        if woken_tid not in self.target_tids:
            self.foreign += 1
            return None
        self.observed_tids.add(woken_tid)
        if header.event == "sched_waking":
            waker, waker_scope = self._scoped_header_task(header)
            candidate = _ProvisionalWaker(waker, waker_scope)
            pending = self.provisional_wakers.get(woken_tid)
            if pending is None:
                self.provisional_wakers[woken_tid] = _PendingWakers(1, candidate)
            else:
                pending.count += 1
            return None

        pending = self.provisional_wakers.pop(woken_tid, None)
        if pending is not None and pending.count == 1:
            self.provisional += 1
            waker = pending.first.task
            waker_scope = pending.first.scope
        else:
            waker = None
            waker_scope = None
            if pending is not None:
                self.unsupported += pending.count
                self._diagnose(
                    "AMBIGUOUS_PROVISIONAL_WAKER",
                    "Multiple sched_waking records prevented exact waker enrichment",
                )
        return SchedWakeupEvent(
            event_id=self._event_id(header, "sched-wakeup"),
            sequence=len(self.events),
            timestamp_ns=header.timestamp_ns,
            cpu=header.cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            woken=TaskIdentity(pid=self.target.pid, tid=woken_tid),
            woken_scope=TraceScope.TARGET,
            source=(
                WakeupSource.WAKEUP_NEW
                if header.event == "sched_wakeup_new"
                else WakeupSource.WAKEUP
            ),
            waker=waker,
            waker_scope=waker_scope,
        )

    def _convert_sched_migrate(self, header: _Header) -> TraceEvent | None:
        if any(
            header.payload.count(label) != 1
            for label in (b" pid=", b" prio=", b" orig_cpu=", b" dest_cpu=")
        ):
            return self._malformed_payload("AMBIGUOUS_SCHED_MIGRATION")
        match = _SCHED_MIGRATE.fullmatch(header.payload)
        if match is None:
            return self._malformed_payload("MALFORMED_SCHED_MIGRATION")
        tid = int(match.group("tid"))
        if tid not in self.target_tids:
            self.foreign += 1
            return None
        self.observed_tids.add(tid)
        return SchedMigrateEvent(
            event_id=self._event_id(header, "sched-migrate"),
            sequence=len(self.events),
            timestamp_ns=header.timestamp_ns,
            cpu=header.cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            task=TaskIdentity(pid=self.target.pid, tid=tid),
            task_scope=TraceScope.TARGET,
            origin_cpu=int(match.group("origin")),
            destination_cpu=int(match.group("destination")),
        )

    def _convert_lock(self, header: _Header) -> TraceEvent | None:
        task, scope = self._scoped_header_task(header)
        if scope is TraceScope.FOREIGN:
            self.foreign += 1
            return None
        assert task.tid is not None
        self.observed_tids.add(task.tid)
        if header.event == "contention_begin":
            match = _MODERN_LOCK_BEGIN.fullmatch(header.payload)
            if match is None:
                return self._malformed_payload("MALFORMED_LOCK_CONTENTION_BEGIN")
            lock_id = self._lock_id(match.group("address"))
            key = (task.tid, lock_id)
            flag_parts = match.group("flags").split(b"|")
            if (
                len(set(flag_parts)) != len(flag_parts)
                or any(flag not in _KNOWN_LOCK_FLAGS for flag in flag_parts)
                or (b"0" in flag_parts and len(flag_parts) != 1)
            ):
                if key in self.audited_contentions:
                    self.audited_contentions[key] = None
                self.unsupported += 1
                self._diagnose(
                    "UNKNOWN_LOCK_FLAGS",
                    "Lock contention flags contain an unsupported value",
                )
                return None
            if key in self.audited_contentions:
                previous_flags = self.audited_contentions[key]
                if previous_flags is not None:
                    # The modern tracepoint may fire repeatedly while one slow-path wait is in
                    # progress, including audited SPIN -> MUTEX -> SPIN phase transitions.
                    # Preserve the earliest timestamp as the wait boundary; exporting every
                    # phase would fabricate duplicate waits in the deterministic analyzer.
                    self.lock_phase_enrichment += 1
                else:
                    self.unsupported += 1
                    self._diagnose(
                        "POISONED_LOCK_PHASE",
                        "An earlier unsupported lock phase prevents exact wait pairing",
                    )
                return None
            self.audited_contentions[key] = b"audited"
            return self._lock_event(header, task, LockAction.WAIT, lock_id)
        if header.event == "contention_end":
            match = _MODERN_LOCK_END.fullmatch(header.payload)
            if match is None:
                return self._malformed_payload("MALFORMED_LOCK_CONTENTION_END")
            lock_id = self._lock_id(match.group("address"))
            key = (task.tid, lock_id)
            audited_flags = self.audited_contentions.pop(key, None)
            outcome = self._wait_outcome(
                self._parse_integer(match.group("ret")),
                audited_begin=audited_flags is not None,
            )
            return self._lock_event(
                header,
                task,
                LockAction.WAIT_ENDED,
                lock_id,
                wait_outcome=outcome,
            )
        if header.event == "lock_acquire":
            # lock_acquire records attempts, including uncontended fast paths.  They are not
            # exact wait observations and cannot be represented as lock_wait.
            self.unsupported += 1
            self._diagnose(
                "UNSUPPORTED_LOCK_ATTEMPT",
                "lock_acquire does not prove that a task waited",
            )
            return None

        match = _LEGACY_LOCK.fullmatch(header.payload)
        if match is None:
            return self._malformed_payload("MALFORMED_LEGACY_LOCK_EVENT")
        lock_id = self._lock_id(match.group("address"))
        if header.event == "lock_contended":
            return self._lock_event(header, task, LockAction.WAIT, lock_id)
        if header.event == "lock_acquired":
            return self._lock_event(header, task, LockAction.ACQUIRED, lock_id)
        if header.event == "lock_release":
            return self._lock_event(header, task, LockAction.RELEASED, lock_id)
        raise AssertionError("fixed lock event allowlist and converter diverged")

    def _convert_futex(self, header: _Header) -> TraceEvent | None:
        task, scope = self._scoped_header_task(header)
        if scope is TraceScope.FOREIGN:
            self.foreign += 1
            return None
        assert task.tid is not None
        self.observed_tids.add(task.tid)
        if header.event == "sys_exit_futex":
            # Exit records do not carry the futex address.  Pairing them with entry records is a
            # separate runtime-adapter concern; silently reusing an address would be unsafe.
            self.unsupported += 1
            self._diagnose(
                "UNPAIRED_FUTEX_EXIT",
                "Futex exit cannot be normalized without an address-bearing entry pair",
            )
            return None
        fields = self._unique_fields(header.payload)
        if fields is None:
            return self._malformed_payload("AMBIGUOUS_FUTEX_PAYLOAD")
        raw_address = fields.get("uaddr")
        raw_op = fields.get("op")
        if (
            raw_address is None
            or _ADDRESS.fullmatch(raw_address) is None
            or raw_op is None
            or _INTEGER.fullmatch(raw_op) is None
        ):
            return self._malformed_payload("MISSING_FUTEX_FIELDS")
        operation = self._parse_integer(raw_op) & _FUTEX_COMMAND_MASK
        if operation == _FUTEX_WAIT:
            action = FutexAction.WAIT
            normalized_operation = FutexOperation.WAIT
        elif operation == _FUTEX_WAIT_BITSET:
            action = FutexAction.WAIT
            normalized_operation = FutexOperation.WAIT_BITSET
        elif operation == _FUTEX_WAIT_REQUEUE_PI:
            action = FutexAction.WAIT
            normalized_operation = FutexOperation.WAIT_REQUEUE_PI
        elif operation == _FUTEX_WAKE:
            action = FutexAction.WAKE
            normalized_operation = FutexOperation.WAKE
        elif operation == _FUTEX_WAKE_BITSET:
            action = FutexAction.WAKE
            normalized_operation = FutexOperation.WAKE_BITSET
        elif operation == _FUTEX_REQUEUE:
            action = FutexAction.WAKE
            normalized_operation = FutexOperation.REQUEUE
        else:
            self.unsupported += 1
            self._diagnose("UNSUPPORTED_FUTEX_OPERATION", "Futex operation is not allowlisted")
            return None
        return FutexEvent(
            event_id=self._event_id(header, f"futex-{action.value}"),
            sequence=len(self.events),
            timestamp_ns=header.timestamp_ns,
            cpu=header.cpu,
            target=self.target,
            semantics=EvidenceSemantics.CANDIDATE,
            task=task,
            task_scope=TraceScope.TARGET,
            action=action,
            futex_id=self._lock_id(raw_address),
            operation=normalized_operation,
        )

    def _lock_event(
        self,
        header: _Header,
        task: TaskIdentity,
        action: LockAction,
        lock_id: str,
        *,
        wait_outcome: LockWaitOutcome | None = None,
    ) -> LockEvent:
        return LockEvent(
            event_id=self._event_id(header, f"lock-{action.value}"),
            sequence=len(self.events),
            timestamp_ns=header.timestamp_ns,
            cpu=header.cpu,
            target=self.target,
            semantics=EvidenceSemantics.EXACT,
            task=task,
            task_scope=TraceScope.TARGET,
            action=action,
            lock_id=lock_id,
            wait_outcome=wait_outcome,
        )

    def _scoped_payload_task(self, tid: int) -> tuple[TaskIdentity, TraceScope]:
        if tid in self.target_tids:
            return TaskIdentity(pid=self.target.pid, tid=tid), TraceScope.TARGET
        return TaskIdentity.external_redacted(), TraceScope.FOREIGN

    def _scoped_header_task(self, header: _Header) -> tuple[TaskIdentity, TraceScope]:
        if header.pid == self.target.pid and header.tid in self.target_tids:
            return (
                TaskIdentity(pid=self.target.pid, tid=header.tid),
                TraceScope.TARGET,
            )
        return TaskIdentity.external_redacted(), TraceScope.FOREIGN

    def _observe_target_tasks(
        self,
        first: TaskIdentity,
        first_scope: TraceScope,
        second: TaskIdentity,
        second_scope: TraceScope,
    ) -> None:
        for task, scope in ((first, first_scope), (second, second_scope)):
            if scope is TraceScope.TARGET and task.tid is not None:
                self.observed_tids.add(task.tid)

    def _unique_fields(self, payload: bytes) -> dict[str, bytes] | None:
        fields: dict[str, bytes] = {}
        cursor = 0
        for match in _FIELD.finditer(payload):
            if payload[cursor : match.start()].strip(b" ,"):
                return None
            name = match.group("name").decode("ascii")
            if name in fields:
                return None
            fields[name] = match.group("value")
            cursor = match.end()
        if payload[cursor:].strip(b" ,"):
            return None
        return fields

    def _lock_id(self, raw_address: bytes) -> str:
        normalized = raw_address.lower()
        if not normalized.startswith(b"0x"):
            normalized = b"0x" + normalized
        digest = hmac.new(
            self.lock_identity_key,
            normalized,
            hashlib.sha256,
        ).hexdigest()
        return f"lock-{digest[:20]}"

    def _event_id(self, header: _Header, kind: str) -> str:
        material = (
            f"{self.input_events}:{header.timestamp_ns}:{header.cpu}:{kind}:{len(self.events)}"
        ).encode("ascii")
        return f"event-{hashlib.sha256(material).hexdigest()[:24]}"

    @staticmethod
    def _parse_integer(value: bytes) -> int:
        if value.startswith(b"-0x"):
            return -int(value[3:], 16)
        if value.startswith(b"0x"):
            parsed = int(value[2:], 16)
            if parsed >= 1 << 63:
                parsed -= 1 << 64
            return parsed
        return int(value)

    @staticmethod
    def _wait_outcome(result: int, *, audited_begin: bool) -> LockWaitOutcome:
        if result == 0:
            return LockWaitOutcome.ACQUIRED if audited_begin else LockWaitOutcome.UNKNOWN
        if result == -110:
            return LockWaitOutcome.TIMED_OUT
        if result == -4:
            return LockWaitOutcome.INTERRUPTED
        if result == -35:
            return LockWaitOutcome.FAILED
        return LockWaitOutcome.FAILED

    def _normalize_sched_state(self, raw_state: bytes) -> str:
        state = raw_state.rstrip(b"+")
        normalized = {
            b"R": "running",
            b"S": "interruptible_sleep",
            b"D": "uninterruptible_sleep",
            b"T": "stopped",
            b"t": "traced",
            b"X": "dead",
            b"x": "dead",
            b"Z": "dead",
            b"P": "parked",
            b"I": "idle",
        }.get(state)
        if normalized is None:
            self._diagnose("UNKNOWN_TASK_STATE", "Scheduler task state is unknown")
            return "unknown"
        return normalized

    def _malformed_payload(self, code: str) -> None:
        self.malformed += 1
        self._diagnose(code, "Trace event payload failed strict field validation")
        return None

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

    def _discard_provisional_wakers(self, code: str, message: str) -> None:
        count = sum(item.count for item in self.provisional_wakers.values())
        if not count:
            return
        self.unsupported += count
        self.provisional_wakers.clear()
        self._diagnose(code, message)

    def _limit_error(self, message: str) -> PerfLensError:
        return PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "trace_input",
            message,
            recoverable=True,
        )

    def finish(self) -> TraceStreamParseResult:
        self._discard_provisional_wakers(
            "UNMATCHED_PROVISIONAL_WAKER",
            "sched_waking records without a canonical wakeup were not exported",
        )
        validate_trace_sequence(
            self.events,
            expected_target=self.target,
            input_line_count=self.input_lines,
            output_bytes=self.input_bytes,
            limits=self.limits,
        )
        statistics = TraceParseStatistics(
            input_bytes=self.input_bytes,
            input_line_count=self.input_lines,
            input_event_count=self.input_events,
            emitted_event_count=len(self.events),
            lost_event_count=self.lost_events,
            malformed_event_count=self.malformed,
            duplicate_event_count=self.duplicates,
            out_of_order_event_count=self.out_of_order,
            unsupported_event_count=self.unsupported,
            truncated_event_count=self.truncated,
            foreign_event_dropped_count=self.foreign,
            provisional_enrichment_event_count=self.provisional,
            lock_phase_enrichment_event_count=self.lock_phase_enrichment,
            diagnostic_count=self.diagnostic_count,
            diagnostics=tuple(self.diagnostics),
            diagnostics_truncated=self.diagnostic_count > len(self.diagnostics),
        )
        return TraceStreamParseResult(
            events=tuple(self.events),
            # Preserve the backend-authenticated allowlist even when a quiet target emitted no
            # event.  Payload TIDs can narrow participation but can never expand authorization.
            observed_target_tids=tuple(sorted(self.target_tids)),
            statistics=statistics,
        )
