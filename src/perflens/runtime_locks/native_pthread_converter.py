"""Strict conversion of the private Native pthread probe stream.

The preload probe writes a deliberately small private NDJSON protocol.  This
module is the only bytes-to-public-contract boundary for that protocol: it
validates the complete target identity, event ordering, LIFO pairs, and source
accounting before passing a normalized schema-1.1 stream to the generic
Runtime Lock importer.  Raw keyed lock tokens and probe-local event identities
are never copied into the resulting public Artifact.

The converter has no path or process-execution API.  A launcher must open and
authenticate the private evidence descriptor before handing its binary stream
to this module.
"""

from __future__ import annotations

import hashlib
import heapq
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from tempfile import SpooledTemporaryFile
from typing import Annotated, Any, BinaryIO, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

from perflens.application.runtime_lock_evidence import (
    canonical_runtime_lock_json_sha256,
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
    validate_runtime_lock_evidence_invariants,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_locks import (
    RuntimeClock,
    RuntimeContainerTargetReference,
    RuntimeLockEvidenceArtifact,
    RuntimeLockResourceLimits,
    RuntimeSourceManifest,
    RuntimeTargetIdentity,
    derive_runtime_execution_context_id,
    derive_runtime_lock_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.importer import import_runtime_lock_ndjson

NATIVE_PTHREAD_PROBE_PROTOCOL = "native_pthread_probe"
NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION = "1.0"
NATIVE_PTHREAD_CONVERTER_VERSION = "native-pthread-converter-v1"

_SPOOL_MEMORY_BYTES = 1_048_576
_MAX_TIME_NS = (1 << 63) - 1
_EXACT_EVENT_LIMIT = 20_000
_SOURCE_EVENT_PATTERN = r"^e[1-9][0-9]{0,19}$"
_SOURCE_STACK_PATTERN = r"^s[1-9][0-9]{0,19}$"
_PROBE_LOCK_KEY_PATTERN = r"^[a-f0-9]{16}$"

type NativeSemantics = Literal["exact", "thresholded"]
type NativeLockKind = Literal[
    "mutex",
    "recursive_mutex",
    "rwlock_read",
    "rwlock_write",
    "condition",
]
type NativeEventKind = Literal["wait_begin", "wait_end", "acquire", "release"]
type NativeResult = Literal[
    "unknown",
    "acquired",
    "notified",
    "timed_out",
    "failed",
    "released",
]

PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
TimeNanoseconds = Annotated[StrictInt, Field(ge=0, le=_MAX_TIME_NS)]


class _StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class _ProbeHeader(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["probe_header"]
    protocol: Literal["native_pthread_probe"]
    protocol_version: Literal["1.0"]
    runtime: Literal["c_cpp"]
    runtime_version: Annotated[StrictStr, Field(min_length=1, max_length=256)]
    adapter_id: Literal["native-pthread"]
    adapter_version: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    backend_id: Literal["ld-preload"]
    backend_version: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    pid: PositiveInt
    uid: NonNegativeInt
    target_start_time_ticks: PositiveInt
    observed_target_tids: tuple[PositiveInt, ...]
    target_kind: Literal["host", "docker"]
    container_reference: RuntimeContainerTargetReference | None
    semantics: NativeSemantics
    duration_threshold_ns: TimeNanoseconds | None
    max_events: PositiveInt
    visible_lock_kinds: tuple[NativeLockKind, ...]
    fast_path_visibility: Literal["complete", "partial"]
    owner_is_source_observed: Literal[False]
    hold_time_is_source_observed: StrictBool

    @model_validator(mode="after")
    def validate_header(self) -> _ProbeHeader:
        required = {
            "schema_version",
            "record_type",
            "protocol",
            "protocol_version",
            "runtime",
            "runtime_version",
            "adapter_id",
            "adapter_version",
            "backend_id",
            "backend_version",
            "pid",
            "uid",
            "target_start_time_ticks",
            "observed_target_tids",
            "target_kind",
            "container_reference",
            "semantics",
            "duration_threshold_ns",
            "max_events",
            "visible_lock_kinds",
            "fast_path_visibility",
            "owner_is_source_observed",
            "hold_time_is_source_observed",
        }
        if not required.issubset(self.model_fields_set):
            raise ValueError("native probe header omitted a required field")
        if tuple(sorted(set(self.observed_target_tids))) != self.observed_target_tids:
            raise ValueError("native probe target TIDs must be unique and sorted")
        if self.pid not in self.observed_target_tids:
            raise ValueError("native probe target TIDs must include the process leader")
        if tuple(sorted(set(self.visible_lock_kinds))) != self.visible_lock_kinds:
            raise ValueError("native probe lock kinds must be unique and sorted")
        if not self.visible_lock_kinds:
            raise ValueError("native probe must declare a visible lock kind")
        if (self.target_kind == "docker") != (self.container_reference is not None):
            raise ValueError("native Docker evidence needs a complete container reference")
        if self.semantics == "exact":
            if self.duration_threshold_ns is not None or self.max_events > _EXACT_EVENT_LIMIT:
                raise ValueError("native exact mode has invalid threshold or event budget")
            if self.fast_path_visibility != "complete":
                raise ValueError("native exact mode must declare complete visible fast paths")
        elif self.duration_threshold_ns is None or self.fast_path_visibility != "partial":
            raise ValueError("native thresholded mode requires a threshold and partial fast paths")
        return self

    def target(self, observed_target_tids: tuple[int, ...] | None = None) -> RuntimeTargetIdentity:
        return RuntimeTargetIdentity(
            target_pid=self.pid,
            target_uid=self.uid,
            target_start_time_ticks=self.target_start_time_ticks,
            observed_target_tids=observed_target_tids or self.observed_target_tids,
            target_kind=self.target_kind,
            container_reference=self.container_reference,
        )


class _ProbeStackFrame(_StrictRecord):
    symbol: Annotated[StrictStr, Field(min_length=1, max_length=4096)]
    module: Annotated[StrictStr, Field(min_length=1, max_length=4096)]
    source_file: Annotated[StrictStr, Field(min_length=1, max_length=4096)] | None
    source_line: PositiveInt | None
    is_runtime: StrictBool
    is_unknown: StrictBool

    @model_validator(mode="after")
    def validate_frame(self) -> _ProbeStackFrame:
        required = {
            "symbol",
            "module",
            "source_file",
            "source_line",
            "is_runtime",
            "is_unknown",
        }
        if not required.issubset(self.model_fields_set):
            raise ValueError("native probe stack frame omitted a required field")
        if self.source_line is not None and self.source_file is None:
            raise ValueError("native probe source line requires a file")
        return self


class _ProbeStack(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["probe_stack"]
    stack_id: Annotated[StrictStr, Field(pattern=_SOURCE_STACK_PATTERN)]
    frames: tuple[_ProbeStackFrame, ...]

    @model_validator(mode="after")
    def validate_stack(self) -> _ProbeStack:
        required = {"schema_version", "record_type", "stack_id", "frames"}
        if not required.issubset(self.model_fields_set) or not self.frames:
            raise ValueError("native probe stack is incomplete")
        return self


class _ProbeEvent(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["probe_event"]
    sequence: PositiveInt
    source_event_id: Annotated[StrictStr, Field(pattern=_SOURCE_EVENT_PATTERN)]
    event_kind: NativeEventKind
    timestamp_ns: TimeNanoseconds
    pid: PositiveInt
    tid: PositiveInt
    raw_lock_token: Annotated[StrictStr, Field(pattern=_PROBE_LOCK_KEY_PATTERN)]
    lock_kind: NativeLockKind
    related_source_event_id: Annotated[StrictStr, Field(pattern=_SOURCE_EVENT_PATTERN)] | None
    duration_ns: TimeNanoseconds | None
    hold_duration_ns: TimeNanoseconds | None
    result: NativeResult | None
    stack_id: Annotated[StrictStr, Field(pattern=_SOURCE_STACK_PATTERN)] | None

    @model_validator(mode="after")
    def validate_shape(self) -> _ProbeEvent:
        required = {
            "schema_version",
            "record_type",
            "sequence",
            "source_event_id",
            "event_kind",
            "timestamp_ns",
            "pid",
            "tid",
            "raw_lock_token",
            "lock_kind",
            "related_source_event_id",
            "duration_ns",
            "hold_duration_ns",
            "result",
            "stack_id",
        }
        if not required.issubset(self.model_fields_set):
            raise ValueError("native probe event omitted a required field")
        if self.source_event_id != f"e{self.sequence}":
            raise ValueError("native probe event identity must match its sequence")
        if self.event_kind == "wait_begin":
            valid = (
                self.related_source_event_id is None
                and self.duration_ns is None
                and self.hold_duration_ns is None
                and self.result == "unknown"
            )
        elif self.event_kind == "wait_end":
            valid = (
                self.related_source_event_id is not None
                and self.duration_ns is not None
                and self.hold_duration_ns is None
                and self.result in {"acquired", "notified", "timed_out", "failed"}
            )
        elif self.event_kind == "acquire":
            valid = (
                self.duration_ns is None
                and self.hold_duration_ns is None
                and self.result == "acquired"
            )
        else:
            valid = (
                self.related_source_event_id is not None
                and self.duration_ns is None
                and self.result == "released"
            )
        if not valid:
            raise ValueError("native probe event fields contradict its event kind")
        return self


class _ProbeFooter(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["probe_footer"]
    protocol: Literal["native_pthread_probe"]
    pid: PositiveInt
    sequence: PositiveInt
    declared_event_count: NonNegativeInt
    lost_event_count: NonNegativeInt
    truncated: StrictBool

    @model_validator(mode="after")
    def validate_footer(self) -> _ProbeFooter:
        required = {
            "schema_version",
            "record_type",
            "protocol",
            "pid",
            "sequence",
            "declared_event_count",
            "lost_event_count",
            "truncated",
        }
        if not required.issubset(self.model_fields_set):
            raise ValueError("native probe footer omitted a required field")
        if self.truncated and self.declared_event_count == 0:
            raise ValueError("truncated native evidence must retain an event")
        return self


@dataclass(frozen=True, slots=True)
class NativePthreadConversionReceipt:
    """Private receipt used to replay one conversion without exposing tokens."""

    evidence: RuntimeLockEvidenceArtifact
    raw_source_sha256: str
    raw_source_bytes: int
    normalized_source_sha256: str
    normalized_source_bytes: int


@dataclass(frozen=True, slots=True)
class _PairSubject:
    tid: int
    raw_lock_token: str
    lock_kind: NativeLockKind


@dataclass(frozen=True, slots=True)
class _SeenEvent:
    event_kind: NativeEventKind
    subject: _PairSubject
    timestamp_ns: int
    result: NativeResult | None


class _BoundedEventSorter:
    """Chunk-sort normalized events without retaining the whole source in RAM."""

    _CHUNK_RECORDS = 1_024

    def __init__(self, *, max_line_bytes: int) -> None:
        self._max_line_bytes = max_line_bytes
        self._buffer: list[tuple[int, int, bytes]] = []
        self._chunks: list[BinaryIO] = []

    def add(self, *, timestamp_ns: int, sequence: int, record: object) -> None:
        line = _record_line(record)
        if len(line) > self._max_line_bytes:
            raise _limit("Normalized native pthread event exceeds max_line_bytes")
        self._buffer.append((timestamp_ns, sequence, line))
        if len(self._buffer) >= self._CHUNK_RECORDS:
            self._flush()

    def write_to(self, destination: BinaryIO) -> None:
        self._flush()
        heap: list[tuple[int, int, int, bytes]] = []
        for index, chunk in enumerate(self._chunks):
            chunk.seek(0)
            item = self._read_tagged(chunk)
            if item is not None:
                timestamp, sequence, line = item
                heapq.heappush(heap, (timestamp, sequence, index, line))
        while heap:
            _timestamp, _sequence, index, line = heapq.heappop(heap)
            destination.write(line)
            item = self._read_tagged(self._chunks[index])
            if item is not None:
                timestamp, sequence, next_line = item
                heapq.heappush(heap, (timestamp, sequence, index, next_line))

    def close(self) -> None:
        for chunk in self._chunks:
            chunk.close()
        self._chunks.clear()
        self._buffer.clear()

    def _flush(self) -> None:
        if not self._buffer:
            return
        self._buffer.sort(key=lambda item: (item[0], item[1]))
        chunk = cast(
            BinaryIO,
            SpooledTemporaryFile(  # noqa: SIM115
                max_size=_SPOOL_MEMORY_BYTES,
                mode="w+b",
            ),
        )
        for timestamp, sequence, line in self._buffer:
            chunk.write(f"{timestamp:020d}\t{sequence:020d}\t".encode("ascii"))
            chunk.write(line)
        chunk.seek(0)
        self._chunks.append(chunk)
        self._buffer.clear()

    @staticmethod
    def _read_tagged(stream: BinaryIO) -> tuple[int, int, bytes] | None:
        tagged = stream.readline()
        if tagged == b"":
            return None
        timestamp_raw, separator, remainder = tagged.partition(b"\t")
        if separator == b"":
            raise _invalid("Native pthread internal event sort record is malformed")
        sequence_raw, separator, line = remainder.partition(b"\t")
        if separator == b"":
            raise _invalid("Native pthread internal event sort record is malformed")
        return int(timestamp_raw), int(sequence_raw), line


class NativePthreadProbeConverter:
    """Bounded streaming converter for ``native_pthread_probe`` NDJSON."""

    def __init__(
        self,
        *,
        limits: RuntimeLockResourceLimits | None = None,
        created_at: str | None = None,
    ) -> None:
        self._limits = limits or RuntimeLockResourceLimits()
        self._created_at = _normalize_created_at(created_at or datetime.now(tz=UTC).isoformat())

    def convert(self, stream: BinaryIO) -> NativePthreadConversionReceipt:
        digest = hashlib.sha256()
        raw_bytes = 0
        line_number = 0
        header: _ProbeHeader | None = None
        footer: _ProbeFooter | None = None
        event_count = 0
        stack_count = 0
        seen_event = False
        last_timestamp_by_tid: dict[int, int] = {}
        observed_target_tids: set[int] = set()
        stack_ids: set[str] = set()
        seen_events: dict[str, _SeenEvent] = {}
        wait_stacks: dict[_PairSubject, list[str]] = {}
        acquire_stacks: dict[_PairSubject, list[str]] = {}
        lock_kinds: dict[str, NativeLockKind] = {}
        event_sorter = _BoundedEventSorter(max_line_bytes=self._limits.max_line_bytes)

        try:
            with SpooledTemporaryFile(max_size=_SPOOL_MEMORY_BYTES, mode="w+b") as records:
                records_io = cast(BinaryIO, records)
                while True:
                    raw_line = _readline(stream, self._limits.max_line_bytes)
                    if raw_line == b"":
                        break
                    line_number += 1
                    raw_bytes += len(raw_line)
                    if raw_bytes > self._limits.max_source_bytes:
                        raise _limit("Native pthread probe input exceeds max_source_bytes")
                    if line_number > (
                        2 + self._limits.max_input_records + self._limits.max_unique_stacks
                    ):
                        raise _limit("Native pthread probe input exceeds its record bound")
                    digest.update(raw_line)
                    raw = _strict_json_line(raw_line, line_number=line_number)
                    record_type = raw.get("record_type")
                    if header is None:
                        if record_type != "probe_header":
                            raise _invalid("Native pthread probe header must be the first record")
                        header = _validate_record(_ProbeHeader, raw, "header")
                        observed_target_tids.update(header.observed_target_tids)
                        if header.max_events > self._limits.max_input_records:
                            raise _limit("Native pthread probe max_events exceeds policy")
                        continue
                    if footer is not None:
                        raise _invalid("Native pthread probe contains records after its footer")
                    if record_type == "probe_header":
                        raise _invalid("Native pthread probe contains a duplicate header")
                    if record_type == "probe_stack":
                        if seen_event:
                            raise _invalid("Native pthread probe stack appears after an event")
                        stack = _validate_record(_ProbeStack, raw, "stack")
                        stack_count += 1
                        if stack_count > self._limits.max_unique_stacks:
                            raise _limit("Native pthread probe exceeds max_unique_stacks")
                        if stack.stack_id in stack_ids:
                            raise _invalid("Native pthread probe repeats a stack identity")
                        if len(stack.frames) > self._limits.max_stack_depth:
                            raise _limit("Native pthread probe stack exceeds max_stack_depth")
                        stack_ids.add(stack.stack_id)
                        _write_record(records_io, _normalized_stack(stack))
                        continue
                    if record_type == "probe_event":
                        seen_event = True
                        event = _validate_record(_ProbeEvent, raw, "event")
                        event_count += 1
                        if event_count > header.max_events:
                            raise _limit("Native pthread probe exceeds its declared event budget")
                        if event.sequence != event_count:
                            raise _invalid("Native pthread probe event sequence is not contiguous")
                        if event.pid != header.pid:
                            raise _invalid("Native pthread probe event escaped the bound target")
                        observed_target_tids.add(event.tid)
                        if len(observed_target_tids) > self._limits.max_unique_target_tids:
                            raise _limit("Native pthread probe exceeds the target TID bound")
                        if event.lock_kind not in header.visible_lock_kinds:
                            raise _invalid(
                                "Native pthread probe event uses an undeclared lock kind"
                            )
                        previous_kind = lock_kinds.setdefault(event.raw_lock_token, event.lock_kind)
                        if previous_kind != event.lock_kind:
                            raise _invalid("Native pthread probe lock identity changed lock kind")
                        if event.stack_id is not None and event.stack_id not in stack_ids:
                            raise _invalid("Native pthread probe event references an unknown stack")
                        prior_tid_timestamp = last_timestamp_by_tid.get(event.tid)
                        if (
                            prior_tid_timestamp is not None
                            and event.timestamp_ns < prior_tid_timestamp
                        ):
                            raise _invalid(
                                "Native pthread probe per-thread timestamps are out of order"
                            )
                        self._validate_pair(
                            event,
                            header=header,
                            seen_events=seen_events,
                            wait_stacks=wait_stacks,
                            acquire_stacks=acquire_stacks,
                        )
                        last_timestamp_by_tid[event.tid] = event.timestamp_ns
                        subject = _subject(event)
                        seen_events[event.source_event_id] = _SeenEvent(
                            event_kind=event.event_kind,
                            subject=subject,
                            timestamp_ns=event.timestamp_ns,
                            result=event.result,
                        )
                        event_sorter.add(
                            timestamp_ns=event.timestamp_ns,
                            sequence=event.sequence,
                            record=_normalized_event(event, header=header),
                        )
                        continue
                    if record_type == "probe_footer":
                        footer = _validate_record(_ProbeFooter, raw, "footer")
                        if footer.pid != header.pid:
                            raise _invalid("Native pthread probe footer escaped the bound target")
                        if footer.sequence != event_count + 1:
                            raise _invalid("Native pthread probe footer sequence is not contiguous")
                        if footer.declared_event_count != event_count:
                            raise _invalid(
                                "Native pthread probe footer event count differs from input"
                            )
                        continue
                    raise _invalid("Native pthread probe contains an unknown record_type")

                if header is None:
                    raise _invalid("Native pthread probe input is empty")
                if footer is None:
                    raise _invalid("Native pthread probe input is missing its completion footer")
                raw_sha256 = digest.hexdigest()
                normalized = self._normalized_stream(
                    records_io,
                    event_sorter=event_sorter,
                    header=header,
                    footer=footer,
                    event_count=event_count,
                    observed_target_tids=tuple(sorted(observed_target_tids)),
                    raw_sha256=raw_sha256,
                )
                try:
                    normalized_sha256, normalized_bytes = _stream_identity(normalized)
                    normalized.seek(0)
                    imported = import_runtime_lock_ndjson(
                        normalized,
                        limits=self._limits,
                        created_at=self._created_at,
                    )
                finally:
                    normalized.close()
        finally:
            event_sorter.close()

        evidence = _rebind_native_source(
            imported,
            header=header,
            raw_source_sha256=raw_sha256,
            raw_source_bytes=raw_bytes,
        )
        validate_runtime_lock_evidence_invariants(evidence)
        return NativePthreadConversionReceipt(
            evidence=evidence,
            raw_source_sha256=raw_sha256,
            raw_source_bytes=raw_bytes,
            normalized_source_sha256=normalized_sha256,
            normalized_source_bytes=normalized_bytes,
        )

    def _normalized_stream(
        self,
        records: BinaryIO,
        *,
        event_sorter: _BoundedEventSorter,
        header: _ProbeHeader,
        footer: _ProbeFooter,
        event_count: int,
        observed_target_tids: tuple[int, ...],
        raw_sha256: str,
    ) -> BinaryIO:
        # Ownership is transferred to the caller and closed in ``convert``.
        normalized = cast(
            BinaryIO,
            SpooledTemporaryFile(  # noqa: SIM115
                max_size=_SPOOL_MEMORY_BYTES,
                mode="w+b",
            ),
        )
        normalized_header: dict[str, object] = {
            "schema_version": "1.1",
            "record_type": "runtime_lock_header",
            "runtime": "c_cpp",
            "runtime_version": header.runtime_version,
            "adapter_id": header.adapter_id,
            "adapter_version": header.adapter_version,
            "backend_id": header.backend_id,
            # Bind byte-distinct raw streams before the generic importer assigns
            # its provisional Artifact ID.  This private backend version never
            # becomes the final public source manifest.
            "backend_version": f"{header.backend_version}+raw.{raw_sha256[:16]}",
            "target": header.target(observed_target_tids).model_dump(
                mode="json", exclude_none=True
            ),
            "clock": {
                "clock": "monotonic",
                "unit": "nanoseconds",
                "epoch_correlation_available": False,
            },
            "measurement_semantics": header.semantics,
            "visible_lock_kinds": list(header.visible_lock_kinds),
            "fast_path_visibility": header.fast_path_visibility,
            "owner_is_source_observed": False,
            "hold_time_is_source_observed": header.hold_time_is_source_observed,
            "duration_threshold_ns": header.duration_threshold_ns,
            "declared_event_count": event_count,
            "declared_lost_event_count": footer.lost_event_count,
            "declared_truncated": footer.truncated,
        }
        _write_record(normalized, normalized_header)
        records.seek(0)
        normalized_bytes = normalized.tell()
        while True:
            chunk = records.read(64 * 1024)
            if chunk == b"":
                break
            normalized_bytes += len(chunk)
            if normalized_bytes > self._limits.max_source_bytes:
                normalized.close()
                raise _limit("Normalized native pthread evidence exceeds max_source_bytes")
            normalized.write(chunk)
        event_sorter.write_to(normalized)
        if normalized.tell() > self._limits.max_source_bytes:
            normalized.close()
            raise _limit("Normalized native pthread evidence exceeds max_source_bytes")
        normalized.seek(0)
        return normalized

    @staticmethod
    def _validate_pair(
        event: _ProbeEvent,
        *,
        header: _ProbeHeader,
        seen_events: Mapping[str, _SeenEvent],
        wait_stacks: dict[_PairSubject, list[str]],
        acquire_stacks: dict[_PairSubject, list[str]],
    ) -> None:
        subject = _subject(event)
        if event.event_kind == "wait_begin":
            wait_stacks.setdefault(subject, []).append(event.source_event_id)
            return
        if event.event_kind == "wait_end":
            assert event.related_source_event_id is not None
            assert event.duration_ns is not None
            stack = wait_stacks.get(subject)
            if not stack or stack[-1] != event.related_source_event_id:
                raise _invalid("Native pthread wait pair violates target-local LIFO order")
            begin = seen_events.get(event.related_source_event_id)
            if begin is None or begin.event_kind != "wait_begin" or begin.subject != subject:
                raise _invalid("Native pthread wait references an invalid begin event")
            if event.duration_ns != event.timestamp_ns - begin.timestamp_ns:
                raise _invalid("Native pthread wait duration contradicts its timestamps")
            if header.semantics == "thresholded" and event.duration_ns < cast(
                int, header.duration_threshold_ns
            ):
                raise _invalid("Native pthread thresholded wait is below its declared threshold")
            stack.pop()
            return
        if event.event_kind == "acquire":
            related = event.related_source_event_id
            if related is not None:
                wait_end = seen_events.get(related)
                if (
                    wait_end is None
                    or wait_end.event_kind != "wait_end"
                    or wait_end.subject != subject
                    or wait_end.result != "acquired"
                    or wait_end.timestamp_ns > event.timestamp_ns
                ):
                    raise _invalid("Native pthread acquire references an invalid wait completion")
            acquire_stacks.setdefault(subject, []).append(event.source_event_id)
            return
        assert event.event_kind == "release"
        assert event.related_source_event_id is not None
        stack = acquire_stacks.get(subject)
        if not stack or stack[-1] != event.related_source_event_id:
            raise _invalid("Native pthread release pair violates target-local LIFO order")
        acquire = seen_events.get(event.related_source_event_id)
        if acquire is None or acquire.event_kind != "acquire" or acquire.subject != subject:
            raise _invalid("Native pthread release references an invalid acquire event")
        expected_hold = event.timestamp_ns - acquire.timestamp_ns
        if header.hold_time_is_source_observed:
            if event.hold_duration_ns is None or event.hold_duration_ns != expected_hold:
                raise _invalid("Native pthread hold duration contradicts its timestamps")
        elif event.hold_duration_ns is not None:
            raise _invalid("Native pthread release fabricated an unavailable hold duration")
        stack.pop()


def convert_native_pthread_probe(
    stream: BinaryIO,
    *,
    limits: RuntimeLockResourceLimits | None = None,
    created_at: str | None = None,
) -> NativePthreadConversionReceipt:
    """Convert one private, cooperatively emitted target-process stream to public Evidence."""

    return NativePthreadProbeConverter(limits=limits, created_at=created_at).convert(stream)


def replay_native_pthread_probe(
    expected: RuntimeLockEvidenceArtifact,
    stream: BinaryIO,
) -> bool:
    """Independently replay a retained raw stream against one public Artifact."""

    if expected.source.source_format != "native_interposer_ndjson_v1":
        raise _invalid("Runtime Lock evidence does not originate from the Native pthread probe")
    receipt = convert_native_pthread_probe(
        stream,
        limits=expected.limits,
        created_at=expected.created_at,
    )
    return receipt.evidence == expected


def _normalized_stack(stack: _ProbeStack) -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "record_type": "runtime_lock_stack",
        "source_stack_id": stack.stack_id,
        "frames": [frame.model_dump(mode="json") for frame in stack.frames],
    }


def _normalized_event(event: _ProbeEvent, *, header: _ProbeHeader) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": "1.1",
        "record_type": "runtime_lock_event",
        "source_event_id": event.source_event_id,
        "event_kind": event.event_kind,
        "timestamp_ns": event.timestamp_ns,
        "execution_context": {
            "kind": "os_thread",
            "target_pid": header.pid,
            "target_tid": event.tid,
        },
        "source_lock_id": event.raw_lock_token,
        "lock_kind": event.lock_kind,
        "source_stack_id": event.stack_id,
    }
    if event.event_kind == "wait_end":
        record.update(
            {
                "wait_begin_source_event_id": event.related_source_event_id,
                "duration_ns": event.duration_ns,
                "outcome": event.result,
            }
        )
    elif event.event_kind == "acquire":
        # A condition wait result such as ``notified`` is not equivalent to a
        # mutex acquisition outcome.  The private protocol therefore permits
        # an unreferenced condition acquire and the converter never invents a
        # successful wait completion relationship.
        record["wait_end_source_event_id"] = event.related_source_event_id
    elif event.event_kind == "release":
        record.update(
            {
                "acquire_source_event_id": (
                    event.related_source_event_id if header.hold_time_is_source_observed else None
                ),
                "hold_duration_ns": (
                    event.hold_duration_ns if header.hold_time_is_source_observed else None
                ),
            }
        )
    return record


def _rebind_native_source(
    imported: RuntimeLockEvidenceArtifact,
    *,
    header: _ProbeHeader,
    raw_source_sha256: str,
    raw_source_bytes: int,
) -> RuntimeLockEvidenceArtifact:
    seed = canonical_runtime_lock_json_sha256(
        {
            "domain": "perflens.native-pthread-evidence-id.v1",
            "raw_source_sha256": raw_source_sha256,
            "raw_source_bytes": raw_source_bytes,
            "created_at": imported.created_at,
            "target": imported.target,
            "converter_version": NATIVE_PTHREAD_CONVERTER_VERSION,
            "limits": imported.limits,
        }
    )
    evidence_id = f"runtime-lock-evidence-{seed[:24]}"
    context_ids = {
        context.context_id: derive_runtime_execution_context_id(evidence_id, ordinal)
        for ordinal, context in enumerate(imported.execution_contexts)
    }
    stack_ids = {
        stack.stack_id: _opaque_id(evidence_id, "stack", ordinal, length=24)
        for ordinal, stack in enumerate(imported.stacks)
    }
    event_ids = {
        event.event_id: _opaque_id(evidence_id, "event", ordinal, length=24)
        for ordinal, event in enumerate(imported.events)
    }
    old_lock_ids = tuple(
        dict.fromkeys(event.lock_id for event in imported.events if event.lock_id is not None)
    )
    lock_ids = {
        lock_id: derive_runtime_lock_id(evidence_id, ordinal)
        for ordinal, lock_id in enumerate(old_lock_ids)
    }
    contexts = tuple(
        context.model_copy(update={"context_id": context_ids[context.context_id]})
        for context in imported.execution_contexts
    )
    stacks = tuple(
        stack.model_copy(update={"stack_id": stack_ids[stack.stack_id]})
        for stack in imported.stacks
    )
    events: list[dict[str, object]] = []
    for event in imported.events:
        data = event.model_dump(mode="json", exclude_none=True)
        data["event_id"] = event_ids[event.event_id]
        if event.execution_context_id is not None:
            data["execution_context_id"] = context_ids[event.execution_context_id]
        if event.lock_id is not None:
            data["lock_id"] = lock_ids[event.lock_id]
        if event.stack_id is not None:
            data["stack_id"] = stack_ids[event.stack_id]
        for field_name in (
            "wait_begin_event_id",
            "wait_end_event_id",
            "acquire_event_id",
        ):
            value = data.get(field_name)
            if isinstance(value, str):
                data[field_name] = event_ids[value]
        events.append(data)
    source_provisional = RuntimeSourceManifest(
        schema_version="1.1",
        runtime="c_cpp",
        adapter_id=header.adapter_id,
        adapter_version=header.adapter_version,
        backend_id=header.backend_id,
        backend_version=header.backend_version,
        measurement_semantics=header.semantics,
        source_format="native_interposer_ndjson_v1",
        converter_version=NATIVE_PTHREAD_CONVERTER_VERSION,
        source_sha256=raw_source_sha256,
        source_bytes=raw_source_bytes,
        conversion_fingerprint="0" * 64,
        clock=RuntimeClock(
            clock="monotonic",
            unit="nanoseconds",
            epoch_correlation_available=False,
        ),
        duration_threshold_ns=header.duration_threshold_ns,
        fast_path_visibility=header.fast_path_visibility,
        owner_is_source_observed=False,
        hold_time_is_source_observed=header.hold_time_is_source_observed,
        target_scope="bound_pid",
        tool=None,
    )
    source = source_provisional.model_copy(
        update={
            "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(
                source_provisional
            )
        }
    )
    provisional = RuntimeLockEvidenceArtifact.model_validate(
        {
            **imported.model_dump(mode="json", exclude_unset=True),
            "runtime_lock_evidence_id": evidence_id,
            "source": source.model_dump(mode="json", exclude_none=True),
            "execution_contexts": [
                context.model_dump(mode="json", exclude_none=True) for context in contexts
            ],
            "stacks": [stack.model_dump(mode="json", exclude_none=True) for stack in stacks],
            "events": events,
            "evidence_fingerprint": "0" * 64,
            "content_sha256": "0" * 64,
            "content_bytes": 1,
        }
    )
    fingerprinted = provisional.model_copy(
        update={"evidence_fingerprint": compute_runtime_lock_evidence_fingerprint(provisional)}
    )
    sized = _with_stable_content_bytes(fingerprinted)
    return RuntimeLockEvidenceArtifact.model_validate(
        {
            **sized.model_dump(mode="json", exclude_unset=True),
            "content_sha256": compute_runtime_lock_evidence_content_sha256(sized),
        }
    )


def _subject(event: _ProbeEvent) -> _PairSubject:
    return _PairSubject(
        tid=event.tid,
        raw_lock_token=event.raw_lock_token,
        lock_kind=event.lock_kind,
    )


def _opaque_id(evidence_id: str, kind: str, ordinal: int, *, length: int) -> str:
    material = f"perflens.runtime-lock.{kind}.v1.1\0{evidence_id}\0{ordinal}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:length]
    return f"runtime-{kind}-{digest}"


def _with_stable_content_bytes(
    evidence: RuntimeLockEvidenceArtifact,
) -> RuntimeLockEvidenceArtifact:
    current = evidence
    for _ in range(8):
        actual = len(serialize_json(current))
        if actual == current.content_bytes:
            return current
        current = current.model_copy(update={"content_bytes": actual})
    raise _invalid("Native pthread Evidence byte identity did not converge")


def _stream_identity(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = stream.read(64 * 1024)
        if chunk == b"":
            break
        digest.update(chunk)
        count += len(chunk)
    stream.seek(0)
    return digest.hexdigest(), count


def _readline(stream: BinaryIO, max_line_bytes: int) -> bytes:
    try:
        line = stream.readline(max_line_bytes + 1)
    except (OSError, TypeError, ValueError):
        raise _invalid("Native pthread probe stream could not be read") from None
    if line != b"" and len(line) > max_line_bytes:
        raise _limit("Native pthread probe contains an oversized line")
    return line


def _strict_json_line(raw_line: bytes, *, line_number: int) -> dict[str, Any]:
    if not raw_line.endswith(b"\n"):
        raise _invalid("Native pthread probe record violates the NDJSON line boundary")
    try:
        value = json.loads(
            raw_line,
            object_pairs_hook=_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _invalid(f"Native pthread probe record {line_number} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _invalid(f"Native pthread probe record {line_number} is not an object")
    return cast(dict[str, Any], value)


def _without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_record[RecordT: BaseModel](
    model: type[RecordT],
    raw: dict[str, Any],
    label: str,
) -> RecordT:
    try:
        return model.model_validate(raw)
    except (TypeError, ValueError, ValidationError):
        raise _invalid(f"Native pthread probe {label} failed strict validation") from None


def parse_native_pthread_probe_footer(
    raw_line: bytes,
    *,
    expected_pid: int,
) -> tuple[int, int, bool] | None:
    """Validate the launcher's completion receipt with the converter schema."""

    if len(raw_line) > 64 << 10:
        return None
    try:
        raw = _strict_json_line(raw_line, line_number=1)
        footer = _validate_record(_ProbeFooter, raw, "footer")
    except PerfLensError:
        return None
    if footer.pid != expected_pid:
        return None
    return (
        footer.declared_event_count,
        footer.lost_event_count,
        footer.truncated,
    )


def _write_record(stream: BinaryIO, record: object) -> None:
    try:
        line = _record_line(record)
        stream.write(line)
    except (OSError, TypeError, ValueError):
        raise _invalid("Native pthread normalization could not write a bounded record") from None


def _record_line(record: object) -> bytes:
    return (
        json.dumps(
            _json_value(record),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return {str(key): _json_value(item) for key, item in mapping.items()}
    if isinstance(value, (tuple, list)):
        sequence = cast(tuple[object, ...] | list[object], value)
        return [_json_value(item) for item in sequence]
    return value


def _normalize_created_at(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise _invalid("Native pthread created_at is not a valid ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise _invalid("Native pthread created_at must include a timezone")
    return parsed.astimezone(UTC).isoformat()


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "native_pthread_conversion",
        message,
        recoverable=True,
    )


def _limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "native_pthread_conversion",
        message,
        recoverable=True,
    )
