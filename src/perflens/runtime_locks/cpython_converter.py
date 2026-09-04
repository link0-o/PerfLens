"""Strict conversion of the private CPython ``threading`` bootstrap stream."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from tempfile import SpooledTemporaryFile
from typing import Annotated, Any, BinaryIO, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, ValidationError

from perflens.application.runtime_lock_evidence import (
    canonical_runtime_lock_json_sha256,
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
    validate_runtime_lock_evidence_invariants,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_lock_sessions import RuntimeLockAdapterExecutionBinding
from perflens.contracts.runtime_locks import (
    RuntimeClock,
    RuntimeLockEvidenceArtifact,
    RuntimeLockResourceLimits,
    RuntimeSourceManifest,
    RuntimeToolIdentity,
    derive_runtime_execution_context_id,
    derive_runtime_lock_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.importer import import_runtime_lock_ndjson

CPYTHON_THREADING_CONVERTER_VERSION = "cpython-threading-converter-v1"
_MAX_TIME_NS = (1 << 63) - 1
_MAX_EVENTS = 20_000
_SPOOL_MEMORY_BYTES = 1 << 20

type CpythonSemantics = Literal["exact", "thresholded"]
type CpythonLockKind = Literal["condition", "mutex", "recursive_mutex", "semaphore"]
type CpythonEventKind = Literal["wait_begin", "wait_end", "acquire", "release"]
type CpythonResult = Literal["unknown", "acquired", "notified", "timed_out", "released"]

PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
Timestamp = Annotated[StrictInt, Field(ge=0, le=_MAX_TIME_NS)]


class _StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class _Header(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["cpython_header"]
    protocol: Literal["cpython_threading_probe"]
    protocol_version: Literal["1.0"]
    runtime_version: StrictStr = Field(pattern=r"^(3\.12|3\.13)\.[0-9]+(?:[+._-][A-Za-z0-9._-]+)?$")
    free_threaded: StrictBool
    pid: PositiveInt
    uid: NonNegativeInt
    target_start_time_ticks: PositiveInt
    semantics: CpythonSemantics
    duration_threshold_ns: Timestamp | None
    max_events: PositiveInt
    visible_lock_kinds: tuple[CpythonLockKind, ...]


class _Frame(_StrictRecord):
    symbol: StrictStr = Field(min_length=1, max_length=4096)
    module: Literal["python"]
    source_file: StrictStr = Field(min_length=1, max_length=4096)
    source_line: PositiveInt
    is_runtime: Literal[False]
    is_unknown: Literal[False]


class _Stack(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["cpython_stack"]
    stack_id: StrictStr = Field(pattern=r"^stack-[1-9][0-9]{0,19}$")
    frames: tuple[_Frame, ...] = Field(min_length=1, max_length=32)


class _Event(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["cpython_event"]
    sequence: PositiveInt
    source_event_id: StrictStr = Field(pattern=r"^event-[1-9][0-9]{0,19}$")
    event_kind: CpythonEventKind
    timestamp_ns: Timestamp
    pid: PositiveInt
    tid: PositiveInt
    raw_lock_token: StrictStr = Field(pattern=r"^lock-[1-9][0-9]{0,19}$")
    lock_kind: CpythonLockKind
    related_source_event_id: StrictStr | None = Field(
        default=None, pattern=r"^event-[1-9][0-9]{0,19}$"
    )
    duration_ns: Timestamp | None
    result: CpythonResult
    stack_id: StrictStr | None = Field(default=None, pattern=r"^stack-[1-9][0-9]{0,19}$")


class _Footer(_StrictRecord):
    schema_version: Literal["1.0"]
    record_type: Literal["cpython_footer"]
    protocol: Literal["cpython_threading_probe"]
    pid: PositiveInt
    sequence: NonNegativeInt
    declared_event_count: NonNegativeInt
    lost_event_count: NonNegativeInt
    truncated: StrictBool
    observed_target_tids: tuple[PositiveInt, ...]


@dataclass(frozen=True, slots=True)
class CpythonThreadingConversionReceipt:
    evidence: RuntimeLockEvidenceArtifact
    raw_source_sha256: str
    raw_source_bytes: int
    normalized_source_sha256: str
    normalized_source_bytes: int


def convert_cpython_threading_stream(
    stream: BinaryIO,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    limits: RuntimeLockResourceLimits | None = None,
    created_at: str | None = None,
) -> CpythonThreadingConversionReceipt:
    """Convert one bounded cooperative stream without exposing object addresses."""

    limits = limits or RuntimeLockResourceLimits(max_input_records=_MAX_EVENTS)
    created = _created_at(created_at)
    binding = _validate_binding(execution_binding)
    digest = hashlib.sha256()
    raw_bytes = 0
    line_number = 0
    header: _Header | None = None
    footer: _Footer | None = None
    stacks: dict[str, _Stack] = {}
    events: list[_Event] = []
    seen_ids: set[str] = set()
    open_waits: dict[tuple[int, str, str], list[_Event]] = {}
    wait_end_by_id: dict[str, _Event] = {}

    while True:
        raw_line = _readline(stream, limits.max_line_bytes)
        if raw_line == b"":
            break
        line_number += 1
        raw_bytes += len(raw_line)
        if raw_bytes > limits.max_source_bytes:
            raise _limit("CPython threading source exceeds max_source_bytes")
        digest.update(raw_line)
        raw = _json_line(raw_line, line_number)
        kind = raw.get("record_type")
        if header is None:
            if kind != "cpython_header":
                raise _invalid("CPython threading header must be first")
            header = _model(_Header, raw, "header")
            _validate_header(header, binding, limits)
            continue
        if footer is not None:
            raise _invalid("CPython threading stream contains data after its footer")
        if kind == "cpython_stack":
            stack = _model(_Stack, raw, "stack")
            if stack.stack_id in stacks:
                raise _invalid("CPython threading stream repeats a stack identity")
            if len(stacks) >= limits.max_unique_stacks:
                raise _limit("CPython threading stream exceeds max_unique_stacks")
            stacks[stack.stack_id] = stack
            continue
        if kind == "cpython_event":
            event = _model(_Event, raw, "event")
            if len(events) >= min(header.max_events, limits.max_input_records):
                raise _limit("CPython threading stream exceeds its event budget")
            if (
                event.sequence != len(events) + 1
                or event.source_event_id != f"event-{event.sequence}"
            ):
                raise _invalid("CPython threading event sequence is not contiguous")
            if event.source_event_id in seen_ids or event.pid != header.pid:
                raise _invalid("CPython threading event escaped or duplicated its target")
            if event.stack_id is not None and event.stack_id not in stacks:
                raise _invalid("CPython threading event references an unknown stack")
            _validate_event(event, header, open_waits, wait_end_by_id)
            seen_ids.add(event.source_event_id)
            if event.event_kind == "wait_end":
                wait_end_by_id[event.source_event_id] = event
            events.append(event)
            continue
        if kind == "cpython_footer":
            footer = _model(_Footer, raw, "footer")
            continue
        raise _invalid("CPython threading stream contains an unknown record type")

    if header is None or footer is None:
        raise _invalid("CPython threading stream is missing its header or footer")
    if (
        footer.pid != header.pid
        or footer.sequence != len(events)
        or footer.declared_event_count != len(events)
        or tuple(sorted(set(footer.observed_target_tids))) != footer.observed_target_tids
        or header.pid not in footer.observed_target_tids
    ):
        raise _invalid("CPython threading footer contradicts the converted stream")
    if header.semantics == "exact" and not footer.truncated and any(open_waits.values()):
        raise _invalid("complete exact CPython evidence has an incomplete wait pair")
    if footer.truncated and not events:
        raise _invalid("truncated CPython evidence must retain at least one event")

    raw_sha256 = digest.hexdigest()
    with SpooledTemporaryFile(max_size=_SPOOL_MEMORY_BYTES, mode="w+b") as normalized:
        normalized_io = cast(BinaryIO, normalized)
        _write(
            normalized_io,
            {
                "schema_version": "1.1",
                "record_type": "runtime_lock_header",
                "runtime": "python",
                "runtime_version": header.runtime_version,
                "adapter_id": "cpython_threading",
                "adapter_version": binding.adapter_version,
                "backend_id": "threading-bootstrap",
                "backend_version": f"{binding.adapter_version}+raw.{raw_sha256[:16]}",
                "target": {
                    "target_pid": header.pid,
                    "target_uid": header.uid,
                    "target_start_time_ticks": header.target_start_time_ticks,
                    "observed_target_tids": list(footer.observed_target_tids),
                    "target_kind": "host",
                },
                "clock": {
                    "clock": "monotonic",
                    "unit": "nanoseconds",
                    "epoch_correlation_available": False,
                },
                "measurement_semantics": header.semantics,
                "visible_lock_kinds": list(header.visible_lock_kinds),
                "fast_path_visibility": "complete" if header.semantics == "exact" else "partial",
                "owner_is_source_observed": False,
                "hold_time_is_source_observed": False,
                "duration_threshold_ns": header.duration_threshold_ns,
                "declared_event_count": len(events),
                "declared_lost_event_count": footer.lost_event_count,
                "declared_truncated": footer.truncated,
            },
        )
        for stack in stacks.values():
            _write(
                normalized_io,
                {
                    "schema_version": "1.1",
                    "record_type": "runtime_lock_stack",
                    "source_stack_id": stack.stack_id,
                    "frames": [frame.model_dump(mode="json") for frame in stack.frames],
                },
            )
        for event in sorted(events, key=lambda item: (item.timestamp_ns, item.sequence)):
            _write(normalized_io, _normalized_event(event))
        normalized_bytes = normalized_io.tell()
        if normalized_bytes > limits.max_source_bytes:
            raise _limit("normalized CPython threading evidence exceeds max_source_bytes")
        normalized_io.seek(0)
        normalized_sha256 = _stream_sha256(normalized_io)
        normalized_io.seek(0)
        imported = import_runtime_lock_ndjson(normalized_io, limits=limits, created_at=created)

    evidence = _rebind_source(
        imported,
        binding=binding,
        header=header,
        raw_source_sha256=raw_sha256,
        raw_source_bytes=raw_bytes,
    )
    validate_runtime_lock_evidence_invariants(evidence)
    return CpythonThreadingConversionReceipt(
        evidence=evidence,
        raw_source_sha256=raw_sha256,
        raw_source_bytes=raw_bytes,
        normalized_source_sha256=normalized_sha256,
        normalized_source_bytes=normalized_bytes,
    )


def verify_cpython_threading_replay(
    expected: RuntimeLockEvidenceArtifact,
    stream: BinaryIO,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
) -> bool:
    if expected.source.source_format != "cpython_threading_ndjson_v1":
        raise _invalid("Runtime Lock evidence is not a CPython threading stream")
    return (
        convert_cpython_threading_stream(
            stream,
            execution_binding=execution_binding,
            limits=expected.limits,
            created_at=expected.created_at,
        ).evidence
        == expected
    )


def _validate_binding(
    binding: RuntimeLockAdapterExecutionBinding,
) -> RuntimeLockAdapterExecutionBinding:
    try:
        binding = RuntimeLockAdapterExecutionBinding.model_validate(binding.model_dump(mode="json"))
    except ValueError:
        raise _invalid("CPython execution binding failed deterministic validation") from None
    if (
        binding.adapter_id != "cpython_threading"
        or binding.adapter_version != "cpython-threading-adapter-v1"
        or binding.backend_id != "threading-bootstrap"
        or binding.measurement_semantics not in {"exact", "thresholded"}
        or len(binding.tools) != 1
        or binding.tools[0].name != "python"
    ):
        raise _invalid("CPython converter requires one authorized execution binding")
    return binding


def _validate_header(
    header: _Header,
    binding: RuntimeLockAdapterExecutionBinding,
    limits: RuntimeLockResourceLimits,
) -> None:
    expected_threshold = 10_000 if header.semantics == "thresholded" else None
    if (
        header.semantics != binding.measurement_semantics
        or header.duration_threshold_ns != expected_threshold
        or binding.duration_threshold_ns != expected_threshold
        or header.runtime_version != binding.runtime_version
        or header.max_events > min(_MAX_EVENTS, limits.max_input_records)
        or tuple(sorted(set(header.visible_lock_kinds))) != header.visible_lock_kinds
        or header.visible_lock_kinds != ("condition", "mutex", "recursive_mutex", "semaphore")
    ):
        raise _invalid("CPython header differs from the authorized execution controls")


def _validate_event(
    event: _Event,
    header: _Header,
    open_waits: dict[tuple[int, str, str], list[_Event]],
    wait_end_by_id: dict[str, _Event],
) -> None:
    subject = (event.tid, event.raw_lock_token, event.lock_kind)
    if event.event_kind == "wait_begin":
        if (
            event.related_source_event_id is not None
            or event.duration_ns is not None
            or event.result != "unknown"
        ):
            raise _invalid("CPython wait_begin fields are inconsistent")
        open_waits.setdefault(subject, []).append(event)
        return
    if event.event_kind == "wait_end":
        stack = open_waits.get(subject)
        if (
            not stack
            or stack[-1].source_event_id != event.related_source_event_id
            or event.duration_ns is None
        ):
            raise _invalid("CPython wait pair violates thread-local LIFO order")
        begin = stack[-1]
        begin_sequence = int(cast(str, event.related_source_event_id).split("-", 1)[1])
        if (
            begin_sequence >= event.sequence
            or event.timestamp_ns < begin.timestamp_ns
            or event.duration_ns != event.timestamp_ns - begin.timestamp_ns
        ):
            raise _invalid("CPython wait pair has impossible timing")
        if header.semantics == "thresholded" and event.duration_ns < 10_000:
            raise _invalid("CPython thresholded wait is below 10 microseconds")
        if event.result not in {"acquired", "notified", "timed_out"}:
            raise _invalid("CPython wait outcome is unsupported")
        stack.pop()
        return
    if event.event_kind == "acquire":
        related = wait_end_by_id.get(cast(str, event.related_source_event_id))
        if (
            related is None
            or related.result != "acquired"
            or related.tid != event.tid
            or related.raw_lock_token != event.raw_lock_token
            or related.lock_kind != event.lock_kind
            or event.duration_ns is not None
            or event.result != "acquired"
        ):
            raise _invalid("CPython acquire does not reference a successful wait")
        return
    if (
        event.related_source_event_id is not None
        or event.duration_ns is not None
        or event.result != "released"
    ):
        raise _invalid("CPython release fabricated pairing or hold time")


def _normalized_event(event: _Event) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": "1.1",
        "record_type": "runtime_lock_event",
        "source_event_id": event.source_event_id,
        "event_kind": event.event_kind,
        "timestamp_ns": event.timestamp_ns,
        "execution_context": {
            "kind": "os_thread",
            "target_pid": event.pid,
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
        record["wait_end_source_event_id"] = event.related_source_event_id
    elif event.event_kind == "release":
        record.update({"acquire_source_event_id": None, "hold_duration_ns": None})
    return record


def _rebind_source(
    imported: RuntimeLockEvidenceArtifact,
    *,
    binding: RuntimeLockAdapterExecutionBinding,
    header: _Header,
    raw_source_sha256: str,
    raw_source_bytes: int,
) -> RuntimeLockEvidenceArtifact:
    seed = canonical_runtime_lock_json_sha256(
        {
            "domain": "perflens.cpython-threading-evidence-id.v1",
            "raw_source_sha256": raw_source_sha256,
            "raw_source_bytes": raw_source_bytes,
            "created_at": imported.created_at,
            "target": imported.target,
            "converter_version": CPYTHON_THREADING_CONVERTER_VERSION,
            "execution_identity_sha256": binding.execution_identity_sha256,
            "limits": imported.limits,
        }
    )
    evidence_id = f"runtime-lock-evidence-{seed[:24]}"
    context_ids = {
        context.context_id: derive_runtime_execution_context_id(evidence_id, ordinal)
        for ordinal, context in enumerate(imported.execution_contexts)
    }
    stack_ids = {
        stack.stack_id: _opaque_id(evidence_id, "stack", ordinal)
        for ordinal, stack in enumerate(imported.stacks)
    }
    event_ids = {
        event.event_id: _opaque_id(evidence_id, "event", ordinal)
        for ordinal, event in enumerate(imported.events)
    }
    old_locks = tuple(
        dict.fromkeys(event.lock_id for event in imported.events if event.lock_id is not None)
    )
    lock_ids = {
        lock_id: derive_runtime_lock_id(evidence_id, ordinal)
        for ordinal, lock_id in enumerate(old_locks)
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
        for field in ("wait_begin_event_id", "wait_end_event_id", "acquire_event_id"):
            value = data.get(field)
            if isinstance(value, str):
                data[field] = event_ids[value]
        events.append(data)
    python_tool = binding.tools[0]
    source_provisional = RuntimeSourceManifest(
        schema_version="1.1",
        runtime="python",
        adapter_id="cpython_threading",
        adapter_version=binding.adapter_version,
        backend_id="threading-bootstrap",
        backend_version=binding.runtime_version,
        runtime_version=header.runtime_version,
        measurement_semantics=header.semantics,
        source_format="cpython_threading_ndjson_v1",
        converter_version=CPYTHON_THREADING_CONVERTER_VERSION,
        source_sha256=raw_source_sha256,
        source_bytes=raw_source_bytes,
        conversion_fingerprint="0" * 64,
        clock=RuntimeClock(clock="monotonic"),
        duration_threshold_ns=header.duration_threshold_ns,
        fast_path_visibility="complete" if header.semantics == "exact" else "partial",
        owner_is_source_observed=False,
        hold_time_is_source_observed=False,
        target_scope="bound_pid",
        tool=RuntimeToolIdentity(
            name="python",
            version=python_tool.version,
            path="python",
            binary_sha256=python_tool.binary_sha256,
            status="available",
        ),
        adapter_execution_identity_sha256=binding.execution_identity_sha256,
        configuration_sha256=binding.configuration_sha256,
        metadata_sha256=binding.metadata_sha256,
    )
    source = source_provisional.model_copy(
        update={
            "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(
                source_provisional
            )
        }
    )
    forbidden = tuple(
        dict.fromkeys(
            (
                *imported.forbidden_conclusions,
                "exact_owner_relationship",
                "exact_hold_time",
                "gil_contention",
                "cpython_internal_lock_behavior",
                "c_extension_lock_behavior",
                "unqualified_runtime_lock_conclusion",
                *(("traditional_gil_conclusion",) if header.free_threaded else ()),
            )
        )
    )
    limitations = tuple(
        dict.fromkeys(
            (
                *imported.quality.limitations,
                "Only public threading.Lock, RLock, Condition, and Semaphore constructors "
                "used after bootstrap installation are visible.",
                "GIL, CPython internal locks, C-extension locks, and custom _thread objects "
                "are not observed.",
                *(
                    (
                        "This is a free-threaded CPython build; traditional GIL conclusions "
                        "are forbidden.",
                    )
                    if header.free_threaded
                    else ("No source-observed GIL event surface is available.",)
                ),
            )
        )
    )
    provisional = RuntimeLockEvidenceArtifact.model_validate(
        {
            **imported.model_dump(mode="json", exclude_unset=True),
            "runtime_lock_evidence_id": evidence_id,
            "source": source.model_dump(mode="json", exclude_none=True),
            "quality": imported.quality.model_copy(
                update={"status": "partial", "limitations": limitations}
            ).model_dump(mode="json"),
            "execution_contexts": [
                value.model_dump(mode="json", exclude_none=True) for value in contexts
            ],
            "stacks": [value.model_dump(mode="json", exclude_none=True) for value in stacks],
            "events": events,
            "forbidden_conclusions": forbidden,
            "evidence_fingerprint": "0" * 64,
            "content_sha256": "0" * 64,
            "content_bytes": 1,
        }
    )
    fingerprinted = provisional.model_copy(
        update={"evidence_fingerprint": compute_runtime_lock_evidence_fingerprint(provisional)}
    )
    sized = _stable_size(fingerprinted)
    return RuntimeLockEvidenceArtifact.model_validate(
        {
            **sized.model_dump(mode="json", exclude_unset=True),
            "content_sha256": compute_runtime_lock_evidence_content_sha256(sized),
        }
    )


def _opaque_id(evidence_id: str, kind: str, ordinal: int) -> str:
    material = f"perflens.runtime-lock.{kind}.v1.1\0{evidence_id}\0{ordinal}"
    return f"runtime-{kind}-{hashlib.sha256(material.encode()).hexdigest()[:24]}"


def _stable_size(evidence: RuntimeLockEvidenceArtifact) -> RuntimeLockEvidenceArtifact:
    current = evidence
    for _ in range(8):
        actual = len(serialize_json(current))
        if actual == current.content_bytes:
            return current
        current = current.model_copy(update={"content_bytes": actual})
    raise _invalid("CPython Evidence byte identity did not converge")


def _created_at(value: str | None) -> str:
    candidate = value or datetime.now(tz=UTC).isoformat()
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        raise _invalid("CPython Evidence creation time is invalid") from None
    if parsed.tzinfo is None:
        raise _invalid("CPython Evidence creation time lacks a timezone")
    return parsed.isoformat()


def _readline(stream: BinaryIO, maximum: int) -> bytes:
    try:
        line = stream.readline(maximum + 1)
    except (OSError, TypeError, ValueError):
        raise _invalid("CPython threading source could not be read") from None
    if len(line) > maximum:
        raise _limit("CPython threading source contains an oversized line")
    return line


def _json_line(line: bytes, number: int) -> dict[str, Any]:
    if not line.endswith(b"\n"):
        raise _invalid("CPython threading source violates NDJSON line boundaries")
    try:
        value = json.loads(
            line,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _invalid(f"CPython threading record {number} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _invalid(f"CPython threading record {number} is not an object")
    return cast(dict[str, Any], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _model[T: BaseModel](model: type[T], raw: dict[str, Any], label: str) -> T:
    try:
        return model.model_validate(raw)
    except (TypeError, ValueError, ValidationError):
        raise _invalid(f"CPython threading {label} failed strict validation") from None


def _write(stream: BinaryIO, value: object) -> None:
    stream.write(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        + b"\n"
    )


def _stream_sha256(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(64 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PROFILE_PARSE_FAILED, "cpython_threading_conversion", message)


def _limit(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "cpython_threading_conversion", message)
