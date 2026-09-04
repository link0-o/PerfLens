"""Strict streaming import for normalized user-space runtime-lock NDJSON.

The adapter consumes a caller-verified binary stream.  It deliberately has no
path API: import-root validation and descriptor ownership checks belong to the
CLI/session layer, while this module is the deterministic bytes-to-contract
boundary.  Raw event, lock, stack, and runtime-native identities are accepted
only as bounded source-local tokens and are replaced before any public
Artifact is built.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, BinaryIO, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

from perflens.application.runtime_lock_evidence import (
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
    validate_runtime_lock_evidence_invariants,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_locks import (
    RuntimeLockEvidenceArtifact,
    RuntimeLockImportHeader,
    RuntimeLockResourceLimits,
    RuntimeSourceManifest,
    derive_runtime_execution_context_id,
    derive_runtime_lock_id,
    derive_runtime_native_context_id,
    is_safe_runtime_public_label,
)
from perflens.domain.errors import ErrorCode, PerfLensError

RUNTIME_LOCK_NDJSON_PARSER_VERSION = "runtime-lock-ndjson-v1.1"
_OUTPUT_SCHEMA_VERSION = "1.1"
_MAX_TIME_NS = (1 << 63) - 1
_DIAGNOSTIC_SAMPLE_LIMIT = 64
_SOURCE_ID_PATTERN = r"^[^\x00\r\n/\\]{1,128}$"
_LABEL_PATTERN = r"^[^\x00\r\n]{1,4096}$"
_RAW_ADDRESS_PATTERN = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9a-fA-F]{8,32})$")
_CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"(?:^|[\s?&;,])"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"password|passwd|pwd|token|secret|client[_-]?secret|credentials?|authorization)"
    r"\s*(?:=|:\s+)\s*[^\s,;&]+",
    re.IGNORECASE,
)
_URI_USERINFO_PATTERN = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s/@]+(?::[^\s/@]*)?@",
    re.IGNORECASE,
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE,
)
_REDACTED_LABEL = "[redacted]"

type RuntimeFamily = Literal["c_cpp", "java", "python", "go", "custom"]
type MeasurementSemantics = Literal["exact", "thresholded", "sampled", "cumulative"]
type LockKind = Literal[
    "mutex",
    "recursive_mutex",
    "rwlock_read",
    "rwlock_write",
    "condition",
    "semaphore",
    "park",
    "gil",
    "runtime_internal",
    "channel",
    "wait_group",
    "custom",
    "unknown",
]
type EventKind = Literal[
    "wait_begin",
    "wait_end",
    "acquire",
    "release",
    "park",
    "unpark",
    "sampled_contention",
]
type ContextKind = Literal[
    "os_thread",
    "java_platform_thread",
    "java_virtual_thread",
    "go_goroutine",
    "process_aggregate",
]

BoundedToken = Annotated[StrictStr, Field(pattern=_SOURCE_ID_PATTERN)]
BoundedLabel = Annotated[StrictStr, Field(pattern=_LABEL_PATTERN)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
TimeNanoseconds = Annotated[StrictInt, Field(ge=0, le=_MAX_TIME_NS)]


class _StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class _RawContainerReference(_StrictRecord):
    container_target_id: Annotated[
        StrictStr,
        Field(pattern=r"^container-target-[a-f0-9]{20}$"),
    ]
    container_target_content_sha256: Annotated[StrictStr, Field(pattern=r"^[a-f0-9]{64}$")]
    container_run_id: Annotated[
        StrictStr,
        Field(pattern=r"^container-run-[a-f0-9]{20}$"),
    ]
    container_run_content_sha256: Annotated[StrictStr, Field(pattern=r"^[a-f0-9]{64}$")]
    container_identity_sha256: Annotated[StrictStr, Field(pattern=r"^[a-f0-9]{64}$")]
    target_identity_sha256: Annotated[StrictStr, Field(pattern=r"^[a-f0-9]{64}$")]
    cgroup_identity_sha256: Annotated[StrictStr, Field(pattern=r"^[a-f0-9]{64}$")]


class _RawTarget(_StrictRecord):
    target_pid: PositiveInt
    target_uid: NonNegativeInt
    target_start_time_ticks: PositiveInt
    observed_target_tids: tuple[PositiveInt, ...] = ()
    target_kind: Literal["host", "docker"] = "host"
    container_reference: _RawContainerReference | None = None

    @model_validator(mode="after")
    def validate_tids(self) -> _RawTarget:
        if tuple(sorted(set(self.observed_target_tids))) != self.observed_target_tids:
            raise ValueError("target TIDs must be sorted and unique")
        if (self.target_kind == "docker") != (self.container_reference is not None):
            raise ValueError("Docker target requires one complete container Artifact reference")
        return self


class _RawClock(_StrictRecord):
    clock: Literal["monotonic", "jfr_ticks", "profile_relative"]
    unit: Literal["nanoseconds"] = "nanoseconds"
    epoch_correlation_available: StrictBool = False


class _RawHeader(_StrictRecord):
    # The published v0.3.2 import-header contract made schema_version
    # optional with a 1.0 default.  Preserve that wire compatibility while
    # requiring every schema-1.1 producer to opt in explicitly.
    schema_version: Literal["1.0", "1.1"] = "1.0"
    record_type: Literal["runtime_lock_header"]
    runtime: RuntimeFamily
    runtime_version: Annotated[StrictStr, Field(min_length=1, max_length=256)]
    adapter_id: Annotated[
        StrictStr,
        Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$"),
    ]
    adapter_version: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    backend_id: Annotated[
        StrictStr,
        Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$"),
    ]
    backend_version: Annotated[StrictStr, Field(min_length=1, max_length=256)]
    target: _RawTarget
    clock: _RawClock
    measurement_semantics: MeasurementSemantics
    visible_lock_kinds: tuple[LockKind, ...]
    fast_path_visibility: Literal["complete", "partial", "none", "unknown"]
    owner_is_source_observed: StrictBool
    hold_time_is_source_observed: StrictBool
    duration_threshold_ns: TimeNanoseconds | None = None
    sampling_period: PositiveInt | None = None
    sampling_fraction: PositiveInt | None = None
    block_profile_rate_ns: PositiveInt | None = None
    declared_event_count: NonNegativeInt
    declared_lost_event_count: NonNegativeInt
    declared_truncated: StrictBool

    @model_validator(mode="after")
    def validate_complete_header(self) -> _RawHeader:
        required = {
            "record_type",
            "runtime",
            "runtime_version",
            "adapter_id",
            "adapter_version",
            "backend_id",
            "backend_version",
            "target",
            "clock",
            "measurement_semantics",
            "visible_lock_kinds",
            "fast_path_visibility",
            "owner_is_source_observed",
            "hold_time_is_source_observed",
            "declared_event_count",
            "declared_lost_event_count",
            "declared_truncated",
        }
        if not required.issubset(self.model_fields_set):
            raise ValueError("runtime lock header omitted a required field")
        target_fields = self.target.model_fields_set
        if self.schema_version == "1.0" and target_fields & {
            "target_kind",
            "container_reference",
        }:
            raise ValueError("schema 1.0 runtime target cannot carry Docker identity references")
        if self.schema_version == "1.1" and "target_kind" not in target_fields:
            raise ValueError("schema 1.1 runtime target requires an explicit target kind")
        if not self.visible_lock_kinds:
            raise ValueError("runtime lock header needs visible lock kinds")
        if tuple(sorted(set(self.visible_lock_kinds))) != self.visible_lock_kinds:
            raise ValueError("visible lock kinds must be sorted and unique")
        controls = (
            self.duration_threshold_ns,
            self.sampling_period,
            self.sampling_fraction,
            self.block_profile_rate_ns,
        )
        if self.measurement_semantics == "exact":
            valid = all(value is None for value in controls)
        elif self.measurement_semantics == "thresholded":
            valid = self.duration_threshold_ns is not None and all(
                value is None for value in controls[1:]
            )
        elif self.measurement_semantics == "sampled":
            valid = (
                self.duration_threshold_ns is None
                and self.block_profile_rate_ns is None
                and ((self.sampling_period is None) != (self.sampling_fraction is None))
            )
        else:
            valid = (
                self.duration_threshold_ns is None
                and sum(value is not None for value in controls[1:]) == 1
            )
        if not valid:
            raise ValueError("measurement controls contradict their semantics")
        if self.declared_truncated and self.declared_event_count == 0:
            raise ValueError("truncated stream must declare at least one event")
        for value in (
            self.runtime_version,
            self.adapter_version,
            self.backend_version,
        ):
            if _contains_sensitive_text(value, reject_path=True):
                raise ValueError("runtime lock header version identity is unsafe")
        return self


class _RawStackFrame(_StrictRecord):
    symbol: BoundedLabel
    module: BoundedLabel
    source_file: BoundedLabel | None = None
    source_line: PositiveInt | None = None
    is_runtime: StrictBool = False
    is_unknown: StrictBool = False

    @model_validator(mode="after")
    def validate_source(self) -> _RawStackFrame:
        if self.source_line is not None and self.source_file is None:
            raise ValueError("source line requires a source file")
        return self


class _RawStack(_StrictRecord):
    schema_version: Literal["1.0", "1.1"]
    record_type: Literal["runtime_lock_stack"]
    source_stack_id: BoundedToken
    frames: tuple[_RawStackFrame, ...]

    @model_validator(mode="after")
    def validate_stack(self) -> _RawStack:
        if not {
            "schema_version",
            "record_type",
            "source_stack_id",
            "frames",
        }.issubset(self.model_fields_set):
            raise ValueError("runtime stack omitted a required field")
        if not self.frames:
            raise ValueError("runtime stack must contain a frame")
        return self


class _RawExecutionContext(_StrictRecord):
    kind: ContextKind
    target_pid: PositiveInt
    target_tid: PositiveInt | None = None
    runtime_context_id: BoundedToken | None = None
    name: Annotated[StrictStr, Field(min_length=1, max_length=256)] | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> _RawExecutionContext:
        if self.kind == "os_thread":
            if self.target_tid is None or self.runtime_context_id is not None:
                raise ValueError("OS context shape is invalid")
        elif self.kind == "process_aggregate":
            if self.target_tid is not None or self.runtime_context_id is not None:
                raise ValueError("process aggregate shape is invalid")
        elif self.runtime_context_id is None:
            raise ValueError("runtime context requires a source-local identity")
        if self.kind in {"java_virtual_thread", "go_goroutine"} and self.target_tid is not None:
            raise ValueError("virtual runtime context cannot claim an OS TID")
        return self


class _RawEvent(_StrictRecord):
    schema_version: Literal["1.0", "1.1"]
    record_type: Literal["runtime_lock_event"]
    source_event_id: BoundedToken
    event_kind: EventKind
    timestamp_ns: TimeNanoseconds
    execution_context: _RawExecutionContext | None = None
    target_tid: PositiveInt | None = None
    source_lock_id: BoundedToken | None = None
    lock_kind: LockKind
    source_stack_id: BoundedToken | None = None
    owner_execution_context: _RawExecutionContext | None = None
    owner_target_tid: PositiveInt | None = None
    wait_begin_source_event_id: BoundedToken | None = None
    duration_ns: TimeNanoseconds | None = None
    outcome: (
        Literal[
            "acquired",
            "notified",
            "unparked",
            "timed_out",
            "interrupted",
            "failed",
            "unknown",
        ]
        | None
    ) = None
    wait_end_source_event_id: BoundedToken | None = None
    acquire_source_event_id: BoundedToken | None = None
    hold_duration_ns: TimeNanoseconds | None = None
    parked_execution_context: _RawExecutionContext | None = None
    parked_target_tid: PositiveInt | None = None
    observed_count: PositiveInt | None = None
    estimated_count: Annotated[StrictFloat | StrictInt, Field(gt=0)] | None = None
    cumulative_wait_ns: PositiveInt | None = None

    @model_validator(mode="after")
    def validate_event_fields(self) -> _RawEvent:
        required = {
            "schema_version",
            "record_type",
            "source_event_id",
            "event_kind",
            "timestamp_ns",
            "lock_kind",
        }
        if not required.issubset(self.model_fields_set):
            raise ValueError("runtime event omitted a required field")
        common = required | {"source_lock_id", "source_stack_id"}
        if self.schema_version == "1.1":
            if self.execution_context is None:
                raise ValueError("schema 1.1 event requires an execution context")
            common.add("execution_context")
        else:
            if self.target_tid is None:
                raise ValueError("schema 1.0 event requires target_tid")
            common.add("target_tid")
        specific: dict[EventKind, set[str]] = {
            "wait_begin": {
                "owner_execution_context" if self.schema_version == "1.1" else "owner_target_tid"
            },
            "wait_end": {
                "wait_begin_source_event_id",
                "duration_ns",
                "outcome",
                ("owner_execution_context" if self.schema_version == "1.1" else "owner_target_tid"),
            },
            "acquire": ({"wait_end_source_event_id"} if self.schema_version == "1.1" else set()),
            "release": {"acquire_source_event_id", "hold_duration_ns"},
            "park": set(),
            "unpark": {
                "parked_execution_context" if self.schema_version == "1.1" else "parked_target_tid"
            },
            "sampled_contention": {
                "observed_count",
                "estimated_count",
                "cumulative_wait_ns",
            },
        }
        if not self.model_fields_set.issubset(common | specific[self.event_kind]):
            raise ValueError("runtime event carries fields for another event kind or schema")
        requires_lock_identity = self.event_kind in {"wait_begin", "acquire", "release"} or (
            self.event_kind == "wait_end" and self.wait_begin_source_event_id is not None
        )
        if requires_lock_identity and self.source_lock_id is None:
            raise ValueError("paired runtime event requires a source-local lock identity")
        if self.event_kind == "wait_end" and (self.duration_ns is None or self.outcome is None):
            raise ValueError("wait completion requires its duration and outcome")
        if self.event_kind == "unpark" and (
            (self.schema_version == "1.1" and self.parked_execution_context is None)
            or (self.schema_version == "1.0" and self.parked_target_tid is None)
        ):
            raise ValueError("unpark requires the parked execution context")
        if self.event_kind == "sampled_contention" and (
            self.observed_count is None or self.cumulative_wait_ns is None
        ):
            raise ValueError("sampled contention requires count and cumulative wait")
        if (
            self.event_kind == "sampled_contention"
            and self.cumulative_wait_ns is not None
            and self.cumulative_wait_ns > _MAX_TIME_NS
        ):
            raise ValueError("cumulative wait exceeds the time representation")
        return self


@dataclass(frozen=True, slots=True)
class _ContextKey:
    kind: ContextKind
    target_pid: int
    target_tid: int | None
    source_runtime_context_id: str | None


@dataclass(frozen=True, slots=True)
class _ParsedStack:
    source_id: str
    ordinal: int
    frames: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class _ParsedEvent:
    source_id: str
    event_kind: EventKind
    timestamp_ns: int
    context: _ContextKey
    owner_context: _ContextKey | None
    parked_context: _ContextKey | None
    source_lock_id: str | None
    lock_ordinal: int | None
    lock_kind: LockKind
    stack_ordinal: int | None
    pair_public_source_id: str | None
    wait_end_public_source_id: str | None
    duration_ns: int | None
    outcome: str | None
    observed_count: int | None
    estimated_count: float | int | None
    cumulative_wait_ns: int | None


@dataclass(frozen=True, slots=True)
class _Diagnostic:
    code: str
    line_number: int
    message: str

    def public_text(self) -> str:
        return f"{self.code} at line {self.line_number}: {self.message}"


class RuntimeLockNdjsonImporter:
    """Consume one bounded NDJSON stream and return schema-1.1 Evidence."""

    def __init__(
        self,
        *,
        limits: RuntimeLockResourceLimits | None = None,
        created_at: str | None = None,
    ) -> None:
        self._limits = limits or RuntimeLockResourceLimits()
        self._created_at = _normalize_created_at(created_at or datetime.now(tz=UTC).isoformat())

    def import_stream(self, stream: BinaryIO) -> RuntimeLockEvidenceArtifact:
        state = _ImportState(limits=self._limits)
        digest = hashlib.sha256()
        total_bytes = 0
        line_number = 0
        max_records = 1 + self._limits.max_input_records + self._limits.max_unique_stacks
        while True:
            try:
                raw_line = stream.readline(self._limits.max_line_bytes + 1)
            except (OSError, ValueError, TypeError):
                raise _invalid("Runtime-lock input could not be read as a binary stream") from None
            if raw_line == b"":
                break
            line_number += 1
            total_bytes += len(raw_line)
            if total_bytes > self._limits.max_source_bytes:
                raise _limit("Runtime-lock input exceeds max_source_bytes")
            if line_number > max_records:
                raise _limit("Runtime-lock input exceeds the bounded record count")
            if len(raw_line) > self._limits.max_line_bytes:
                raise _limit("Runtime-lock input contains an oversized line")
            digest.update(raw_line)
            state.consume(raw_line, line_number=line_number)
        if total_bytes == 0:
            raise _invalid("Runtime-lock input is empty")
        return state.finish(
            source_sha256=digest.hexdigest(),
            source_bytes=total_bytes,
            created_at=self._created_at,
        )


def import_runtime_lock_ndjson(
    stream: BinaryIO,
    *,
    limits: RuntimeLockResourceLimits | None = None,
    created_at: str | None = None,
) -> RuntimeLockEvidenceArtifact:
    """Convenience wrapper around :class:`RuntimeLockNdjsonImporter`."""

    return RuntimeLockNdjsonImporter(limits=limits, created_at=created_at).import_stream(stream)


class _ImportState:
    def __init__(self, *, limits: RuntimeLockResourceLimits) -> None:
        self.limits = limits
        self.header: _RawHeader | None = None
        self.public_header: RuntimeLockImportHeader | None = None
        self.seen_event = False
        self.stack_records = 0
        self.malformed_stacks = 0
        self.duplicate_stacks = 0
        self.truncated_stacks = 0
        self.input_events = 0
        self.malformed_events = 0
        self.duplicate_events = 0
        self.out_of_order_events = 0
        self.unsupported_events = 0
        self.filtered_events = 0
        self.diagnostic_count = 0
        self.diagnostics: list[_Diagnostic] = []
        self.diagnostics_capped = False
        self.last_timestamp_ns: int | None = None
        self.stacks: dict[str, _ParsedStack] = {}
        self.seen_event_ids: set[str] = set()
        self.events: list[_ParsedEvent] = []
        self.events_by_source_id: dict[str, _ParsedEvent] = {}
        self.lock_ordinals: dict[str, int] = {}
        self.context_ordinals: dict[_ContextKey, int] = {}

    def consume(self, raw_line: bytes, *, line_number: int) -> None:
        if not raw_line.endswith(b"\n"):
            if self.header is None:
                raise _invalid("Runtime-lock header violates the NDJSON line boundary")
            self.input_events += 1
            self.malformed_events += 1
            self._diagnose(
                "INVALID_LINE_BOUNDARY",
                line_number,
                "runtime event does not end with a newline",
            )
            return
        try:
            payload = json.loads(
                raw_line,
                object_pairs_hook=_without_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            if self.header is None:
                raise _invalid("Runtime-lock header is not strict JSON") from None
            self.input_events += 1
            self.malformed_events += 1
            self._diagnose("INVALID_JSON", line_number, "runtime record is not strict JSON")
            return
        if not isinstance(payload, dict):
            if self.header is None:
                raise _invalid("Runtime-lock header must be a JSON object")
            self.input_events += 1
            self.malformed_events += 1
            self._diagnose("INVALID_RECORD", line_number, "runtime record must be an object")
            return
        raw = cast(dict[str, Any], payload)
        record_type = raw.get("record_type")
        if self.header is None:
            self._consume_header(raw)
        elif record_type == "runtime_lock_header":
            raise _invalid("Runtime-lock input contains a duplicate header")
        elif record_type == "runtime_lock_stack":
            self._consume_stack(raw, line_number=line_number)
        elif record_type == "runtime_lock_event":
            self._consume_event(raw, line_number=line_number)
        else:
            self.input_events += 1
            self.unsupported_events += 1
            self._diagnose(
                "UNSUPPORTED_RECORD",
                line_number,
                "runtime record_type is not supported",
            )

    def _consume_header(self, raw: dict[str, Any]) -> None:
        if raw.get("record_type") != "runtime_lock_header":
            raise _invalid("Runtime-lock header must be the first record")
        try:
            header = _RawHeader.model_validate(raw)
            public_header = RuntimeLockImportHeader.model_validate(
                header.model_dump(mode="json", exclude_unset=True)
            )
        except (TypeError, ValueError, ValidationError):
            raise _invalid("Runtime-lock header failed strict validation") from None
        if header.declared_event_count > self.limits.max_input_records:
            raise _limit("Runtime-lock header declares too many events")
        if len(header.target.observed_target_tids) > self.limits.max_unique_target_tids:
            raise _limit("Runtime-lock header declares too many target TIDs")
        self.header = header
        self.public_header = public_header

    def _consume_stack(self, raw: dict[str, Any], *, line_number: int) -> None:
        self.stack_records += 1
        if self.stack_records > self.limits.max_unique_stacks:
            raise _limit("Runtime-lock input exceeds max_unique_stacks records")
        if self.seen_event:
            self.malformed_stacks += 1
            self._diagnose(
                "STACK_AFTER_EVENT",
                line_number,
                "runtime stack records must precede event records",
            )
            return
        try:
            stack = _RawStack.model_validate(raw)
        except (TypeError, ValueError, ValidationError):
            self.malformed_stacks += 1
            self._diagnose(
                "INVALID_STACK",
                line_number,
                "runtime stack failed strict validation",
            )
            return
        assert self.header is not None
        if stack.schema_version != self.header.schema_version:
            self.malformed_stacks += 1
            self._diagnose(
                "SCHEMA_MISMATCH",
                line_number,
                "runtime stack schema differs from the header",
            )
            return
        if stack.source_stack_id in self.stacks:
            self.duplicate_stacks += 1
            self._diagnose(
                "DUPLICATE_STACK_ID",
                line_number,
                "runtime stack source identity is duplicated",
            )
            return
        if len(stack.frames) > self.limits.max_stack_depth:
            self.truncated_stacks += 1
            self._diagnose(
                "STACK_DEPTH_EXCEEDED",
                line_number,
                "runtime stack exceeds max_stack_depth",
            )
            return
        frames = tuple(_public_frame(frame) for frame in stack.frames)
        self.stacks[stack.source_stack_id] = _ParsedStack(
            source_id=stack.source_stack_id,
            ordinal=len(self.stacks),
            frames=frames,
        )

    def _consume_event(self, raw: dict[str, Any], *, line_number: int) -> None:
        self.seen_event = True
        self.input_events += 1
        if self.input_events > self.limits.max_input_records:
            raise _limit("Runtime-lock input exceeds max_input_records")
        event_kind = raw.get("event_kind")
        if event_kind not in {
            "wait_begin",
            "wait_end",
            "acquire",
            "release",
            "park",
            "unpark",
            "sampled_contention",
        }:
            self.unsupported_events += 1
            self._diagnose(
                "UNSUPPORTED_EVENT",
                line_number,
                "runtime event_kind is not supported",
            )
            return
        try:
            event = _RawEvent.model_validate(raw)
        except (TypeError, ValueError, ValidationError):
            self.malformed_events += 1
            self._diagnose(
                "INVALID_EVENT",
                line_number,
                "runtime event failed strict validation",
            )
            return
        assert self.header is not None
        if event.schema_version != self.header.schema_version:
            self.malformed_events += 1
            self._diagnose(
                "SCHEMA_MISMATCH",
                line_number,
                "runtime event schema differs from the header",
            )
            return
        # Resolve the complete target identity before mutating any target-local
        # duplicate/order state.  A foreign event must be dispositioned as
        # filtered evidence only; otherwise its source ID or timestamp could
        # poison later authorized records.
        try:
            context = self._event_context(event)
            owner_context = self._owner_context(event)
            parked_context = self._parked_context(event)
        except _OutsideTarget:
            self.filtered_events += 1
            self._diagnose(
                "OUTSIDE_TARGET_CONTEXT",
                line_number,
                "runtime event context is outside the bound target",
            )
            return
        except ValueError:
            self.malformed_events += 1
            self._diagnose(
                "INVALID_CONTEXT",
                line_number,
                "runtime event context is incompatible with its runtime",
            )
            return
        if event.source_event_id in self.seen_event_ids:
            self.duplicate_events += 1
            self._diagnose(
                "DUPLICATE_EVENT_ID",
                line_number,
                "runtime event source identity is duplicated",
            )
            return
        if self.last_timestamp_ns is not None and event.timestamp_ns < self.last_timestamp_ns:
            self.out_of_order_events += 1
            self._diagnose(
                "OUT_OF_ORDER_EVENT",
                line_number,
                "runtime event timestamp is out of order",
            )
            return
        if event.lock_kind not in self.header.visible_lock_kinds:
            self.unsupported_events += 1
            self._diagnose(
                "UNDECLARED_LOCK_KIND",
                line_number,
                "runtime event uses an undeclared lock kind",
            )
            return
        if event.event_kind == "sampled_contention" and (
            self.header.measurement_semantics not in {"sampled", "cumulative"}
        ):
            self.unsupported_events += 1
            self._diagnose(
                "SEMANTICS_MISMATCH",
                line_number,
                "sampled contention contradicts the source semantics",
            )
            return
        if event.event_kind != "sampled_contention" and (
            self.header.measurement_semantics in {"sampled", "cumulative"}
        ):
            self.unsupported_events += 1
            self._diagnose(
                "SEMANTICS_MISMATCH",
                line_number,
                "event stream contradicts sampled or cumulative semantics",
            )
            return
        if event.source_stack_id is not None and event.source_stack_id not in self.stacks:
            self.malformed_events += 1
            self._diagnose(
                "UNKNOWN_STACK_ID",
                line_number,
                "runtime event references an unknown stack",
            )
            return
        if owner_context is not None and not self.header.owner_is_source_observed:
            self.malformed_events += 1
            self._diagnose(
                "OWNER_VISIBILITY_MISMATCH",
                line_number,
                "runtime event claims undeclared owner visibility",
            )
            return
        pair = self._paired_event(event, context=context)
        if pair is False:
            self.malformed_events += 1
            self._diagnose(
                "INVALID_EVENT_PAIR",
                line_number,
                "runtime event pair is missing or inconsistent",
            )
            return
        pair_event = pair if isinstance(pair, _ParsedEvent) else None
        if event.event_kind == "release":
            paired_hold = (
                event.acquire_source_event_id is not None and event.hold_duration_ns is not None
            )
            if paired_hold != self.header.hold_time_is_source_observed:
                self.malformed_events += 1
                self._diagnose(
                    "HOLD_VISIBILITY_MISMATCH",
                    line_number,
                    "runtime release contradicts declared hold visibility",
                )
                return
        lock_ordinal = self._lock_ordinal(event.source_lock_id)
        stack_ordinal = (
            self.stacks[event.source_stack_id].ordinal
            if event.source_stack_id is not None
            else None
        )
        parsed = _ParsedEvent(
            source_id=event.source_event_id,
            event_kind=event.event_kind,
            timestamp_ns=event.timestamp_ns,
            context=context,
            owner_context=owner_context,
            parked_context=parked_context,
            source_lock_id=event.source_lock_id,
            lock_ordinal=lock_ordinal,
            lock_kind=event.lock_kind,
            stack_ordinal=stack_ordinal,
            pair_public_source_id=(
                pair_event.source_id
                if event.event_kind in {"wait_end", "release"} and pair_event is not None
                else None
            ),
            wait_end_public_source_id=(
                pair_event.source_id
                if event.event_kind == "acquire" and pair_event is not None
                else None
            ),
            duration_ns=(
                event.duration_ns if event.event_kind == "wait_end" else event.hold_duration_ns
            ),
            outcome=event.outcome,
            observed_count=event.observed_count,
            estimated_count=event.estimated_count,
            cumulative_wait_ns=event.cumulative_wait_ns,
        )
        # Commit duplicate/order state only after every acceptance check has
        # passed.  A rejected record is not part of the normalized target
        # stream and therefore must not reserve its source identity or advance
        # the timestamp watermark for a later authorized record.
        self.seen_event_ids.add(event.source_event_id)
        self.last_timestamp_ns = event.timestamp_ns
        self.events.append(parsed)
        self.events_by_source_id[event.source_event_id] = parsed
        for item in (context, owner_context, parked_context):
            if item is not None:
                self._context_ordinal(item)

    def _event_context(self, event: _RawEvent) -> _ContextKey:
        assert self.header is not None
        if event.schema_version == "1.0":
            assert event.target_tid is not None
            raw = _RawExecutionContext(
                kind="os_thread",
                target_pid=self.header.target.target_pid,
                target_tid=event.target_tid,
            )
        else:
            assert event.execution_context is not None
            raw = event.execution_context
        return self._context_key(raw)

    def _owner_context(self, event: _RawEvent) -> _ContextKey | None:
        assert self.header is not None
        if event.schema_version == "1.0" and event.owner_target_tid is not None:
            return self._context_key(
                _RawExecutionContext(
                    kind="os_thread",
                    target_pid=self.header.target.target_pid,
                    target_tid=event.owner_target_tid,
                )
            )
        if event.owner_execution_context is not None:
            return self._context_key(event.owner_execution_context)
        return None

    def _parked_context(self, event: _RawEvent) -> _ContextKey | None:
        assert self.header is not None
        if event.schema_version == "1.0" and event.parked_target_tid is not None:
            return self._context_key(
                _RawExecutionContext(
                    kind="os_thread",
                    target_pid=self.header.target.target_pid,
                    target_tid=event.parked_target_tid,
                )
            )
        if event.parked_execution_context is not None:
            return self._context_key(event.parked_execution_context)
        return None

    def _context_key(self, raw: _RawExecutionContext) -> _ContextKey:
        assert self.header is not None
        target = self.header.target
        if raw.target_pid != target.target_pid:
            raise _OutsideTarget
        if raw.target_tid is not None and raw.target_tid not in target.observed_target_tids:
            raise _OutsideTarget
        allowed: dict[RuntimeFamily, set[ContextKind]] = {
            "c_cpp": {"os_thread", "process_aggregate"},
            "java": {
                "os_thread",
                "java_platform_thread",
                "java_virtual_thread",
                "process_aggregate",
            },
            "python": {"os_thread", "process_aggregate"},
            "go": {"os_thread", "go_goroutine", "process_aggregate"},
            "custom": {
                "os_thread",
                "java_platform_thread",
                "java_virtual_thread",
                "go_goroutine",
                "process_aggregate",
            },
        }
        if raw.kind not in allowed[self.header.runtime]:
            raise ValueError("runtime context kind is incompatible")
        if raw.kind == "process_aggregate" and self.header.measurement_semantics not in {
            "sampled",
            "cumulative",
        }:
            raise ValueError("event stream cannot use an aggregate context")
        return _ContextKey(
            kind=raw.kind,
            target_pid=raw.target_pid,
            target_tid=raw.target_tid,
            source_runtime_context_id=raw.runtime_context_id,
        )

    def _paired_event(
        self,
        event: _RawEvent,
        *,
        context: _ContextKey,
    ) -> _ParsedEvent | bool | None:
        reference: str | None
        expected_kind: EventKind | None
        duration: int | None
        if event.event_kind == "wait_end":
            reference = event.wait_begin_source_event_id
            expected_kind = "wait_begin"
            duration = event.duration_ns
        elif event.event_kind == "acquire":
            reference = event.wait_end_source_event_id
            expected_kind = "wait_end" if reference is not None else None
            duration = None
        elif event.event_kind == "release":
            reference = event.acquire_source_event_id
            expected_kind = "acquire" if reference is not None else None
            duration = event.hold_duration_ns
            if (reference is None) != (duration is None):
                return False
        else:
            return None
        if expected_kind is None:
            return None
        if reference is None:
            return (
                None
                if event.event_kind == "wait_end"
                and self.header is not None
                and self.header.measurement_semantics == "thresholded"
                else False
            )
        pair = self.events_by_source_id.get(reference)
        if (
            pair is None
            or pair.event_kind != expected_kind
            or pair.context != context
            or pair.source_lock_id != event.source_lock_id
            or pair.lock_kind != event.lock_kind
            or pair.timestamp_ns > event.timestamp_ns
        ):
            return False
        if duration is not None and duration != event.timestamp_ns - pair.timestamp_ns:
            return False
        if event.event_kind == "acquire" and pair.outcome != "acquired":
            return False
        return pair

    def _lock_ordinal(self, source_lock_id: str | None) -> int | None:
        if source_lock_id is None:
            return None
        existing = self.lock_ordinals.get(source_lock_id)
        if existing is not None:
            return existing
        if len(self.lock_ordinals) >= self.limits.max_unique_locks:
            raise _limit("Runtime-lock input exceeds max_unique_locks")
        ordinal = len(self.lock_ordinals)
        self.lock_ordinals[source_lock_id] = ordinal
        return ordinal

    def _context_ordinal(self, context: _ContextKey) -> int:
        existing = self.context_ordinals.get(context)
        if existing is not None:
            return existing
        if len(self.context_ordinals) >= self.limits.max_unique_target_tids:
            raise _limit("Runtime-lock input exceeds the execution-context cardinality bound")
        ordinal = len(self.context_ordinals)
        self.context_ordinals[context] = ordinal
        return ordinal

    def _diagnose(self, code: str, line_number: int, message: str) -> None:
        if self.diagnostic_count < self.limits.max_diagnostics:
            self.diagnostic_count += 1
            if len(self.diagnostics) < min(
                _DIAGNOSTIC_SAMPLE_LIMIT,
                self.limits.max_diagnostics,
            ):
                self.diagnostics.append(
                    _Diagnostic(code=code, line_number=line_number, message=message)
                )
        else:
            self.diagnostics_capped = True
            if len(self.diagnostics) == self.diagnostic_count and self.diagnostics:
                # ``RuntimeEvidenceQuality`` stores a bounded diagnostic count
                # and requires an omitted sample to make truncation explicit.
                self.diagnostics.pop()

    def finish(
        self,
        *,
        source_sha256: str,
        source_bytes: int,
        created_at: str,
    ) -> RuntimeLockEvidenceArtifact:
        if self.header is None or self.public_header is None:
            raise _invalid("Runtime-lock input does not contain a header")
        if self.header.declared_event_count != self.input_events:
            raise _invalid("Runtime-lock declared event count differs from the stream")
        seed = _canonical_sha256(
            {
                "domain": "perflens.runtime-lock-evidence-id.v1.1",
                "source_sha256": source_sha256,
                "created_at": created_at,
                "header": self.public_header,
                "limits": self.limits,
                "parser_version": RUNTIME_LOCK_NDJSON_PARSER_VERSION,
            }
        )
        evidence_id = f"runtime-lock-evidence-{seed[:24]}"
        stack_ids = {
            stack.ordinal: _opaque_id(evidence_id, "stack", stack.ordinal, length=24)
            for stack in self.stacks.values()
        }
        event_ids = {
            event.source_id: _opaque_id(evidence_id, "event", index, length=24)
            for index, event in enumerate(self.events)
        }
        context_ids = {
            context: derive_runtime_execution_context_id(evidence_id, ordinal)
            for context, ordinal in self.context_ordinals.items()
        }
        contexts = tuple(
            _public_context(
                evidence_id,
                context,
                ordinal=ordinal,
                context_id=context_ids[context],
            )
            for context, ordinal in self.context_ordinals.items()
        )
        stacks = tuple(
            {
                "stack_id": stack_ids[stack.ordinal],
                "frames": stack.frames,
            }
            for stack in self.stacks.values()
        )
        events = tuple(
            self._public_event(
                event,
                index=index,
                evidence_id=evidence_id,
                event_ids=event_ids,
                stack_ids=stack_ids,
                context_ids=context_ids,
            )
            for index, event in enumerate(self.events)
        )
        quality, limitations = self._quality()
        allowed, forbidden = _conclusions(
            header=self.header,
            events=self.events,
            partial=quality["status"] == "partial",
        )
        source_data: dict[str, object] = {
            "schema_version": _OUTPUT_SCHEMA_VERSION,
            "runtime": self.header.runtime,
            "adapter_id": self.header.adapter_id,
            "adapter_version": self.header.adapter_version,
            "backend_id": self.header.backend_id,
            "backend_version": self.header.backend_version,
            "runtime_version": self.header.runtime_version,
            "measurement_semantics": self.header.measurement_semantics,
            "source_format": "perflens_runtime_lock_ndjson_v1",
            "converter_version": RUNTIME_LOCK_NDJSON_PARSER_VERSION,
            "source_sha256": source_sha256,
            "source_bytes": source_bytes,
            "conversion_fingerprint": "0" * 64,
            "clock": self.header.clock.model_dump(mode="json"),
            "duration_threshold_ns": self.header.duration_threshold_ns,
            "sampling_period": self.header.sampling_period,
            "sampling_fraction": self.header.sampling_fraction,
            "block_profile_rate_ns": self.header.block_profile_rate_ns,
            "fast_path_visibility": self.header.fast_path_visibility,
            "owner_is_source_observed": self.header.owner_is_source_observed,
            "hold_time_is_source_observed": self.header.hold_time_is_source_observed,
            "target_scope": "verified_import",
            "tool": None,
        }
        source_provisional = RuntimeSourceManifest.model_validate(source_data)
        source = source_provisional.model_copy(
            update={
                "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(
                    source_provisional
                )
            }
        )
        common: dict[str, object] = {
            "schema_version": _OUTPUT_SCHEMA_VERSION,
            "runtime_lock_evidence_id": evidence_id,
            "created_at": created_at,
            "target": self.header.target.model_dump(mode="json"),
            "source": source,
            "limits": self.limits.model_dump(mode="json"),
            "quality": {**quality, "limitations": limitations},
            "execution_contexts": contexts,
            "stacks": stacks,
            "events": events,
            "allowed_conclusions": allowed,
            "forbidden_conclusions": forbidden,
            "evidence_fingerprint": "0" * 64,
            "content_sha256": "0" * 64,
            "content_bytes": 1,
        }
        try:
            provisional = RuntimeLockEvidenceArtifact.model_validate(common)
            fingerprint = compute_runtime_lock_evidence_fingerprint(provisional)
            identified = provisional.model_copy(update={"evidence_fingerprint": fingerprint})
            sized = _with_stable_content_bytes(identified)
            content_sha256 = compute_runtime_lock_evidence_content_sha256(sized)
            evidence = RuntimeLockEvidenceArtifact.model_validate(
                {
                    # Preserve the schema-specific field shape.  A full dump
                    # materializes defaulted legacy TID fields as explicit
                    # nulls on schema-1.1 events, which correctly fails the
                    # strict version-boundary validator.
                    **sized.model_dump(mode="json", exclude_unset=True),
                    "content_sha256": content_sha256,
                }
            )
        except PerfLensError:
            raise
        except (TypeError, ValueError, ValidationError):
            raise _invalid("Runtime-lock Evidence projection failed strict validation") from None
        if evidence.content_bytes > self.limits.max_output_bytes:
            raise _limit("Runtime-lock Evidence exceeds max_output_bytes")
        validate_runtime_lock_evidence_invariants(evidence)
        return evidence

    def _public_event(
        self,
        event: _ParsedEvent,
        *,
        index: int,
        evidence_id: str,
        event_ids: Mapping[str, str],
        stack_ids: Mapping[int, str],
        context_ids: Mapping[_ContextKey, str],
    ) -> dict[str, object]:
        common: dict[str, object] = {
            "event_kind": event.event_kind,
            "event_id": event_ids[event.source_id],
            "event_index": index,
            "timestamp_ns": event.timestamp_ns,
            "execution_context_id": context_ids[event.context],
            "lock_id": (
                derive_runtime_lock_id(evidence_id, event.lock_ordinal)
                if event.lock_ordinal is not None
                else None
            ),
            "lock_kind": event.lock_kind,
            "stack_id": (
                stack_ids[event.stack_ordinal] if event.stack_ordinal is not None else None
            ),
            "measurement_semantics": self.header.measurement_semantics
            if self.header is not None
            else "exact",
        }
        if event.event_kind == "wait_begin":
            common["owner_execution_context_id"] = (
                context_ids[event.owner_context] if event.owner_context is not None else None
            )
        elif event.event_kind == "wait_end":
            assert event.duration_ns is not None
            assert event.outcome is not None
            common.update(
                {
                    "wait_begin_event_id": (
                        event_ids[event.pair_public_source_id]
                        if event.pair_public_source_id is not None
                        else None
                    ),
                    "duration_ns": event.duration_ns,
                    "outcome": event.outcome,
                    "owner_execution_context_id": (
                        context_ids[event.owner_context]
                        if event.owner_context is not None
                        else None
                    ),
                }
            )
        elif event.event_kind == "acquire":
            common["wait_end_event_id"] = (
                event_ids[event.wait_end_public_source_id]
                if event.wait_end_public_source_id is not None
                else None
            )
        elif event.event_kind == "release":
            common.update(
                {
                    "acquire_event_id": (
                        event_ids[event.pair_public_source_id]
                        if event.pair_public_source_id is not None
                        else None
                    ),
                    "hold_duration_ns": event.duration_ns,
                }
            )
        elif event.event_kind == "unpark":
            assert event.parked_context is not None
            common["parked_execution_context_id"] = context_ids[event.parked_context]
        elif event.event_kind == "sampled_contention":
            assert event.observed_count is not None
            assert event.cumulative_wait_ns is not None
            common.update(
                {
                    "observed_count": event.observed_count,
                    "estimated_count": event.estimated_count,
                    "cumulative_wait_ns": event.cumulative_wait_ns,
                }
            )
        return common

    def _quality(self) -> tuple[dict[str, object], tuple[str, ...]]:
        assert self.header is not None
        limitations: list[str] = []
        counters = (
            (self.malformed_events, "malformed runtime event records were omitted"),
            (self.duplicate_events, "duplicate runtime event records were omitted"),
            (self.out_of_order_events, "out-of-order runtime event records were omitted"),
            (self.unsupported_events, "unsupported runtime event records were omitted"),
            (self.filtered_events, "outside-target runtime event records were omitted"),
            (self.malformed_stacks, "malformed runtime stack records were omitted"),
            (self.duplicate_stacks, "duplicate runtime stack records were omitted"),
            (self.truncated_stacks, "over-depth runtime stack records were omitted"),
            (self.header.declared_lost_event_count, "the source reported lost runtime events"),
        )
        limitations.extend(message for count, message in counters if count)
        if self.header.declared_truncated:
            limitations.append("the source declared truncated runtime evidence")
        if not self.events:
            limitations.append("the runtime evidence contains no accepted events")
        limitations.extend(self._pairing_limitations())
        if self.diagnostics_capped:
            limitations.append("runtime diagnostics reached their configured bound")
        partial = bool(limitations)
        semantics_counts = {
            "exact_event_count": 0,
            "thresholded_event_count": 0,
            "sampled_event_count": 0,
            "cumulative_event_count": 0,
        }
        semantics_counts[f"{self.header.measurement_semantics}_event_count"] = len(self.events)
        quality: dict[str, object] = {
            "status": "partial" if partial else "complete",
            "input_record_count": self.input_events,
            "emitted_event_count": len(self.events),
            "filtered_outside_target_count": self.filtered_events,
            "malformed_record_count": self.malformed_events,
            "duplicate_record_count": self.duplicate_events,
            "out_of_order_record_count": self.out_of_order_events,
            "unsupported_record_count": self.unsupported_events,
            "lost_event_count": self.header.declared_lost_event_count,
            "truncated_event_count": 0,
            "stack_input_record_count": self.stack_records,
            "emitted_stack_count": len(self.stacks),
            "malformed_stack_record_count": self.malformed_stacks,
            "duplicate_stack_record_count": self.duplicate_stacks,
            "truncated_stack_record_count": self.truncated_stacks,
            **semantics_counts,
            "owner_observed_event_count": sum(
                event.owner_context is not None for event in self.events
            ),
            "diagnostic_count": self.diagnostic_count,
            "diagnostics_truncated": (self.diagnostic_count > len(self.diagnostics)),
            "diagnostics": tuple(item.public_text() for item in self.diagnostics),
        }
        return quality, tuple(limitations)

    def _pairing_limitations(self) -> tuple[str, ...]:
        """Describe accepted exact records whose counterpart left the bounded window."""

        assert self.header is not None
        if self.header.measurement_semantics != "exact":
            return ()
        messages: list[str] = []
        waits = {event.source_id for event in self.events if event.event_kind == "wait_begin"}
        paired_waits = {
            event.pair_public_source_id
            for event in self.events
            if event.event_kind == "wait_end" and event.pair_public_source_id is not None
        }
        if waits != paired_waits:
            messages.append("exact runtime waits include an incomplete begin/end pair")

        acquired_waits = {
            event.source_id
            for event in self.events
            if event.event_kind == "wait_end" and event.outcome == "acquired"
        }
        paired_acquired_waits = {
            event.wait_end_public_source_id
            for event in self.events
            if event.event_kind == "acquire" and event.wait_end_public_source_id is not None
        }
        has_acquire_surface = any(event.event_kind == "acquire" for event in self.events)
        if (has_acquire_surface or self.header.hold_time_is_source_observed) and (
            acquired_waits != paired_acquired_waits
        ):
            messages.append("exact acquired waits include an incomplete acquire pair")

        if self.header.hold_time_is_source_observed:
            acquires = {event.source_id for event in self.events if event.event_kind == "acquire"}
            released_acquires = {
                event.pair_public_source_id
                for event in self.events
                if event.event_kind == "release" and event.pair_public_source_id is not None
            }
            if acquires != released_acquires:
                messages.append("exact runtime holds include an incomplete acquire/release pair")

        parks = Counter(
            (event.context, event.source_lock_id, event.lock_kind)
            for event in self.events
            if event.event_kind == "park"
        )
        unparks = Counter(
            (event.parked_context, event.source_lock_id, event.lock_kind)
            for event in self.events
            if event.event_kind == "unpark"
        )
        if parks != unparks:
            messages.append("exact runtime parks include an incomplete park/unpark pair")
        return tuple(messages)


class _OutsideTarget(Exception):
    pass


def _without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _normalize_created_at(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise _invalid("Runtime-lock created_at is not a valid ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise _invalid("Runtime-lock created_at must include a timezone")
    return parsed.astimezone(UTC).isoformat()


def _public_frame(frame: _RawStackFrame) -> dict[str, object]:
    return {
        "symbol": _redact_sensitive_label(frame.symbol),
        "module": _redact_path(frame.module),
        "source_file": (_redact_path(frame.source_file) if frame.source_file is not None else None),
        "source_line": frame.source_line,
        "is_runtime": frame.is_runtime,
        "is_unknown": frame.is_unknown,
    }


def _redact_path(value: str) -> str:
    if _contains_sensitive_text(value):
        return _REDACTED_LABEL
    normalized = value.replace("\\", "/")
    leaf = normalized.rsplit("/", maxsplit=1)[-1]
    if leaf in {"", ".", ".."} or _contains_sensitive_text(leaf):
        return _REDACTED_LABEL
    return leaf


def _redact_sensitive_label(value: str) -> str:
    return (
        _REDACTED_LABEL
        if _contains_sensitive_text(value) or not is_safe_runtime_public_label(value)
        else value
    )


def _contains_sensitive_text(value: str, *, reject_path: bool = False) -> bool:
    normalized = value.strip()
    if not normalized or any(ord(character) < 32 or ord(character) == 127 for character in value):
        return True
    if reject_path and ("/" in normalized or "\\" in normalized):
        return True
    return bool(
        _RAW_ADDRESS_PATTERN.fullmatch(normalized)
        or _CREDENTIAL_ASSIGNMENT_PATTERN.search(normalized)
        or _URI_USERINFO_PATTERN.search(normalized)
        or _PRIVATE_KEY_PATTERN.search(normalized)
    )


def _opaque_id(evidence_id: str, kind: str, ordinal: int, *, length: int) -> str:
    material = f"perflens.runtime-lock.{kind}.v1.1\0{evidence_id}\0{ordinal}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:length]
    return f"runtime-{kind}-{digest}"


def _public_context(
    evidence_id: str,
    context: _ContextKey,
    *,
    ordinal: int,
    context_id: str,
) -> dict[str, object]:
    runtime_native_id = None
    if context.source_runtime_context_id is not None:
        runtime_native_id = derive_runtime_native_context_id(evidence_id, ordinal)
    return {
        "context_id": context_id,
        "kind": context.kind,
        "target_pid": context.target_pid,
        "target_tid": context.target_tid,
        "runtime_context_id": runtime_native_id,
        # Raw names are target-controlled and may contain paths, credentials, or
        # instruction-like text.  Runtime adapters can add reviewed safe labels
        # later; the strict generic importer does not disclose them.
        "name": None,
    }


def _conclusions(
    *,
    header: _RawHeader,
    events: list[_ParsedEvent],
    partial: bool,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    kinds = {event.event_kind for event in events}
    allowed = ["runtime_lock_evidence_quality_and_identity"]
    if "wait_end" in kinds:
        allowed.append("observed_runtime_wait_distribution")
    if "release" in kinds and header.hold_time_is_source_observed:
        allowed.append("observed_runtime_hold_distribution")
    if "sampled_contention" in kinds:
        allowed.append("observed_runtime_contention_profile")
    forbidden = [
        "performance_root_cause",
        "verified_improvement",
        "cross_artifact_lock_identity",
        "system_wide_or_cross_target_behavior",
    ]
    if header.measurement_semantics != "exact":
        forbidden.append("exact_contention_count")
    if not header.owner_is_source_observed or header.adapter_id == "java_jfr":
        forbidden.append("exact_owner_relationship")
    if not header.hold_time_is_source_observed:
        forbidden.append("exact_hold_time")
    if partial:
        forbidden.append("unqualified_runtime_lock_conclusion")
    return tuple(allowed), tuple(forbidden)


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        _json_value(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return {str(key): _json_value(item) for key, item in mapping.items()}
    if isinstance(value, (tuple, list)):
        items = cast(tuple[object, ...] | list[object], value)
        return [_json_value(item) for item in items]
    return value


def _with_stable_content_bytes(
    evidence: RuntimeLockEvidenceArtifact,
) -> RuntimeLockEvidenceArtifact:
    current = evidence
    for _ in range(8):
        actual = len(serialize_json(current))
        if actual == current.content_bytes:
            return current
        current = current.model_copy(update={"content_bytes": actual})
    raise _invalid("Runtime-lock Evidence byte identity did not converge")


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "runtime_lock_import",
        message,
        recoverable=True,
    )


def _limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "runtime_lock_import",
        message,
        recoverable=True,
    )
