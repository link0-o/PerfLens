"""Strict, bounded Python side of the private Python/Rust Helper protocol."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal, cast

from pydantic import Field, TypeAdapter, model_validator

from perflens.contracts.artifacts import ContractModel
from perflens.domain.errors import ErrorCode, PerfLensError

HELPER_SCHEMA_VERSION = "1.1"
MAX_HELPER_MESSAGE_BYTES = 64 << 10
MAX_HELPER_PLAN_TTL_MILLISECONDS = 120_000
MAX_HELPER_DURATION_MILLISECONDS = 86_400_000
MAX_HELPER_OUTPUT_BYTES = 1 << 40
MAX_HELPER_FREQUENCY_HZ = 10_000
MAX_HELPER_EVENTS = 64
_HARDWARE_STAT_EVENTS = frozenset(
    {"cycles", "instructions", "cache-references", "cache-misses", "branches", "branch-misses"}
)
_SOFTWARE_STAT_EVENTS = (
    "task-clock",
    "context-switches",
    "cpu-migrations",
    "page-faults",
)


class HelperTarget(ContractModel):
    pid: int = Field(gt=0, le=2_147_483_647)
    uid: int = Field(ge=0, le=4_294_967_295)
    start_time_ticks: int = Field(gt=0, le=18_446_744_073_709_551_615)


class HelperHealthRequest(ContractModel):
    schema_version: Literal["1.1"] = HELPER_SCHEMA_VERSION
    operation: Literal["health"] = "health"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")


class HelperCollectPidRequest(ContractModel):
    schema_version: Literal["1.1"] = HELPER_SCHEMA_VERSION
    operation: Literal["collect_pid"] = "collect_pid"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")
    plan_id: str = Field(pattern=r"^plan-[a-f0-9]{20}$")
    caller_uid: int = Field(ge=0, le=4_294_967_295)
    target: HelperTarget
    mode: Literal["record", "stat"]
    duration_milliseconds: int = Field(gt=0, le=MAX_HELPER_DURATION_MILLISECONDS)
    frequency_hz: int | None = Field(default=None, ge=1, le=MAX_HELPER_FREQUENCY_HZ)
    call_graph: Literal["fp", "dwarf", "lbr"] | None = None
    events: tuple[str, ...] = Field(default=(), max_length=MAX_HELPER_EVENTS)
    requested_event_source: Literal["auto", "hardware_required", "software_only"]
    fallback_allowed: bool
    fallback_events: tuple[str, ...] = Field(default=(), max_length=MAX_HELPER_EVENTS)
    record_event: Literal["cycles", "cpu-clock"] | None = None
    fallback_record_event: Literal["cpu-clock"] | None = None
    max_output_bytes: int = Field(gt=0, le=MAX_HELPER_OUTPUT_BYTES)
    expires_at_unix_milliseconds: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_mode_fields(self) -> HelperCollectPidRequest:
        all_events = (*self.events, *self.fallback_events)
        if any(not event or len(event) > 128 or "\0" in event for event in all_events):
            raise ValueError("Helper events must be non-empty, bounded, and contain no NUL")
        if len(set(self.events)) != len(self.events) or len(set(self.fallback_events)) != len(
            self.fallback_events
        ):
            raise ValueError("Helper events must not contain duplicates")
        if self.mode == "stat":
            if (
                not self.events
                or self.frequency_hz is not None
                or self.call_graph is not None
                or self.record_event is not None
                or self.fallback_record_event is not None
            ):
                raise ValueError("stat requires events and forbids frequency/call graph")
        elif (
            self.events
            or self.fallback_events
            or self.frequency_hz is None
            or self.call_graph is None
            or self.record_event is None
        ):
            raise ValueError("record requires frequency/call graph and forbids stat events")
        if self.fallback_allowed and self.requested_event_source != "auto":
            raise ValueError("Only auto event-source plans may permit software fallback")
        if self.fallback_allowed:
            if self.mode == "stat" and self.fallback_events != _SOFTWARE_STAT_EVENTS:
                raise ValueError("Auto stat plans require the fixed software fallback events")
            if self.mode == "record" and self.fallback_record_event != "cpu-clock":
                raise ValueError("Auto record plans require the cpu-clock fallback")
        elif self.fallback_events or self.fallback_record_event is not None:
            raise ValueError("Non-fallback plans must not carry fallback events")
        if self.requested_event_source == "software_only":
            if self.mode == "record" and self.record_event != "cpu-clock":
                raise ValueError("Software-only record plans require cpu-clock")
            if self.mode == "stat" and self.events != _SOFTWARE_STAT_EVENTS:
                raise ValueError("Software-only stat plans require the fixed software events")
        elif self.mode == "stat" and not set(self.events).issubset(_HARDWARE_STAT_EVENTS):
            raise ValueError("Hardware stat plans accept only fixed hardware events")
        if (
            self.mode == "record"
            and self.requested_event_source != "software_only"
            and self.record_event != "cycles"
        ):
            raise ValueError("Hardware record plans require cycles")
        return self


HelperRequest = Annotated[
    HelperHealthRequest | HelperCollectPidRequest,
    Field(discriminator="operation"),
]
HELPER_REQUEST_ADAPTER: TypeAdapter[HelperRequest] = TypeAdapter(HelperRequest)


class HelperHealthResult(ContractModel):
    kind: Literal["health"]
    helper_version: str = Field(min_length=1, max_length=64)
    helper_pid: int = Field(gt=0)
    helper_uid: int = Field(ge=0, le=4_294_967_295)
    privilege_mode: Literal["paranoid3_helper"]
    ready: Literal[True]


class HelperCollectionResult(ContractModel):
    kind: Literal["collection"]
    plan_id: str = Field(pattern=r"^plan-[a-f0-9]{20}$")
    mode: Literal["record", "stat"]
    target_pid: int = Field(gt=0)
    artifact_name: str = Field(pattern=r"^plan-[a-f0-9]{20}\.(stat\.csv|perf\.data)$")
    output_bytes: int = Field(gt=0, le=MAX_HELPER_OUTPUT_BYTES)
    output_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_format: Literal["perf_data", "perf_stat_delimited"]
    actual_event_source: Literal["hardware", "software"]
    fallback_used: bool
    fallback_reason: (
        Literal[
            "hardware_probe_skipped_for_short_collection",
            "hardware_probe_failed",
            "hardware_probe_produced_no_usable_counts",
            "hardware_execution_failed_after_probe",
        ]
        | None
    ) = None
    events: tuple[str, ...] = Field(default=(), max_length=MAX_HELPER_EVENTS)
    record_event: Literal["cycles", "cpu-clock"] | None = None
    started_at_unix_milliseconds: int = Field(gt=0)
    finished_at_unix_milliseconds: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_evidence_source(self) -> HelperCollectionResult:
        if self.fallback_used != (self.fallback_reason is not None):
            raise ValueError("Fallback results require exactly one bounded fallback reason")
        if self.fallback_used and self.actual_event_source != "software":
            raise ValueError("Fallback results must identify software evidence")
        if self.mode == "stat":
            if self.record_event is not None or not self.events:
                raise ValueError("Stat results require events and forbid a record event")
            if self.actual_event_source == "software" and self.events != _SOFTWARE_STAT_EVENTS:
                raise ValueError("Software stat results require the fixed software events")
            if self.actual_event_source == "hardware" and not set(self.events).issubset(
                _HARDWARE_STAT_EVENTS
            ):
                raise ValueError("Hardware stat results accept only fixed hardware events")
        elif self.events or (
            self.actual_event_source == "software" and self.record_event != "cpu-clock"
        ) or (self.actual_event_source == "hardware" and self.record_event != "cycles"):
            raise ValueError("Record result event does not match its evidence source")
        return self


class HelperErrorBody(ContractModel):
    code: str = Field(min_length=1, max_length=64)
    stage: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1024)
    recoverable: bool


class HelperResponse(ContractModel):
    schema_version: Literal["1.1"] = HELPER_SCHEMA_VERSION
    request_id: str = Field(pattern=r"^(unknown|request-[a-f0-9]{16,64})$")
    ok: bool
    result: (
        Annotated[
            HelperHealthResult | HelperCollectionResult,
            Field(discriminator="kind"),
        ]
        | None
    ) = None
    error: HelperErrorBody | None = None

    @model_validator(mode="after")
    def require_exactly_one_payload(self) -> HelperResponse:
        if self.ok and (self.result is None or self.error is not None):
            raise ValueError("Successful Helper responses require only a result")
        if not self.ok and (self.error is None or self.result is not None):
            raise ValueError("Failed Helper responses require only an error")
        return self


def parse_helper_request_frame(
    frame: bytes,
    *,
    now_unix_milliseconds: int,
) -> HelperRequest:
    """Parse one newline-delimited frame while rejecting duplicate keys and unsafe TTLs."""
    if len(frame) > MAX_HELPER_MESSAGE_BYTES:
        raise _invalid_helper_request("Privileged Helper request exceeds the protocol limit")
    payload, separator, trailing = frame.partition(b"\n")
    if not separator or trailing:
        raise _invalid_helper_request(
            "Privileged Helper requires exactly one newline-delimited request"
        )
    try:
        raw = _strict_json_object(payload)
        request = HELPER_REQUEST_ADAPTER.validate_python(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _invalid_helper_request("Privileged Helper request is not strict valid JSON") from exc
    if isinstance(request, HelperCollectPidRequest):
        remaining = request.expires_at_unix_milliseconds - now_unix_milliseconds
        if remaining <= 0 or remaining > MAX_HELPER_PLAN_TTL_MILLISECONDS:
            raise _invalid_helper_request(
                "Privileged Helper plan is expired or exceeds TTL ceiling"
            )
    return request


def parse_helper_response_frame(frame: bytes) -> HelperResponse:
    """Parse exactly one bounded Helper response with duplicate-field rejection."""
    if len(frame) > MAX_HELPER_MESSAGE_BYTES:
        raise _invalid_helper_request("Privileged Helper response exceeds the protocol limit")
    payload, separator, trailing = frame.partition(b"\n")
    if not separator or trailing:
        raise _invalid_helper_request(
            "Privileged Helper requires exactly one newline-delimited response"
        )
    try:
        return HelperResponse.model_validate(_strict_json_object(payload))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _invalid_helper_request(
            "Privileged Helper response is not strict valid JSON"
        ) from exc


def _strict_json_object(payload: bytes) -> dict[str, Any]:
    decoded = payload.decode("utf-8", errors="strict")
    raw = json.loads(decoded, object_pairs_hook=_object_without_duplicate_keys)
    if not isinstance(raw, dict):
        raise TypeError("Helper protocol payload must be a JSON object")
    return cast(dict[str, Any], raw)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _invalid_helper_request(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "privileged_helper_protocol",
        message,
        recoverable=True,
    )


def helper_request_schema() -> dict[str, Any]:
    """Return the private request schema for checked-in cross-language conformance."""
    return HELPER_REQUEST_ADAPTER.json_schema()


def helper_response_schema() -> dict[str, Any]:
    """Return the private response schema for checked-in cross-language conformance."""
    return HelperResponse.model_json_schema()
