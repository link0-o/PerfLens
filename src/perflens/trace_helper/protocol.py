"""Strict, bounded Python side of the independent Trace Helper protocol."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal, cast

from pydantic import Field, TypeAdapter, model_validator

from perflens.contracts.artifacts import ContractModel
from perflens.domain.errors import ErrorCode, PerfLensError

TRACE_HELPER_SCHEMA_VERSION = "1.0"
MAX_TRACE_HELPER_MESSAGE_BYTES = 64 << 10
MAX_TRACE_HELPER_PLAN_TTL_MILLISECONDS = 120_000
MAX_TRACE_HELPER_DURATION_MILLISECONDS = 10_000
MAX_TRACE_HELPER_OUTPUT_BYTES = 64 << 20
MAX_TRACE_HELPER_OBSERVED_TIDS = 65_536


class TraceHelperTarget(ContractModel):
    pid: int = Field(gt=0, le=2_147_483_647)
    uid: int = Field(ge=0, le=4_294_967_295)
    start_time_ticks: int = Field(gt=0, le=18_446_744_073_709_551_615)


class TraceHelperHealthRequest(ContractModel):
    schema_version: Literal["1.0"] = TRACE_HELPER_SCHEMA_VERSION
    operation: Literal["health"] = "health"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")


class TraceHelperCollectPidRequest(ContractModel):
    schema_version: Literal["1.0"] = TRACE_HELPER_SCHEMA_VERSION
    operation: Literal["collect_pid"] = "collect_pid"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")
    plan_id: str = Field(pattern=r"^trace-plan-[a-f0-9]{20}$")
    caller_uid: int = Field(ge=0, le=4_294_967_295)
    target: TraceHelperTarget
    mode: Literal["sched", "off_cpu", "lock"]
    duration_milliseconds: int = Field(
        gt=0,
        le=MAX_TRACE_HELPER_DURATION_MILLISECONDS,
    )
    max_output_bytes: int = Field(gt=0, le=MAX_TRACE_HELPER_OUTPUT_BYTES)
    expires_at_unix_milliseconds: int = Field(gt=0)
    expected_policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_capture_backend: Literal["target_filtered_kernel_v1"]
    report_ready: bool = Field(strict=True)

    @model_validator(mode="after")
    def require_caller_to_match_target(self) -> TraceHelperCollectPidRequest:
        if self.caller_uid != self.target.uid:
            raise ValueError("Trace Helper caller UID must match the target UID")
        return self


TraceHelperRequest = Annotated[
    TraceHelperHealthRequest | TraceHelperCollectPidRequest,
    Field(discriminator="operation"),
]
TRACE_HELPER_REQUEST_ADAPTER: TypeAdapter[TraceHelperRequest] = TypeAdapter(
    TraceHelperRequest
)


class TraceHelperHealthResult(ContractModel):
    kind: Literal["health"]
    helper_version: str = Field(min_length=1, max_length=64)
    helper_pid: int = Field(gt=0)
    helper_uid: int = Field(ge=0, le=4_294_967_295)
    ready: Literal[True]
    capture_backend: Literal["target_filtered_kernel_v1"]
    capture_backend_status: Literal["available", "unavailable"]
    supported_modes: tuple[Literal["sched", "off_cpu", "lock"], ...] = Field(
        max_length=3
    )
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    max_duration_milliseconds: Literal[10000]
    max_output_bytes: Literal[67108864]
    max_concurrent_collections: Literal[1]
    target_filter_before_userspace: bool

    @model_validator(mode="after")
    def validate_backend_claims(self) -> TraceHelperHealthResult:
        if len(set(self.supported_modes)) != len(self.supported_modes):
            raise ValueError("Trace Helper supported modes must be unique")
        if self.capture_backend_status == "available":
            if not self.supported_modes or not self.target_filter_before_userspace:
                raise ValueError("Available Trace backend requires target-filtered modes")
        elif self.supported_modes or self.target_filter_before_userspace:
            raise ValueError("Unavailable Trace backend cannot claim supported collection")
        return self


class TraceHelperCollectionReadyResult(ContractModel):
    kind: Literal["collection_ready"]
    plan_id: str = Field(pattern=r"^trace-plan-[a-f0-9]{20}$")
    target_pid: int = Field(gt=0)


class TraceHelperCollectionResult(ContractModel):
    kind: Literal["collection"]
    plan_id: str = Field(pattern=r"^trace-plan-[a-f0-9]{20}$")
    mode: Literal["sched", "off_cpu", "lock"]
    target_pid: int = Field(gt=0)
    target_start_time_ticks: int = Field(gt=0)
    artifact_name: str = Field(
        pattern=r"^trace-plan-[a-f0-9]{20}\.trace\.ndjson$"
    )
    output_bytes: int = Field(gt=0, le=MAX_TRACE_HELPER_OUTPUT_BYTES)
    output_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_format: Literal["target_filtered_trace_ndjson"]
    capture_backend: Literal["target_filtered_kernel_v1"]
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_target_tids: tuple[int, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_HELPER_OBSERVED_TIDS,
    )
    event_count: int = Field(gt=0)
    lost_event_count: int = Field(ge=0)
    truncated: bool
    started_at_monotonic_nanoseconds: int = Field(ge=0)
    finished_at_monotonic_nanoseconds: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_collection_result(self) -> TraceHelperCollectionResult:
        if tuple(sorted(set(self.observed_target_tids))) != self.observed_target_tids:
            raise ValueError("Observed target TIDs must be unique and sorted")
        if self.finished_at_monotonic_nanoseconds < self.started_at_monotonic_nanoseconds:
            raise ValueError("Trace Helper collection ended before it started")
        return self


class TraceHelperErrorBody(ContractModel):
    code: str = Field(min_length=1, max_length=64)
    stage: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1024)
    recoverable: bool


class TraceHelperResponse(ContractModel):
    schema_version: Literal["1.0"] = TRACE_HELPER_SCHEMA_VERSION
    request_id: str = Field(pattern=r"^(unknown|request-[a-f0-9]{16,64})$")
    ok: bool
    result: (
        Annotated[
            TraceHelperHealthResult
            | TraceHelperCollectionReadyResult
            | TraceHelperCollectionResult,
            Field(discriminator="kind"),
        ]
        | None
    ) = None
    error: TraceHelperErrorBody | None = None

    @model_validator(mode="after")
    def require_exactly_one_payload(self) -> TraceHelperResponse:
        if self.ok and (self.result is None or self.error is not None):
            raise ValueError("Successful Trace Helper responses require only a result")
        if not self.ok and (self.error is None or self.result is not None):
            raise ValueError("Failed Trace Helper responses require only an error")
        return self


def parse_trace_helper_request_frame(
    frame: bytes,
    *,
    now_unix_milliseconds: int,
) -> TraceHelperRequest:
    """Parse one strict frame and independently enforce the plan TTL ceiling."""
    if len(frame) > MAX_TRACE_HELPER_MESSAGE_BYTES:
        raise _invalid("Trace Helper request exceeds the protocol limit")
    payload, separator, trailing = frame.partition(b"\n")
    if not separator or trailing:
        raise _invalid("Trace Helper requires exactly one newline-delimited request")
    try:
        request = TRACE_HELPER_REQUEST_ADAPTER.validate_python(_strict_json_object(payload))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _invalid("Trace Helper request is not strict valid JSON") from exc
    if isinstance(request, TraceHelperCollectPidRequest):
        remaining = request.expires_at_unix_milliseconds - now_unix_milliseconds
        if remaining <= 0 or remaining > MAX_TRACE_HELPER_PLAN_TTL_MILLISECONDS:
            raise _invalid("Trace Helper plan is expired or exceeds TTL ceiling")
    return request


def parse_trace_helper_response_frame(frame: bytes) -> TraceHelperResponse:
    if len(frame) > MAX_TRACE_HELPER_MESSAGE_BYTES:
        raise _invalid("Trace Helper response exceeds the protocol limit")
    payload, separator, trailing = frame.partition(b"\n")
    if not separator or trailing:
        raise _invalid("Trace Helper requires exactly one newline-delimited response")
    try:
        return TraceHelperResponse.model_validate(_strict_json_object(payload))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _invalid("Trace Helper response is not strict valid JSON") from exc


def trace_helper_request_schema() -> dict[str, Any]:
    return TRACE_HELPER_REQUEST_ADAPTER.json_schema()


def trace_helper_response_schema() -> dict[str, Any]:
    return TraceHelperResponse.model_json_schema()


def _strict_json_object(payload: bytes) -> dict[str, Any]:
    decoded = payload.decode("utf-8", errors="strict")
    raw = json.loads(decoded, object_pairs_hook=_object_without_duplicate_keys)
    if not isinstance(raw, dict):
        raise TypeError("Trace Helper protocol payload must be a JSON object")
    return cast(dict[str, Any], raw)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "trace_helper_protocol",
        message,
    )
