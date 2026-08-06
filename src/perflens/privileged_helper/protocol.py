"""Strict, bounded Python side of the private Python/Rust Helper protocol."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal, cast

from pydantic import Field, TypeAdapter, model_validator

from perflens.contracts.artifacts import ContractModel
from perflens.domain.errors import ErrorCode, PerfLensError

HELPER_SCHEMA_VERSION = "1.0"
MAX_HELPER_MESSAGE_BYTES = 64 << 10
MAX_HELPER_PLAN_TTL_MILLISECONDS = 120_000
MAX_HELPER_DURATION_MILLISECONDS = 86_400_000
MAX_HELPER_OUTPUT_BYTES = 1 << 40
MAX_HELPER_FREQUENCY_HZ = 10_000
MAX_HELPER_EVENTS = 64


class HelperTarget(ContractModel):
    pid: int = Field(gt=0, le=2_147_483_647)
    uid: int = Field(ge=0, le=4_294_967_295)
    start_time_ticks: int = Field(gt=0, le=18_446_744_073_709_551_615)


class HelperHealthRequest(ContractModel):
    schema_version: Literal["1.0"] = HELPER_SCHEMA_VERSION
    operation: Literal["health"] = "health"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")


class HelperCollectPidRequest(ContractModel):
    schema_version: Literal["1.0"] = HELPER_SCHEMA_VERSION
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
    max_output_bytes: int = Field(gt=0, le=MAX_HELPER_OUTPUT_BYTES)
    expires_at_unix_milliseconds: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_mode_fields(self) -> HelperCollectPidRequest:
        if any(not event or len(event) > 128 or "\0" in event for event in self.events):
            raise ValueError("Helper events must be non-empty, bounded, and contain no NUL")
        if len(set(self.events)) != len(self.events):
            raise ValueError("Helper events must not contain duplicates")
        if self.mode == "stat":
            if not self.events or self.frequency_hz is not None or self.call_graph is not None:
                raise ValueError("stat requires events and forbids frequency/call graph")
        elif self.events or self.frequency_hz is None or self.call_graph is None:
            raise ValueError("record requires frequency/call graph and forbids stat events")
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
    started_at_unix_milliseconds: int = Field(gt=0)
    finished_at_unix_milliseconds: int = Field(gt=0)


class HelperErrorBody(ContractModel):
    code: str = Field(min_length=1, max_length=64)
    stage: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1024)
    recoverable: bool


class HelperResponse(ContractModel):
    schema_version: Literal["1.0"] = HELPER_SCHEMA_VERSION
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
