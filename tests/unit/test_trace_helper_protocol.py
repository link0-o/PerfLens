from __future__ import annotations

import json
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.trace_helper.protocol import (
    MAX_TRACE_HELPER_MESSAGE_BYTES,
    TraceHelperCollectionResult,
    TraceHelperCollectPidRequest,
    TraceHelperHealthRequest,
    TraceHelperHealthResult,
    TraceHelperResponse,
    parse_trace_helper_request_frame,
    parse_trace_helper_response_frame,
    trace_helper_request_schema,
    trace_helper_response_schema,
)

_NOW_MILLISECONDS = 4_102_444_700_000


def test_checked_in_trace_helper_schemas_match_python_models() -> None:
    root = Path(__file__).resolve().parents[2]
    assert json.loads(
        (root / "schemas/trace-helper-request.schema.json").read_text(encoding="utf-8")
    ) == trace_helper_request_schema()
    assert json.loads(
        (root / "schemas/trace-helper-response.schema.json").read_text(encoding="utf-8")
    ) == trace_helper_response_schema()


def test_trace_helper_valid_golden_frames_and_unavailable_health() -> None:
    fixture_root = Path(__file__).resolve().parents[1] / "fixtures/trace_helper"
    health = parse_trace_helper_request_frame(
        (fixture_root / "valid/health.jsonl").read_bytes(),
        now_unix_milliseconds=_NOW_MILLISECONDS,
    )
    collect = parse_trace_helper_request_frame(
        (fixture_root / "valid/sched.jsonl").read_bytes(),
        now_unix_milliseconds=_NOW_MILLISECONDS,
    )
    response = parse_trace_helper_response_frame(
        (fixture_root / "responses/health-unavailable.jsonl").read_bytes()
    )

    assert isinstance(health, TraceHelperHealthRequest)
    assert isinstance(collect, TraceHelperCollectPidRequest)
    assert collect.mode == "sched"
    assert isinstance(response.result, TraceHelperHealthResult)
    assert response.result.capture_backend_status == "unavailable"
    assert response.result.supported_modes == ()


@pytest.mark.parametrize(
    "fixture",
    sorted(
        (Path(__file__).resolve().parents[1] / "fixtures/trace_helper/invalid").glob(
            "*.jsonl"
        )
    ),
    ids=lambda path: path.name,
)
def test_trace_helper_invalid_golden_frames_are_rejected(fixture: Path) -> None:
    with pytest.raises(PerfLensError):
        parse_trace_helper_request_frame(
            fixture.read_bytes(),
            now_unix_milliseconds=_NOW_MILLISECONDS,
        )


@pytest.mark.parametrize(
    "frame",
    [
        b'{"schema_version":"1.0","operation":"health","request_id":"request-0123456789abcdef"}',
        b'{"schema_version":"1.0","operation":"health","request_id":"request-0123456789abcdef"}\n{}\n',
        b'{"schema_version":"1.0","operation":"health","request_id":"request-0123456789abcdef","request_id":"request-fedcba9876543210"}\n',
    ],
)
def test_trace_helper_rejects_missing_extra_and_duplicate_frames(frame: bytes) -> None:
    with pytest.raises(PerfLensError):
        parse_trace_helper_request_frame(
            frame,
            now_unix_milliseconds=_NOW_MILLISECONDS,
        )


def test_trace_helper_rejects_expired_and_excessive_ttl() -> None:
    fixture = (
        Path(__file__).resolve().parents[1]
        / "fixtures/trace_helper/valid/sched.jsonl"
    ).read_bytes()
    with pytest.raises(PerfLensError, match="expired"):
        parse_trace_helper_request_frame(
            fixture,
            now_unix_milliseconds=4_102_444_760_000,
        )
    with pytest.raises(PerfLensError, match="TTL ceiling"):
        parse_trace_helper_request_frame(
            fixture,
            now_unix_milliseconds=4_102_444_000_000,
        )


def test_trace_helper_health_cannot_claim_modes_when_backend_is_unavailable() -> None:
    with pytest.raises(ValueError):
        TraceHelperHealthResult(
            kind="health",
            helper_version="test",
            helper_pid=1,
            helper_uid=0,
            ready=True,
            capture_backend="target_filtered_kernel_v1",
            capture_backend_status="unavailable",
            supported_modes=("sched",),
            policy_sha256="a" * 64,
            max_duration_milliseconds=10_000,
            max_output_bytes=67_108_864,
            max_concurrent_collections=1,
            target_filter_before_userspace=False,
        )

    with pytest.raises(ValueError, match="target-filtered modes"):
        TraceHelperHealthResult(
            kind="health",
            helper_version="test",
            helper_pid=1,
            helper_uid=0,
            ready=True,
            capture_backend="target_filtered_kernel_v1",
            capture_backend_status="available",
            supported_modes=(),
            policy_sha256="a" * 64,
            max_duration_milliseconds=10_000,
            max_output_bytes=67_108_864,
            max_concurrent_collections=1,
            target_filter_before_userspace=False,
        )


def test_trace_helper_response_requires_exactly_one_payload() -> None:
    with pytest.raises(ValueError):
        TraceHelperResponse(
            request_id="request-0123456789abcdef",
            ok=True,
        )


def test_trace_helper_rejects_invalid_response_frames_and_collection_order() -> None:
    with pytest.raises(PerfLensError, match="protocol limit"):
        parse_trace_helper_response_frame(b"x" * (MAX_TRACE_HELPER_MESSAGE_BYTES + 1))
    with pytest.raises(PerfLensError, match="strict valid JSON"):
        parse_trace_helper_response_frame(b"[]\n")

    values = {
        "kind": "collection",
        "plan_id": "trace-plan-0123456789abcdefabcd",
        "mode": "sched",
        "target_pid": 10,
        "target_start_time_ticks": 20,
        "artifact_name": "trace-plan-0123456789abcdefabcd.trace.ndjson",
        "output_bytes": 100,
        "output_sha256": "c" * 64,
        "output_format": "target_filtered_trace_ndjson",
        "capture_backend": "target_filtered_kernel_v1",
        "policy_sha256": "d" * 64,
        "observed_target_tids": (12, 11),
        "event_count": 1,
        "lost_event_count": 0,
        "truncated": False,
        "started_at_monotonic_nanoseconds": 20,
        "finished_at_monotonic_nanoseconds": 10,
    }
    with pytest.raises(ValueError, match="unique and sorted"):
        TraceHelperCollectionResult.model_validate(values)
    values["observed_target_tids"] = (11, 12)
    with pytest.raises(ValueError, match="ended before"):
        TraceHelperCollectionResult.model_validate(values)
