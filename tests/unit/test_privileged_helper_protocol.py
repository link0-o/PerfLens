from __future__ import annotations

import json
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.privileged_helper.protocol import (
    HelperCollectionResult,
    HelperCollectPidRequest,
    HelperHealthRequest,
    HelperResponse,
    helper_request_schema,
    helper_response_schema,
    parse_helper_request_frame,
)

_NOW_MILLISECONDS = 4_102_444_700_000


def test_checked_in_privileged_helper_schema_matches_python_model() -> None:
    root = Path(__file__).resolve().parents[2]
    checked_in = json.loads(
        (root / "schemas/privileged-helper-request.schema.json").read_text(encoding="utf-8")
    )
    assert checked_in == helper_request_schema()
    checked_in_response = json.loads(
        (root / "schemas/privileged-helper-response.schema.json").read_text(encoding="utf-8")
    )
    assert checked_in_response == helper_response_schema()


def test_privileged_helper_valid_golden_frames() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures/privileged_helper/valid"
    parsed = {
        path.name: parse_helper_request_frame(
            path.read_bytes(), now_unix_milliseconds=_NOW_MILLISECONDS
        )
        for path in sorted(root.glob("*.jsonl"))
    }
    assert isinstance(parsed["health.jsonl"], HelperHealthRequest)
    assert isinstance(parsed["record.jsonl"], HelperCollectPidRequest)
    assert isinstance(parsed["stat.jsonl"], HelperCollectPidRequest)


@pytest.mark.parametrize(
    "fixture",
    sorted(
        (Path(__file__).resolve().parents[1] / "fixtures/privileged_helper/invalid").glob("*.jsonl")
    ),
    ids=lambda path: path.name,
)
def test_privileged_helper_invalid_golden_frames_are_rejected(fixture: Path) -> None:
    with pytest.raises(PerfLensError):
        parse_helper_request_frame(fixture.read_bytes(), now_unix_milliseconds=_NOW_MILLISECONDS)


def test_privileged_helper_rejects_missing_newline_and_trailing_frame() -> None:
    valid = b'{"schema_version":"1.1","operation":"health","request_id":"request-0123456789abcdef"}'
    with pytest.raises(PerfLensError):
        parse_helper_request_frame(valid, now_unix_milliseconds=_NOW_MILLISECONDS)
    with pytest.raises(PerfLensError):
        parse_helper_request_frame(valid + b"\n{}\n", now_unix_milliseconds=_NOW_MILLISECONDS)


def test_privileged_helper_response_requires_exactly_one_payload() -> None:
    with pytest.raises(ValueError):
        HelperResponse(
            request_id="request-0123456789abcdef",
            ok=True,
            result=None,
            error=None,
        )


@pytest.mark.parametrize(
    "updates",
    [
        {
            "actual_event_source": "hardware",
            "fallback_used": True,
            "fallback_reason": "hardware_probe_failed",
        },
        {"actual_event_source": "software", "events": ("cycles",)},
        {"actual_event_source": "hardware", "events": ("task-clock",)},
        {"record_event": "cycles"},
    ],
)
def test_helper_collection_result_rejects_inconsistent_event_provenance(
    updates: dict[str, object],
) -> None:
    fields: dict[str, object] = {
        "kind": "collection",
        "plan_id": "plan-0123456789abcdefabcd",
        "mode": "stat",
        "target_pid": 1234,
        "artifact_name": "plan-0123456789abcdefabcd.stat.csv",
        "output_bytes": 1,
        "output_sha256": "a" * 64,
        "output_format": "perf_stat_delimited",
        "actual_event_source": "hardware",
        "fallback_used": False,
        "events": ("cycles",),
        "started_at_unix_milliseconds": 1,
        "finished_at_unix_milliseconds": 2,
    }
    fields.update(updates)

    with pytest.raises(ValueError):
        HelperCollectionResult.model_validate(fields)


@pytest.mark.parametrize(
    "fields",
    [
        {
            "mode": "stat",
            "events": ("cycles",),
            "requested_event_source": "auto",
            "fallback_allowed": True,
            "fallback_events": ("task-clock",),
        },
        {
            "mode": "record",
            "events": (),
            "frequency_hz": 99,
            "call_graph": "dwarf",
            "record_event": "cycles",
            "requested_event_source": "auto",
            "fallback_allowed": True,
        },
        {
            "mode": "stat",
            "events": ("cycles",),
            "requested_event_source": "hardware_required",
            "fallback_allowed": True,
            "fallback_events": (
                "task-clock",
                "context-switches",
                "cpu-migrations",
                "page-faults",
            ),
        },
        {
            "mode": "stat",
            "events": ("cycles",),
            "requested_event_source": "hardware_required",
            "fallback_allowed": False,
            "fallback_events": ("task-clock",),
        },
        {
            "mode": "record",
            "events": (),
            "frequency_hz": 99,
            "call_graph": "dwarf",
            "record_event": "cycles",
            "requested_event_source": "software_only",
            "fallback_allowed": False,
        },
        {
            "mode": "stat",
            "events": ("cycles",),
            "requested_event_source": "software_only",
            "fallback_allowed": False,
        },
        {
            "mode": "stat",
            "events": ("task-clock",),
            "requested_event_source": "hardware_required",
            "fallback_allowed": False,
        },
        {
            "mode": "record",
            "events": (),
            "frequency_hz": 99,
            "call_graph": "dwarf",
            "record_event": "cpu-clock",
            "requested_event_source": "hardware_required",
            "fallback_allowed": False,
        },
    ],
)
def test_helper_collect_request_rejects_inconsistent_fallback_policy(
    fields: dict[str, object],
) -> None:
    request = {
        "request_id": "request-0123456789abcdef",
        "plan_id": "plan-0123456789abcdefabcd",
        "caller_uid": 1000,
        "target": {"pid": 1234, "uid": 1000, "start_time_ticks": 5678},
        "duration_milliseconds": 1000,
        "max_output_bytes": 1024,
        "expires_at_unix_milliseconds": _NOW_MILLISECONDS + 1000,
        **fields,
    }

    with pytest.raises(ValueError):
        HelperCollectPidRequest.model_validate(request)
