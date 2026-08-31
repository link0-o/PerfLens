from __future__ import annotations

import json
from io import BytesIO
from typing import Literal

import pytest

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.cpython_converter import (
    convert_cpython_threading_stream,
    verify_cpython_threading_replay,
)

CREATED_AT = "2026-08-31T00:00:00+00:00"


def _binding(
    semantics: Literal["exact", "thresholded"] = "exact",
) -> RuntimeLockAdapterExecutionBinding:
    threshold = 10_000 if semantics == "thresholded" else None
    tools = (
        RuntimeLockAdapterToolBinding(
            name="python", version="3.13.7", binary_sha256="1" * 64
        ),
    )
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    identity = derive_runtime_lock_adapter_execution_identity(
        "cpython_threading",
        "cpython-threading-adapter-v1",
        "threading-bootstrap",
        "3.13.7",
        semantics,
        semantics,
        threshold,
        toolchain,
        "2" * 64,
        "3" * 64,
        "2" * 64,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="cpython_threading",
        adapter_version="cpython-threading-adapter-v1",
        backend_id="threading-bootstrap",
        runtime_version="3.13.7",
        profile=semantics,
        measurement_semantics=semantics,
        duration_threshold_ns=threshold,
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256="2" * 64,
        metadata_sha256="3" * 64,
        runtime_payload_identity_sha256="2" * 64,
        execution_identity_sha256=identity,
    )


def _raw(
    semantics: Literal["exact", "thresholded"] = "exact",
    *,
    duration: int | None = None,
    free_threaded: bool = False,
) -> bytes:
    threshold = 10_000 if semantics == "thresholded" else None
    wait_duration = duration if duration is not None else (20_000 if threshold else 10)
    records: list[dict[str, object]] = [
        {
            "schema_version": "1.0",
            "record_type": "cpython_header",
            "protocol": "cpython_threading_probe",
            "protocol_version": "1.0",
            "runtime_version": "3.13.7",
            "free_threaded": free_threaded,
            "pid": 9000,
            "uid": 1000,
            "target_start_time_ticks": 77,
            "semantics": semantics,
            "duration_threshold_ns": threshold,
            "max_events": 20_000,
            "visible_lock_kinds": ["condition", "mutex", "recursive_mutex", "semaphore"],
        },
        {
            "schema_version": "1.0",
            "record_type": "cpython_stack",
            "stack_id": "stack-1",
            "frames": [
                {
                    "symbol": "critical_section",
                    "module": "python",
                    "source_file": "workload.py",
                    "source_line": 12,
                    "is_runtime": False,
                    "is_unknown": False,
                }
            ],
        },
    ]
    common = {
        "schema_version": "1.0",
        "record_type": "cpython_event",
        "pid": 9000,
        "tid": 9001,
        "raw_lock_token": "lock-1",
        "lock_kind": "mutex",
        "stack_id": "stack-1",
    }
    records.extend(
        [
            {
                **common,
                "sequence": 1,
                "source_event_id": "event-1",
                "event_kind": "wait_begin",
                "timestamp_ns": 5,
                "related_source_event_id": None,
                "duration_ns": None,
                "result": "unknown",
            },
            {
                **common,
                "sequence": 2,
                "source_event_id": "event-2",
                "event_kind": "wait_end",
                "timestamp_ns": 5 + wait_duration,
                "related_source_event_id": "event-1",
                "duration_ns": wait_duration,
                "result": "acquired",
            },
            {
                **common,
                "sequence": 3,
                "source_event_id": "event-3",
                "event_kind": "acquire",
                "timestamp_ns": 5 + wait_duration,
                "related_source_event_id": "event-2",
                "duration_ns": None,
                "result": "acquired",
            },
            {
                **common,
                "sequence": 4,
                "source_event_id": "event-4",
                "event_kind": "release",
                "timestamp_ns": 10 + wait_duration,
                "related_source_event_id": None,
                "duration_ns": None,
                "result": "released",
            },
            {
                "schema_version": "1.0",
                "record_type": "cpython_footer",
                "protocol": "cpython_threading_probe",
                "pid": 9000,
                "sequence": 4,
                "declared_event_count": 4,
                "lost_event_count": 0,
                "truncated": False,
                "observed_target_tids": [9000, 9001],
            },
        ]
    )
    return b"".join(
        json.dumps(item, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        for item in records
    )


def test_exact_stream_converts_replays_and_hides_private_lock_identity() -> None:
    raw = _raw()
    receipt = convert_cpython_threading_stream(
        BytesIO(raw), execution_binding=_binding(), created_at=CREATED_AT
    )
    evidence = receipt.evidence

    assert evidence.source.runtime == "python"
    assert evidence.source.source_format == "cpython_threading_ndjson_v1"
    assert evidence.source.measurement_semantics == "exact"
    assert evidence.quality.status == "partial"
    assert len(evidence.events) == 4
    assert "lock-1" not in evidence.model_dump_json()
    assert "exact_owner_relationship" in evidence.forbidden_conclusions
    assert "exact_hold_time" in evidence.forbidden_conclusions
    assert verify_cpython_threading_replay(
        evidence, BytesIO(raw), execution_binding=_binding()
    )


def test_free_threaded_and_thresholded_semantics_remain_explicit() -> None:
    evidence = convert_cpython_threading_stream(
        BytesIO(_raw("thresholded", free_threaded=True)),
        execution_binding=_binding("thresholded"),
        created_at=CREATED_AT,
    ).evidence

    assert evidence.source.duration_threshold_ns == 10_000
    assert evidence.source.fast_path_visibility == "partial"
    assert "traditional_gil_conclusion" in evidence.forbidden_conclusions
    assert any("free-threaded" in item for item in evidence.quality.limitations)


def test_converter_rejects_below_threshold_and_false_duration_pairing() -> None:
    with pytest.raises(PerfLensError) as below:
        convert_cpython_threading_stream(
            BytesIO(_raw("thresholded", duration=9_999)),
            execution_binding=_binding("thresholded"),
        )
    assert below.value.code == ErrorCode.PROFILE_PARSE_FAILED

    payload = _raw().replace(b'"duration_ns":10', b'"duration_ns":9', 1)
    with pytest.raises(PerfLensError, match="impossible timing"):
        convert_cpython_threading_stream(BytesIO(payload), execution_binding=_binding())


def test_converter_rejects_unknown_fields_and_execution_binding_drift() -> None:
    payload = _raw().replace(
        b'"record_type":"cpython_header"',
        b'"extra":1,"record_type":"cpython_header"',
    )
    with pytest.raises(PerfLensError, match="strict validation"):
        convert_cpython_threading_stream(BytesIO(payload), execution_binding=_binding())

    with pytest.raises(PerfLensError, match="authorized execution controls"):
        convert_cpython_threading_stream(
            BytesIO(_raw()), execution_binding=_binding("thresholded")
        )


def test_truncated_stream_preserves_bounded_loss_without_claiming_complete_quality() -> None:
    records = [json.loads(line) for line in _raw().splitlines()]
    footer = records[-1]
    footer["lost_event_count"] = 3
    footer["truncated"] = True
    payload = b"".join(
        json.dumps(item, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        for item in records
    )

    evidence = convert_cpython_threading_stream(
        BytesIO(payload), execution_binding=_binding()
    ).evidence

    assert evidence.quality.status == "partial"
    assert evidence.quality.lost_event_count == 3
    assert "unqualified_runtime_lock_conclusion" in evidence.forbidden_conclusions
