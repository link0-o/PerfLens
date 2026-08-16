"""Small, fully verified Trace artifacts for storage and transport tests."""

from __future__ import annotations

import hashlib

from perflens.application.trace_evidence import (
    compute_trace_capture_fingerprint,
    compute_trace_conversion_fingerprint,
    compute_trace_evidence_content_sha256,
    compute_trace_evidence_fingerprint,
    normalized_trace_ndjson_identity,
)
from perflens.contracts.trace import (
    TraceCaptureManifest,
    TraceConversionManifest,
    TraceEventFormatIdentity,
    TraceEvidenceArtifact,
)


def make_scheduler_trace_evidence(
    raw: bytes = b"private scheduler trace",
) -> TraceEvidenceArtifact:
    """Build a compact scheduler artifact without exposing a private source path."""
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    capture = _capture()
    conversion = _conversion()
    events = (
        {
            "event_type": "sched_switch",
            "event_id": "event-0000000000000001",
            "event_index": 0,
            "source_sequence": 1,
            "timestamp_ns": 10,
            "cpu": 0,
            "target_pid": 4242,
            "target_tid": 4242,
            "direction": "switch_in",
        },
        {
            "event_type": "sched_switch",
            "event_id": "event-0000000000000002",
            "event_index": 1,
            "source_sequence": 2,
            "timestamp_ns": 30,
            "cpu": 0,
            "target_pid": 4242,
            "target_tid": 4242,
            "direction": "switch_out",
            "previous_state": "running",
        },
    )
    common = {
        "schema_version": "1.0",
        "perflens_version": "0.3.0",
        "mode": "sched",
        "status": "complete",
        "input_sha256": raw_sha256,
        "input_bytes": len(raw),
        "source": {
            "collection_id": "collection-1111111111111111",
            "mode": "sched",
            "collection_artifact_sha256": "b" * 64,
            "output_sha256": raw_sha256,
            "output_bytes": len(raw),
            "output_format": "perf_data",
            "capture": capture.model_dump(mode="json"),
        },
        "target": {
            "target_pid": 4242,
            "target_uid": 1000,
            "target_start_time_ticks": 998877,
            "observed_target_tids": [4242],
        },
        "conversion": conversion.model_dump(mode="json"),
        "clock": {
            "clock": "monotonic",
            "unit": "nanoseconds",
            "source": "linux_perf",
        },
        "observation_window": {
            "start_timestamp_ns": 10,
            "end_timestamp_ns": 30,
            "source": "observed_event_bounds",
        },
        "quality": {
            "quality_status": "verified",
            "input_event_count": 2,
            "emitted_event_count": 2,
            "lost_event_count": 0,
            "malformed_event_count": 0,
            "duplicate_event_count": 0,
            "out_of_order_event_count": 0,
            "unpaired_event_count": 0,
            "unsupported_event_count": 0,
            "truncated_event_count": 0,
            "foreign_event_dropped_count": 0,
        },
        "limits": {
            "max_duration_seconds": 10,
            "max_input_bytes": 4096,
            "max_input_lines": 100,
            "max_input_events": 100,
            "max_line_bytes": 4096,
            "max_stack_depth": 32,
            "max_exported_events": 100,
            "max_exported_intervals": 100,
            "max_unique_target_tids": 8,
            "max_unique_locks": 8,
            "max_diagnostics": 8,
            "max_warnings": 8,
            "max_output_bytes": 1_048_576,
        },
        "allowed_conclusions": ["target_scheduler_transition_distribution"],
        "forbidden_conclusions": [
            "performance_root_cause",
            "verified_improvement",
            "unqualified_trace_conclusion",
        ],
        "content_sha256": "0" * 64,
        "input_line_count": 2,
        "diagnostic_count": 0,
    }
    typed_events = TraceEvidenceArtifact.model_validate(
        {
            **common,
            "trace_evidence_id": "trace-evidence-0000000000000000",
            "evidence_fingerprint": "0" * 64,
            "normalized_ndjson_sha256": "0" * 64,
            "normalized_ndjson_bytes": 1,
            "events": events,
        }
    ).events
    ndjson_sha256, ndjson_bytes = normalized_trace_ndjson_identity(typed_events)
    provisional = TraceEvidenceArtifact.model_validate(
        {
            **common,
            "trace_evidence_id": "trace-evidence-0000000000000000",
            "evidence_fingerprint": "0" * 64,
            "normalized_ndjson_sha256": ndjson_sha256,
            "normalized_ndjson_bytes": ndjson_bytes,
            "events": events,
        }
    )
    fingerprint = compute_trace_evidence_fingerprint(provisional)
    identified = provisional.model_copy(
        update={
            "trace_evidence_id": f"trace-evidence-{fingerprint[:16]}",
            "evidence_fingerprint": fingerprint,
        }
    )
    return identified.model_copy(
        update={"content_sha256": compute_trace_evidence_content_sha256(identified)}
    )


def _capture() -> TraceCaptureManifest:
    provisional = TraceCaptureManifest(
        mode="sched",
        backend_id="target_filtered_kernel_v1",
        backend_version="test-v1",
        producer_path="/usr/lib/perflens/perflens-trace-helper",
        producer_sha256="c" * 64,
        kernel_release="6.12-test",
        architecture="x86_64",
        byte_order="little",
        pointer_size_bits=64,
        target_scope="kernel_tgid_filtered",
        dynamic_thread_coverage="complete",
        switch_in_visibility="complete",
        external_wakeup_visibility="complete",
        foreign_metadata_before_userspace=False,
        event_formats=(
            TraceEventFormatIdentity(
                event_name="perflens:typed_trace",
                format_sha256="d" * 64,
            ),
        ),
        capture_fingerprint="0" * 64,
    )
    return provisional.model_copy(
        update={"capture_fingerprint": compute_trace_capture_fingerprint(provisional)}
    )


def _conversion() -> TraceConversionManifest:
    provisional = TraceConversionManifest(
        recipe_id="sched-v1",
        converter_path="/usr/bin/perf",
        converter_sha256="e" * 64,
        converter_version="perf version test",
        parser_version="trace-perf-script-v1",
        normalization_version="trace-normalizer-v1",
        argv=(
            "/usr/bin/perf",
            "script",
            "--force",
            "--ns",
            "--show-lost-events",
            "-F",
            "trace:pid,tid,cpu,time,event,trace",
            "-i",
            "<private-input>",
        ),
        locale="C",
        conversion_fingerprint="0" * 64,
    )
    return provisional.model_copy(
        update={
            "conversion_fingerprint": compute_trace_conversion_fingerprint(provisional)
        }
    )
