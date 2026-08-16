from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from perflens.contracts.runtime_locks import (
    RuntimeAdapterCapabilityArtifact,
    RuntimeLockAggregate,
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockEvidenceArtifact,
    RuntimeLockImportHeader,
    RuntimeLockVerificationCheck,
    RuntimeNanosecondDistribution,
    RuntimeSourceManifest,
    RuntimeToolIdentity,
)

ZERO_SHA = "0" * 64
ONE_SHA = "1" * 64


def _target() -> dict[str, Any]:
    return {
        "target_pid": 100,
        "target_uid": 1000,
        "target_start_time_ticks": 55,
        "observed_target_tids": [100, 101],
    }


def _tool() -> dict[str, Any]:
    return {
        "name": "python3",
        "path": "/usr/bin/python3",
        "version": "Python 3.13.5",
        "binary_sha256": ZERO_SHA,
        "status": "available",
    }


def _source(*, semantics: str = "exact", **overrides: Any) -> dict[str, Any]:
    source: dict[str, Any] = {
        "runtime": "python",
        "adapter_id": "cpython-locks",
        "adapter_version": "runtime-lock-adapter-v1",
        "backend_id": "strict-ndjson-import",
        "backend_version": "1",
        "measurement_semantics": semantics,
        "source_format": "perflens_runtime_lock_ndjson_v1",
        "source_sha256": ZERO_SHA,
        "source_bytes": 512,
        "conversion_fingerprint": ONE_SHA,
        "clock": {"clock": "monotonic"},
        "fast_path_visibility": "partial",
        "owner_is_source_observed": False,
        "hold_time_is_source_observed": False,
        "target_scope": "verified_import",
        "tool": _tool(),
    }
    if semantics == "thresholded":
        source["duration_threshold_ns"] = 10_000_000
    elif semantics == "sampled":
        source["sampling_fraction"] = 5
    elif semantics == "cumulative":
        source["block_profile_rate_ns"] = 1_000_000
    source.update(overrides)
    return source


def _quality(*, semantics: str = "exact", status: str = "complete") -> dict[str, Any]:
    counts = {
        "exact_event_count": 2 if semantics == "exact" else 0,
        "thresholded_event_count": 2 if semantics == "thresholded" else 0,
        "sampled_event_count": 2 if semantics == "sampled" else 0,
        "cumulative_event_count": 2 if semantics == "cumulative" else 0,
    }
    return {
        "status": status,
        "input_record_count": 2,
        "emitted_event_count": 2,
        "filtered_outside_target_count": 0,
        "malformed_record_count": 0,
        "duplicate_record_count": 0,
        "unsupported_record_count": 0,
        "lost_event_count": 0,
        "truncated_event_count": 0,
        **counts,
        "owner_observed_event_count": 0,
        "diagnostic_count": 0,
        "diagnostics_truncated": False,
        "diagnostics": [],
        "limitations": [] if status == "complete" else ["test limitation"],
    }


def _events(*, semantics: str = "exact") -> list[dict[str, Any]]:
    return [
        {
            "event_kind": "wait_begin",
            "event_id": "runtime-event-" + "a" * 16,
            "event_index": 0,
            "timestamp_ns": 100,
            "target_tid": 101,
            "lock_id": "runtime-lock-" + "a" * 20,
            "lock_kind": "mutex",
            "measurement_semantics": semantics,
        },
        {
            "event_kind": "wait_end",
            "event_id": "runtime-event-" + "b" * 16,
            "event_index": 1,
            "timestamp_ns": 150,
            "target_tid": 101,
            "lock_id": "runtime-lock-" + "a" * 20,
            "lock_kind": "mutex",
            "measurement_semantics": semantics,
            "wait_begin_event_id": "runtime-event-" + "a" * 16,
            "duration_ns": 50,
            "outcome": "acquired",
        },
    ]


def _evidence(*, semantics: str = "exact", **overrides: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "runtime_lock_evidence_id": "runtime-lock-evidence-" + "a" * 16,
        "created_at": "2026-08-16T00:00:00+00:00",
        "target": _target(),
        "source": _source(semantics=semantics),
        "limits": {},
        "quality": _quality(semantics=semantics),
        "stacks": [],
        "events": _events(semantics=semantics),
        "allowed_conclusions": ["observed_runtime_wait_distribution"],
        "forbidden_conclusions": [
            "exact_hold_time",
            "exact_owner_relationship",
            *([] if semantics == "exact" else ["exact_contention_count"]),
        ],
        "evidence_fingerprint": ZERO_SHA,
        "content_sha256": ONE_SHA,
        "content_bytes": 1024,
    }
    evidence.update(overrides)
    return evidence


def _zero_distribution() -> dict[str, int]:
    return {
        "sample_count": 0,
        "total_ns": 0,
        "minimum_ns": 0,
        "mean_ns": 0,
        "p50_ns": 0,
        "p95_ns": 0,
        "p99_ns": 0,
        "maximum_ns": 0,
    }


def _one_distribution() -> dict[str, int]:
    return {
        "sample_count": 1,
        "total_ns": 50,
        "minimum_ns": 50,
        "mean_ns": 50,
        "p50_ns": 50,
        "p95_ns": 50,
        "p99_ns": 50,
        "maximum_ns": 50,
    }


def test_available_capability_requires_concrete_observable_semantics() -> None:
    capability = RuntimeAdapterCapabilityArtifact.model_validate(
        {
            "capability_id": "runtime-capability-" + "a" * 16,
            "created_at": "2026-08-16T00:00:00+00:00",
            "runtime": "python",
            "runtime_name": "CPython",
            "runtime_version": "3.13.5",
            "runtime_build": "main",
            "adapter_id": "cpython-locks",
            "adapter_version": "runtime-lock-adapter-v1",
            "backend_id": "usdt-import",
            "availability": "available",
            "supported_lock_kinds": ["gil", "mutex"],
            "supported_event_kinds": ["wait_begin", "wait_end"],
            "measurement_semantics": ["exact"],
            "fast_path_visibility": "partial",
            "owner_visibility": "unavailable",
            "hold_time_visibility": "unavailable",
            "launch_instrumentation_required": False,
            "attach_required": False,
            "privileged_backend_required": False,
            "tools": [_tool()],
            "content_sha256": ZERO_SHA,
        }
    )
    assert capability.availability == "available"

    payload = capability.model_dump(mode="json")
    payload["supported_event_kinds"] = []
    with pytest.raises(ValidationError, match="observable semantics"):
        RuntimeAdapterCapabilityArtifact.model_validate(payload)


def test_unavailable_capability_cannot_advertise_active_events() -> None:
    with pytest.raises(ValidationError, match="cannot claim active observations"):
        RuntimeAdapterCapabilityArtifact.model_validate(
            {
                "capability_id": "runtime-capability-" + "a" * 16,
                "created_at": "2026-08-16T00:00:00+00:00",
                "runtime": "go",
                "runtime_name": "Go",
                "adapter_id": "go-pprof-locks",
                "adapter_version": "1",
                "backend_id": "go-tool-pprof",
                "availability": "unavailable",
                "supported_event_kinds": ["sampled_contention"],
                "measurement_semantics": ["cumulative"],
                "fast_path_visibility": "unknown",
                "owner_visibility": "unavailable",
                "hold_time_visibility": "unavailable",
                "launch_instrumentation_required": False,
                "attach_required": False,
                "privileged_backend_required": False,
                "limitations": ["go tool is missing"],
                "content_sha256": ZERO_SHA,
            }
        )


def test_available_tool_identity_is_complete_and_absolute() -> None:
    assert RuntimeToolIdentity.model_validate(_tool()).status == "available"
    invalid = _tool()
    invalid["path"] = "python3"
    with pytest.raises(ValidationError, match="absolute"):
        RuntimeToolIdentity.model_validate(invalid)


@pytest.mark.parametrize(
    ("semantics", "missing_field"),
    [
        ("thresholded", "duration_threshold_ns"),
        ("sampled", "sampling_fraction"),
        ("cumulative", "block_profile_rate_ns"),
    ],
)
def test_source_manifest_requires_declared_measurement_controls(
    semantics: str, missing_field: str
) -> None:
    payload = _source(semantics=semantics)
    del payload[missing_field]
    with pytest.raises(ValidationError):
        RuntimeSourceManifest.model_validate(payload)


def test_import_header_is_strict_and_has_no_path_or_command_surface() -> None:
    header = RuntimeLockImportHeader.model_validate(
        {
            "runtime": "custom",
            "runtime_version": "1",
            "adapter_id": "custom-import",
            "adapter_version": "1",
            "backend_id": "strict-ndjson",
            "backend_version": "1",
            "target": _target(),
            "clock": {"clock": "monotonic"},
            "measurement_semantics": "exact",
            "visible_lock_kinds": ["custom"],
            "fast_path_visibility": "partial",
            "owner_is_source_observed": False,
            "hold_time_is_source_observed": False,
            "declared_event_count": 2,
            "declared_lost_event_count": 0,
            "declared_truncated": False,
        }
    )
    assert header.record_type == "runtime_lock_header"
    with pytest.raises(ValidationError, match="Extra inputs"):
        RuntimeLockImportHeader.model_validate(
            {**header.model_dump(mode="json"), "command": ["arbitrary"]}
        )


@pytest.mark.parametrize("semantics", ["exact", "thresholded"])
def test_event_evidence_preserves_exact_or_thresholded_semantics(semantics: str) -> None:
    evidence = RuntimeLockEvidenceArtifact.model_validate(_evidence(semantics=semantics))
    assert evidence.source.measurement_semantics == semantics
    assert len(evidence.events) == 2


def test_non_exact_evidence_must_forbid_exact_contention_counts() -> None:
    payload = _evidence(semantics="thresholded")
    payload["forbidden_conclusions"] = ["exact_hold_time", "exact_owner_relationship"]
    with pytest.raises(ValidationError, match="forbid exact contention"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_evidence_rejects_foreign_tid_and_unknown_stack() -> None:
    payload = _evidence()
    payload["events"][0]["target_tid"] = 999
    with pytest.raises(ValidationError, match="escaped"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][0]["stack_id"] = "runtime-stack-" + "a" * 16
    with pytest.raises(ValidationError, match="unknown stack"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_evidence_rejects_count_and_order_tampering() -> None:
    payload = _evidence()
    payload["quality"]["input_record_count"] = 3
    with pytest.raises(ValidationError, match="not conserved"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][1]["event_index"] = 2
    with pytest.raises(ValidationError, match="contiguous"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_partial_evidence_requires_unqualified_conclusion_boundary() -> None:
    payload = _evidence()
    payload["quality"] = _quality(status="partial")
    with pytest.raises(ValidationError, match="unqualified"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_evidence_rejects_fabricated_owner_and_hold_visibility() -> None:
    payload = _evidence()
    payload["events"][0]["owner_target_tid"] = 100
    payload["quality"]["owner_observed_event_count"] = 1
    with pytest.raises(ValidationError, match="fabricated owner"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"] = [
        {
            "event_kind": "acquire",
            "event_id": "runtime-event-" + "a" * 16,
            "event_index": 0,
            "timestamp_ns": 100,
            "target_tid": 101,
            "lock_id": "runtime-lock-" + "a" * 20,
            "lock_kind": "mutex",
            "measurement_semantics": "exact",
        },
        {
            "event_kind": "release",
            "event_id": "runtime-event-" + "b" * 16,
            "event_index": 1,
            "timestamp_ns": 150,
            "target_tid": 101,
            "lock_id": "runtime-lock-" + "a" * 20,
            "lock_kind": "mutex",
            "measurement_semantics": "exact",
            "acquire_event_id": "runtime-event-" + "a" * 16,
            "hold_duration_ns": 50,
        },
    ]
    with pytest.raises(ValidationError, match="fabricated hold"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_evidence_enforces_resource_and_diagnostic_limits() -> None:
    payload = _evidence()
    payload["limits"] = {"max_source_bytes": 511}
    with pytest.raises(ValidationError, match="max_source_bytes"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["quality"].update(
        {
            "status": "partial",
            "diagnostic_count": 2,
            "diagnostics_truncated": True,
            "diagnostics": ["one bounded diagnostic"],
            "limitations": ["adapter diagnostics were emitted"],
        }
    )
    payload["limits"] = {"max_diagnostics": 1}
    with pytest.raises(ValidationError, match="max_diagnostics"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_release_requires_paired_identity_and_duration() -> None:
    payload = _evidence()
    payload["events"][1] = {
        "event_kind": "release",
        "event_id": "runtime-event-" + "b" * 16,
        "event_index": 1,
        "timestamp_ns": 150,
        "target_tid": 101,
        "lock_id": "runtime-lock-" + "a" * 20,
        "lock_kind": "mutex",
        "measurement_semantics": "exact",
        "hold_duration_ns": 50,
    }
    with pytest.raises(ValidationError, match="identity and duration together"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_distribution_rejects_non_floor_mean_and_non_monotonic_quantiles() -> None:
    payload = _one_distribution()
    payload["mean_ns"] = 49
    with pytest.raises(ValidationError, match="integer floor"):
        RuntimeNanosecondDistribution.model_validate(payload)

    payload = _one_distribution()
    payload["p95_ns"] = 60
    with pytest.raises(ValidationError, match="monotonic"):
        RuntimeNanosecondDistribution.model_validate(payload)


def test_analysis_aggregate_counts_are_conserved() -> None:
    aggregate = RuntimeLockAggregate.model_validate(
        {
            "lock_id": "runtime-lock-" + "a" * 20,
            "lock_kind": "mutex",
            "exact_waits": _one_distribution(),
            "thresholded_waits": _zero_distribution(),
            "sampled_observation_count": 0,
            "cumulative_observation_count": 0,
            "observed_or_estimated_wait_ns": 50,
            "exact_holds": _zero_distribution(),
            "waiter_thread_count": 1,
            "owner_observed_count": 0,
        }
    )
    payload: dict[str, Any] = {
        "runtime_lock_analysis_id": "runtime-lock-analysis-" + "a" * 16,
        "runtime_lock_evidence_id": "runtime-lock-evidence-" + "a" * 16,
        "runtime_lock_evidence_content_sha256": ZERO_SHA,
        "runtime_lock_evidence_content_bytes": 1024,
        "created_at": "2026-08-16T00:00:00+00:00",
        "runtime": "python",
        "measurement_semantics": "exact",
        "quality_status": "complete",
        "limits": {},
        "aggregates": [aggregate.model_dump(mode="json")],
        "total_exact_wait_count": 1,
        "total_thresholded_wait_count": 0,
        "total_sampled_observation_count": 0,
        "total_cumulative_observation_count": 0,
        "total_exact_hold_count": 0,
        "omitted_lock_count": 0,
        "allowed_conclusions": ["observed_runtime_wait_distribution"],
        "forbidden_conclusions": ["exact_owner_relationship", "exact_hold_time"],
        "analysis_fingerprint": ONE_SHA,
        "content_sha256": ZERO_SHA,
        "content_bytes": 512,
    }
    analysis = RuntimeLockAnalysisArtifact.model_validate(payload)
    assert analysis.total_exact_wait_count == 1

    payload["total_exact_wait_count"] = 2
    with pytest.raises(ValidationError, match="not conserved"):
        RuntimeLockAnalysisArtifact.model_validate(payload)


def test_non_exact_analysis_cannot_claim_exact_count() -> None:
    payload: dict[str, Any] = {
        "runtime_lock_analysis_id": "runtime-lock-analysis-" + "a" * 16,
        "runtime_lock_evidence_id": "runtime-lock-evidence-" + "a" * 16,
        "runtime_lock_evidence_content_sha256": ZERO_SHA,
        "runtime_lock_evidence_content_bytes": 1024,
        "created_at": "2026-08-16T00:00:00+00:00",
        "runtime": "go",
        "measurement_semantics": "cumulative",
        "quality_status": "complete",
        "limits": {},
        "aggregates": [],
        "total_exact_wait_count": 0,
        "total_thresholded_wait_count": 0,
        "total_sampled_observation_count": 0,
        "total_cumulative_observation_count": 0,
        "total_exact_hold_count": 0,
        "omitted_lock_count": 0,
        "allowed_conclusions": ["cumulative_runtime_contention_distribution"],
        "forbidden_conclusions": ["exact_owner_relationship"],
        "analysis_fingerprint": ONE_SHA,
        "content_sha256": ZERO_SHA,
        "content_bytes": 512,
    }
    with pytest.raises(ValidationError, match="forbid exact counts"):
        RuntimeLockAnalysisArtifact.model_validate(payload)


def test_verification_status_is_derived_from_checks() -> None:
    passed = RuntimeLockVerificationCheck(
        name="content_hash", status="passed", detail="content digest matches"
    )
    verification = RuntimeLockAnalysisVerificationArtifact.model_validate(
        {
            "runtime_lock_verification_id": "runtime-lock-verification-" + "a" * 16,
            "runtime_lock_evidence_id": "runtime-lock-evidence-" + "a" * 16,
            "runtime_lock_evidence_content_sha256": ZERO_SHA,
            "runtime_lock_analysis_id": "runtime-lock-analysis-" + "a" * 16,
            "runtime_lock_analysis_content_sha256": ONE_SHA,
            "created_at": "2026-08-16T00:00:00+00:00",
            "verification_status": "verified",
            "checks": [passed.model_dump(mode="json")],
            "content_sha256": ZERO_SHA,
        }
    )
    assert verification.verification_status == "verified"

    payload = verification.model_dump(mode="json")
    payload["checks"][0]["status"] = "failed"
    with pytest.raises(ValidationError, match="contradicts"):
        RuntimeLockAnalysisVerificationArtifact.model_validate(payload)
