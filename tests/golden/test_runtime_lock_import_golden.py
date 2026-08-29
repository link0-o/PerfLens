from __future__ import annotations

import json
from pathlib import Path

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.runtime_lock_evidence import canonical_runtime_lock_json_sha256
from perflens.application.verify_runtime_locks import verify_runtime_lock_analysis_artifact
from perflens.runtime_locks import import_runtime_lock_ndjson


def test_runtime_lock_import_matches_privacy_safe_golden(fixture_root: Path) -> None:
    source = fixture_root / "runtime_locks" / "valid-v1.1.ndjson"
    with source.open("rb") as stream:
        evidence = import_runtime_lock_ndjson(
            stream,
            created_at="2026-08-30T00:00:00+00:00",
        )
    actual = {
        "schema_version": evidence.schema_version,
        "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
        "evidence_fingerprint": evidence.evidence_fingerprint,
        "content_sha256": evidence.content_sha256,
        "content_bytes": evidence.content_bytes,
        "source": evidence.source.model_dump(mode="json", exclude_none=True),
        "quality": evidence.quality.model_dump(mode="json", exclude_none=True),
        "contexts": [
            context.model_dump(mode="json", exclude_none=True)
            for context in evidence.execution_contexts
        ],
        "stacks": [stack.model_dump(mode="json", exclude_none=True) for stack in evidence.stacks],
        "events": [event.model_dump(mode="json", exclude_none=True) for event in evidence.events],
        "allowed_conclusions": list(evidence.allowed_conclusions),
        "forbidden_conclusions": list(evidence.forbidden_conclusions),
    }
    expected = json.loads(
        (fixture_root / "golden" / "runtime-lock-import.summary.json").read_text(encoding="utf-8")
    )

    assert actual == expected


def test_runtime_lock_analysis_and_verification_match_golden(fixture_root: Path) -> None:
    source = fixture_root / "runtime_locks" / "valid-v1.1.ndjson"
    with source.open("rb") as stream:
        evidence = import_runtime_lock_ndjson(
            stream,
            created_at="2026-08-30T00:00:00+00:00",
        )
    analysis = build_runtime_lock_analysis(evidence)
    with source.open("rb") as stream:
        verification = verify_runtime_lock_analysis_artifact(
            analysis,
            evidence,
            private_source_stream=stream,
        )
    assert analysis.lock_coverage is not None
    assert analysis.execution_context_coverage is not None
    assert analysis.call_path_coverage is not None
    assert analysis.wait_outcome_coverage is not None
    assert analysis.lock_kind_coverage is not None
    actual = {
        "analysis": {
            "schema_version": analysis.schema_version,
            "runtime_lock_analysis_id": analysis.runtime_lock_analysis_id,
            "runtime_lock_evidence_id": analysis.runtime_lock_evidence_id,
            "runtime_lock_evidence_content_sha256": (analysis.runtime_lock_evidence_content_sha256),
            "runtime_lock_evidence_content_bytes": analysis.runtime_lock_evidence_content_bytes,
            "quality_status": analysis.quality_status,
            "measurement_semantics": analysis.measurement_semantics,
            "totals": {
                "exact_wait_count": analysis.total_exact_wait_count,
                "exact_wait_ns": analysis.total_exact_wait_ns,
                "thresholded_wait_count": analysis.total_thresholded_wait_count,
                "thresholded_wait_ns": analysis.total_thresholded_wait_ns,
                "sampled_observation_count": analysis.total_sampled_observation_count,
                "cumulative_observation_count": analysis.total_cumulative_observation_count,
                "observed_or_estimated_wait_ns": analysis.total_observed_or_estimated_wait_ns,
                "exact_hold_count": analysis.total_exact_hold_count,
                "exact_hold_ns": analysis.total_exact_hold_ns,
                "owner_observed_count": analysis.total_owner_observed_count,
            },
            "projection_sha256": {
                "locks": canonical_runtime_lock_json_sha256(analysis.aggregates),
                "contexts": canonical_runtime_lock_json_sha256(
                    analysis.execution_context_aggregates
                ),
                "call_paths": canonical_runtime_lock_json_sha256(analysis.call_path_aggregates),
                "outcomes": canonical_runtime_lock_json_sha256(analysis.wait_outcome_aggregates),
                "lock_kinds": canonical_runtime_lock_json_sha256(analysis.lock_kind_aggregates),
            },
            "coverage": {
                "locks": analysis.lock_coverage.model_dump(mode="json"),
                "contexts": analysis.execution_context_coverage.model_dump(mode="json"),
                "call_paths": analysis.call_path_coverage.model_dump(mode="json"),
                "outcomes": analysis.wait_outcome_coverage.model_dump(mode="json"),
                "lock_kinds": analysis.lock_kind_coverage.model_dump(mode="json"),
            },
            "allowed_conclusions": list(analysis.allowed_conclusions),
            "forbidden_conclusions": list(analysis.forbidden_conclusions),
            "analysis_fingerprint": analysis.analysis_fingerprint,
            "content_sha256": analysis.content_sha256,
            "content_bytes": analysis.content_bytes,
        },
        "verification": verification.model_dump(mode="json", exclude_none=True),
    }
    expected = json.loads(
        (fixture_root / "golden" / "runtime-lock-analysis-verification.summary.json").read_text(
            encoding="utf-8"
        )
    )

    assert actual == expected
