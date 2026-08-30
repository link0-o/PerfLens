from __future__ import annotations

import json
from pathlib import Path

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.runtime_lock_evidence import canonical_runtime_lock_json_sha256
from perflens.application.verify_runtime_locks import verify_runtime_lock_analysis_artifact
from perflens.runtime_locks.native_pthread_converter import convert_native_pthread_probe


def test_native_pthread_conversion_analysis_matches_golden(fixture_root: Path) -> None:
    source = fixture_root / "runtime_locks" / "native-pthread-exact.ndjson"
    with source.open("rb") as stream:
        receipt = convert_native_pthread_probe(
            stream,
            created_at="2026-08-30T00:00:00+00:00",
        )
    evidence = receipt.evidence
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
    actual = {
        "receipt": {
            "raw_source_sha256": receipt.raw_source_sha256,
            "raw_source_bytes": receipt.raw_source_bytes,
            "normalized_source_sha256": receipt.normalized_source_sha256,
            "normalized_source_bytes": receipt.normalized_source_bytes,
        },
        "evidence": {
            "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
            "source": evidence.source.model_dump(mode="json", exclude_none=True),
            "quality": evidence.quality.model_dump(mode="json", exclude_none=True),
            "target": evidence.target.model_dump(mode="json", exclude_none=True),
            "normalized_sha256": canonical_runtime_lock_json_sha256(
                {
                    "contexts": evidence.execution_contexts,
                    "stacks": evidence.stacks,
                    "events": evidence.events,
                }
            ),
            "allowed_conclusions": list(evidence.allowed_conclusions),
            "forbidden_conclusions": list(evidence.forbidden_conclusions),
            "evidence_fingerprint": evidence.evidence_fingerprint,
            "content_sha256": evidence.content_sha256,
            "content_bytes": evidence.content_bytes,
        },
        "analysis": {
            "runtime_lock_analysis_id": analysis.runtime_lock_analysis_id,
            "quality_status": analysis.quality_status,
            "measurement_semantics": analysis.measurement_semantics,
            "totals": {
                "exact_wait_count": analysis.total_exact_wait_count,
                "exact_wait_ns": analysis.total_exact_wait_ns,
                "exact_hold_count": analysis.total_exact_hold_count,
                "exact_hold_ns": analysis.total_exact_hold_ns,
                "owner_observed_count": analysis.total_owner_observed_count,
                "observed_or_estimated_wait_ns": (analysis.total_observed_or_estimated_wait_ns),
            },
            "projection_sha256": canonical_runtime_lock_json_sha256(
                {
                    "locks": analysis.aggregates,
                    "contexts": analysis.execution_context_aggregates,
                    "paths": analysis.call_path_aggregates,
                    "outcomes": analysis.wait_outcome_aggregates,
                    "kinds": analysis.lock_kind_aggregates,
                }
            ),
            "analysis_fingerprint": analysis.analysis_fingerprint,
            "content_sha256": analysis.content_sha256,
            "content_bytes": analysis.content_bytes,
        },
        "verification": verification.model_dump(mode="json", exclude_none=True),
    }
    expected = json.loads(
        (fixture_root / "golden" / "native-pthread-runtime-lock.summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert actual == expected
