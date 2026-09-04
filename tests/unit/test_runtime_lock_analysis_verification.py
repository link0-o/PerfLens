from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import NoReturn

import pytest

from perflens.application import analyze_runtime_locks as analyzer_module
from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_evidence import (
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
)
from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
    require_usable_runtime_lock_analysis,
    verify_runtime_lock_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_locks import (
    RuntimeLockEvidenceArtifact,
    RuntimeLockResourceLimits,
)
from perflens.domain import runtime_lock_analysis as domain_module
from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import import_runtime_lock_ndjson


def _raw(fixture_root: Path) -> bytes:
    return (fixture_root / "runtime_locks" / "valid-v1.1.ndjson").read_bytes()


def _evidence(fixture_root: Path) -> RuntimeLockEvidenceArtifact:
    return import_runtime_lock_ndjson(
        io.BytesIO(_raw(fixture_root)), created_at="2026-08-30T00:00:00+00:00"
    )


def _rehash_evidence(evidence: RuntimeLockEvidenceArtifact) -> RuntimeLockEvidenceArtifact:
    evidence = evidence.model_copy(
        update={"evidence_fingerprint": compute_runtime_lock_evidence_fingerprint(evidence)}
    )
    for _attempt in range(8):
        actual_bytes = len(serialize_json(evidence))
        if evidence.content_bytes == actual_bytes:
            break
        evidence = evidence.model_copy(update={"content_bytes": actual_bytes})
    return evidence.model_copy(
        update={"content_sha256": compute_runtime_lock_evidence_content_sha256(evidence)}
    )


def test_analysis_builds_all_five_projections_and_verified_replay(
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)

    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
    )

    assert analysis.schema_version == "1.1"
    assert analysis.total_exact_wait_count == 1
    assert analysis.total_exact_wait_ns == 50
    assert analysis.total_observed_or_estimated_wait_ns == 50
    assert analysis.total_exact_hold_count == 1
    assert analysis.total_exact_hold_ns == 50
    assert analysis.total_owner_observed_count == 1
    assert len(analysis.aggregates) == 1
    assert len(analysis.execution_context_aggregates) == 1
    assert len(analysis.call_path_aggregates) == 1
    assert len(analysis.wait_outcome_aggregates) == 1
    assert len(analysis.lock_kind_aggregates) == 1
    assert analysis.wait_outcome_aggregates[0].wait_outcome == "acquired"
    assert analysis.content_bytes > 0
    assert verification.verification_status == "verified"
    assert all(check.status == "passed" for check in verification.checks)
    assert verification.content_sha256 == contract_content_sha256(
        verification, exclude={"content_sha256"}
    )


def test_public_only_verification_is_explicitly_partial(fixture_root: Path) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)

    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)

    assert verification.verification_status == "partial"
    assert verification.checks[0].name == "source_identity"
    assert verification.checks[0].status == "skipped"
    require_usable_runtime_lock_analysis(verification)


def test_independent_verifier_rejects_resurrection_of_invalid_wait_begin(
    fixture_root: Path,
) -> None:
    records = [json.loads(line) for line in _raw(fixture_root).decode().splitlines()]
    header = records[0]
    header["declared_event_count"] = 3
    header["hold_time_is_source_observed"] = False
    first = records[2]
    duplicate = {**first, "source_event_id": "duplicate-wait", "timestamp_ns": 110}
    end = records[3]
    payload = "".join(
        json.dumps(record, separators=(",", ":")) + "\n"
        for record in (header, records[1], first, duplicate, end)
    ).encode()
    evidence = import_runtime_lock_ndjson(
        io.BytesIO(payload),
        created_at="2026-08-30T00:00:00+00:00",
    )

    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(payload),
    )

    assert analysis.quality_status == "partial"
    assert analysis.total_exact_wait_count == 0
    assert analysis.total_observed_or_estimated_wait_ns == 0
    assert verification.verification_status == "verified"
    assert all(check.status == "passed" for check in verification.checks)


def test_verifier_does_not_call_or_trust_application_analysis_builder(
    fixture_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)

    def broken_builder(_evidence: RuntimeLockEvidenceArtifact) -> NoReturn:
        raise AssertionError("verifier called the application Analysis builder")

    monkeypatch.setattr(
        analyzer_module,
        "build_runtime_lock_analysis",
        broken_builder,
    )

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
    )

    assert verification.verification_status == "verified"
    assert all(check.status == "passed" for check in verification.checks)


def test_verifier_does_not_call_or_trust_domain_replay_or_analyzer(
    fixture_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)

    def broken_domain(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("verifier called the Analyzer domain implementation")

    monkeypatch.setattr(domain_module, "replay_runtime_lock_events", broken_domain)
    monkeypatch.setattr(domain_module, "analyze_runtime_lock_events", broken_domain)

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
    )

    assert verification.verification_status == "verified"
    assert all(check.status == "passed" for check in verification.checks)


def test_tampered_totals_and_agent_projection_fail_independent_replay(
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    tampered = analysis.model_copy(update={"total_exact_wait_ns": 51})

    verification = verify_runtime_lock_analysis_artifact(
        tampered,
        evidence,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
    )

    assert verification.verification_status == "failed"
    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert "wait_hold_conservation" in failed
    assert "aggregate_projection_conservation" in failed
    assert "agent_visible_content_sha256" in failed
    with pytest.raises(PerfLensError, match="failed deterministic verification"):
        require_usable_runtime_lock_analysis(verification)


def test_tampered_evidence_hash_is_reported_without_trusting_stored_analysis(
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    tampered = evidence.model_copy(update={"content_sha256": "0" * 64})

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        tampered,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
    )

    assert verification.verification_status == "failed"
    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert "source_identity" in failed
    assert "agent_visible_content_sha256" in failed


@pytest.mark.parametrize("tamper", ["context", "native_context", "lock"])
def test_public_only_verification_fails_closed_on_artifact_local_identity_tampering(
    fixture_root: Path,
    tamper: str,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    if tamper == "lock":
        events = tuple(
            event.model_copy(
                update={"lock_id": "runtime-lock-" + "0" * 20} if event.lock_id is not None else {}
            )
            for event in evidence.events
        )
        tampered = evidence.model_copy(update={"events": events})
    else:
        original_context = evidence.execution_contexts[0]
        if tamper == "context":
            replacement_id = "runtime-context-" + "0" * 20
            replacement = original_context.model_copy(update={"context_id": replacement_id})
            events = tuple(
                event.model_copy(
                    update={
                        field: replacement_id
                        for field in (
                            "execution_context_id",
                            "owner_execution_context_id",
                            "parked_execution_context_id",
                        )
                        if getattr(event, field, None) == original_context.context_id
                    }
                )
                for event in evidence.events
            )
        else:
            replacement = original_context.model_copy(
                update={"runtime_context_id": "runtime-native-" + "0" * 20}
            )
            events = evidence.events
        tampered = evidence.model_copy(
            update={
                "execution_contexts": (replacement, *evidence.execution_contexts[1:]),
                "events": events,
            }
        )
    tampered = _rehash_evidence(tampered)

    verification = verify_runtime_lock_analysis_artifact(analysis, tampered)

    assert verification.verification_status == "failed"
    checks = {check.name: check.status for check in verification.checks}
    assert checks["source_identity"] == "skipped"
    assert checks["source_conversion_replay"] == "skipped"
    assert checks["evidence_invariants"] == "failed"
    with pytest.raises(PerfLensError, match="failed deterministic verification"):
        require_usable_runtime_lock_analysis(verification)


def test_non_replayable_source_still_binds_retained_raw_bytes(fixture_root: Path) -> None:
    evidence = _evidence(fixture_root)
    retained = b"bounded-jfr-json-placeholder"
    source = evidence.source.model_copy(
        update={
            "source_format": "jfr_json_v1",
            "source_sha256": hashlib.sha256(retained).hexdigest(),
            "source_bytes": len(retained),
        }
    )
    source = source.model_copy(
        update={"conversion_fingerprint": compute_runtime_source_conversion_fingerprint(source)}
    )
    converted = _rehash_evidence(evidence.model_copy(update={"source": source}))
    analysis = build_runtime_lock_analysis(converted)

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        converted,
        private_source_stream=io.BytesIO(retained),
    )

    checks = {check.name: check.status for check in verification.checks}
    assert checks["source_identity"] == "passed"
    assert checks["source_conversion_replay"] == "skipped"
    assert verification.verification_status == "partial"
    require_usable_runtime_lock_analysis(verification)


def test_persisted_replay_receipt_does_not_claim_a_fresh_conversion(
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    receipt = build_runtime_lock_source_replay_receipt(evidence)

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        source_replay_receipt=receipt,
    )

    replay_check = next(
        check for check in verification.checks if check.name == "source_conversion_replay"
    )
    assert replay_check.status == "passed"
    assert "content-bound receipt attests" in replay_check.detail
    assert "reran" not in replay_check.detail
    assert "reproduced" not in replay_check.detail
    assert "reproduced" not in replay_check.detail


def test_non_replayable_source_still_fails_closed_on_forbidden_conclusion_tampering(
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    source = evidence.source.model_copy(update={"source_format": "jfr_json_v1"})
    source = source.model_copy(
        update={"conversion_fingerprint": compute_runtime_source_conversion_fingerprint(source)}
    )
    forbidden = tuple(
        conclusion
        for conclusion in evidence.forbidden_conclusions
        if conclusion != "cross_artifact_lock_identity"
    )
    tampered = _rehash_evidence(
        evidence.model_copy(
            update={
                "source": source,
                "allowed_conclusions": (
                    *evidence.allowed_conclusions,
                    "cross_artifact_lock_identity",
                ),
                "forbidden_conclusions": forbidden,
            }
        )
    )

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        tampered,
        private_source_stream=io.BytesIO(b"unsupported-jfr-private-source"),
    )

    assert verification.verification_status == "failed"
    checks = {check.name: check.status for check in verification.checks}
    assert checks["source_identity"] == "failed"
    assert checks["source_conversion_replay"] == "failed"
    assert checks["evidence_invariants"] == "failed"


def test_unobserved_hold_duration_is_never_derived_from_event_timestamps(
    fixture_root: Path,
) -> None:
    records = [json.loads(line) for line in _raw(fixture_root).decode().splitlines()]
    records[0]["hold_time_is_source_observed"] = False
    release = records[-1]
    release.pop("acquire_source_event_id")
    release.pop("hold_duration_ns")
    raw = "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records).encode()
    evidence = import_runtime_lock_ndjson(io.BytesIO(raw), created_at="2026-08-30T00:00:00+00:00")

    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(raw),
    )

    assert analysis.total_exact_wait_count == 1
    assert analysis.total_exact_hold_count == 0
    assert analysis.total_exact_hold_ns == 0
    assert analysis.aggregates[0].exact_holds.sample_count == 0
    assert "exact_hold_time" in analysis.forbidden_conclusions
    assert verification.verification_status == "verified"


def test_lock_projection_omission_conserves_semantic_count_and_weight(
    fixture_root: Path,
) -> None:
    lines = [
        json.loads(line)
        for line in (fixture_root / "runtime_locks" / "valid-v1.1.ndjson").read_text().splitlines()
    ]
    lines[0]["declared_event_count"] = 8
    second_cycle: list[dict[str, object]] = []
    for record in lines[2:]:
        copied = dict(record)
        copied["source_event_id"] = f"second-{record['source_event_id']}"
        copied["source_lock_id"] = "second-private-lock"
        copied["timestamp_ns"] = int(record["timestamp_ns"]) + 200
        for field in (
            "wait_begin_source_event_id",
            "wait_end_source_event_id",
            "acquire_source_event_id",
        ):
            if field in copied:
                copied[field] = f"second-{copied[field]}"
        second_cycle.append(copied)
    payload = "".join(
        json.dumps(record, separators=(",", ":")) + "\n" for record in (*lines, *second_cycle)
    ).encode()
    evidence = import_runtime_lock_ndjson(
        io.BytesIO(payload),
        created_at="2026-08-30T00:00:00+00:00",
        limits=RuntimeLockResourceLimits(max_exported_locks=1),
    )

    analysis = build_runtime_lock_analysis(evidence)

    assert analysis.total_exact_wait_count == 2
    assert analysis.total_exact_wait_ns == 100
    assert analysis.total_exact_hold_count == 2
    assert analysis.total_exact_hold_ns == 100
    assert len(analysis.aggregates) == 1
    assert analysis.lock_coverage is not None
    assert analysis.lock_coverage.total_row_count == 2
    assert analysis.lock_coverage.omitted_row_count == 1
    assert analysis.lock_coverage.omitted_exact_wait_count == 1
    assert analysis.lock_coverage.omitted_exact_wait_ns == 50
    assert analysis.lock_coverage.omitted_observed_or_estimated_wait_ns == 50
    assert analysis.lock_coverage.omitted_exact_hold_count == 1
    assert analysis.lock_coverage.omitted_exact_hold_ns == 50
