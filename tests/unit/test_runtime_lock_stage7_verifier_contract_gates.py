from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import io
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.unit.test_runtime_lock_analysis_verification import _evidence, _raw

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.runtime_lock_queries import (
    build_runtime_lock_diagnosis_bundle,
    get_runtime_lock_call_paths,
    list_runtime_lock_hotspots,
)
from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
    verify_runtime_lock_analysis_artifact,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockCallPathPage,
    RuntimeLockDiagnosisBundleArtifact,
    RuntimeLockEvidenceArtifact,
    RuntimeLockHotspotPage,
    RuntimeLockProjectionName,
    RuntimeLockSourceReplayReceipt,
    RuntimeProjectionCoverage,
)


class _FailingStream:
    def read(self, _size: int) -> bytes:
        raise OSError("bounded test read failure")


def _verified(
    fixture_root: Path,
) -> tuple[
    RuntimeLockEvidenceArtifact,
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
]:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
    )
    return evidence, analysis, verification


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    (
        ({"normalized_source_sha256": "0" * 64}, "normalized source replay identity"),
        ({"normalized_source_bytes": 1}, "normalized source replay identity"),
        ({"origin_source_sha256": "0" * 64}, "origin source replay identity"),
        ({"origin_source_bytes": 1}, "origin source replay identity"),
    ),
)
def test_replay_receipt_builder_rejects_unpaired_identities(
    fixture_root: Path,
    kwargs: dict[str, object],
    expected: str,
) -> None:
    evidence = _evidence(fixture_root)

    with pytest.raises(ValueError, match=expected):
        build_runtime_lock_source_replay_receipt(evidence, **kwargs)  # type: ignore[arg-type]


def test_replay_receipt_requires_v11_converter_identity(fixture_root: Path) -> None:
    evidence = _evidence(fixture_root)
    source = evidence.source.model_copy(update={"converter_version": None})
    legacy_like = evidence.model_copy(update={"source": source})

    with pytest.raises(ValueError, match=r"schema 1\.1 converter identity"):
        build_runtime_lock_source_replay_receipt(legacy_like)


@pytest.mark.parametrize(
    ("stream", "expected_source_status", "expected_replay_status"),
    (
        (io.BytesIO(b"short"), "failed", "failed"),
        (io.BytesIO(b"x" * 1024), "failed", "failed"),
        (_FailingStream(), "failed", "failed"),
    ),
)
def test_verifier_fails_closed_on_private_source_faults(
    fixture_root: Path,
    stream: object,
    expected_source_status: str,
    expected_replay_status: str,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    if isinstance(stream, io.BytesIO) and len(stream.getvalue()) == 1024:
        limits = evidence.limits.model_copy(update={"max_source_bytes": 16})
        evidence = evidence.model_copy(update={"limits": limits})

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=stream,  # type: ignore[arg-type]
    )
    checks = {check.name: check.status for check in verification.checks}

    assert checks["source_identity"] == expected_source_status
    assert checks["source_conversion_replay"] == expected_replay_status
    assert verification.verification_status == "failed"


def test_verifier_rejects_ambiguous_private_source_and_receipt(fixture_root: Path) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    receipt = build_runtime_lock_source_replay_receipt(evidence)

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(_raw(fixture_root)),
        source_replay_receipt=receipt,
    )

    checks = {check.name: check.status for check in verification.checks}
    assert checks["source_identity"] == "failed"
    assert checks["source_conversion_replay"] == "failed"


def test_verifier_rejects_tampered_persisted_replay_receipt(fixture_root: Path) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    receipt = build_runtime_lock_source_replay_receipt(evidence).model_copy(
        update={"conversion_fingerprint": "f" * 64}
    )

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        source_replay_receipt=receipt,
    )

    checks = {check.name: check.status for check in verification.checks}
    assert checks["source_identity"] == "failed"
    assert checks["source_conversion_replay"] == "failed"


@pytest.mark.parametrize(
    ("case", "failed_check"),
    (
        ("schema", "target_scope"),
        ("evidence_id", "target_scope"),
        ("runtime", "target_scope"),
        ("context_scope", "target_scope"),
        ("semantics", "semantic_count_conservation"),
        ("evidence_digest", "agent_visible_content_sha256"),
        ("evidence_bytes", "agent_visible_content_sha256"),
        ("analysis_digest", "agent_visible_content_sha256"),
        ("analysis_bytes", "agent_visible_content_sha256"),
        ("fingerprint", "agent_visible_content_sha256"),
        ("analysis_id", "agent_visible_content_sha256"),
    ),
)
def test_verifier_detects_independent_analysis_binding_tampering(
    fixture_root: Path,
    case: str,
    failed_check: str,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    if case == "schema":
        analysis = analysis.model_copy(update={"schema_version": "1.0"})
    elif case == "evidence_id":
        analysis = analysis.model_copy(update={"runtime_lock_evidence_id": "other-artifact"})
    elif case == "runtime":
        analysis = analysis.model_copy(update={"runtime": "java"})
    elif case == "context_scope":
        row = analysis.execution_context_aggregates[0].model_copy(
            update={"execution_context_id": "runtime-context-" + "f" * 20}
        )
        analysis = analysis.model_copy(update={"execution_context_aggregates": (row,)})
    elif case == "semantics":
        analysis = analysis.model_copy(update={"measurement_semantics": "sampled"})
    elif case == "evidence_digest":
        analysis = analysis.model_copy(update={"runtime_lock_evidence_content_sha256": "f" * 64})
    elif case == "evidence_bytes":
        analysis = analysis.model_copy(
            update={
                "runtime_lock_evidence_content_bytes": (
                    analysis.runtime_lock_evidence_content_bytes + 1
                )
            }
        )
    elif case == "analysis_digest":
        analysis = analysis.model_copy(update={"content_sha256": "f" * 64})
    elif case == "analysis_bytes":
        analysis = analysis.model_copy(update={"content_bytes": analysis.content_bytes + 1})
    elif case == "fingerprint":
        analysis = analysis.model_copy(update={"analysis_fingerprint": "f" * 64})
    elif case == "analysis_id":
        analysis = analysis.model_copy(
            update={"runtime_lock_analysis_id": "runtime-lock-analysis-" + "f" * 16}
        )
    else:
        raise AssertionError(case)

    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)

    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert failed_check in failed
    assert verification.verification_status == "failed"


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("wrong_verifier", "verifier version contradicts"),
        ("legacy_receipt", "schema 1.0 verification cannot carry"),
        ("foreign_receipt", "receipt differs from verified"),
        ("duplicate_check", "check names must be unique"),
        ("status", "status contradicts its checks"),
    ),
)
def test_verification_contract_rejects_contradictory_state(
    fixture_root: Path,
    case: str,
    expected: str,
) -> None:
    evidence, _analysis, verification = _verified(fixture_root)
    data = verification.model_dump(mode="json")
    if case == "wrong_verifier":
        data["verifier_version"] = "runtime-lock-verifier-v1"
    elif case == "legacy_receipt":
        data["schema_version"] = "1.0"
        data["verifier_version"] = "runtime-lock-verifier-v1"
    elif case == "foreign_receipt":
        data["source_replay_receipt"]["runtime_lock_evidence_id"] = (
            "runtime-lock-evidence-" + "f" * 20
        )
    elif case == "duplicate_check":
        data["checks"][1]["name"] = data["checks"][0]["name"]
    elif case == "status":
        data["verification_status"] = "partial"
    else:
        raise AssertionError(case)

    with pytest.raises(ValidationError, match=expected):
        RuntimeLockAnalysisVerificationArtifact.model_validate(data)

    assert evidence.schema_version == "1.1"


def test_verification_contract_defaults_v11_verifier(fixture_root: Path) -> None:
    _evidence_value, _analysis, verification = _verified(fixture_root)
    data = verification.model_dump(mode="json")
    data.pop("verifier_version")

    parsed = RuntimeLockAnalysisVerificationArtifact.model_validate(data)

    assert parsed.verifier_version == "runtime-lock-verifier-v2"


def test_replay_receipt_contract_rejects_unpaired_origin(fixture_root: Path) -> None:
    evidence = _evidence(fixture_root)
    data = build_runtime_lock_source_replay_receipt(evidence).model_dump(mode="json")
    data["origin_source_sha256"] = hashlib.sha256(b"origin").hexdigest()

    with pytest.raises(ValidationError, match="origin source replay identity"):
        RuntimeLockSourceReplayReceipt.model_validate(data)


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("omitted_metrics", "without omitted rows cannot omit metrics"),
        ("wait_duration", "exact wait duration requires"),
        ("threshold_duration", "thresholded duration requires"),
        ("hold_duration", "exact hold duration requires"),
    ),
)
def test_projection_coverage_rejects_impossible_omissions(
    fixture_root: Path,
    case: str,
    expected: str,
) -> None:
    analysis = build_runtime_lock_analysis(_evidence(fixture_root))
    assert analysis.lock_coverage is not None
    data = analysis.lock_coverage.model_dump(mode="json")
    if case == "omitted_metrics":
        data["omitted_exact_wait_count"] = 1
    elif case == "wait_duration":
        data["total_row_count"] = 2
        data["omitted_row_count"] = 1
        data["omitted_exact_wait_ns"] = 1
    elif case == "threshold_duration":
        data["total_row_count"] = 2
        data["omitted_row_count"] = 1
        data["omitted_thresholded_wait_ns"] = 1
    elif case == "hold_duration":
        data["total_row_count"] = 2
        data["omitted_row_count"] = 1
        data["omitted_exact_hold_ns"] = 1
    else:
        raise AssertionError(case)

    with pytest.raises(ValidationError, match=expected):
        RuntimeProjectionCoverage.model_validate(data)


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("projection_type", "another projection type"),
        ("overflow", "exceeds its total item count"),
        ("cursor", "next cursor is inconsistent"),
        ("missing_coverage", "requires coverage"),
        ("coverage_total", "total differs from projection coverage"),
        ("overlap", "conclusion sets overlap"),
    ),
)
def test_hotspot_page_rejects_projection_and_pagination_tampering(
    fixture_root: Path,
    case: str,
    expected: str,
) -> None:
    analysis = build_runtime_lock_analysis(_evidence(fixture_root))
    page = list_runtime_lock_hotspots(analysis)
    data = page.model_dump(mode="json")
    if case == "projection_type":
        data["projection"] = "execution_context"
    elif case == "overflow":
        data["total_items"] = 0
    elif case == "cursor":
        data["next_cursor"] = 1
    elif case == "missing_coverage":
        data["coverage"] = None
    elif case == "coverage_total":
        data["total_items"] = 2
        data["next_cursor"] = 1
    elif case == "overlap":
        data["allowed_conclusions"].append(data["forbidden_conclusions"][0])
    else:
        raise AssertionError(case)

    with pytest.raises(ValidationError, match=expected):
        RuntimeLockHotspotPage.model_validate(data)


@pytest.mark.parametrize(
    "projection",
    ["lock", "execution_context", "call_path", "wait_outcome", "lock_kind"],
)
def test_hotspot_page_accepts_each_projection_type(
    fixture_root: Path,
    projection: RuntimeLockProjectionName,
) -> None:
    analysis = build_runtime_lock_analysis(_evidence(fixture_root))

    page = list_runtime_lock_hotspots(analysis, projection=projection)

    assert page.projection == projection
    assert page.total_items == 1


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("length", "rows and stacks must have equal length"),
        ("stack", "rows do not match their public stacks"),
        ("overflow", "exceeds its total item count"),
        ("cursor", "next cursor is inconsistent"),
        ("missing_coverage", "requires coverage"),
        ("coverage_total", "total differs from projection coverage"),
        ("overlap", "conclusion sets overlap"),
    ),
)
def test_call_path_page_rejects_join_and_pagination_tampering(
    fixture_root: Path,
    case: str,
    expected: str,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    page = get_runtime_lock_call_paths(analysis, evidence)
    data = page.model_dump(mode="json")
    if case == "length":
        data["stacks"] = []
    elif case == "stack":
        data["stacks"][0]["stack_id"] = "runtime-stack-" + "f" * 20
    elif case == "overflow":
        data["total_items"] = 0
    elif case == "cursor":
        data["next_cursor"] = 1
    elif case == "missing_coverage":
        data["coverage"] = None
    elif case == "coverage_total":
        data["total_items"] = 2
        data["next_cursor"] = 1
    elif case == "overlap":
        data["allowed_conclusions"].append(data["forbidden_conclusions"][0])
    else:
        raise AssertionError(case)

    with pytest.raises(ValidationError, match=expected):
        RuntimeLockCallPathPage.model_validate(data)


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("id", "diagnosis ID differs"),
        ("lock", "diagnosis lock IDs must be unique"),
        ("context", "diagnosis execution-context IDs must be unique"),
        ("stack", "diagnosis stack IDs must be unique"),
        ("blank", "diagnosis text cannot be blank"),
        ("overlap", "diagnosis conclusion sets overlap"),
    ),
)
def test_diagnosis_contract_rejects_agent_visible_tampering(
    fixture_root: Path,
    case: str,
    expected: str,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
    bundle = build_runtime_lock_diagnosis_bundle(analysis, evidence, verification)
    data = bundle.model_dump(mode="json")
    if case == "id":
        data["runtime_lock_diagnosis_id"] = "runtime-lock-diagnosis-" + "f" * 20
    elif case == "lock":
        data["top_lock_ids"] *= 2
    elif case == "context":
        data["top_execution_context_ids"] *= 2
    elif case == "stack":
        data["top_stack_ids"] *= 2
    elif case == "blank":
        data["observations"][0] = " "
    elif case == "overlap":
        data["allowed_conclusions"].append(data["forbidden_conclusions"][0])
    else:
        raise AssertionError(case)

    with pytest.raises(ValidationError, match=expected):
        RuntimeLockDiagnosisBundleArtifact.model_validate(data)
