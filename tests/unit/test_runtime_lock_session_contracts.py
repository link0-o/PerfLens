from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterCapabilityReference,
    RuntimeLockCapabilityArtifact,
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    RuntimeLockSessionArtifact,
    RuntimeLockSessionBudget,
    RuntimeLockSessionPreviewArtifact,
    derive_runtime_lock_capability_id,
    derive_runtime_lock_comparison_id,
    derive_runtime_lock_preview_id,
    derive_runtime_lock_run_id,
    derive_runtime_lock_session_artifact_id,
)

_ZERO = "0" * 64
_ONE = "1" * 64
_TWO = "2" * 64
_THREE = "3" * 64
_FOUR = "4" * 64
_FIVE = "5" * 64
_SIX = "6" * 64


def _times() -> tuple[str, str]:
    created = datetime(2026, 8, 30, tzinfo=UTC)
    return created.isoformat(), (created + timedelta(minutes=10)).isoformat()


def _capability() -> RuntimeLockCapabilityArtifact:
    created, _ = _times()
    return RuntimeLockCapabilityArtifact(
        perflens_version="0.4.0",
        capability_id=derive_runtime_lock_capability_id(_ZERO, _ONE, created),
        created_at=created,
        project_identity_sha256=_ZERO,
        project_policy_sha256=_ONE,
        status="available",
        adapters=(
            RuntimeLockAdapterCapabilityReference(
                adapter_id="cpython_threading",
                capability_id="runtime-adapter-" + "a" * 16,
                capability_content_sha256=_TWO,
                availability="available",
                supported_semantics=("exact", "thresholded"),
            ),
        ),
        content_sha256=_THREE,
    )


def _preview() -> RuntimeLockSessionPreviewArtifact:
    created, expires = _times()
    capability = _capability()
    return RuntimeLockSessionPreviewArtifact(
        perflens_version="0.4.0",
        preview_id=derive_runtime_lock_preview_id(
            _ZERO,
            _ONE,
            capability.content_sha256,
            created,
        ),
        created_at=created,
        expires_at=expires,
        project_identity_sha256=_ZERO,
        client_connection_identity_sha256=_FOUR,
        project_policy_sha256=_ONE,
        capability_id=capability.capability_id,
        capability_content_sha256=capability.content_sha256,
        runtime_lock_config_sha256=_FIVE,
        target_scope="host_launched_workload",
        allowed_adapters=("cpython_threading",),
        allowed_semantics=("exact", "thresholded"),
        budget=RuntimeLockSessionBudget(),
        planned_actions=("Launch one authorized CPython workload.",),
        authorization_summary_sha256=_SIX,
        content_sha256="7" * 64,
    )


def _session() -> RuntimeLockSessionArtifact:
    preview = _preview()
    session_id = "runtime-lock-session-" + "8" * 20
    return RuntimeLockSessionArtifact(
        perflens_version="0.4.0",
        session_artifact_id=derive_runtime_lock_session_artifact_id(
            session_id,
            0,
            "active",
            preview.created_at,
            None,
            None,
            0,
            0,
            0,
            0,
        ),
        session_id=session_id,
        revision=0,
        created_at=preview.created_at,
        updated_at=preview.created_at,
        expires_at=(datetime.fromisoformat(preview.created_at) + timedelta(hours=1)).isoformat(),
        state="active",
        project_identity_sha256=preview.project_identity_sha256,
        client_connection_identity_sha256=preview.client_connection_identity_sha256,
        project_policy_sha256=preview.project_policy_sha256,
        capability_id=preview.capability_id,
        capability_content_sha256=preview.capability_content_sha256,
        runtime_lock_config_sha256=preview.runtime_lock_config_sha256,
        preview_id=preview.preview_id,
        preview_content_sha256=preview.content_sha256,
        authorization_receipt_sha256="9" * 64,
        target_scope=preview.target_scope,
        allowed_adapters=preview.allowed_adapters,
        allowed_semantics=preview.allowed_semantics,
        budget=preview.budget,
        content_sha256="a" * 64,
    )


def _run(*, candidate: bool = False) -> RuntimeLockRunArtifact:
    session = _session()
    started = datetime.fromisoformat(session.created_at) + timedelta(seconds=1 + candidate)
    finished = started + timedelta(seconds=1)
    evidence_content = ("b" if candidate else "c") * 64
    return RuntimeLockRunArtifact(
        perflens_version="0.4.0",
        run_id=derive_runtime_lock_run_id(
            session.session_id,
            "cpython_threading",
            evidence_content,
            started.isoformat(),
        ),
        created_at=finished.isoformat(),
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        session_id=session.session_id,
        session_artifact_id=session.session_artifact_id,
        session_artifact_content_sha256=session.content_sha256,
        session_revision=session.revision,
        target_scope=session.target_scope,
        operation_identity_sha256="d" * 64,
        target_identity_sha256="e" * 64,
        adapter_id="cpython_threading",
        measurement_semantics="thresholded",
        workload_identity_sha256="f" * 64,
        runtime_lock_evidence_id="runtime-lock-evidence-" + "1" * 16,
        runtime_lock_evidence_content_sha256=evidence_content,
        runtime_lock_analysis_id="runtime-lock-analysis-" + "2" * 16,
        runtime_lock_analysis_content_sha256="3" * 64,
        runtime_lock_verification_id="runtime-lock-verification-" + "4" * 16,
        runtime_lock_verification_content_sha256="5" * 64,
        duration_seconds=1,
        evidence_bytes=2048,
        event_count=4,
        correctness_status="passed",
        quality_status="complete",
        allowed_conclusions=("runtime_lock_wait_distribution",),
        forbidden_conclusions=("performance_root_cause",),
        content_sha256=("6" if candidate else "7") * 64,
    )


def test_runtime_lock_session_contracts_bind_capability_preview_session_and_run() -> None:
    capability = _capability()
    preview = _preview()
    session = _session()
    run = _run()

    assert capability.status == "available"
    assert preview.capability_id == capability.capability_id
    assert session.preview_id == preview.preview_id
    assert run.session_id == session.session_id
    assert run.operation_identity_sha256 != run.target_identity_sha256


def test_runtime_lock_preview_rejects_unsafe_import_root() -> None:
    payload = _preview().model_dump(mode="json")
    payload["target_scope"] = "controlled_import"
    payload["import_roots"] = ["../secrets"]

    with pytest.raises(ValidationError, match="normalized project-relative"):
        RuntimeLockSessionPreviewArtifact.model_validate(payload)


def test_runtime_lock_session_rejects_budget_overrun() -> None:
    payload = _session().model_dump(mode="json")
    payload["workload_runs_used"] = 7

    with pytest.raises(ValidationError):
        RuntimeLockSessionArtifact.model_validate(payload)


def test_runtime_lock_session_requires_reason_only_after_termination() -> None:
    payload = _session().model_dump(mode="json")
    payload["state"] = "revoked"
    payload["revision"] = 1
    payload["previous_session_artifact_id"] = payload["session_artifact_id"]
    payload["previous_session_artifact_content_sha256"] = payload["content_sha256"]
    payload["session_artifact_id"] = derive_runtime_lock_session_artifact_id(
        payload["session_id"],
        payload["revision"],
        "revoked",
        payload["updated_at"],
        payload["previous_session_artifact_id"],
        payload["previous_session_artifact_content_sha256"],
        payload["workload_runs_used"],
        payload["active_seconds_used"],
        payload["evidence_bytes_used"],
        payload["exact_events_used"],
    )

    with pytest.raises(ValidationError, match="must explain"):
        RuntimeLockSessionArtifact.model_validate(payload)

    payload["invalidation_reason"] = "/home/user/private/token=secret"
    with pytest.raises(ValidationError):
        RuntimeLockSessionArtifact.model_validate(payload)


def test_runtime_lock_session_requires_a_complete_predecessor_chain() -> None:
    payload = _session().model_dump(mode="json")
    payload["revision"] = 1
    with pytest.raises(ValidationError, match="must reference its predecessor"):
        RuntimeLockSessionArtifact.model_validate(payload)

    payload = _session().model_dump(mode="json")
    payload["previous_session_artifact_id"] = "runtime-lock-session-state-" + "b" * 20
    payload["previous_session_artifact_content_sha256"] = "c" * 64
    with pytest.raises(ValidationError, match=r"initial .* cannot reference"):
        RuntimeLockSessionArtifact.model_validate(payload)


def test_runtime_lock_run_rejects_evidence_identity_mismatch() -> None:
    payload = _run().model_dump(mode="json")
    payload["runtime_lock_evidence_content_sha256"] = "8" * 64

    with pytest.raises(ValidationError, match="Run ID differs"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_run_timestamps_and_duration_must_be_conserved() -> None:
    payload = _run().model_dump(mode="json")
    payload["duration_seconds"] = 0
    with pytest.raises(ValidationError, match="duration differs"):
        RuntimeLockRunArtifact.model_validate(payload)

    payload = _run().model_dump(mode="json")
    payload["created_at"] = payload["started_at"]
    with pytest.raises(ValidationError, match="timestamps are inconsistent"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_comparison_requires_all_matched_inputs_for_verified_improvement() -> None:
    baseline = _run()
    candidate = _run(candidate=True)
    created = datetime(2026, 8, 30, 0, 1, tzinfo=UTC).isoformat()
    comparison = RuntimeLockComparisonArtifact(
        perflens_version="0.4.0",
        comparison_id=derive_runtime_lock_comparison_id(
            baseline.session_id,
            baseline.content_sha256,
            candidate.content_sha256,
            created,
        ),
        created_at=created,
        session_id=baseline.session_id,
        baseline_run_id=baseline.run_id,
        baseline_run_content_sha256=baseline.content_sha256,
        candidate_run_id=candidate.run_id,
        candidate_run_content_sha256=candidate.content_sha256,
        adapter_match=True,
        semantics_match=True,
        threshold_or_sampling_match=True,
        workload_match=True,
        resource_environment_match=True,
        baseline_quality_status="complete",
        candidate_quality_status="complete",
        correctness_status="passed",
        deterministic_replay_passed=True,
        resource_transfer_status="no_observed_regression",
        comparable=True,
        conclusion="verified_improvement",
        improved_metrics=("total_wait_ns",),
        allowed_conclusions=("verified_improvement",),
        forbidden_conclusions=("performance_root_cause",),
        content_sha256="9" * 64,
    )
    assert comparison.conclusion == "verified_improvement"

    payload = comparison.model_dump(mode="json")
    payload["resource_environment_match"] = False
    with pytest.raises(ValidationError, match="comparability"):
        RuntimeLockComparisonArtifact.model_validate(payload)

    payload = comparison.model_dump(mode="json")
    payload["candidate_quality_status"] = "partial"
    with pytest.raises(ValidationError, match="verified Runtime Lock"):
        RuntimeLockComparisonArtifact.model_validate(payload)


def test_runtime_lock_exact_run_enforces_short_duration_and_event_bound() -> None:
    payload = _run().model_dump(mode="json")
    payload["measurement_semantics"] = "exact"
    payload["duration_seconds"] = 4
    finished = datetime.fromisoformat(payload["started_at"]) + timedelta(seconds=4)
    payload["finished_at"] = finished.isoformat()
    payload["created_at"] = finished.isoformat()

    with pytest.raises(ValidationError, match="exact Runtime Lock Run"):
        RuntimeLockRunArtifact.model_validate(payload)
