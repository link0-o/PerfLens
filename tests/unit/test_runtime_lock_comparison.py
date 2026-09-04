from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, NamedTuple

import pytest

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.evidence import contract_content_sha256
from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
    verify_runtime_lock_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    derive_docker_build_artifact_id,
)
from perflens.contracts.runtime_lock_sessions import (
    DockerRuntimeLockRunBinding,
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_run_id,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockEvidenceArtifact,
)
from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import import_runtime_lock_ndjson
from perflens.runtime_locks.comparison import (
    compare_runtime_lock_analyses,
    runtime_lock_resource_environment_sha256,
)
from perflens.runtime_locks.docker_capture import bind_observed_runtime_execution


class _ComparisonInputs(NamedTuple):
    baseline_run: RuntimeLockRunArtifact
    baseline_analysis: RuntimeLockAnalysisArtifact
    baseline_evidence: RuntimeLockEvidenceArtifact
    baseline_verification: RuntimeLockAnalysisVerificationArtifact
    candidate_run: RuntimeLockRunArtifact
    candidate_analysis: RuntimeLockAnalysisArtifact
    candidate_evidence: RuntimeLockEvidenceArtifact
    candidate_verification: RuntimeLockAnalysisVerificationArtifact


def _evidence_pair() -> tuple[RuntimeLockEvidenceArtifact, RuntimeLockEvidenceArtifact]:
    source = (Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson").read_bytes()
    candidate = source.replace(b'"timestamp_ns":150', b'"timestamp_ns":140')
    candidate = candidate.replace(b'"timestamp_ns":200', b'"timestamp_ns":180')
    candidate = candidate.replace(b'"duration_ns":50', b'"duration_ns":40')
    candidate = candidate.replace(b'"hold_duration_ns":50', b'"hold_duration_ns":40')
    return import_runtime_lock_ndjson(io.BytesIO(source)), import_runtime_lock_ndjson(
        io.BytesIO(candidate)
    )


def _evidence_with_duration(
    duration_ns: int,
    *,
    runtime_version: str = "3.13.5",
) -> RuntimeLockEvidenceArtifact:
    source = (Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson").read_bytes()
    source = source.replace(
        b'"timestamp_ns":150',
        f'"timestamp_ns":{100 + duration_ns}'.encode(),
    )
    source = source.replace(
        b'"timestamp_ns":200',
        f'"timestamp_ns":{100 + duration_ns * 2}'.encode(),
    )
    source = source.replace(
        b'"duration_ns":50',
        f'"duration_ns":{duration_ns}'.encode(),
    )
    source = source.replace(
        b'"hold_duration_ns":50',
        f'"hold_duration_ns":{duration_ns}'.encode(),
    )
    source = source.replace(
        b'"runtime_version":"3.13.5"',
        f'"runtime_version":"{runtime_version}"'.encode(),
    )
    return import_runtime_lock_ndjson(io.BytesIO(source))


def _docker_build(
    *,
    kind: Literal["baseline", "candidate"],
    round_number: int,
    marker: str,
    treatment_marker: str,
) -> DockerBuildArtifact:
    image_digest = "sha256:" + marker * 64
    started_at = f"2026-08-31T00:00:0{round_number}+00:00"
    provisional = DockerBuildArtifact(
        schema_version="1.0",
        perflens_version="0.4.0",
        build_id=derive_docker_build_artifact_id(
            "6" * 64,
            kind,
            round_number,
            image_digest,
            started_at,
        ),
        build_kind=kind,
        candidate_round=round_number,
        started_at=started_at,
        finished_at=started_at,
        recipe_id="docker-build-recipe-" + "3" * 20,
        recipe_content_sha256="4" * 64,
        context_id="docker-build-context-" + marker * 20,
        context_content_sha256="6" * 64,
        builder_identity_sha256="7" * 64,
        network_policy_sha256="8" * 64,
        final_image_digest=image_digest,
        platform="linux/amd64",
        image_size_bytes=4096,
        iid_file_sha256="9" * 64,
        metadata_file_sha256="a" * 64,
        provenance_sha256="b" * 64,
        immutable_manifest_sha256="c" * 64,
        treatment_manifest_sha256=treatment_marker * 64,
        cleanup_eligible=True,
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _docker_run(
    evidence: RuntimeLockEvidenceArtifact,
    build: DockerBuildArtifact,
    *,
    ordinal: int,
    session_marker: str = "1",
    measurement_marker: str,
) -> RuntimeLockRunArtifact:
    run = _run(evidence, ordinal=ordinal)
    session_id = "docker-optimization-session-" + session_marker * 20
    started_at = run.started_at
    runtime_version = evidence.source.runtime_version
    assert runtime_version is not None
    toolchain = derive_runtime_lock_toolchain_identity(())
    configuration_sha256 = "6" * 64
    metadata_sha256 = "7" * 64
    authorized_identity = derive_runtime_lock_adapter_execution_identity(
        run.adapter_id,
        evidence.source.adapter_version,
        evidence.source.backend_id,
        runtime_version,
        "exact",
        evidence.source.measurement_semantics,
        evidence.source.duration_threshold_ns,
        toolchain,
        configuration_sha256,
        metadata_sha256,
    )
    authorized_execution = RuntimeLockAdapterExecutionBinding(
        adapter_id=run.adapter_id,
        adapter_version=evidence.source.adapter_version,
        backend_id=evidence.source.backend_id,
        runtime_version=runtime_version,
        profile="exact",
        measurement_semantics=evidence.source.measurement_semantics,
        duration_threshold_ns=evidence.source.duration_threshold_ns,
        tools=(),
        toolchain_identity_sha256=toolchain,
        configuration_sha256=configuration_sha256,
        metadata_sha256=metadata_sha256,
        execution_identity_sha256=authorized_identity,
    )
    actual_execution = bind_observed_runtime_execution(
        authorized_execution,
        runtime_version=runtime_version,
        runtime_characteristics="generic-import",
    )
    binding = DockerRuntimeLockRunBinding(
        docker_optimization_session_id=session_id,
        docker_optimization_session_artifact_id=(
            "docker-optimization-session-state-" + str(ordinal + 1) * 20
        ),
        docker_optimization_session_artifact_content_sha256=str(ordinal + 2) * 64,
        build_id=build.build_id,
        build_content_sha256=build.content_sha256,
        container_target_id="container-target-" + measurement_marker * 20,
        container_target_content_sha256=measurement_marker * 64,
        container_run_id="container-run-" + measurement_marker * 20,
        container_run_content_sha256=measurement_marker * 64,
        container_measurement_id="container-measurement-" + measurement_marker * 20,
        container_measurement_content_sha256=measurement_marker * 64,
        authorized_execution_identity_sha256=authorized_identity,
        actual_execution_binding=actual_execution,
        actual_runtime_characteristics="generic-import",
        accounted_evidence_bytes=4096,
    )
    provisional = run.model_copy(
        update={
            "run_id": derive_runtime_lock_run_id(
                session_id,
                run.adapter_id,
                evidence.content_sha256,
                started_at,
            ),
            "authorization_kind": "docker_optimization",
            "session_id": session_id,
            "session_artifact_id": None,
            "session_artifact_content_sha256": None,
            "session_revision": None,
            "docker_optimization_binding": binding,
            "target_scope": "docker_optimization",
            "adapter_execution_identity_sha256": (actual_execution.execution_identity_sha256),
            "workload_identity_sha256": build.recipe_content_sha256,
            "content_sha256": "0" * 64,
        }
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _run(evidence: RuntimeLockEvidenceArtifact, *, ordinal: int = 0) -> RuntimeLockRunArtifact:
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        source_replay_receipt=build_runtime_lock_source_replay_receipt(evidence),
    )
    started = datetime(2026, 8, 31, 0, 0, tzinfo=UTC) + timedelta(seconds=ordinal * 2)
    finished = started + timedelta(seconds=1)
    provisional = RuntimeLockRunArtifact(
        schema_version="1.1",
        perflens_version="0.4.0",
        run_id=derive_runtime_lock_run_id(
            "runtime-lock-session-" + "1" * 20,
            "generic_ndjson_import",
            evidence.content_sha256,
            started.isoformat(),
        ),
        created_at=finished.isoformat(),
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        authorization_kind="runtime_lock_session",
        session_id="runtime-lock-session-" + "1" * 20,
        session_artifact_id="runtime-lock-session-state-" + str(ordinal + 1) * 20,
        session_artifact_content_sha256=str(ordinal + 2) * 64,
        session_revision=ordinal + 1,
        target_scope="host_launched_workload",
        operation_identity_sha256=str(ordinal + 3) * 64,
        target_identity_sha256="7" * 64,
        adapter_id="generic_ndjson_import",
        measurement_semantics="exact",
        workload_identity_sha256="8" * 64,
        runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
        runtime_lock_evidence_content_sha256=evidence.content_sha256,
        runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
        runtime_lock_analysis_content_sha256=analysis.content_sha256,
        runtime_lock_verification_id=verification.runtime_lock_verification_id,
        runtime_lock_verification_content_sha256=verification.content_sha256,
        duration_seconds=1,
        evidence_bytes=len(serialize_json(evidence)),
        event_count=len(evidence.events),
        correctness_status="passed",
        quality_status=analysis.quality_status,
        allowed_conclusions=analysis.allowed_conclusions,
        forbidden_conclusions=analysis.forbidden_conclusions,
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _inputs() -> _ComparisonInputs:
    return _inputs_from_evidence(*_evidence_pair())


def _inputs_from_evidence(
    baseline_evidence: RuntimeLockEvidenceArtifact,
    candidate_evidence: RuntimeLockEvidenceArtifact,
) -> _ComparisonInputs:
    baseline_analysis = build_runtime_lock_analysis(baseline_evidence)
    candidate_analysis = build_runtime_lock_analysis(candidate_evidence)
    baseline_verification = verify_runtime_lock_analysis_artifact(
        baseline_analysis,
        baseline_evidence,
        source_replay_receipt=build_runtime_lock_source_replay_receipt(baseline_evidence),
    )
    candidate_verification = verify_runtime_lock_analysis_artifact(
        candidate_analysis,
        candidate_evidence,
        source_replay_receipt=build_runtime_lock_source_replay_receipt(candidate_evidence),
    )
    return _ComparisonInputs(
        _run(baseline_evidence),
        baseline_analysis,
        baseline_evidence,
        baseline_verification,
        _run(candidate_evidence, ordinal=1),
        candidate_analysis,
        candidate_evidence,
        candidate_verification,
    )


def _compare(
    values: _ComparisonInputs,
    *,
    baseline_run: RuntimeLockRunArtifact | None = None,
    candidate_run: RuntimeLockRunArtifact | None = None,
    baseline_resource_environment_sha256: str | None = None,
    candidate_resource_environment_sha256: str | None = None,
    baseline_build: DockerBuildArtifact | None = None,
    candidate_build: DockerBuildArtifact | None = None,
) -> RuntimeLockComparisonArtifact:
    selected_baseline_run = baseline_run or values.baseline_run
    selected_candidate_run = candidate_run or values.candidate_run
    if baseline_resource_environment_sha256 is None:
        baseline_resource_environment_sha256 = runtime_lock_resource_environment_sha256(
            selected_baseline_run,
            values.baseline_evidence,
        )
    if candidate_resource_environment_sha256 is None:
        candidate_resource_environment_sha256 = runtime_lock_resource_environment_sha256(
            selected_candidate_run,
            values.candidate_evidence,
        )
    return compare_runtime_lock_analyses(
        baseline_run=selected_baseline_run,
        baseline_analysis=values.baseline_analysis,
        baseline_evidence=values.baseline_evidence,
        baseline_verification=values.baseline_verification,
        candidate_run=selected_candidate_run,
        candidate_analysis=values.candidate_analysis,
        candidate_evidence=values.candidate_evidence,
        candidate_verification=values.candidate_verification,
        baseline_resource_environment_sha256=baseline_resource_environment_sha256,
        candidate_resource_environment_sha256=candidate_resource_environment_sha256,
        resource_transfer_status=(
            "no_observed_regression" if baseline_build is not None else "incomplete"
        ),
        resource_comparison_id=(
            "container-comparison-" + "a" * 20 if baseline_build is not None else None
        ),
        resource_comparison_content_sha256=("b" * 64 if baseline_build is not None else None),
        baseline_build=baseline_build,
        candidate_build=candidate_build,
        created_at=datetime(2026, 8, 31, 0, 10, tzinfo=UTC),
    )


def test_standalone_runtime_lock_comparison_keeps_improvement_candidate_only() -> None:
    (
        baseline_run,
        baseline_analysis,
        baseline_evidence,
        baseline_verification,
        candidate_run,
        candidate_analysis,
        candidate_evidence,
        candidate_verification,
    ) = _inputs()
    environment = runtime_lock_resource_environment_sha256(
        baseline_run,
        baseline_evidence,
    )
    comparison = compare_runtime_lock_analyses(
        baseline_run=baseline_run,
        baseline_analysis=baseline_analysis,
        baseline_evidence=baseline_evidence,
        baseline_verification=baseline_verification,
        candidate_run=candidate_run,
        candidate_analysis=candidate_analysis,
        candidate_evidence=candidate_evidence,
        candidate_verification=candidate_verification,
        baseline_resource_environment_sha256=environment,
        candidate_resource_environment_sha256=environment,
        resource_transfer_status="incomplete",
        created_at=datetime(2026, 8, 31, 0, 10, tzinfo=UTC),
    )

    assert comparison.comparable
    assert comparison.conclusion == "candidate_improvement"
    assert comparison.improved_metrics == (
        "total_exact_hold_ns",
        "total_exact_wait_ns",
    )
    assert comparison.regressed_metrics == ()
    assert "verified_improvement" in comparison.forbidden_conclusions


def test_runtime_lock_comparison_fails_closed_on_workload_or_replay_mismatch() -> None:
    values = _inputs()
    baseline_run = values.baseline_run
    candidate_run = values.candidate_run.model_copy(update={"workload_identity_sha256": "f" * 64})
    candidate_run = candidate_run.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                candidate_run,
                exclude={"content_sha256"},
            )
        }
    )
    environment = runtime_lock_resource_environment_sha256(
        baseline_run,
        values.baseline_evidence,
    )
    comparison = compare_runtime_lock_analyses(
        baseline_run=values.baseline_run,
        baseline_analysis=values.baseline_analysis,
        baseline_evidence=values.baseline_evidence,
        baseline_verification=values.baseline_verification,
        candidate_run=candidate_run,
        candidate_analysis=values.candidate_analysis,
        candidate_evidence=values.candidate_evidence,
        candidate_verification=values.candidate_verification,
        baseline_resource_environment_sha256=environment,
        candidate_resource_environment_sha256=environment,
        resource_transfer_status="incomplete",
    )

    assert not comparison.comparable
    assert comparison.conclusion == "not_comparable"
    assert comparison.improved_metrics == ()
    assert "verified_improvement" in comparison.forbidden_conclusions


def test_standalone_runtime_lock_comparison_rejects_unbound_resource_claim() -> None:
    values = _inputs()
    environment = runtime_lock_resource_environment_sha256(
        values.baseline_run,
        values.baseline_evidence,
    )
    with pytest.raises(PerfLensError, match="lacks bound resource-transfer evidence"):
        compare_runtime_lock_analyses(
            baseline_run=values.baseline_run,
            baseline_analysis=values.baseline_analysis,
            baseline_evidence=values.baseline_evidence,
            baseline_verification=values.baseline_verification,
            candidate_run=values.candidate_run,
            candidate_analysis=values.candidate_analysis,
            candidate_evidence=values.candidate_evidence,
            candidate_verification=values.candidate_verification,
            baseline_resource_environment_sha256=environment,
            candidate_resource_environment_sha256=environment,
            resource_transfer_status="regression",
        )


@pytest.mark.parametrize(
    ("candidate_duration_ns", "expected_conclusion"),
    (
        (9_901, "no_material_change"),
        (9_900, "candidate_improvement"),
    ),
)
def test_runtime_lock_comparison_applies_one_percent_materiality_floor(
    candidate_duration_ns: int,
    expected_conclusion: str,
) -> None:
    values = _inputs_from_evidence(
        _evidence_with_duration(10_000),
        _evidence_with_duration(candidate_duration_ns),
    )

    comparison = _compare(values)

    assert comparison.comparable
    assert comparison.minimum_material_change_percent == 1.0
    assert comparison.conclusion == expected_conclusion
    assert bool(comparison.improved_metrics) == (expected_conclusion == "candidate_improvement")
    assert "verified_improvement" in comparison.forbidden_conclusions


def test_runtime_lock_comparison_rejects_cross_session_run_splice() -> None:
    values = _inputs()
    candidate_run = values.candidate_run.model_copy(
        update={
            "session_id": "runtime-lock-session-" + "f" * 20,
            "run_id": derive_runtime_lock_run_id(
                "runtime-lock-session-" + "f" * 20,
                values.candidate_run.adapter_id,
                values.candidate_evidence.content_sha256,
                values.candidate_run.started_at,
            ),
            "content_sha256": "0" * 64,
        }
    )
    candidate_run = candidate_run.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                candidate_run,
                exclude={"content_sha256"},
            )
        }
    )

    with pytest.raises(PerfLensError, match="different authorization Sessions"):
        _compare(values, candidate_run=candidate_run)


def test_docker_runtime_lock_comparison_rejects_cross_build_splice() -> None:
    values = _inputs()
    baseline_build = _docker_build(
        kind="baseline",
        round_number=0,
        marker="d",
        treatment_marker="1",
    )
    candidate_build = _docker_build(
        kind="candidate",
        round_number=1,
        marker="e",
        treatment_marker="2",
    )
    replacement_baseline = _docker_build(
        kind="baseline",
        round_number=0,
        marker="c",
        treatment_marker="1",
    )
    baseline_run = _docker_run(
        values.baseline_evidence,
        baseline_build,
        ordinal=0,
        measurement_marker="b",
    )
    candidate_run = _docker_run(
        values.candidate_evidence,
        candidate_build,
        ordinal=1,
        measurement_marker="c",
    )

    with pytest.raises(PerfLensError, match="fixed Build environment"):
        _compare(
            values,
            baseline_run=baseline_run,
            candidate_run=candidate_run,
            baseline_resource_environment_sha256="e" * 64,
            candidate_resource_environment_sha256="e" * 64,
            baseline_build=replacement_baseline,
            candidate_build=candidate_build,
        )


@pytest.mark.parametrize(
    ("baseline_kind", "baseline_round", "candidate_kind", "candidate_round"),
    (
        ("candidate", 1, "candidate", 2),
        ("baseline", 0, "baseline", 0),
    ),
)
def test_docker_runtime_lock_comparison_requires_baseline_zero_and_candidate_round(
    baseline_kind: Literal["baseline", "candidate"],
    baseline_round: int,
    candidate_kind: Literal["baseline", "candidate"],
    candidate_round: int,
) -> None:
    values = _inputs()
    baseline_build = _docker_build(
        kind=baseline_kind,
        round_number=baseline_round,
        marker="d",
        treatment_marker="1",
    )
    candidate_build = _docker_build(
        kind=candidate_kind,
        round_number=candidate_round,
        marker="e",
        treatment_marker="2",
    )
    baseline_run = _docker_run(
        values.baseline_evidence,
        baseline_build,
        ordinal=0,
        measurement_marker="b",
    )
    candidate_run = _docker_run(
        values.candidate_evidence,
        candidate_build,
        ordinal=1,
        measurement_marker="c",
    )

    with pytest.raises(PerfLensError, match="fixed Build environment"):
        _compare(
            values,
            baseline_run=baseline_run,
            candidate_run=candidate_run,
            baseline_resource_environment_sha256="e" * 64,
            candidate_resource_environment_sha256="e" * 64,
            baseline_build=baseline_build,
            candidate_build=candidate_build,
        )


@pytest.mark.parametrize("mismatch", ("fixed_environment", "runtime_version"))
def test_docker_runtime_lock_comparison_marks_fixed_mismatch_not_comparable(
    mismatch: str,
) -> None:
    baseline_evidence = _evidence_with_duration(10_000)
    candidate_evidence = _evidence_with_duration(
        8_000,
        runtime_version=("3.12.9" if mismatch == "runtime_version" else "3.13.5"),
    )
    values = _inputs_from_evidence(baseline_evidence, candidate_evidence)
    baseline_build = _docker_build(
        kind="baseline",
        round_number=0,
        marker="d",
        treatment_marker="1",
    )
    candidate_build = _docker_build(
        kind="candidate",
        round_number=1,
        marker="e",
        treatment_marker="2",
    )
    baseline_run = _docker_run(
        baseline_evidence,
        baseline_build,
        ordinal=0,
        measurement_marker="b",
    )
    candidate_run = _docker_run(
        candidate_evidence,
        candidate_build,
        ordinal=1,
        measurement_marker="c",
    )

    comparison = _compare(
        values,
        baseline_run=baseline_run,
        candidate_run=candidate_run,
        baseline_resource_environment_sha256="e" * 64,
        candidate_resource_environment_sha256=(
            "f" * 64 if mismatch == "fixed_environment" else "e" * 64
        ),
        baseline_build=baseline_build,
        candidate_build=candidate_build,
    )

    assert not comparison.comparable
    assert comparison.conclusion == "not_comparable"
    assert comparison.adapter_match == (mismatch != "runtime_version")
    assert comparison.resource_environment_match == (mismatch != "fixed_environment")
    assert comparison.improved_metrics == ()
