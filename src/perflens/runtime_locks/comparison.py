"""Deterministic, evidence-bound Runtime Lock A/B comparison."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_evidence import (
    canonical_runtime_lock_json_sha256,
)
from perflens.contracts.docker import ContainerMeasurementArtifact
from perflens.contracts.docker_build import DockerBuildArtifact
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    derive_runtime_lock_comparison_id,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockEvidenceArtifact,
    RuntimeSourceManifest,
)
from perflens.domain.errors import ErrorCode, PerfLensError

ResourceTransferStatus = Literal[
    "no_observed_regression",
    "regression",
    "incomplete",
]

_MINIMUM_MATERIAL_CHANGE_PERCENT = 1.0


def compare_runtime_lock_analyses(
    *,
    baseline_run: RuntimeLockRunArtifact,
    baseline_analysis: RuntimeLockAnalysisArtifact,
    baseline_evidence: RuntimeLockEvidenceArtifact,
    baseline_verification: RuntimeLockAnalysisVerificationArtifact,
    candidate_run: RuntimeLockRunArtifact,
    candidate_analysis: RuntimeLockAnalysisArtifact,
    candidate_evidence: RuntimeLockEvidenceArtifact,
    candidate_verification: RuntimeLockAnalysisVerificationArtifact,
    baseline_resource_environment_sha256: str,
    candidate_resource_environment_sha256: str,
    resource_transfer_status: ResourceTransferStatus,
    resource_comparison_id: str | None = None,
    resource_comparison_content_sha256: str | None = None,
    baseline_build: DockerBuildArtifact | None = None,
    candidate_build: DockerBuildArtifact | None = None,
    created_at: datetime | None = None,
) -> RuntimeLockComparisonArtifact:
    """Compare only totals that preserve the source measurement semantics.

    Lock IDs are deliberately absent from the comparison because they are
    Artifact-local opaque identities.  The caller supplies independently
    computed resource-environment fingerprints; the Artifact records both so
    ArtifactStore can reproduce the match instead of trusting one boolean.
    """

    _verify_run_inputs(
        baseline_run,
        baseline_analysis,
        baseline_evidence,
        baseline_verification,
        "baseline",
    )
    _verify_run_inputs(
        candidate_run,
        candidate_analysis,
        candidate_evidence,
        candidate_verification,
        "candidate",
    )
    if baseline_run.schema_version != "1.1" or candidate_run.schema_version != "1.1":
        raise _comparison_error("Runtime Lock A/B requires schema 1.1 Runs")
    if baseline_run.session_id != candidate_run.session_id:
        raise _comparison_error("Runtime Lock Runs belong to different authorization Sessions")
    if baseline_run.authorization_kind != candidate_run.authorization_kind:
        raise _comparison_error("Runtime Lock Runs use different authorization authorities")
    baseline_docker = baseline_run.docker_optimization_binding
    candidate_docker = candidate_run.docker_optimization_binding
    docker_treatment_changed: bool | None = None
    if baseline_run.authorization_kind == "runtime_lock_session":
        expected_baseline_environment = runtime_lock_resource_environment_sha256(
            baseline_run,
            baseline_evidence,
        )
        expected_candidate_environment = runtime_lock_resource_environment_sha256(
            candidate_run,
            candidate_evidence,
        )
        if (
            baseline_resource_environment_sha256 != expected_baseline_environment
            or candidate_resource_environment_sha256 != expected_candidate_environment
        ):
            raise _comparison_error(
                "Standalone Runtime Lock resource-environment fingerprints are invalid"
            )
        if (
            resource_transfer_status != "incomplete"
            or resource_comparison_id is not None
            or resource_comparison_content_sha256 is not None
            or baseline_build is not None
            or candidate_build is not None
        ):
            raise _comparison_error(
                "Standalone Runtime Lock comparison lacks bound resource-transfer evidence"
            )
    else:
        if (
            baseline_docker is None
            or candidate_docker is None
            or resource_comparison_id is None
            or resource_comparison_content_sha256 is None
            or baseline_build is None
            or candidate_build is None
        ):
            raise _comparison_error(
                "Docker Runtime Lock comparison requires bound Build and resource evidence"
            )
        _verify_content(
            baseline_build,
            baseline_build.content_sha256,
            "baseline Docker Build",
        )
        _verify_content(
            candidate_build,
            candidate_build.content_sha256,
            "candidate Docker Build",
        )
        if (
            baseline_docker.build_id != baseline_build.build_id
            or baseline_docker.build_content_sha256 != baseline_build.content_sha256
            or candidate_docker.build_id != candidate_build.build_id
            or candidate_docker.build_content_sha256 != candidate_build.content_sha256
            or baseline_build.build_kind != "baseline"
            or baseline_build.candidate_round != 0
            or candidate_build.build_kind != "candidate"
            or candidate_build.candidate_round < 1
            or baseline_build.recipe_id != candidate_build.recipe_id
            or baseline_build.recipe_content_sha256 != candidate_build.recipe_content_sha256
            or baseline_build.builder_identity_sha256
            != candidate_build.builder_identity_sha256
            or baseline_build.network_policy_sha256
            != candidate_build.network_policy_sha256
            or baseline_build.platform != candidate_build.platform
            or baseline_build.immutable_manifest_sha256
            != candidate_build.immutable_manifest_sha256
        ):
            raise _comparison_error(
                "Docker Runtime Lock Runs are not bound to one fixed Build environment"
            )
        docker_treatment_changed = (
            baseline_build.treatment_manifest_sha256
            != candidate_build.treatment_manifest_sha256
            and baseline_build.final_image_digest != candidate_build.final_image_digest
        )
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _comparison_error("Runtime Lock comparison time must include a timezone")

    adapter_match = (
        baseline_run.adapter_id == candidate_run.adapter_id
        and baseline_run.adapter_execution_identity_sha256
        == candidate_run.adapter_execution_identity_sha256
        and _adapter_environment(baseline_evidence.source)
        == _adapter_environment(candidate_evidence.source)
    )
    semantics_match = (
        baseline_run.measurement_semantics == candidate_run.measurement_semantics
        and baseline_analysis.measurement_semantics == candidate_analysis.measurement_semantics
        and baseline_evidence.source.measurement_semantics
        == candidate_evidence.source.measurement_semantics
    )
    threshold_or_sampling_match = _measurement_controls(
        baseline_evidence.source
    ) == _measurement_controls(candidate_evidence.source)
    workload_match = (
        baseline_run.workload_identity_sha256 == candidate_run.workload_identity_sha256
    )
    resource_environment_match = (
        baseline_resource_environment_sha256 == candidate_resource_environment_sha256
    )
    correctness_status = _correctness_status(baseline_run, candidate_run)
    deterministic_replay_passed = (
        baseline_verification.verification_status == "verified"
        and candidate_verification.verification_status == "verified"
    )
    comparable = all(
        (
            adapter_match,
            semantics_match,
            threshold_or_sampling_match,
            workload_match,
            resource_environment_match,
            correctness_status == "passed",
            deterministic_replay_passed,
            docker_treatment_changed is not False,
        )
    )

    improved_metrics: tuple[str, ...] = ()
    regressed_metrics: tuple[str, ...] = ()
    if comparable:
        baseline_metrics = _comparison_metrics(baseline_analysis)
        candidate_metrics = _comparison_metrics(candidate_analysis)
        if baseline_metrics.keys() != candidate_metrics.keys():
            raise _comparison_error("Runtime Lock analyses expose different semantic metrics")
        improved_metrics = tuple(
            sorted(
                name
                for name, baseline_value in baseline_metrics.items()
                if _material_change_percent(baseline_value, candidate_metrics[name])
                <= -_MINIMUM_MATERIAL_CHANGE_PERCENT
            )
        )
        regressed_metrics = tuple(
            sorted(
                name
                for name, baseline_value in baseline_metrics.items()
                if _material_change_percent(baseline_value, candidate_metrics[name])
                >= _MINIMUM_MATERIAL_CHANGE_PERCENT
            )
        )
        if resource_transfer_status == "regression":
            regressed_metrics = tuple(sorted((*regressed_metrics, "resource_transfer")))

    if not comparable:
        conclusion = "not_comparable"
    elif regressed_metrics:
        conclusion = "candidate_regression"
    elif improved_metrics:
        conclusion = "candidate_improvement"
    else:
        conclusion = "no_material_change"

    warnings: list[str] = []
    if not adapter_match:
        warnings.append("Runtime Lock Adapter, runtime, tool, or configuration identity differs.")
    if not semantics_match:
        warnings.append("Runtime Lock measurement semantics differ.")
    if not threshold_or_sampling_match:
        warnings.append("Runtime Lock threshold, sampling, or profile-rate controls differ.")
    if not workload_match:
        warnings.append("Runtime Lock workload identities differ.")
    if docker_treatment_changed is False:
        warnings.append(
            "Docker Runtime Lock Runs do not contain a distinct authorized Treatment."
        )
    if not resource_environment_match:
        warnings.append("Runtime Lock resource-environment fingerprints differ.")
    if correctness_status != "passed":
        warnings.append("Runtime Lock A/B correctness is not proven for both Runs.")
    if not deterministic_replay_passed:
        warnings.append(
            "Runtime Lock source conversion was not independently replayed for both Runs."
        )
    if resource_transfer_status == "incomplete":
        warnings.append("Resource-transfer evidence is incomplete.")
    elif resource_transfer_status == "regression":
        warnings.append("A resource-transfer regression was observed.")
    if "partial" in {baseline_run.quality_status, candidate_run.quality_status}:
        warnings.append("Partial Runtime Lock evidence cannot establish Verified Improvement.")

    allowed = set(baseline_analysis.allowed_conclusions) & set(
        candidate_analysis.allowed_conclusions
    )
    allowed.add("runtime_lock_comparison")
    forbidden = set(baseline_analysis.forbidden_conclusions) | set(
        candidate_analysis.forbidden_conclusions
    )
    forbidden.add("performance_root_cause")
    forbidden.add("verified_improvement")
    allowed.discard("verified_improvement")
    allowed -= forbidden

    provisional = RuntimeLockComparisonArtifact(
        schema_version="1.1",
        perflens_version=__version__,
        comparison_id=derive_runtime_lock_comparison_id(
            baseline_run.session_id,
            baseline_run.content_sha256,
            candidate_run.content_sha256,
            timestamp.isoformat(),
        ),
        created_at=timestamp.isoformat(),
        comparison_kind=baseline_run.authorization_kind,
        session_id=baseline_run.session_id,
        baseline_run_id=baseline_run.run_id,
        baseline_run_content_sha256=baseline_run.content_sha256,
        candidate_run_id=candidate_run.run_id,
        candidate_run_content_sha256=candidate_run.content_sha256,
        baseline_build_id=(baseline_docker.build_id if baseline_docker is not None else None),
        baseline_build_content_sha256=(
            baseline_docker.build_content_sha256 if baseline_docker is not None else None
        ),
        candidate_build_id=(candidate_docker.build_id if candidate_docker is not None else None),
        candidate_build_content_sha256=(
            candidate_docker.build_content_sha256 if candidate_docker is not None else None
        ),
        baseline_measurement_id=(
            baseline_docker.container_measurement_id if baseline_docker is not None else None
        ),
        candidate_measurement_id=(
            candidate_docker.container_measurement_id if candidate_docker is not None else None
        ),
        resource_comparison_id=resource_comparison_id,
        resource_comparison_content_sha256=resource_comparison_content_sha256,
        docker_treatment_changed=docker_treatment_changed,
        minimum_material_change_percent=_MINIMUM_MATERIAL_CHANGE_PERCENT,
        adapter_match=adapter_match,
        semantics_match=semantics_match,
        threshold_or_sampling_match=threshold_or_sampling_match,
        workload_match=workload_match,
        resource_environment_match=resource_environment_match,
        baseline_resource_environment_sha256=baseline_resource_environment_sha256,
        candidate_resource_environment_sha256=candidate_resource_environment_sha256,
        baseline_quality_status=baseline_run.quality_status,
        candidate_quality_status=candidate_run.quality_status,
        correctness_status=correctness_status,
        deterministic_replay_passed=deterministic_replay_passed,
        resource_transfer_status=resource_transfer_status,
        comparable=comparable,
        conclusion=conclusion,
        improved_metrics=improved_metrics,
        regressed_metrics=regressed_metrics,
        warnings=tuple(warnings),
        allowed_conclusions=tuple(sorted(allowed)),
        forbidden_conclusions=tuple(sorted(forbidden)),
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


def runtime_lock_resource_environment_sha256(
    run: RuntimeLockRunArtifact,
    evidence: RuntimeLockEvidenceArtifact,
) -> str:
    """Derive the standalone environment surface available in Runtime Lock evidence.

    Ephemeral PID/TID, timestamps, source bytes, and opaque lock identities are
    excluded.  Docker comparisons use their independently replayable
    ContainerMeasurement environment fingerprint instead.
    """

    if run.schema_version != "1.1" or run.authorization_kind != "runtime_lock_session":
        raise _comparison_error(
            "Docker Runtime Lock environments require ContainerMeasurement evidence"
        )
    return canonical_runtime_lock_json_sha256(
        {
            "schema": "perflens-runtime-lock-resource-environment-v1",
            "target_scope": run.target_scope,
            "target_kind": evidence.target.target_kind,
            "target_uid": evidence.target.target_uid,
            "adapter_environment": _adapter_environment(evidence.source),
            "measurement_controls": _measurement_controls(evidence.source),
        }
    )


def docker_runtime_lock_fixed_environment_sha256(
    measurement: ContainerMeasurementArtifact,
) -> str:
    """Hash Docker A/B invariants while excluding the authorized Treatment."""

    environment = measurement.environment.model_dump(
        mode="json",
        exclude={
            "environment_fingerprint_sha256",
            "image_identity_sha256",
            "workload_fingerprint",
        },
    )
    return canonical_runtime_lock_json_sha256(
        {
            "schema": "perflens-runtime-lock-docker-fixed-environment-v1",
            "environment": environment,
        }
    )


def _verify_run_inputs(
    run: RuntimeLockRunArtifact,
    analysis: RuntimeLockAnalysisArtifact,
    evidence: RuntimeLockEvidenceArtifact,
    verification: RuntimeLockAnalysisVerificationArtifact,
    label: str,
) -> None:
    for model, expected, name in (
        (run, run.content_sha256, "Run"),
        (analysis, analysis.content_sha256, "Analysis"),
        (evidence, evidence.content_sha256, "Evidence"),
        (verification, verification.content_sha256, "Verification"),
    ):
        _verify_content(model, expected, f"{label} {name}")
    if (
        run.runtime_lock_evidence_id != evidence.runtime_lock_evidence_id
        or run.runtime_lock_evidence_content_sha256 != evidence.content_sha256
        or run.runtime_lock_analysis_id != analysis.runtime_lock_analysis_id
        or run.runtime_lock_analysis_content_sha256 != analysis.content_sha256
        or run.runtime_lock_verification_id != verification.runtime_lock_verification_id
        or run.runtime_lock_verification_content_sha256 != verification.content_sha256
        or analysis.runtime_lock_evidence_id != evidence.runtime_lock_evidence_id
        or analysis.runtime_lock_evidence_content_sha256 != evidence.content_sha256
        or verification.runtime_lock_evidence_id != evidence.runtime_lock_evidence_id
        or verification.runtime_lock_evidence_content_sha256 != evidence.content_sha256
        or verification.runtime_lock_analysis_id != analysis.runtime_lock_analysis_id
        or verification.runtime_lock_analysis_content_sha256 != analysis.content_sha256
        or run.measurement_semantics != analysis.measurement_semantics
        or run.measurement_semantics != evidence.source.measurement_semantics
        or run.quality_status != analysis.quality_status
    ):
        raise _comparison_error(f"{label} Runtime Lock evidence chain is inconsistent")


def _adapter_environment(source: RuntimeSourceManifest) -> tuple[object, ...]:
    return (
        source.runtime,
        source.runtime_version,
        source.adapter_id,
        source.adapter_version,
        source.backend_id,
        source.backend_version,
        source.source_format,
        source.converter_version,
        source.clock.clock,
        source.clock.unit,
        source.clock.epoch_correlation_available,
        source.fast_path_visibility,
        source.owner_is_source_observed,
        source.hold_time_is_source_observed,
        source.target_scope,
        source.tool.model_dump(mode="json") if source.tool is not None else None,
        source.adapter_execution_identity_sha256,
        source.configuration_sha256,
        source.metadata_sha256,
    )


def _measurement_controls(source: RuntimeSourceManifest) -> tuple[int | None, ...]:
    return (
        source.duration_threshold_ns,
        source.sampling_period,
        source.sampling_fraction,
        source.block_profile_rate_ns,
    )


def _comparison_metrics(analysis: RuntimeLockAnalysisArtifact) -> dict[str, int]:
    semantics = analysis.measurement_semantics
    if semantics == "exact":
        return {
            "total_exact_hold_ns": analysis.total_exact_hold_ns,
            "total_exact_wait_ns": analysis.total_exact_wait_ns,
        }
    if semantics == "thresholded":
        return {"total_thresholded_wait_ns": analysis.total_thresholded_wait_ns}
    if semantics == "sampled":
        if analysis.total_observed_or_estimated_wait_ns:
            return {
                "total_observed_or_estimated_wait_ns": (
                    analysis.total_observed_or_estimated_wait_ns
                )
            }
        return {"total_sampled_observation_count": analysis.total_sampled_observation_count}
    if analysis.total_observed_or_estimated_wait_ns:
        return {
            "total_observed_or_estimated_wait_ns": (
                analysis.total_observed_or_estimated_wait_ns
            )
        }
    return {"total_cumulative_observation_count": analysis.total_cumulative_observation_count}


def _material_change_percent(baseline: int, candidate: int) -> float:
    """Return a signed bounded change where reductions are negative."""

    if baseline == candidate:
        return 0.0
    if baseline == 0:
        return 100.0
    return ((candidate - baseline) / baseline) * 100.0


def _correctness_status(
    baseline: RuntimeLockRunArtifact,
    candidate: RuntimeLockRunArtifact,
) -> Literal["passed", "failed", "unavailable"]:
    statuses = {baseline.correctness_status, candidate.correctness_status}
    if "failed" in statuses:
        return "failed"
    if statuses == {"passed"}:
        return "passed"
    return "unavailable"


def _verify_content(model: BaseModel, expected: str, label: str) -> None:
    try:
        model.__class__.model_validate(model.model_dump(mode="json", exclude_none=True))
    except ValueError as exc:
        raise _comparison_error(f"{label} contract validation failed") from exc
    if contract_content_sha256(model, exclude={"content_sha256"}) != expected:
        raise _comparison_error(f"{label} content digest is invalid")


def _comparison_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "runtime_lock_comparison",
        message,
    )
