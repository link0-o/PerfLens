"""Deterministic A/B verification for one bounded Docker optimization round."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    BenchmarkArtifact,
    BenchmarkComparison,
    ProfileComparison,
)
from perflens.contracts.docker import (
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
)
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerOptimizationIterationArtifact,
    DockerOptimizationSessionArtifact,
    derive_docker_optimization_iteration_id,
)
from perflens.docker.comparison import compare_container_measurements
from perflens.domain.errors import ErrorCode, PerfLensError

_TREATMENT_ENVIRONMENT_FIELDS = frozenset(
    {
        "image_identity_sha256",
        "workload_fingerprint",
    }
)


def compare_docker_optimization_iteration(
    *,
    session: DockerOptimizationSessionArtifact,
    baseline_build: DockerBuildArtifact,
    candidate_build: DockerBuildArtifact,
    baseline_measurement: ContainerMeasurementArtifact,
    candidate_measurement: ContainerMeasurementArtifact,
    baseline_analysis: AnalysisArtifact,
    candidate_analysis: AnalysisArtifact,
    profile_comparison: ProfileComparison,
    baseline_benchmark: BenchmarkArtifact,
    candidate_benchmark: BenchmarkArtifact,
    benchmark_comparison: BenchmarkComparison,
    source_container_comparison: ContainerMatchedComparisonArtifact,
    created_at: datetime | None = None,
) -> DockerOptimizationIterationArtifact:
    """Verify all source evidence and allow only image/workload treatment changes."""
    _verify_content(session, session.content_sha256, "optimization session")
    _verify_content(baseline_build, baseline_build.content_sha256, "baseline build")
    _verify_content(candidate_build, candidate_build.content_sha256, "candidate build")
    replayed = compare_container_measurements(
        baseline_measurement,
        candidate_measurement,
        baseline_analysis=baseline_analysis,
        candidate_analysis=candidate_analysis,
        profile_comparison=profile_comparison,
        baseline_benchmark=baseline_benchmark,
        candidate_benchmark=candidate_benchmark,
        benchmark_comparison=benchmark_comparison,
        created_at=datetime.fromisoformat(source_container_comparison.created_at),
    )
    if replayed != source_container_comparison:
        raise _comparison_error("source container comparison failed deterministic replay")
    if (
        session.baseline_build_id != baseline_build.build_id
        or session.latest_candidate_build_id != candidate_build.build_id
        or session.recipe_id != baseline_build.recipe_id
        or session.recipe_id != candidate_build.recipe_id
        or session.recipe_content_sha256 != baseline_build.recipe_content_sha256
        or session.recipe_content_sha256 != candidate_build.recipe_content_sha256
        or baseline_build.build_kind != "baseline"
        or baseline_build.candidate_round != 0
        or candidate_build.build_kind != "candidate"
        or candidate_build.candidate_round < 1
        or candidate_build.candidate_round > session.candidate_rounds_used
    ):
        raise _comparison_error("optimization Session and Build bindings differ")
    if (
        baseline_measurement.environment.image_identity_sha256
        != baseline_build.final_image_digest.removeprefix("sha256:")
        or candidate_measurement.environment.image_identity_sha256
        != candidate_build.final_image_digest.removeprefix("sha256:")
    ):
        raise _comparison_error("measurement image identity is not bound to its Build Artifact")

    fixed_build_differences = _fixed_build_differences(baseline_build, candidate_build)
    fixed_environment_differences = {
        key: value
        for key, value in source_container_comparison.environment_differences.items()
        if key not in _TREATMENT_ENVIRONMENT_FIELDS
    }
    fixed_differences = {
        **{f"build.{key}": value for key, value in fixed_build_differences.items()},
        **{
            f"runtime.{key}": value
            for key, value in fixed_environment_differences.items()
        },
    }
    fixed_environment_match = not fixed_differences
    treatment_changed = (
        baseline_build.treatment_manifest_sha256
        != candidate_build.treatment_manifest_sha256
        and baseline_build.final_image_digest != candidate_build.final_image_digest
    )
    actual_event_source_match = (
        baseline_measurement.environment.actual_event_source
        == candidate_measurement.environment.actual_event_source
    )
    analyses_verified = all(
        analysis.status == "complete"
        and analysis.evidence_quality.quality_status == "verified"
        and analysis.evidence_quality.parser_invariants_passed
        for analysis in (baseline_analysis, candidate_analysis)
    )
    comparable = (
        fixed_environment_match
        and profile_comparison.comparable
        and benchmark_comparison.comparable
        and baseline_benchmark.environment.containerized is True
        and candidate_benchmark.environment.containerized is True
        and actual_event_source_match
    )
    improved_metrics = source_container_comparison.improved_metrics
    regressed_metrics = source_container_comparison.regressed_metrics
    resource_status = source_container_comparison.resource_transfer_status
    correctness_status = source_container_comparison.correctness_status
    if not comparable:
        conclusion = "not_comparable"
    elif regressed_metrics:
        conclusion = "candidate_regression"
    elif improved_metrics:
        verified = (
            treatment_changed
            and correctness_status == "passed"
            and resource_status == "no_observed_regression"
            and analyses_verified
            and baseline_measurement.quality_status == "verified"
            and candidate_measurement.quality_status == "verified"
        )
        conclusion = "verified_improvement" if verified else "candidate_improvement"
    else:
        conclusion = "no_material_change"

    warnings = list(source_container_comparison.warnings)
    if not fixed_environment_match:
        warnings.append(
            "Fixed Docker optimization environment changed; A/B attribution is invalid."
        )
    if not treatment_changed:
        warnings.append(
            "Mutable context and final image must both differ for a candidate Treatment."
        )
    if not analyses_verified:
        warnings.append("Partial or failed profile evidence cannot establish Verified Improvement.")
    if not actual_event_source_match:
        warnings.append("Actual perf event sources differ between baseline and candidate.")
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _comparison_error("Docker optimization comparison time must include a timezone")
    provisional = DockerOptimizationIterationArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        iteration_id=derive_docker_optimization_iteration_id(
            session.session_id,
            baseline_build.build_id,
            candidate_build.build_id,
            baseline_measurement.content_sha256,
            candidate_measurement.content_sha256,
        ),
        created_at=timestamp.isoformat(),
        session_id=session.session_id,
        session_artifact_id=session.session_artifact_id,
        session_artifact_content_sha256=session.content_sha256,
        candidate_round=candidate_build.candidate_round,
        baseline_build_id=baseline_build.build_id,
        baseline_build_content_sha256=baseline_build.content_sha256,
        candidate_build_id=candidate_build.build_id,
        candidate_build_content_sha256=candidate_build.content_sha256,
        baseline_measurement_id=baseline_measurement.measurement_id,
        baseline_measurement_content_sha256=baseline_measurement.content_sha256,
        candidate_measurement_id=candidate_measurement.measurement_id,
        candidate_measurement_content_sha256=candidate_measurement.content_sha256,
        baseline_analysis_id=baseline_analysis.analysis_id,
        baseline_analysis_content_sha256=baseline_analysis.content_sha256,
        candidate_analysis_id=candidate_analysis.analysis_id,
        candidate_analysis_content_sha256=candidate_analysis.content_sha256,
        profile_comparison_id=profile_comparison.comparison_id,
        profile_comparison_content_sha256=contract_content_sha256(profile_comparison),
        baseline_benchmark_id=baseline_benchmark.benchmark_id,
        baseline_benchmark_content_sha256=contract_content_sha256(baseline_benchmark),
        candidate_benchmark_id=candidate_benchmark.benchmark_id,
        candidate_benchmark_content_sha256=contract_content_sha256(candidate_benchmark),
        benchmark_comparison_id=benchmark_comparison.comparison_id,
        benchmark_comparison_content_sha256=contract_content_sha256(benchmark_comparison),
        source_container_comparison_id=source_container_comparison.comparison_id,
        source_container_comparison_content_sha256=source_container_comparison.content_sha256,
        fixed_environment_match=fixed_environment_match,
        fixed_environment_differences=fixed_differences,
        treatment_changed=treatment_changed,
        correctness_status=correctness_status,
        actual_event_source_match=actual_event_source_match,
        resource_transfer_status=resource_status,
        deterministic_replay_passed=True,
        comparable=comparable,
        conclusion=conclusion,
        improved_metrics=improved_metrics,
        regressed_metrics=regressed_metrics,
        warnings=tuple(dict.fromkeys(warnings)),
        allowed_conclusions=(
            "Verified Improvement may be reported only when conclusion is verified_improvement.",
            "Different final image digests are allowed only as Build-bound Treatment evidence.",
        ),
        forbidden_conclusions=(
            "Partial, mismatched, or failed evidence must not be presented as "
            "Verified Improvement.",
            "A performance change does not by itself prove a microarchitectural mechanism.",
        ),
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


def _fixed_build_differences(
    baseline: DockerBuildArtifact,
    candidate: DockerBuildArtifact,
) -> dict[str, tuple[str, str]]:
    fields = (
        "recipe_id",
        "recipe_content_sha256",
        "builder_identity_sha256",
        "network_policy_sha256",
        "platform",
        "immutable_manifest_sha256",
    )
    return {
        field: (str(getattr(baseline, field)), str(getattr(candidate, field)))
        for field in fields
        if getattr(baseline, field) != getattr(candidate, field)
    }


def _verify_content(model: BaseModel, expected: str, label: str) -> None:
    try:
        model.__class__.model_validate(model.model_dump(mode="json"))
    except ValueError as exc:
        raise _comparison_error(f"{label} contract validation failed") from exc
    if contract_content_sha256(model, exclude={"content_sha256"}) != expected:
        raise _comparison_error(f"{label} content digest is invalid")


def _comparison_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "docker_optimization_comparison",
        message,
        recoverable=False,
    )
