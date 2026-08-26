"""Deterministic, evidence-bound container measurement and matched A/B comparison."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel

from perflens import __version__
from perflens.application.evidence import (
    compute_analysis_content_sha256,
    contract_content_sha256,
)
from perflens.comparison.benchmarks import compare_benchmarks
from perflens.comparison.profiles import compare_profiles
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    BenchmarkArtifact,
    BenchmarkComparison,
    CollectionArtifact,
    CollectionEvidenceProvenance,
    ProfileComparison,
)
from perflens.contracts.docker import (
    ContainerEnvironmentFingerprint,
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerWorkloadSpecArtifact,
    container_environment_fingerprint,
    derive_container_measurement_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError

CONTAINER_ENVIRONMENT_MISMATCH_WARNING = (
    "Container environment fingerprints differ; attribution is invalid."
)


def build_container_measurement(
    collection: CollectionArtifact,
    resource_context: ContainerResourceContextArtifact,
    *,
    run: ContainerRunArtifact | None = None,
    workload: ContainerWorkloadSpecArtifact | None = None,
    created_at: datetime | None = None,
) -> ContainerMeasurementArtifact:
    """Bind stable environment invariants without treating container/PID IDs as A/B inputs."""
    target = collection.container_target
    if collection.target_runtime != "docker" or target is None:
        raise _comparison_error("Container measurement requires a Docker Collection")
    if collection.mode not in {"stat", "record"}:
        raise _comparison_error("Matched container A/B currently requires stat or record evidence")
    if (
        resource_context.source_collection_id != collection.collection_id
        or resource_context.source_output_sha256 != collection.output_sha256
        or resource_context.container_identity_sha256 != target.container_identity_sha256
        or resource_context.cgroup_identity_sha256 != target.cgroup.identity_sha256
    ):
        raise _comparison_error(
            "Container resource context belongs to different Collection evidence"
        )
    _verify_content(resource_context, resource_context.content_sha256, "resource context")
    managed = target.target_kind == "managed_temporary_container"
    if managed != (run is not None) or managed != (workload is not None):
        raise _comparison_error("Managed measurement requires its exact run and workload spec")
    limitations = set(resource_context.limitations)
    workload_fingerprint: str | None = None
    gate_sha256: str | None = None
    source_run_id: str | None = None
    source_run_content_sha256: str | None = None
    workload_spec_sha256: str | None = None
    treatments: tuple[str, ...] = ()
    if run is not None and workload is not None:
        _verify_content(run, run.content_sha256, "container run")
        _verify_content(workload, workload.content_sha256, "workload spec")
        if (
            run.workload_spec_sha256 != workload.content_sha256
            or run.treatment_path_sha256 != workload.treatment_path_sha256
            or (workload.benchmark_output_contract_sha256 is None)
            != (run.benchmark_id is None)
            or collection.collection_id not in run.collection_ids
            or run.resource_context_id != resource_context.resource_context_id
            or run.container_identity_sha256 != target.container_identity_sha256
            or run.image_identity_sha256 != target.image_identity_sha256
            or run.target_identity_sha256 != target.identity_fingerprint
        ):
            raise _comparison_error(
                "Container run, workload, Collection, and target bindings differ"
            )
        workload_fingerprint = workload.workload_fingerprint
        gate_sha256 = workload.container_gate_sha256
        source_run_id = run.run_id
        source_run_content_sha256 = run.content_sha256
        workload_spec_sha256 = workload.content_sha256
        treatments = tuple(sorted(set((*treatments, *run.build_artifact_sha256))))
        if run.status != "exited" or run.exit_code != 0:
            limitations.add("Managed workload did not complete successfully.")
        if run.benchmark_id is None:
            limitations.add("Managed workload did not produce a run-bound benchmark.")
    else:
        limitations.add(
            "Existing-container command, input, and correctness contract are not "
            "cryptographically bound."
        )
    collector_values = (
        collection.collector_config_sha256,
        collection.collector_privilege_mode,
        collection.collector_feature_profile,
        collection.host_kernel_release,
        collection.perf_executable_sha256,
    )
    if any(value is None for value in collector_values):
        raise _comparison_error("Docker Collection omits Collector and perf environment provenance")
    if resource_context.before.io_limits != resource_context.after.io_limits:
        limitations.add("I/O limits changed during the measurement window.")
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _comparison_error("Container measurement timestamp must include a timezone")
    environment_values = {
        "target_kind": target.target_kind,
        "image_identity_sha256": target.image_identity_sha256,
        "uid_mapping": target.uid_mapping,
        "adapter_recipe_id": target.adapter_recipe_id,
        "adapter_sha256": target.adapter_sha256,
        "workload_fingerprint": workload_fingerprint,
        "container_gate_sha256": gate_sha256,
        "mount_layout_recipe": (
            "managed-workspace-readonly-v1" if managed else "existing-container-unverified-v1"
        ),
        "network_mode": "none" if managed else "unknown",
        "host_kernel_release": collection.host_kernel_release,
        "perf_executable_sha256": collection.perf_executable_sha256,
        "collector_config_sha256": collection.collector_config_sha256,
        "collector_privilege_mode": collection.collector_privilege_mode,
        "collector_feature_profile": collection.collector_feature_profile,
        "collection_mode": collection.mode,
        "collection_frequency_hz": collection.frequency_hz,
        "collection_call_graph": collection.call_graph,
        "collection_record_event": collection.record_event,
        "collection_events": collection.events,
        "requested_event_source": collection.requested_event_source,
        "actual_event_source": collection.actual_event_source,
        "fallback_used": collection.fallback_used,
        "fallback_reason": collection.fallback_reason,
        "evidence_limitations": collection.evidence_limitations,
        "cpu_quota_usec": resource_context.before.cpu_quota_usec,
        "cpu_period_usec": resource_context.before.cpu_period_usec,
        "cpuset_cpus_effective": resource_context.before.cpuset_cpus_effective,
        "memory_max_bytes": resource_context.before.memory_max_bytes,
        "io_limits": resource_context.before.io_limits,
        "pids_max": resource_context.before.pids_max,
        "environment_fingerprint_sha256": "0" * 64,
    }
    unchecked_environment = ContainerEnvironmentFingerprint.model_construct(
        _fields_set=set(environment_values), **environment_values
    )
    environment = ContainerEnvironmentFingerprint.model_validate(
        {
            **environment_values,
            "environment_fingerprint_sha256": container_environment_fingerprint(
                unchecked_environment
            ),
        }
    )
    limitation_tuple = tuple(sorted(limitations))
    provisional = ContainerMeasurementArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        measurement_id=derive_container_measurement_id(collection.collection_id),
        created_at=timestamp.isoformat(),
        source_collection_id=collection.collection_id,
        source_collection_artifact_sha256=contract_content_sha256(collection),
        source_output_sha256=collection.output_sha256,
        resource_context_id=resource_context.resource_context_id,
        resource_context_content_sha256=resource_context.content_sha256,
        source_run_id=source_run_id,
        source_run_content_sha256=source_run_content_sha256,
        workload_spec_id=(workload.workload_spec_id if workload is not None else None),
        workload_spec_sha256=workload_spec_sha256,
        correctness_command_sha256=(
            workload.correctness_command_sha256 if workload is not None else None
        ),
        benchmark_output_contract_sha256=(
            workload.benchmark_output_contract_sha256 if workload is not None else None
        ),
        source_benchmark_id=(run.benchmark_id if run is not None else None),
        source_benchmark_content_sha256=(
            run.benchmark_content_sha256 if run is not None else None
        ),
        environment=environment,
        treatment_sha256=treatments,
        resource_observation=resource_context.delta,
        quality_status=("partial" if limitation_tuple else "verified"),
        limitations=limitation_tuple,
        allowed_conclusions=(
            "Matched environment invariants and whole-container resource deltas may be compared.",
            "Ephemeral container IDs and PIDs may differ between managed A/B runs.",
        ),
        forbidden_conclusions=(
            "Profile percentages alone do not establish an absolute performance improvement.",
            "Container-wide cgroup deltas are not exclusive target-process resource use.",
            "Verified Improvement requires matched environment, correctness, absolute metrics, "
            "and no observed resource regression.",
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


def compare_container_measurements(
    baseline_measurement: ContainerMeasurementArtifact,
    candidate_measurement: ContainerMeasurementArtifact,
    *,
    baseline_analysis: AnalysisArtifact,
    candidate_analysis: AnalysisArtifact,
    profile_comparison: ProfileComparison,
    baseline_benchmark: BenchmarkArtifact,
    candidate_benchmark: BenchmarkArtifact,
    benchmark_comparison: BenchmarkComparison,
    created_at: datetime | None = None,
) -> ContainerMatchedComparisonArtifact:
    """Produce a conservative verdict and independently recompute both supplied comparisons."""
    _verify_content(
        baseline_measurement,
        baseline_measurement.content_sha256,
        "baseline measurement",
    )
    _verify_content(
        candidate_measurement,
        candidate_measurement.content_sha256,
        "candidate measurement",
    )
    _verify_profile_binding(
        baseline_measurement,
        candidate_measurement,
        baseline_analysis,
        candidate_analysis,
        profile_comparison,
    )
    _verify_benchmark_binding(
        baseline_measurement,
        candidate_measurement,
        baseline_benchmark,
        candidate_benchmark,
        benchmark_comparison,
    )
    environment_differences = _environment_differences(
        baseline_measurement.environment,
        candidate_measurement.environment,
    )
    environment_match = not environment_differences
    treatment_changed = (
        baseline_measurement.treatment_sha256 != candidate_measurement.treatment_sha256
    )
    correctness_status = _correctness_status(baseline_benchmark, candidate_benchmark)
    resource_status = _resource_transfer_status(
        baseline_measurement,
        candidate_measurement,
    )
    containerized_benchmarks = (
        baseline_benchmark.environment.containerized is True
        and candidate_benchmark.environment.containerized is True
    )
    comparable = (
        environment_match
        and profile_comparison.comparable
        and benchmark_comparison.comparable
        and containerized_benchmarks
    )
    improved_metrics = tuple(
        sorted(
            item.metric
            for item in benchmark_comparison.metrics
            if item.status == "candidate_improvement"
        )
    )
    regressed_metrics = tuple(
        sorted(
            item.metric
            for item in benchmark_comparison.metrics
            if item.status == "candidate_regression"
        )
    )
    if not comparable:
        conclusion = "not_comparable"
    elif regressed_metrics:
        conclusion = "candidate_regression"
    elif improved_metrics:
        verified = (
            treatment_changed
            and correctness_status == "passed"
            and resource_status == "no_observed_regression"
            and baseline_measurement.quality_status == "verified"
            and candidate_measurement.quality_status == "verified"
        )
        conclusion = "verified_improvement" if verified else "candidate_improvement"
    else:
        conclusion = "no_material_change"
    warnings = list(
        dict.fromkeys(
            (
                *baseline_measurement.limitations,
                *candidate_measurement.limitations,
                *profile_comparison.warnings,
                *benchmark_comparison.warnings,
            )
        )
    )
    if not environment_match:
        warnings.append(CONTAINER_ENVIRONMENT_MISMATCH_WARNING)
    if not containerized_benchmarks:
        warnings.append("Both benchmark artifacts must explicitly declare containerized=true.")
    if correctness_status != "passed":
        warnings.append("Correctness requires zero reported errors on both benchmark sides.")
    if resource_status != "no_observed_regression":
        warnings.append("Whole-container resource evidence is incomplete or shows a transfer.")
    if not treatment_changed:
        warnings.append("No changed source/build treatment digest was supplied.")
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _comparison_error("Container comparison timestamp must include a timezone")
    material = "\0".join(
        (
            baseline_measurement.content_sha256,
            candidate_measurement.content_sha256,
            contract_content_sha256(profile_comparison),
            contract_content_sha256(benchmark_comparison),
        )
    )
    provisional = ContainerMatchedComparisonArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        comparison_id=f"container-comparison-{hashlib.sha256(material.encode()).hexdigest()[:20]}",
        created_at=timestamp.isoformat(),
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
        environment_match=environment_match,
        environment_differences=environment_differences,
        treatment_changed=treatment_changed,
        baseline_treatment_sha256=baseline_measurement.treatment_sha256,
        candidate_treatment_sha256=candidate_measurement.treatment_sha256,
        correctness_status=correctness_status,
        resource_transfer_status=resource_status,
        comparable=comparable,
        conclusion=conclusion,
        improved_metrics=improved_metrics,
        regressed_metrics=regressed_metrics,
        warnings=tuple(warnings),
        allowed_conclusions=(
            "Verified Improvement may be reported only when conclusion is verified_improvement.",
            "Candidate and regression conclusions retain their explicit evidence qualifiers.",
        ),
        forbidden_conclusions=(
            "A non-comparable or candidate result must not be presented as Verified Improvement.",
            "A matched container environment does not prove a microarchitectural mechanism.",
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


def _verify_profile_binding(
    baseline_measurement: ContainerMeasurementArtifact,
    candidate_measurement: ContainerMeasurementArtifact,
    baseline_analysis: AnalysisArtifact,
    candidate_analysis: AnalysisArtifact,
    comparison: ProfileComparison,
) -> None:
    baseline_collection = baseline_analysis.metadata.collection
    candidate_collection = candidate_analysis.metadata.collection
    if (
        compute_analysis_content_sha256(baseline_analysis) != baseline_analysis.content_sha256
        or compute_analysis_content_sha256(candidate_analysis) != candidate_analysis.content_sha256
        or baseline_collection is None
        or candidate_collection is None
        or not _analysis_matches_measurement(
            baseline_analysis,
            baseline_collection,
            baseline_measurement,
        )
        or not _analysis_matches_measurement(
            candidate_analysis,
            candidate_collection,
            candidate_measurement,
        )
        or comparison.baseline_analysis_id != baseline_analysis.analysis_id
        or comparison.candidate_analysis_id != candidate_analysis.analysis_id
    ):
        raise _comparison_error("Profile comparison is not bound to both container measurements")
    recomputed = compare_profiles(
        baseline_analysis,
        candidate_analysis,
        minimum_delta_percent=comparison.minimum_delta_percent,
    )
    if recomputed != comparison:
        raise _comparison_error("Profile comparison content failed deterministic replay")


def _analysis_matches_measurement(
    analysis: AnalysisArtifact,
    collection: CollectionEvidenceProvenance,
    measurement: ContainerMeasurementArtifact,
) -> bool:
    quality = analysis.evidence_quality
    return bool(
        collection.mode == "record"
        and collection.target_runtime == "docker"
        and analysis.metadata.source_type == "perf_data"
        and analysis.metadata.conversion.adapter == "perf_data"
        and analysis.metadata.event == collection.record_event
        and collection.collection_id == measurement.source_collection_id
        and collection.collection_artifact_sha256 == measurement.source_collection_artifact_sha256
        and collection.output_sha256 == measurement.source_output_sha256
        and analysis.metadata.input_sha256 == measurement.source_output_sha256
        and analysis.metadata.input_bytes == collection.output_bytes
        and quality.input_sha256 == measurement.source_output_sha256
        and quality.input_bytes == collection.output_bytes
        and quality.source_collection_id == measurement.source_collection_id
        and quality.source_collection_artifact_sha256
        == measurement.source_collection_artifact_sha256
        and quality.actual_event_source == collection.actual_event_source
        and quality.fallback_used == collection.fallback_used
        and quality.fallback_reason == collection.fallback_reason
        and quality.collection_limitations == collection.evidence_limitations
    )


def _verify_benchmark_binding(
    baseline_measurement: ContainerMeasurementArtifact,
    candidate_measurement: ContainerMeasurementArtifact,
    baseline: BenchmarkArtifact,
    candidate: BenchmarkArtifact,
    comparison: BenchmarkComparison,
) -> None:
    if (
        baseline_measurement.source_benchmark_id != baseline.benchmark_id
        or baseline_measurement.source_benchmark_content_sha256
        != contract_content_sha256(baseline)
        or candidate_measurement.source_benchmark_id != candidate.benchmark_id
        or candidate_measurement.source_benchmark_content_sha256
        != contract_content_sha256(candidate)
        or comparison.baseline_benchmark_id != baseline.benchmark_id
        or comparison.candidate_benchmark_id != candidate.benchmark_id
        or compare_benchmarks(
            baseline,
            candidate,
            minimum_practical_impact_percent=comparison.minimum_practical_impact_percent,
        )
        != comparison
    ):
        raise _comparison_error("Benchmark comparison content failed deterministic replay")


def _environment_differences(
    baseline: ContainerEnvironmentFingerprint,
    candidate: ContainerEnvironmentFingerprint,
) -> dict[str, tuple[str, str]]:
    before = baseline.model_dump(mode="json", exclude={"environment_fingerprint_sha256"})
    after = candidate.model_dump(mode="json", exclude={"environment_fingerprint_sha256"})
    return {
        field: (str(before[field]), str(after[field]))
        for field in sorted(before)
        if before[field] != after[field]
    }


def _correctness_status(
    baseline: BenchmarkArtifact,
    candidate: BenchmarkArtifact,
) -> Literal["passed", "failed", "unavailable"]:
    if baseline.error_count is None or candidate.error_count is None:
        return "unavailable"
    if baseline.error_count or candidate.error_count:
        return "failed"
    return "passed"


def _resource_transfer_status(
    baseline: ContainerMeasurementArtifact,
    candidate: ContainerMeasurementArtifact,
) -> Literal["no_observed_regression", "regression", "incomplete"]:
    if baseline.quality_status != "verified" or candidate.quality_status != "verified":
        return "incomplete"
    before = baseline.resource_observation
    after = candidate.resource_observation
    scalar_fields = (
        "cpu_usage_usec",
        "cpu_nr_throttled",
        "cpu_throttled_usec",
        "io_read_bytes",
        "io_write_bytes",
        "io_read_ios",
        "io_write_ios",
        "memory_pressure_some_usec",
        "memory_pressure_full_usec",
        "io_pressure_some_usec",
        "io_pressure_full_usec",
    )
    for field in scalar_fields:
        first = getattr(before, field)
        second = getattr(after, field)
        if first is None or second is None:
            return "incomplete"
        if second > first:
            return "regression"
    memory_before = dict(before.memory_event_deltas)
    memory_after = dict(after.memory_event_deltas)
    if set(memory_before) != set(memory_after):
        return "incomplete"
    if any(memory_after[name] > memory_before[name] for name in memory_before):
        return "regression"
    return "no_observed_regression"


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
        "docker_comparison",
        message,
        recoverable=True,
    )
