from __future__ import annotations

import hashlib
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from tests.support.docker import make_container_resource_context

from perflens import __version__
from perflens.application.analyze import analyze_folded
from perflens.application.evidence import (
    build_collection_evidence_provenance,
    compute_analysis_content_sha256,
    contract_content_sha256,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.comparison.benchmarks import compare_benchmarks
from perflens.comparison.profiles import compare_profiles
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    BenchmarkArtifact,
    BenchmarkComparison,
    BenchmarkEnvironment,
    BenchmarkMetric,
    CollectionArtifact,
    ContainerCollectionCgroupBinding,
    ContainerCollectionNamespaceBinding,
    ContainerCollectionTargetBinding,
    ProfileComparison,
)
from perflens.contracts.docker import (
    ContainerEnvironmentFingerprint,
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
    ContainerResourceContextArtifact,
    ContainerResourceLimits,
    ContainerRunArtifact,
    ContainerWorkloadSpecArtifact,
    container_environment_fingerprint,
)
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerOptimizationBudget,
    DockerOptimizationSessionArtifact,
    derive_docker_build_artifact_id,
    derive_docker_optimization_session_artifact_id,
)
from perflens.docker.comparison import (
    build_container_measurement,
    compare_container_measurements,
)
from perflens.docker.optimization_comparison import (
    compare_docker_optimization_iteration,
)
from perflens.domain.errors import PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy

_SOFTWARE_LIMITATIONS = (
    "instructions-per-cycle unavailable",
    "hardware cache-miss evidence unavailable",
    "hardware branch-miss evidence unavailable",
)


def _binding(*, marker: str, host_pid: int) -> ContainerCollectionTargetBinding:
    return ContainerCollectionTargetBinding(
        target_id="container-target-" + marker * 20,
        target_kind="managed_temporary_container",
        target_content_sha256=marker * 64,
        container_identity_sha256=marker * 64,
        image_identity_sha256="d" * 64,
        identity_fingerprint=hashlib.sha256(f"identity-{marker}".encode()).hexdigest(),
        container_pid=1,
        host_pid=host_pid,
        host_uid=1000,
        host_start_time_ticks=host_pid * 10,
        executable_name="workload",
        namespace=ContainerCollectionNamespaceBinding(
            pid_namespace_inode=host_pid + 1,
            user_namespace_inode=host_pid + 2,
            mount_namespace_inode=host_pid + 3,
            cgroup_namespace_inode=host_pid + 4,
        ),
        cgroup=ContainerCollectionCgroupBinding(
            inode=host_pid + 5,
            identity_sha256="7" * 64,
        ),
        uid_mapping="rootless_same_uid",
        adapter_recipe_id="local-docker-managed-v1",
        adapter_sha256="8" * 64,
    )


def _collection(
    profile: Path,
    *,
    marker: str,
    host_pid: int,
) -> CollectionArtifact:
    payload = profile.read_bytes()
    return CollectionArtifact(
        collection_id="collection-" + marker * 16,
        mode="record",
        target_type="pid",
        target_argument_count=0,
        target_pid=host_pid,
        target_runtime="docker",
        container_target=_binding(marker=marker, host_pid=host_pid),
        output_path=str(profile),
        output_sha256=hashlib.sha256(payload).hexdigest(),
        output_bytes=len(payload),
        output_format="perf_data",
        output_owner_uid=1000,
        perf_executable="/usr/bin/perf",
        started_at="2026-08-22T00:00:00+00:00",
        finished_at="2026-08-22T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=99,
        call_graph="dwarf",
        record_event="cpu-clock",
        requested_event_source="auto",
        actual_event_source="software",
        fallback_used=True,
        fallback_reason="hardware_probe_produced_no_usable_counts",
        evidence_limitations=_SOFTWARE_LIMITATIONS,
        collector_config_sha256="9" * 64,
        collector_privilege_mode="paranoid3_helper",
        collector_feature_profile="full_diagnostics",
        host_kernel_release="6.12-test",
        perf_executable_sha256="a" * 64,
        authorization="explicit",
    )


def _workload() -> ContainerWorkloadSpecArtifact:
    treatment_path_sha256 = hashlib.sha256(
        b"perflens-container-treatment-path-v1\0src/workload.py"
    ).hexdigest()
    provisional = ContainerWorkloadSpecArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        workload_spec_id="container-workload-" + "1" * 20,
        created_at="2026-08-22T00:00:00+00:00",
        project_identity_sha256="2" * 64,
        image_digest="sha256:" + "d" * 64,
        container_gate_sha256="3" * 64,
        entrypoint="/usr/bin/python3",
        arguments=("/workspace/bench.py",),
        working_directory="/workspace",
        container_user="1000:1000",
        resources=ContainerResourceLimits(cpus=1, memory_bytes=64 << 20, pids=32),
        allowed_modes=("stat", "record"),
        authorization_mode="bounded_session",
        correctness_command_sha256="5" * 64,
        benchmark_output_contract_sha256="6" * 64,
        treatment_path_sha256=(treatment_path_sha256,),
        workload_fingerprint="4" * 64,
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


def _run(
    collection: CollectionArtifact,
    resource: ContainerResourceContextArtifact,
    workload: ContainerWorkloadSpecArtifact,
    *,
    marker: str,
    treatment: str,
    benchmark: BenchmarkArtifact,
) -> ContainerRunArtifact:
    target = collection.container_target
    assert target is not None
    provisional = ContainerRunArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        run_id="container-run-" + marker * 20,
        created_at="2026-08-22T00:00:02+00:00",
        session_id="container-session-" + marker * 20,
        workload_spec_sha256=workload.content_sha256,
        container_identity_sha256=target.container_identity_sha256,
        image_identity_sha256=target.image_identity_sha256,
        target_identity_sha256=target.identity_fingerprint,
        container_pid=target.container_pid,
        host_pid=target.host_pid,
        host_start_time_ticks=target.host_start_time_ticks,
        started_at="2026-08-22T00:00:00+00:00",
        finished_at="2026-08-22T00:00:02+00:00",
        status="exited",
        exit_code=0,
        collection_ids=(collection.collection_id,),
        treatment_path_sha256=workload.treatment_path_sha256,
        build_artifact_sha256=(treatment,),
        benchmark_id=benchmark.benchmark_id,
        benchmark_content_sha256=contract_content_sha256(benchmark),
        resource_context_id=resource.resource_context_id,
        cleanup_status="removed",
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


def _analysis(profile: Path, collection: CollectionArtifact) -> AnalysisArtifact:
    original = analyze_folded(profile)
    provenance = build_collection_evidence_provenance(collection)
    metadata = original.metadata.model_copy(
        update={
            "source_type": "perf_data",
            "event": "cpu-clock",
            "conversion": original.metadata.conversion.model_copy(update={"adapter": "perf_data"}),
            "collection": provenance,
        }
    )
    quality = original.evidence_quality.model_copy(
        update={
            "quality_status": "verified",
            "actual_event_source": collection.actual_event_source,
            "fallback_used": collection.fallback_used,
            "fallback_reason": collection.fallback_reason,
            "source_collection_id": collection.collection_id,
            "source_collection_artifact_sha256": provenance.collection_artifact_sha256,
            "collection_limitations": collection.evidence_limitations,
        }
    )
    provisional = original.model_copy(
        update={
            "metadata": metadata,
            "evidence_quality": quality,
            "content_sha256": "0" * 64,
        }
    )
    return provisional.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(provisional)}
    )


def _benchmark(
    benchmark_id: str,
    values: tuple[float, ...],
    *,
    commit: str,
    error_count: int | None = 0,
    containerized: bool | None = True,
) -> BenchmarkArtifact:
    return BenchmarkArtifact(
        benchmark_id=f"benchmark-{hashlib.sha256(benchmark_id.encode()).hexdigest()[:16]}",
        name="throughput",
        commit=commit,
        build_type="release",
        duration_seconds=5,
        warmup_seconds=1,
        repetitions=len(values),
        concurrency=1,
        operations=10_000,
        metrics={
            "throughput": BenchmarkMetric(
                unit="operations/second",
                higher_is_better=True,
                values=values,
                median=statistics.median(values),
                mean=statistics.fmean(values),
                standard_deviation=(statistics.stdev(values) if len(values) > 1 else 0),
            )
        },
        environment=BenchmarkEnvironment(
            cpu_model="same-cpu",
            cpu_count=4,
            kernel="6.12-test",
            containerized=containerized,
        ),
        error_count=error_count,
        source_format="perflens",
    )


def _measurement_pair(
    tmp_path: Path,
    *,
    benchmarks: tuple[BenchmarkArtifact, BenchmarkArtifact] | None = None,
):
    baseline_profile = tmp_path / "baseline.folded"
    candidate_profile = tmp_path / "candidate.folded"
    baseline_profile.write_text("main;slow 80\nmain;other 20\n", encoding="utf-8")
    candidate_profile.write_text("main;slow 60\nmain;other 40\n", encoding="utf-8")
    workload = _workload()
    bound_benchmarks = benchmarks or (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    collections = (
        _collection(baseline_profile, marker="b", host_pid=1200),
        _collection(candidate_profile, marker="c", host_pid=2400),
    )
    resources = tuple(
        make_container_resource_context(
            container_identity_sha256=collection.container_target.container_identity_sha256,
            source_collection_id=collection.collection_id,
            source_output_sha256=collection.output_sha256,
        )
        for collection in collections
        if collection.container_target is not None
    )
    runs = (
        _run(
            collections[0],
            resources[0],
            workload,
            marker="b",
            treatment="1" * 64,
            benchmark=bound_benchmarks[0],
        ),
        _run(
            collections[1],
            resources[1],
            workload,
            marker="c",
            treatment="2" * 64,
            benchmark=bound_benchmarks[1],
        ),
    )
    measurements = tuple(
        build_container_measurement(
            collection,
            resource,
            run=run,
            workload=workload,
            created_at=datetime(2026, 8, 22, tzinfo=UTC),
        )
        for collection, resource, run in zip(collections, resources, runs, strict=True)
    )
    analyses = tuple(
        _analysis(profile, collection)
        for profile, collection in zip(
            (baseline_profile, candidate_profile),
            collections,
            strict=True,
        )
    )
    return collections, resources, workload, runs, measurements, analyses


def _optimization_build(
    *,
    kind: Literal["baseline", "candidate"],
    round_number: int,
    image_marker: str,
    treatment_marker: str,
) -> DockerBuildArtifact:
    image_digest = "sha256:" + image_marker * 64
    started_at = f"2026-08-22T00:00:0{round_number}+00:00"
    provisional = DockerBuildArtifact(
        schema_version="1.0",
        perflens_version=__version__,
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
        context_id="docker-build-context-" + image_marker * 20,
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


def _optimization_session(
    baseline: DockerBuildArtifact,
    candidate: DockerBuildArtifact,
) -> DockerOptimizationSessionArtifact:
    updated_at = "2026-08-22T00:00:03+00:00"
    session_id = "docker-optimization-session-" + "1" * 20
    provisional = DockerOptimizationSessionArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        session_artifact_id=derive_docker_optimization_session_artifact_id(
            session_id,
            "active",
            updated_at,
            2,
            2,
            4096,
        ),
        session_id=session_id,
        created_at="2026-08-22T00:00:00+00:00",
        updated_at=updated_at,
        expires_at="2026-08-22T02:00:00+00:00",
        state="active",
        project_identity_sha256="1" * 64,
        client_connection_identity_sha256="2" * 64,
        project_policy_sha256="3" * 64,
        preview_id="docker-optimization-preview-" + "1" * 20,
        preview_content_sha256="2" * 64,
        build_capability_content_sha256="3" * 64,
        recipe_id=baseline.recipe_id,
        recipe_content_sha256=baseline.recipe_content_sha256,
        authorization_receipt_sha256="5" * 64,
        allowed_modes=("stat", "record"),
        budget=DockerOptimizationBudget(
            max_candidate_rounds=3,
            max_builds=4,
            max_workload_runs=10,
            max_recoverable_retries=1,
            max_build_seconds=900,
            max_total_build_seconds=3600,
            max_workload_active_seconds=1800,
            hard_expiry_seconds=7200,
            max_evidence_bytes=1 << 30,
            max_temporary_image_bytes=10 << 30,
            record_max_duration_seconds=30,
            record_frequency_hz=99,
            trace_max_duration_seconds=10,
        ),
        builds_used=2,
        candidate_rounds_used=1,
        workload_runs_used=2,
        recoverable_retries_used=0,
        build_seconds_used=2,
        workload_active_seconds_used=2,
        evidence_bytes_used=4096,
        temporary_image_bytes_used=8192,
        baseline_build_id=baseline.build_id,
        latest_candidate_build_id=candidate.build_id,
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


def _bind_measurement_image(
    measurement: ContainerMeasurementArtifact,
    image_digest: str,
) -> ContainerMeasurementArtifact:
    environment = measurement.environment.model_copy(
        update={"image_identity_sha256": image_digest.removeprefix("sha256:")}
    )
    environment = environment.model_copy(
        update={
            "environment_fingerprint_sha256": container_environment_fingerprint(environment)
        }
    )
    provisional = measurement.model_copy(
        update={"environment": environment, "content_sha256": "0" * 64}
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def test_managed_measurements_ignore_ephemeral_container_and_pid_identity(tmp_path: Path) -> None:
    _, _, _, _, measurements, _ = _measurement_pair(tmp_path)

    assert measurements[0].environment == measurements[1].environment
    assert measurements[0].measurement_id != measurements[1].measurement_id
    assert measurements[0].treatment_sha256 == ("1" * 64,)
    assert measurements[1].treatment_sha256 == ("2" * 64,)
    serialized = measurements[0].model_dump_json()
    assert "1200" not in serialized
    assert "container_identity_sha256" not in serialized


def test_measurement_rejects_cross_collection_and_tampered_evidence(tmp_path: Path) -> None:
    collections, resources, _, _, _, _ = _measurement_pair(tmp_path)
    workload = _workload()
    wrong_run = _run(
        collections[0],
        resources[0],
        workload,
        marker="d",
        treatment="3" * 64,
        benchmark=_benchmark("benchmark-wrong", (1, 1, 1), commit="wrong"),
    )
    with pytest.raises(PerfLensError, match="belongs to different Collection"):
        build_container_measurement(
            collections[0],
            resources[1],
            run=wrong_run,
            workload=workload,
        )
    tampered = resources[0].model_copy(update={"limitations": ("invented",)})
    with pytest.raises(PerfLensError, match="content digest is invalid"):
        build_container_measurement(
            collections[0],
            tampered,
            run=wrong_run,
            workload=workload,
        )


def test_verified_improvement_requires_full_matched_evidence(tmp_path: Path) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])

    result = compare_container_measurements(
        measurements[0],
        measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert result.comparable
    assert result.environment_match
    assert result.correctness_status == "passed"
    assert result.resource_transfer_status == "no_observed_regression"
    assert result.conclusion == "verified_improvement"
    assert result.improved_metrics == ("throughput",)
    assert result.baseline_analysis_content_sha256 == analyses[0].content_sha256
    assert result.candidate_benchmark_content_sha256 == contract_content_sha256(benchmarks[1])


def test_optimization_allows_verified_build_image_as_treatment(tmp_path: Path) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    baseline_build = _optimization_build(
        kind="baseline",
        round_number=0,
        image_marker="d",
        treatment_marker="1",
    )
    candidate_build = _optimization_build(
        kind="candidate",
        round_number=1,
        image_marker="e",
        treatment_marker="2",
    )
    bound_measurements = (
        _bind_measurement_image(measurements[0], baseline_build.final_image_digest),
        _bind_measurement_image(measurements[1], candidate_build.final_image_digest),
    )
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])
    source = compare_container_measurements(
        bound_measurements[0],
        bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )

    result = compare_docker_optimization_iteration(
        session=_optimization_session(baseline_build, candidate_build),
        baseline_build=baseline_build,
        candidate_build=candidate_build,
        baseline_measurement=bound_measurements[0],
        candidate_measurement=bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        source_container_comparison=source,
        created_at=datetime(2026, 8, 22, 0, 1, tzinfo=UTC),
    )

    assert source.conclusion == "not_comparable"
    assert source.environment_differences == {
        "image_identity_sha256": ("d" * 64, "e" * 64)
    }
    assert (
        "Container environment fingerprints differ; attribution is invalid."
        in source.warnings
    )
    assert result.fixed_environment_match
    assert result.treatment_changed
    assert result.conclusion == "verified_improvement"
    assert result.deterministic_replay_passed
    assert (
        "Container environment fingerprints differ; attribution is invalid."
        not in result.warnings
    )


def test_optimization_rejects_fixed_build_change_and_partial_profile(tmp_path: Path) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    baseline_build = _optimization_build(
        kind="baseline",
        round_number=0,
        image_marker="d",
        treatment_marker="1",
    )
    candidate_build = _optimization_build(
        kind="candidate",
        round_number=1,
        image_marker="e",
        treatment_marker="2",
    ).model_copy(update={"builder_identity_sha256": "f" * 64})
    candidate_build = candidate_build.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                candidate_build,
                exclude={"content_sha256"},
            )
        }
    )
    bound_measurements = (
        _bind_measurement_image(measurements[0], baseline_build.final_image_digest),
        _bind_measurement_image(measurements[1], candidate_build.final_image_digest),
    )
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])
    source = compare_container_measurements(
        bound_measurements[0],
        bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    result = compare_docker_optimization_iteration(
        session=_optimization_session(baseline_build, candidate_build),
        baseline_build=baseline_build,
        candidate_build=candidate_build,
        baseline_measurement=bound_measurements[0],
        candidate_measurement=bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        source_container_comparison=source,
    )
    assert not result.comparable
    assert result.conclusion == "not_comparable"
    assert "build.builder_identity_sha256" in result.fixed_environment_differences
    assert (
        "Fixed Docker optimization environment changed; A/B attribution is invalid."
        in result.warnings
    )

    partial_analysis = analyses[1].model_copy(
        update={
            "status": "partial",
            "evidence_quality": analyses[1].evidence_quality.model_copy(
                update={"quality_status": "partial"}
            ),
        }
    )
    partial_analysis = partial_analysis.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(partial_analysis)}
    )
    partial_profiles = compare_profiles(analyses[0], partial_analysis)
    partial_source = compare_container_measurements(
        bound_measurements[0],
        bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=partial_analysis,
        profile_comparison=partial_profiles,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
    )
    partial_result = compare_docker_optimization_iteration(
        session=_optimization_session(baseline_build, candidate_build),
        baseline_build=baseline_build,
        candidate_build=candidate_build,
        baseline_measurement=bound_measurements[0],
        candidate_measurement=bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=partial_analysis,
        profile_comparison=partial_profiles,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        source_container_comparison=partial_source,
    )
    assert partial_result.conclusion == "not_comparable"
    assert any("Partial" in warning for warning in partial_result.warnings)


def test_missing_correctness_or_non_container_benchmark_stays_qualified(tmp_path: Path) -> None:
    baseline = _benchmark(
        "benchmark-before",
        (100, 101, 99),
        commit="before",
        error_count=None,
        containerized=None,
    )
    candidate = _benchmark(
        "benchmark-after",
        (120, 121, 119),
        commit="after",
        error_count=None,
        containerized=None,
    )
    _, _, _, _, measurements, analyses = _measurement_pair(
        tmp_path,
        benchmarks=(baseline, candidate),
    )
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmark_comparison = compare_benchmarks(baseline, candidate)

    result = compare_container_measurements(
        measurements[0],
        measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=baseline,
        candidate_benchmark=candidate,
        benchmark_comparison=benchmark_comparison,
    )

    assert not result.comparable
    assert result.conclusion == "not_comparable"
    assert result.correctness_status == "unavailable"
    assert any("containerized=true" in warning for warning in result.warnings)


def test_comparison_rejects_tampered_analysis_and_comparison(tmp_path: Path) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])
    tampered_analysis = analyses[0].model_copy(update={"analysis_id": "analysis-tampered"})
    with pytest.raises(PerfLensError, match="not bound"):
        compare_container_measurements(
            measurements[0],
            measurements[1],
            baseline_analysis=tampered_analysis,
            candidate_analysis=analyses[1],
            profile_comparison=profile_comparison,
            baseline_benchmark=benchmarks[0],
            candidate_benchmark=benchmarks[1],
            benchmark_comparison=benchmark_comparison,
        )
    forged = benchmark_comparison.model_copy(update={"minimum_practical_impact_percent": 50})
    with pytest.raises(PerfLensError, match="deterministic replay"):
        compare_container_measurements(
            measurements[0],
            measurements[1],
            baseline_analysis=analyses[0],
            candidate_analysis=analyses[1],
            profile_comparison=profile_comparison,
            baseline_benchmark=benchmarks[0],
            candidate_benchmark=benchmarks[1],
            benchmark_comparison=forged,
        )
    substituted = _benchmark("benchmark-substitute", (130, 131, 129), commit="after")
    substituted_comparison = compare_benchmarks(benchmarks[0], substituted)
    with pytest.raises(PerfLensError, match="Benchmark comparison content failed"):
        compare_container_measurements(
            measurements[0],
            measurements[1],
            baseline_analysis=analyses[0],
            candidate_analysis=analyses[1],
            profile_comparison=profile_comparison,
            baseline_benchmark=benchmarks[0],
            candidate_benchmark=substituted,
            benchmark_comparison=substituted_comparison,
        )


def test_environment_change_or_resource_transfer_blocks_verified_claim(tmp_path: Path) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])
    unchecked_environment = measurements[1].environment.model_copy(
        update={
            "host_kernel_release": "6.13-different",
            "environment_fingerprint_sha256": "0" * 64,
        }
    )
    changed_environment = ContainerEnvironmentFingerprint.model_validate(
        unchecked_environment.model_copy(
            update={
                "environment_fingerprint_sha256": container_environment_fingerprint(
                    unchecked_environment
                )
            }
        ).model_dump(mode="python")
    )
    changed_measurement = measurements[1].model_copy(
        update={
            "environment": changed_environment,
        }
    )
    changed_measurement = changed_measurement.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                changed_measurement,
                exclude={"content_sha256"},
            )
        }
    )
    mismatch = compare_container_measurements(
        measurements[0],
        changed_measurement,
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
    )
    assert mismatch.conclusion == "not_comparable"
    assert "host_kernel_release" in mismatch.environment_differences

    invalid_environment = changed_environment.model_copy(
        update={"host_kernel_release": "6.14-unbound"}
    )
    invalid_measurement = measurements[1].model_copy(update={"environment": invalid_environment})
    invalid_measurement = invalid_measurement.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                invalid_measurement,
                exclude={"content_sha256"},
            )
        }
    )
    with pytest.raises(PerfLensError, match="contract validation failed"):
        compare_container_measurements(
            measurements[0],
            invalid_measurement,
            baseline_analysis=analyses[0],
            candidate_analysis=analyses[1],
            profile_comparison=profile_comparison,
            baseline_benchmark=benchmarks[0],
            candidate_benchmark=benchmarks[1],
            benchmark_comparison=benchmark_comparison,
        )

    increased_delta = measurements[1].resource_observation.model_copy(
        update={
            "cpu_usage_usec": measurements[0].resource_observation.cpu_usage_usec + 1,
        }
    )
    transferred = measurements[1].model_copy(update={"resource_observation": increased_delta})
    transferred = transferred.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                transferred,
                exclude={"content_sha256"},
            )
        }
    )
    result = compare_container_measurements(
        measurements[0],
        transferred,
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
    )
    assert result.resource_transfer_status == "regression"
    assert result.conclusion == "candidate_improvement"


def test_store_replays_container_measurement_links_before_returning_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collections, resources, workload, runs, measurements, _ = _measurement_pair(tmp_path)
    store = ArtifactStore(
        tmp_path / "artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    measurement = measurements[0]
    benchmark = _benchmark("benchmark-before", (100, 101, 99), commit="before")
    path = store.save(
        measurement,
        measurement.measurement_id,
        "container-measurement",
    )

    def load_collection(_artifact_id: str) -> CollectionArtifact:
        return collections[0]

    def load_resource(_artifact_id: str) -> ContainerResourceContextArtifact:
        return resources[0]

    def load_run(_artifact_id: str) -> ContainerRunArtifact:
        return runs[0]

    def load_workload(_artifact_id: str) -> ContainerWorkloadSpecArtifact:
        return workload

    def load_bound_benchmark(_artifact_id: str) -> BenchmarkArtifact:
        return benchmark

    monkeypatch.setattr(store, "load_collection", load_collection)
    monkeypatch.setattr(
        store,
        "load_container_resource_context",
        load_resource,
    )
    monkeypatch.setattr(store, "load_container_run", load_run)
    monkeypatch.setattr(
        store,
        "load_container_workload_spec",
        load_workload,
    )
    monkeypatch.setattr(store, "load_benchmark", load_bound_benchmark)

    assert store.load_container_measurement(measurement.measurement_id) == measurement

    forged = measurement.model_copy(update={"treatment_sha256": ("f" * 64,)})
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)
    with pytest.raises(PerfLensError, match="Agent-visible content"):
        store.load_container_measurement(measurement.measurement_id)


def test_store_replays_matched_comparison_and_rejects_qualified_claim_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])
    comparison = compare_container_measurements(
        measurements[0],
        measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    store = ArtifactStore(
        tmp_path / "artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    path = store.save(
        comparison,
        comparison.comparison_id,
        "container-matched-comparison",
    )

    def load_measurement(artifact_id: str) -> ContainerMeasurementArtifact:
        return measurements[0] if artifact_id == measurements[0].measurement_id else measurements[1]

    def load_analysis(artifact_id: str) -> AnalysisArtifact:
        return analyses[0] if artifact_id == analyses[0].analysis_id else analyses[1]

    def load_profile_comparison(_artifact_id: str) -> ProfileComparison:
        return profile_comparison

    def load_benchmark(artifact_id: str) -> BenchmarkArtifact:
        return benchmarks[0] if artifact_id == benchmarks[0].benchmark_id else benchmarks[1]

    def load_benchmark_comparison(_artifact_id: str) -> BenchmarkComparison:
        return benchmark_comparison

    monkeypatch.setattr(
        store,
        "load_container_measurement",
        load_measurement,
    )
    monkeypatch.setattr(
        store,
        "load_analysis",
        load_analysis,
    )
    monkeypatch.setattr(
        store,
        "load_profile_comparison",
        load_profile_comparison,
    )
    monkeypatch.setattr(
        store,
        "load_benchmark",
        load_benchmark,
    )
    monkeypatch.setattr(
        store,
        "load_benchmark_comparison",
        load_benchmark_comparison,
    )

    assert store.load_container_matched_comparison(comparison.comparison_id) == comparison

    forged = comparison.model_copy(update={"conclusion": "candidate_improvement"})
    forged = forged.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                forged,
                exclude={"content_sha256"},
            )
        }
    )
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)
    with pytest.raises(PerfLensError, match="Agent-visible content"):
        store.load_container_matched_comparison(comparison.comparison_id)


def test_store_replays_complete_docker_optimization_iteration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, _, measurements, analyses = _measurement_pair(tmp_path)
    baseline_build = _optimization_build(
        kind="baseline",
        round_number=0,
        image_marker="d",
        treatment_marker="1",
    )
    candidate_build = _optimization_build(
        kind="candidate",
        round_number=1,
        image_marker="e",
        treatment_marker="2",
    )
    session = _optimization_session(baseline_build, candidate_build)
    bound_measurements = (
        _bind_measurement_image(measurements[0], baseline_build.final_image_digest),
        _bind_measurement_image(measurements[1], candidate_build.final_image_digest),
    )
    benchmarks = (
        _benchmark("benchmark-before", (100, 101, 99), commit="before"),
        _benchmark("benchmark-after", (120, 121, 119), commit="after"),
    )
    profile_comparison = compare_profiles(analyses[0], analyses[1])
    benchmark_comparison = compare_benchmarks(benchmarks[0], benchmarks[1])
    source = compare_container_measurements(
        bound_measurements[0],
        bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    iteration = compare_docker_optimization_iteration(
        session=session,
        baseline_build=baseline_build,
        candidate_build=candidate_build,
        baseline_measurement=bound_measurements[0],
        candidate_measurement=bound_measurements[1],
        baseline_analysis=analyses[0],
        candidate_analysis=analyses[1],
        profile_comparison=profile_comparison,
        baseline_benchmark=benchmarks[0],
        candidate_benchmark=benchmarks[1],
        benchmark_comparison=benchmark_comparison,
        source_container_comparison=source,
        created_at=datetime(2026, 8, 22, 0, 1, tzinfo=UTC),
    )
    store = ArtifactStore(
        tmp_path / "stored-artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    store.save(session, session.session_artifact_id, "docker-optimization-session")
    store.save(baseline_build, baseline_build.build_id, "docker-build")
    store.save(candidate_build, candidate_build.build_id, "docker-build")
    store.save(iteration, iteration.iteration_id, "docker-optimization-iteration")

    def load_measurement(artifact_id: str) -> ContainerMeasurementArtifact:
        if artifact_id == bound_measurements[0].measurement_id:
            return bound_measurements[0]
        return bound_measurements[1]

    def load_analysis(artifact_id: str) -> AnalysisArtifact:
        return analyses[0] if artifact_id == analyses[0].analysis_id else analyses[1]

    def load_profile(_artifact_id: str) -> ProfileComparison:
        return profile_comparison

    def load_benchmark(artifact_id: str) -> BenchmarkArtifact:
        return benchmarks[0] if artifact_id == benchmarks[0].benchmark_id else benchmarks[1]

    def load_benchmark_comparison(_artifact_id: str) -> BenchmarkComparison:
        return benchmark_comparison

    def load_source(_artifact_id: str) -> ContainerMatchedComparisonArtifact:
        return source

    monkeypatch.setattr(store, "load_container_measurement", load_measurement)
    monkeypatch.setattr(store, "load_analysis", load_analysis)
    monkeypatch.setattr(store, "load_profile_comparison", load_profile)
    monkeypatch.setattr(store, "load_benchmark", load_benchmark)
    monkeypatch.setattr(store, "load_benchmark_comparison", load_benchmark_comparison)
    monkeypatch.setattr(store, "load_container_matched_comparison", load_source)

    assert store.load_docker_build(baseline_build.build_id) == baseline_build
    assert store.load_docker_optimization_session(session.session_artifact_id) == session
    assert store.load_docker_optimization_iteration(iteration.iteration_id) == iteration
