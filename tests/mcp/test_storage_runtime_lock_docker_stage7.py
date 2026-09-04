# pyright: reportPrivateUsage=false
"""Stage 7 append-only replay gates for Docker Runtime Lock artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from tests.mcp.test_server_runtime_lock_docker import (
    _native_evidence_for_target,
    _runtime_lock_scope,
)
from tests.unit.test_docker_comparison import (
    _analysis,
    _benchmark,
    _collection,
    _run,
    _workload,
)
from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.evidence import (
    compute_analysis_content_sha256,
    compute_analysis_fingerprint,
    contract_content_sha256,
)
from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
    verify_runtime_lock_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.comparison.benchmarks import compare_benchmarks
from perflens.comparison.profiles import compare_profiles
from perflens.contracts.artifacts import CollectionArtifact
from perflens.contracts.docker import (
    ContainerCgroupIdentity,
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
    ContainerNamespaceIdentity,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerTargetArtifact,
    ContainerWorkloadSpecArtifact,
)
from perflens.contracts.docker_build import DockerBuildArtifact
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockEvidenceArtifact,
)
from perflens.docker.adapter import NativePthreadDockerLaunch
from perflens.docker.comparison import (
    build_container_measurement,
    compare_container_measurements,
)
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
)
from perflens.domain.errors import PerfLensError
from perflens.mcp.server import (
    _DockerRuntimeLockCollected,
    _DockerRuntimeLockRequest,
    _finalize_docker_runtime_lock_run,
)
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks.comparison import (
    compare_runtime_lock_analyses,
    docker_runtime_lock_fixed_environment_sha256,
)
from perflens.runtime_locks.docker_binding import bind_runtime_lock_evidence_to_container
from perflens.runtime_locks.docker_capture import bind_observed_runtime_execution


@dataclass(frozen=True)
class _Side:
    build: DockerBuildArtifact
    target: ContainerTargetArtifact
    collection: CollectionArtifact
    resource: ContainerResourceContextArtifact
    workload: ContainerWorkloadSpecArtifact
    container_run: ContainerRunArtifact
    measurement: ContainerMeasurementArtifact
    evidence: RuntimeLockEvidenceArtifact
    analysis: RuntimeLockAnalysisArtifact
    verification: RuntimeLockAnalysisVerificationArtifact
    runtime_run: RuntimeLockRunArtifact


@dataclass(frozen=True)
class _Graph:
    store: ArtifactStore
    runtime: Any
    session_id: str
    baseline: _Side
    candidate: _Side
    resource_comparison: ContainerMatchedComparisonArtifact
    comparison: RuntimeLockComparisonArtifact


def _save(
    store: ArtifactStore,
    artifact: Any,
    artifact_id: str,
    artifact_type: str,
) -> None:
    store.save(artifact, artifact_id, artifact_type)


def _rebind_content(artifact: Any, **changes: object) -> Any:
    provisional = artifact.model_copy(update={**changes, "content_sha256": "0" * 64})
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _verified_profile_analysis(profile: Path, collection: CollectionArtifact) -> Any:
    analysis = _analysis(profile, collection)
    parse_statistics = analysis.metadata.parse_statistics.model_copy(
        update={
            "frame_lines": analysis.evidence_quality.aggregated_frame_occurrence_count,
        }
    )
    conversion = analysis.metadata.conversion.model_copy(
        update={
            "converter_path": "@PRIVATE_CONVERTER@",
            "argv": ("@PRIVATE_CONVERTER@", "@PRIVATE_INPUT@"),
        }
    )
    metadata = analysis.metadata.model_copy(
        update={
            "input_path": "@PRIVATE_COLLECTION@",
            "parse_statistics": parse_statistics,
            "conversion": conversion,
            "weight_source": "sample_count_fallback",
        }
    )
    quality = analysis.evidence_quality.model_copy(
        update={
            "quality_status": "partial",
            "event": analysis.metadata.event,
            "weight_source": "sample_count_fallback",
            "frame_line_count": analysis.evidence_quality.aggregated_frame_occurrence_count,
            "unresolved_self_weight": analysis.metadata.total_weight,
            "unresolved_self_percent": 100.0,
            "unresolved_unknown_context_self_weight": analysis.metadata.total_weight,
            "unresolved_unknown_context_self_percent": 100.0,
            "limitations": tuple(
                dict.fromkeys(
                    (
                        *analysis.evidence_quality.limitations,
                        *collection.evidence_limitations,
                    )
                )
            ),
            "allowed_conclusions": tuple(
                dict.fromkeys(
                    (
                        *analysis.evidence_quality.allowed_conclusions,
                        "on_cpu_hotspot_distribution",
                    )
                )
            ),
            "forbidden_conclusions": tuple(
                dict.fromkeys(
                    (
                        *analysis.evidence_quality.forbidden_conclusions,
                        "unqualified_profile_conclusion",
                    )
                )
            ),
        }
    )
    analysis = analysis.model_copy(
        update={
            "status": "partial",
            "metadata": metadata,
            "evidence_quality": quality,
        }
    )
    fingerprint = compute_analysis_fingerprint(
        input_sha256=analysis.metadata.input_sha256,
        source_type=analysis.metadata.source_type,
        aggregation_semantics=analysis.aggregation_semantics,
        limits={key: int(value) for key, value in analysis.limits.model_dump().items()},
        conversion=analysis.metadata.conversion,
        collection=analysis.metadata.collection,
    )
    provisional = analysis.model_copy(
        update={
            "analysis_fingerprint": fingerprint,
            "analysis_id": f"analysis-{fingerprint[:16]}",
            "content_sha256": "0" * 64,
        }
    )
    return provisional.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(provisional)}
    )


def _persist_container_graph(
    store: ArtifactStore,
    root: Path,
    build: DockerBuildArtifact,
    *,
    marker: str,
    host_pid: int,
    benchmark_values: tuple[float, ...],
) -> tuple[
    ContainerTargetArtifact,
    CollectionArtifact,
    ContainerResourceContextArtifact,
    ContainerWorkloadSpecArtifact,
    ContainerRunArtifact,
    ContainerMeasurementArtifact,
    Any,
    Any,
]:
    root.mkdir(parents=True, exist_ok=True)
    profile = root / f"{marker}.folded"
    critical_weight = 80 if marker == "b" else 60
    other_weight = 100 - critical_weight
    profile.write_text(
        f"main;worker;critical {critical_weight}\n"
        f"main;worker;other {other_weight}\n",
        encoding="utf-8",
    )
    initial = _collection(profile, marker=marker, host_pid=host_pid)
    initial_binding = initial.container_target
    assert initial_binding is not None
    target_provisional = ContainerTargetArtifact(
        schema_version="1.1",
        perflens_version="0.4.0",
        target_id=initial_binding.target_id,
        created_at="2026-08-22T00:00:00+00:00",
        target_kind=initial_binding.target_kind,
        container_identity_sha256=initial_binding.container_identity_sha256,
        image_identity_sha256=build.final_image_digest.removeprefix("sha256:"),
        container_pid=initial_binding.container_pid,
        host_pid=initial_binding.host_pid,
        host_uid=initial_binding.host_uid,
        container_uid=1000,
        uid_map_sha256="6" * 64,
        host_start_time_ticks=initial_binding.host_start_time_ticks,
        executable_name=initial_binding.executable_name,
        namespace=ContainerNamespaceIdentity(
            pid_namespace_inode=initial_binding.namespace.pid_namespace_inode,
            user_namespace_inode=initial_binding.namespace.user_namespace_inode,
            mount_namespace_inode=initial_binding.namespace.mount_namespace_inode,
            cgroup_namespace_inode=initial_binding.namespace.cgroup_namespace_inode,
        ),
        cgroup=ContainerCgroupIdentity(
            inode=initial_binding.cgroup.inode,
            identity_sha256=initial_binding.cgroup.identity_sha256,
        ),
        uid_mapping=initial_binding.uid_mapping,
        adapter_recipe_id=initial_binding.adapter_recipe_id,
        adapter_sha256=initial_binding.adapter_sha256,
        identity_fingerprint=initial_binding.identity_fingerprint,
        content_sha256="0" * 64,
    )
    target = _rebind_content(target_provisional)
    collection_binding = initial_binding.model_copy(
        update={
            "target_content_sha256": target.content_sha256,
            "image_identity_sha256": target.image_identity_sha256,
            "container_uid": target.container_uid,
            "uid_map_sha256": target.uid_map_sha256,
        }
    )
    collection = initial.model_copy(update={"container_target": collection_binding})
    from tests.support.docker import make_container_resource_context

    resource = make_container_resource_context(
        container_identity_sha256=target.container_identity_sha256,
        source_collection_id=collection.collection_id,
        source_output_sha256=collection.output_sha256,
    )
    workload = _workload()
    benchmark = _benchmark(
        f"benchmark-{marker}",
        benchmark_values,
        commit=marker,
    )
    container_run = _run(
        collection,
        resource,
        workload,
        marker=marker,
        treatment=build.treatment_manifest_sha256,
        benchmark=benchmark,
    )
    measurement = build_container_measurement(
        collection,
        resource,
        run=container_run,
        workload=workload,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    analysis = _verified_profile_analysis(profile, collection)
    for artifact, artifact_id, artifact_type in (
        (build, build.build_id, "docker-build"),
        (target, target.target_id, "container-target"),
        (collection, collection.collection_id, "collection"),
        (resource, resource.resource_context_id, "container-resource-context"),
        (workload, workload.workload_spec_id, "container-workload-spec"),
        (benchmark, benchmark.benchmark_id, "benchmark"),
        (container_run, container_run.run_id, "container-run"),
        (measurement, measurement.measurement_id, "container-measurement"),
        (analysis, analysis.analysis_id, "analysis"),
    ):
        _save(store, artifact, artifact_id, artifact_type)
    return (
        target,
        collection,
        resource,
        workload,
        container_run,
        measurement,
        benchmark,
        analysis,
    )


def _finish_runtime_lock_side(
    graph_root: Path,
    store: ArtifactStore,
    runtime: Any,
    session_id: str,
    build: DockerBuildArtifact,
    *,
    marker: str,
    host_pid: int,
    benchmark_values: tuple[float, ...],
    fixture_root: Path,
) -> _Side:
    lease = runtime.begin_workload(
        session_id,
        build_id=build.build_id,
        mode="record",
        reserve_active_seconds=3,
        reserve_evidence_bytes=4 << 20,
    )
    runtime.finish_workload(
        session_id,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=64 << 10,
    )
    (
        target,
        collection,
        resource,
        workload,
        container_run,
        measurement,
        _,
        _,
    ) = _persist_container_graph(
        store,
        graph_root,
        build,
        marker=marker,
        host_pid=host_pid,
        benchmark_values=benchmark_values,
    )
    host_evidence = _native_evidence_for_target(fixture_root, target)
    scope = runtime.snapshot(session_id).runtime_lock_scope
    assert scope is not None
    authorized = scope.adapter_execution_bindings[0]
    runtime_version = host_evidence.source.runtime_version
    assert runtime_version is not None
    execution = bind_observed_runtime_execution(
        authorized,
        runtime_version=runtime_version,
        runtime_characteristics="glibc-2.41",
    )
    evidence = bind_runtime_lock_evidence_to_container(
        host_evidence,
        execution_binding=execution,
        target=target,
        run=container_run,
    )
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        source_replay_receipt=build_runtime_lock_source_replay_receipt(
            evidence,
            origin_source_sha256=evidence.source.source_sha256,
            origin_source_bytes=evidence.source.source_bytes,
        ),
    )
    collected = _DockerRuntimeLockCollected(
        request=_DockerRuntimeLockRequest(
            docker_optimization_session_id=session_id,
            build_id=build.build_id,
            adapter_id="native_pthread",
            execution_binding=execution,
            authorized_execution_identity_sha256=authorized.execution_identity_sha256,
            launch=NativePthreadDockerLaunch(
                probe_path=graph_root / "probe.so",
                probe_sha256=execution.configuration_sha256,
                semantics="exact",
                duration_threshold_ns=None,
                max_events=20_000,
            ),
            observation_limit_seconds=3,
            runtime_characteristics="glibc-2.41",
        ),
        evidence=evidence,
        analysis=analysis,
        verification=verification,
        target=target,
        container_run=container_run,
        measurement=measurement,
        started_at="2026-08-22T00:00:00.100000+00:00",
        finished_at="2026-08-22T00:00:01.100000+00:00",
        replay_verified=True,
    )
    _, runtime_run = _finalize_docker_runtime_lock_run(
        store,
        runtime,
        session_id,
        lease,
        build,
        collected,
    )
    return _Side(
        build=build,
        target=target,
        collection=collection,
        resource=resource,
        workload=workload,
        container_run=container_run,
        measurement=measurement,
        evidence=evidence,
        analysis=analysis,
        verification=verification,
        runtime_run=runtime_run,
    )


def _complete_graph(tmp_path: Path, fixture_root: Path) -> _Graph:
    tmp_path.mkdir(parents=True, exist_ok=True)
    runtime, project, _ = make_optimization_runtime(tmp_path)
    scope = _runtime_lock_scope(fixture_root)
    preview = runtime.preview(allowed_modes=("record",), runtime_lock_scope=scope)
    session = runtime.authorize(
        preview_id=preview.preview.preview_id,
        preview_content_sha256=preview.preview.content_sha256,
        authorization_summary_sha256=preview.preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    )
    store = ArtifactStore(
        tmp_path / "artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    baseline_build = runtime.build(
        session.session_id,
        build_kind="baseline",
        candidate_round=0,
    ).build
    baseline = _finish_runtime_lock_side(
        tmp_path / "baseline",
        store,
        runtime,
        session.session_id,
        baseline_build,
        marker="b",
        host_pid=1200,
        benchmark_values=(100, 101, 99),
        fixture_root=fixture_root,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate_build = runtime.build(
        session.session_id,
        build_kind="candidate",
        candidate_round=1,
    ).build
    candidate = _finish_runtime_lock_side(
        tmp_path / "candidate",
        store,
        runtime,
        session.session_id,
        candidate_build,
        marker="c",
        host_pid=2400,
        benchmark_values=(120, 121, 119),
        fixture_root=fixture_root,
    )

    baseline_analysis = _verified_profile_analysis(
        Path(baseline.collection.output_path),
        baseline.collection,
    )
    candidate_analysis = _verified_profile_analysis(
        Path(candidate.collection.output_path),
        candidate.collection,
    )
    profile_comparison = compare_profiles(baseline_analysis, candidate_analysis)
    baseline_benchmark = store.load_benchmark(baseline.container_run.benchmark_id or "")
    candidate_benchmark = store.load_benchmark(candidate.container_run.benchmark_id or "")
    benchmark_comparison = compare_benchmarks(baseline_benchmark, candidate_benchmark)
    resource_comparison = compare_container_measurements(
        baseline.measurement,
        candidate.measurement,
        baseline_analysis=baseline_analysis,
        candidate_analysis=candidate_analysis,
        profile_comparison=profile_comparison,
        baseline_benchmark=baseline_benchmark,
        candidate_benchmark=candidate_benchmark,
        benchmark_comparison=benchmark_comparison,
        created_at=datetime(2026, 8, 22, 0, 0, 5, tzinfo=UTC),
    )
    for artifact, artifact_id, artifact_type in (
        (baseline_analysis, baseline_analysis.analysis_id, "analysis"),
        (candidate_analysis, candidate_analysis.analysis_id, "analysis"),
        (profile_comparison, profile_comparison.comparison_id, "profile-comparison"),
        (
            benchmark_comparison,
            benchmark_comparison.comparison_id,
            "benchmark-comparison",
        ),
        (
            resource_comparison,
            resource_comparison.comparison_id,
            "container-matched-comparison",
        ),
    ):
        _save(store, artifact, artifact_id, artifact_type)
    baseline_environment = docker_runtime_lock_fixed_environment_sha256(
        baseline.measurement
    )
    candidate_environment = docker_runtime_lock_fixed_environment_sha256(
        candidate.measurement
    )
    comparison = compare_runtime_lock_analyses(
        baseline_run=baseline.runtime_run,
        baseline_analysis=baseline.analysis,
        baseline_evidence=baseline.evidence,
        baseline_verification=baseline.verification,
        candidate_run=candidate.runtime_run,
        candidate_analysis=candidate.analysis,
        candidate_evidence=candidate.evidence,
        candidate_verification=candidate.verification,
        baseline_resource_environment_sha256=baseline_environment,
        candidate_resource_environment_sha256=candidate_environment,
        resource_transfer_status=resource_comparison.resource_transfer_status,
        resource_comparison_id=resource_comparison.comparison_id,
        resource_comparison_content_sha256=resource_comparison.content_sha256,
        baseline_build=baseline.build,
        candidate_build=candidate.build,
        created_at=datetime(2026, 8, 22, 0, 0, 6, tzinfo=UTC),
    )
    _save(store, comparison, comparison.comparison_id, "runtime-lock-comparison")
    return _Graph(
        store=store,
        runtime=runtime,
        session_id=session.session_id,
        baseline=baseline,
        candidate=candidate,
        resource_comparison=resource_comparison,
        comparison=comparison,
    )


def _artifact_path(store: ArtifactStore, artifact_id: str, artifact_type: str) -> Path:
    return store.root / f"{artifact_id}.{artifact_type}.json"


def test_docker_runtime_lock_run_and_comparison_replay_full_append_only_graph(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)

    assert graph.store.load_runtime_lock_run(graph.baseline.runtime_run.run_id) == (
        graph.baseline.runtime_run
    )
    assert graph.store.load_runtime_lock_run(graph.candidate.runtime_run.run_id) == (
        graph.candidate.runtime_run
    )
    assert graph.store.load_runtime_lock_comparison(graph.comparison.comparison_id) == (
        graph.comparison
    )
    page, next_offset, size = graph.store.read_page(
        graph.comparison.comparison_id,
        "runtime-lock-comparison",
        offset=0,
        limit=65_536,
    )
    assert next_offset is None
    assert size == len(page.encode())
    assert graph.baseline.build.build_id in page
    assert graph.candidate.measurement.measurement_id in page


@pytest.mark.parametrize(
    ("dependency", "artifact_type"),
    (
        ("session", "docker-optimization-session"),
        ("build", "docker-build"),
        ("target", "container-target"),
        ("container_run", "container-run"),
        ("measurement", "container-measurement"),
        ("evidence", "runtime-lock-evidence"),
        ("analysis", "runtime-lock-analysis"),
        ("verification", "runtime-lock-verification"),
    ),
)
def test_docker_runtime_lock_run_rejects_missing_parent_artifact(
    tmp_path: Path,
    fixture_root: Path,
    dependency: str,
    artifact_type: str,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    run = graph.baseline.runtime_run
    binding = run.docker_optimization_binding
    assert binding is not None
    ids = {
        "session": binding.docker_optimization_session_artifact_id,
        "build": binding.build_id,
        "target": binding.container_target_id,
        "container_run": binding.container_run_id,
        "measurement": binding.container_measurement_id,
        "evidence": run.runtime_lock_evidence_id,
        "analysis": run.runtime_lock_analysis_id,
        "verification": run.runtime_lock_verification_id,
    }
    _artifact_path(graph.store, ids[dependency], artifact_type).unlink()

    with pytest.raises(PerfLensError):
        graph.store.load_runtime_lock_run(run.run_id)


@pytest.mark.parametrize(
    ("dependency", "changes"),
    (
        ("session", {"authorization_receipt_sha256": "f" * 64}),
        ("build", {"image_size_bytes": 8192}),
        ("target", {"executable_name": "forged-worker"}),
        ("container_run", {"cleanup_status": "retained_for_review"}),
        ("measurement", {"treatment_sha256": ("f" * 64,)}),
    ),
)
def test_docker_runtime_lock_run_rejects_forged_parent_with_valid_content_hash(
    tmp_path: Path,
    fixture_root: Path,
    dependency: str,
    changes: dict[str, object],
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    run = graph.baseline.runtime_run
    binding = run.docker_optimization_binding
    assert binding is not None
    artifacts: dict[str, tuple[Any, str, str]] = {
        "session": (
            graph.store.load_docker_optimization_session(
                binding.docker_optimization_session_artifact_id
            ),
            binding.docker_optimization_session_artifact_id,
            "docker-optimization-session",
        ),
        "build": (graph.baseline.build, binding.build_id, "docker-build"),
        "target": (graph.baseline.target, binding.container_target_id, "container-target"),
        "container_run": (
            graph.baseline.container_run,
            binding.container_run_id,
            "container-run",
        ),
        "measurement": (
            graph.baseline.measurement,
            binding.container_measurement_id,
            "container-measurement",
        ),
    }
    original, artifact_id, artifact_type = artifacts[dependency]
    forged = _rebind_content(original, **changes)
    path = _artifact_path(graph.store, artifact_id, artifact_type)
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)

    with pytest.raises(PerfLensError):
        graph.store.load_runtime_lock_run(run.run_id)


def test_docker_runtime_lock_run_rejects_forged_replay_receipt(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    verification = graph.baseline.verification
    receipt = verification.source_replay_receipt
    assert receipt is not None
    forged_receipt = receipt.model_copy(update={"raw_source_bytes": receipt.raw_source_bytes + 1})
    forged = _rebind_content(verification, source_replay_receipt=forged_receipt)
    path = _artifact_path(
        graph.store,
        verification.runtime_lock_verification_id,
        "runtime-lock-verification",
    )
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)

    with pytest.raises(PerfLensError):
        graph.store.load_runtime_lock_run(graph.baseline.runtime_run.run_id)


@pytest.mark.parametrize(
    "grafted_dependency",
    ("build", "target", "container_run", "measurement"),
)
def test_docker_runtime_lock_run_rejects_cross_run_parent_graft(
    tmp_path: Path,
    fixture_root: Path,
    grafted_dependency: str,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    run = graph.baseline.runtime_run
    baseline_binding = run.docker_optimization_binding
    candidate_binding = graph.candidate.runtime_run.docker_optimization_binding
    assert baseline_binding is not None
    assert candidate_binding is not None
    updates_by_dependency: dict[str, dict[str, object]] = {
        "build": {
            "build_id": candidate_binding.build_id,
            "build_content_sha256": candidate_binding.build_content_sha256,
        },
        "target": {
            "container_target_id": candidate_binding.container_target_id,
            "container_target_content_sha256": (
                candidate_binding.container_target_content_sha256
            ),
        },
        "container_run": {
            "container_run_id": candidate_binding.container_run_id,
            "container_run_content_sha256": candidate_binding.container_run_content_sha256,
        },
        "measurement": {
            "container_measurement_id": candidate_binding.container_measurement_id,
            "container_measurement_content_sha256": (
                candidate_binding.container_measurement_content_sha256
            ),
        },
    }
    updates = updates_by_dependency[grafted_dependency]
    forged_binding = baseline_binding.model_copy(update=updates)
    forged_run = _rebind_content(run, docker_optimization_binding=forged_binding)
    path = _artifact_path(graph.store, run.run_id, "runtime-lock-run")
    path.write_bytes(serialize_json(forged_run))
    path.chmod(0o600)

    with pytest.raises(PerfLensError):
        graph.store.load_runtime_lock_run(run.run_id)


def test_docker_runtime_lock_run_rejects_different_authorization_session_graft(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    graph = _complete_graph(tmp_path / "left", fixture_root)
    other = _complete_graph(tmp_path / "right", fixture_root)
    run = graph.baseline.runtime_run
    binding = run.docker_optimization_binding
    other_binding = other.baseline.runtime_run.docker_optimization_binding
    assert binding is not None
    assert other_binding is not None
    assert graph.session_id != other.session_id
    other_session = other.store.load_docker_optimization_session(
        other_binding.docker_optimization_session_artifact_id
    )
    _save(
        graph.store,
        other_session,
        other_session.session_artifact_id,
        "docker-optimization-session",
    )
    forged_binding = binding.model_copy(
        update={
            "docker_optimization_session_id": other.session_id,
            "docker_optimization_session_artifact_id": other_session.session_artifact_id,
            "docker_optimization_session_artifact_content_sha256": other_session.content_sha256,
        }
    )
    forged_run = _rebind_content(run, docker_optimization_binding=forged_binding)
    path = _artifact_path(graph.store, run.run_id, "runtime-lock-run")
    path.write_bytes(serialize_json(forged_run))
    path.chmod(0o600)

    with pytest.raises(PerfLensError):
        graph.store.load_runtime_lock_run(run.run_id)


@pytest.mark.parametrize(
    "grafted_field",
    (
        "baseline_run",
        "candidate_run",
        "baseline_build",
        "candidate_build",
        "baseline_measurement",
        "candidate_measurement",
        "resource_comparison",
    ),
)
def test_docker_runtime_lock_comparison_rejects_cross_artifact_graft(
    tmp_path: Path,
    fixture_root: Path,
    grafted_field: str,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    comparison = graph.comparison
    baseline = graph.baseline
    candidate = graph.candidate
    changes: dict[str, dict[str, object]] = {
        "baseline_run": {
            "baseline_run_id": candidate.runtime_run.run_id,
            "baseline_run_content_sha256": candidate.runtime_run.content_sha256,
        },
        "candidate_run": {
            "candidate_run_id": baseline.runtime_run.run_id,
            "candidate_run_content_sha256": baseline.runtime_run.content_sha256,
        },
        "baseline_build": {
            "baseline_build_id": candidate.build.build_id,
            "baseline_build_content_sha256": candidate.build.content_sha256,
        },
        "candidate_build": {
            "candidate_build_id": baseline.build.build_id,
            "candidate_build_content_sha256": baseline.build.content_sha256,
        },
        "baseline_measurement": {
            "baseline_measurement_id": candidate.measurement.measurement_id,
        },
        "candidate_measurement": {
            "candidate_measurement_id": baseline.measurement.measurement_id,
        },
        "resource_comparison": {
            "resource_comparison_content_sha256": "f" * 64,
        },
    }
    forged = _rebind_content(comparison, **changes[grafted_field])
    path = _artifact_path(
        graph.store,
        comparison.comparison_id,
        "runtime-lock-comparison",
    )
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)

    with pytest.raises(PerfLensError):
        graph.store.load_runtime_lock_comparison(comparison.comparison_id)


def test_artifact_store_append_only_save_is_idempotent_and_rejects_replacement(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    run = graph.baseline.runtime_run
    path = graph.store.save(run, run.run_id, "runtime-lock-run")
    original = path.read_bytes()

    assert graph.store.save(run, run.run_id, "runtime-lock-run") == path
    assert path.read_bytes() == original
    forged = _rebind_content(run, warnings=(*run.warnings, "forged append"))
    with pytest.raises(PerfLensError, match="already exists with different content"):
        graph.store.save(forged, run.run_id, "runtime-lock-run")
    assert path.read_bytes() == original


def test_docker_runtime_lock_accounting_binds_all_replay_representations(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    graph = _complete_graph(tmp_path, fixture_root)
    run = graph.baseline.runtime_run
    binding = run.docker_optimization_binding
    receipt = graph.baseline.verification.source_replay_receipt
    assert binding is not None
    assert receipt is not None
    assert receipt.origin_source_bytes is not None
    expected = (
        len(serialize_json(graph.baseline.evidence))
        + receipt.origin_source_bytes
        + receipt.raw_source_bytes
        + receipt.normalized_source_bytes
    )
    assert binding.accounted_evidence_bytes == expected
    assert expected > run.evidence_bytes
