"""PerfLens MCP server built on the official Python SDK."""
# pyright: reportUnusedFunction=false

from __future__ import annotations

import argparse
import hashlib
import math
import os
import stat
import tempfile
import time
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from perflens import __version__
from perflens.application.analyze import analyze_folded, analyze_perf_data, analyze_perf_script
from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.evidence import (
    build_collection_evidence_provenance,
    contract_content_sha256,
)
from perflens.application.runtime_lock_queries import (
    build_runtime_lock_diagnosis_bundle as create_runtime_lock_diagnosis,
)
from perflens.application.runtime_lock_queries import (
    get_runtime_lock_call_paths as query_runtime_lock_call_paths,
)
from perflens.application.runtime_lock_queries import (
    list_runtime_lock_hotspots as query_runtime_lock_hotspots,
)
from perflens.application.symbols import get_source_context as resolve_source_context
from perflens.application.symbols import resolve_source as resolve_module_source
from perflens.application.trace_evidence import canonical_trace_json_sha256
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
    require_usable_runtime_lock_analysis,
    verify_runtime_lock_analysis_artifact,
)
from perflens.application.verify_trace import (
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.benchmarks.adapters import load_benchmark
from perflens.classification.engine import build_diagnosis_bundle as create_diagnosis
from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.collection.collector import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_STAT_EVENTS,
    HARDWARE_STAT_EVENTS,
    CollectionRequest,
    CollectionTarget,
)
from perflens.collection.collector import (
    collect_profile as run_collection,
)
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    assert_plan_current,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.comparison.benchmarks import compare_benchmarks as compare_benchmark_artifacts
from perflens.comparison.profiles import compare_profiles as compare_profile_artifacts
from perflens.contracts.artifacts import (
    AnalysisVerificationArtifact,
    ArtifactReference,
    ArtifactTextPage,
    CallPathPage,
    ClassificationPage,
    CollectionArtifact,
    CollectionCapabilityArtifact,
    CollectionPlanArtifact,
    HotspotDetails,
    HotspotPage,
    SourceContextArtifact,
    SourceResolutionArtifact,
)
from perflens.contracts.docker import (
    CollectionMode,
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
    ContainerModuleSnapshotArtifact,
    ContainerOptimizationSessionArtifact,
    ContainerProcessInventoryArtifact,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerSymbolContextArtifact,
    ContainerTargetArtifact,
    DockerRuntimeCapabilityArtifact,
)
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerOptimizationIterationArtifact,
    DockerOptimizationPreviewArtifact,
    DockerOptimizationSessionArtifact,
    DockerRuntimeLockAuthorizationScope,
    OptimizationCollectionMode,
    OptimizationEvaluationReason,
    docker_runtime_lock_scope_sha256,
    docker_runtime_lock_version_constraints,
)
from perflens.contracts.runtime_lock_sessions import (
    DockerRuntimeLockRunBinding,
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterId,
    RuntimeLockCapabilityArtifact,
    RuntimeLockComparisonArtifact,
    RuntimeLockProcessTargetBinding,
    RuntimeLockRunArtifact,
    RuntimeLockSessionArtifact,
    RuntimeLockSessionPreviewArtifact,
    RuntimeLockTargetScope,
    RuntimeLockWorkloadBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_run_boundaries,
    derive_runtime_lock_run_id,
    derive_runtime_lock_toolchain_identity,
    derive_runtime_lock_workload_identity,
)
from perflens.contracts.runtime_locks import (
    MeasurementSemantics,
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockCallPathPage,
    RuntimeLockEvidenceArtifact,
    RuntimeLockHotspotPage,
    RuntimeLockResourceLimits,
)
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceAnalysisVerificationArtifact,
    TraceEvidenceArtifact,
)
from perflens.docker.adapter import (
    CpythonDockerLaunch,
    GoPprofDockerLaunch,
    JavaJfrDockerLaunch,
    NativePthreadDockerLaunch,
    RuntimeLockDockerLaunch,
)
from perflens.docker.benchmark import load_managed_benchmark
from perflens.docker.build_adapter import open_local_docker_build_adapter
from perflens.docker.builder_policy import load_docker_administrator_builder_policy
from perflens.docker.capability import discover_docker_capability
from perflens.docker.cgroup import (
    CapturedCgroupSnapshot,
    CgroupSnapshotMonitor,
    CgroupV2ResourceReader,
    build_container_resource_context,
)
from perflens.docker.comparison import (
    build_container_measurement,
    compare_container_measurements,
)
from perflens.docker.identity import (
    NamespaceIdentity,
    namespace_attestation_from_target,
)
from perflens.docker.managed import build_container_run_artifact
from perflens.docker.optimization_comparison import (
    compare_docker_optimization_iteration,
)
from perflens.docker.optimization_runtime import DockerOptimizationRuntime
from perflens.docker.optimization_session import DockerOptimizationWorkloadLease
from perflens.docker.project_config import (
    assert_docker_project_policy_current,
    load_docker_project_policy,
)
from perflens.docker.runtime import ExistingDockerRuntime
from perflens.docker.runtime_root import prepare_default_managed_runtime_root
from perflens.docker.symbols import (
    PinnedContainerProcessRoot,
    build_container_symbol_context,
    capture_container_module_snapshot,
    materialize_container_workspace_symfs,
    pin_container_process_root,
    project_container_analysis,
)
from perflens.docker.treatment import (
    assert_treatment_snapshot_current,
    capture_treatment_snapshot,
)
from perflens.docker.workload import assert_managed_project_current, inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks import import_runtime_lock_ndjson
from perflens.runtime_locks.capability import (
    NATIVE_PTHREAD_PROVENANCE_LIMITATION,
    RuntimeLockCapabilityInspection,
    inspect_runtime_lock_capability,
)
from perflens.runtime_locks.comparison import (
    compare_runtime_lock_analyses as compare_runtime_lock_artifacts,
)
from perflens.runtime_locks.comparison import (
    docker_runtime_lock_fixed_environment_sha256,
    runtime_lock_resource_environment_sha256,
)
from perflens.runtime_locks.cpython_adapter import (
    CpythonAdapterBridge,
    CpythonLaunchPolicy,
    assert_cpython_launch_policy_current,
    build_cpython_adapter_bridge,
    discover_cpython_adapter_bridge,
    inspect_cpython_installation,
)
from perflens.runtime_locks.cpython_converter import (
    convert_cpython_threading_stream,
    verify_cpython_threading_replay,
)
from perflens.runtime_locks.cpython_launcher import (
    CpythonLaunchRequest,
    CpythonLaunchResult,
    CpythonThreadingLauncher,
    cleanup_cpython_launch_result,
    open_cpython_private_stream,
)
from perflens.runtime_locks.docker_binding import bind_runtime_lock_evidence_to_container
from perflens.runtime_locks.docker_capture import (
    DockerRuntimeLockCapture,
    GoDockerPprofAuthority,
    JavaDockerJfrAuthority,
    bind_observed_runtime_execution,
    capture_docker_runtime_lock_evidence,
)
from perflens.runtime_locks.go_pprof_adapter import (
    GoPprofAdapterBridge,
    GoToolIdentity,
    build_go_pprof_adapter_bridge,
    discover_go_pprof_adapter_bridge,
    inspect_go_pprof_installation,
)
from perflens.runtime_locks.go_pprof_converter import (
    GoProfileKind,
    convert_go_pprof_raw,
    verify_go_pprof_replay,
)
from perflens.runtime_locks.go_pprof_launcher import (
    GoPprofLauncher,
    GoPprofLaunchRequest,
    GoPprofLaunchResult,
    GoPprofRawResult,
    assert_go_tool_identity,
    cleanup_go_pprof_raw_result,
    cleanup_go_pprof_result,
    inspect_pinned_go_executable_version,
    open_go_pprof_raw,
)
from perflens.runtime_locks.go_pprof_loopback import (
    GoPprofLoopbackCapture,
    capture_go_pprof_loopback_profile,
    cleanup_go_pprof_loopback_capture,
    inspect_go_pprof_loopback_target,
    open_go_pprof_loopback_capture,
)
from perflens.runtime_locks.java_jfr_adapter import (
    JavaJfrAdapterBridge,
    discover_java_jfr_adapter_bridge,
)
from perflens.runtime_locks.java_jfr_converter import (
    convert_java_jfr_json,
    verify_java_jfr_replay,
)
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrArtifactRootLease,
    JavaJfrLauncher,
    JavaJfrLaunchFailure,
    JavaJfrLaunchPolicy,
    JavaJfrLaunchRequest,
    JavaJfrLaunchResult,
    JavaJfrPrivateEvidence,
    SubprocessJavaJfrJsonRunner,
    acquire_java_jfr_artifact_root_lease,
    assert_java_jfr_launch_policy_current,
    cleanup_java_jfr_empty_private_roots,
    cleanup_java_jfr_launch_result,
    inspect_java_jfr_tool_identity,
    inventory_java_jfr_retained_evidence,
    java_jfr_arguments_sha256,
    open_java_jfr_private_file,
    release_java_jfr_artifact_root_lease,
)
from perflens.runtime_locks.native_launcher import (
    NativeLaunchCapability,
    NativeLaunchRequest,
    NativeLaunchResult,
    NativePthreadLauncher,
    discover_native_pthread_probe_policy,
    inspect_native_pthread_installation,
)
from perflens.runtime_locks.native_pthread_abi import (
    NATIVE_PTHREAD_PROBE_ABI_VERSION,
    NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION,
)
from perflens.runtime_locks.native_pthread_converter import (
    convert_native_pthread_probe,
)
from perflens.runtime_locks.project_config import (
    RuntimeLockProjectPolicy,
    assert_runtime_lock_project_policy_current,
    load_runtime_lock_project_policy,
)
from perflens.runtime_locks.session import (
    RuntimeLockRunSettlement,
    RuntimeLockSessionRuntime,
)
from perflens.workloads.project import (
    ProjectWorkloadRequest,
    collect_project_workload,
)

READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
WRITES_ARTIFACTS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
EXECUTES_TARGET = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)
AUTHORIZES_DOCKER = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)
REVOKES_DOCKER = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


@dataclass(frozen=True, slots=True)
class ServerConfig:
    allowed_roots: tuple[Path, ...]
    artifact_root: Path
    allow_writes: bool = False
    allow_process_execution: bool = False
    allow_active_collection: bool = False
    allow_pid_attach: bool = False
    allow_automatic_collection: bool = False
    allow_project_execution: bool = False
    allow_docker_targets: bool = False
    allow_docker_optimization: bool = False
    allow_runtime_locks: bool = False
    docker_project_config: Path | None = None
    runtime_lock_project_config: Path | None = None
    docker_runtime_root: Path | None = None
    docker_builder_policy: Path | None = None
    docker_gate_path: Path = Path("/usr/lib/perflens/perflens-container-gate")
    collector_socket: Path | None = None
    automatic_collection_policy: AutomaticCollectionPolicy = field(
        default_factory=AutomaticCollectionPolicy
    )
    perf_path: Path | None = None
    max_artifact_bytes: int = 128 << 20
    docker_optimization_runtime_factory: Callable[[], DockerOptimizationRuntime] | None = None
    runtime_lock_runtime_factory: Callable[[], RuntimeLockSessionRuntime] | None = None
    runtime_lock_capability_factory: Callable[[], RuntimeLockCapabilityInspection] | None = None
    runtime_lock_native_launcher_factory: Callable[[Path, Path], NativePthreadLauncher] | None = (
        None
    )
    runtime_lock_java_bridge_factory: Callable[[], JavaJfrAdapterBridge] | None = None
    runtime_lock_java_launcher_factory: (
        Callable[[Path, Path, JavaJfrLaunchPolicy], JavaJfrLauncher] | None
    ) = None
    runtime_lock_cpython_bridge_factory: Callable[[], CpythonAdapterBridge] | None = None
    runtime_lock_cpython_launcher_factory: (
        Callable[[Path, Path, CpythonLaunchPolicy], CpythonThreadingLauncher] | None
    ) = None
    runtime_lock_go_bridge_factory: Callable[[], GoPprofAdapterBridge] | None = None
    runtime_lock_go_launcher_factory: (
        Callable[[Path, Path, GoToolIdentity, GoToolIdentity], GoPprofLauncher] | None
    ) = None


@dataclass(frozen=True, slots=True)
class _ExecutedBrokerPlan:
    reference: ArtifactReference
    collection: CollectionArtifact | None
    collection_id: str
    output_sha256: str
    evidence_bytes: int
    active_seconds: float


@dataclass(frozen=True, slots=True)
class _PinnedRuntimeLockImport:
    descriptor: int
    path: Path
    project_relative_path: str
    source_sha256: str
    metadata: os.stat_result


@dataclass(frozen=True, slots=True)
class _DockerRuntimeLockRequest:
    docker_optimization_session_id: str
    build_id: str
    adapter_id: RuntimeLockAdapterId
    execution_binding: RuntimeLockAdapterExecutionBinding
    authorized_execution_identity_sha256: str
    launch: RuntimeLockDockerLaunch
    observation_limit_seconds: int
    go_profile_kind: GoProfileKind | None = None
    runtime_characteristics: str | None = None


@dataclass(frozen=True, slots=True)
class _DockerRuntimeLockCollected:
    request: _DockerRuntimeLockRequest
    evidence: RuntimeLockEvidenceArtifact
    analysis: RuntimeLockAnalysisArtifact
    verification: RuntimeLockAnalysisVerificationArtifact
    target: ContainerTargetArtifact
    container_run: ContainerRunArtifact
    measurement: ContainerMeasurementArtifact
    started_at: str
    finished_at: str
    replay_verified: bool


def _docker_runtime_lock_accounted_bytes(collected: _DockerRuntimeLockCollected) -> int:
    """Return the conservative byte charge for every bounded evidence representation."""

    receipt = collected.verification.source_replay_receipt
    if receipt is None or receipt.origin_source_bytes is None:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "runtime_lock_docker_binding",
            "Docker Runtime Lock replay receipt lacks its complete source chain",
            recoverable=False,
        )
    return (
        len(serialize_json(collected.evidence))
        + receipt.origin_source_bytes
        + receipt.raw_source_bytes
        + receipt.normalized_source_bytes
    )


def _finalize_docker_runtime_lock_run(
    store: ArtifactStore,
    optimization_runtime: DockerOptimizationRuntime,
    session_id: str,
    lease: DockerOptimizationWorkloadLease,
    build: DockerBuildArtifact,
    collected: _DockerRuntimeLockCollected,
) -> tuple[DockerOptimizationSessionArtifact, RuntimeLockRunArtifact]:
    evidence_bytes = len(serialize_json(collected.evidence))
    accounted_evidence_bytes = _docker_runtime_lock_accounted_bytes(collected)
    event_count = len(collected.evidence.events)
    started = datetime.fromisoformat(collected.started_at)
    finished = datetime.fromisoformat(collected.finished_at)
    lifecycle_seconds = math.ceil((finished - started).total_seconds())
    active_seconds = min(
        collected.request.observation_limit_seconds,
        lifecycle_seconds,
    )
    exact_events = (
        event_count
        if collected.request.execution_binding.measurement_semantics == "exact"
        else 0
    )
    # Persist the replayable evidence chain before consuming the nested Runtime Lock
    # allowance.  A failure at any point is handled by the outer collection path, which
    # marks this completed workload unavailable and blocks further collection.  These
    # append-only inputs may safely remain as bounded orphans; no Run exposes them until
    # the charged parent Session revision and final Run both exist.
    for artifact, artifact_id, artifact_type in (
        (
            collected.evidence,
            collected.evidence.runtime_lock_evidence_id,
            "runtime-lock-evidence",
        ),
        (
            collected.analysis,
            collected.analysis.runtime_lock_analysis_id,
            "runtime-lock-analysis",
        ),
        (
            collected.verification,
            collected.verification.runtime_lock_verification_id,
            "runtime-lock-verification",
        ),
    ):
        store.save(artifact, artifact_id, artifact_type)
    session = optimization_runtime.charge_runtime_lock_use(
        session_id,
        lease,
        actual_active_seconds=active_seconds,
        actual_evidence_bytes=accounted_evidence_bytes,
        exact_event_count=exact_events,
        result_status=(
            "active" if collected.analysis.quality_status == "complete" else "partial"
        ),
    )
    if collected.request.runtime_characteristics is None:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "runtime_lock_docker_binding",
            "Docker Runtime Lock actual execution characteristics are unavailable",
            recoverable=False,
        )
    binding = DockerRuntimeLockRunBinding(
        docker_optimization_session_id=session.session_id,
        docker_optimization_session_artifact_id=session.session_artifact_id,
        docker_optimization_session_artifact_content_sha256=session.content_sha256,
        build_id=build.build_id,
        build_content_sha256=build.content_sha256,
        container_target_id=collected.target.target_id,
        container_target_content_sha256=collected.target.content_sha256,
        container_run_id=collected.container_run.run_id,
        container_run_content_sha256=collected.container_run.content_sha256,
        container_measurement_id=collected.measurement.measurement_id,
        container_measurement_content_sha256=collected.measurement.content_sha256,
        authorized_execution_identity_sha256=(
            collected.request.authorized_execution_identity_sha256
        ),
        actual_execution_binding=collected.request.execution_binding,
        actual_runtime_characteristics=collected.request.runtime_characteristics,
        accounted_evidence_bytes=accounted_evidence_bytes,
    )
    warnings = tuple(
        dict.fromkeys(
            (
                *collected.evidence.quality.limitations,
                "Docker Runtime Lock duration is the bounded observation interval; "
                "lifecycle timestamps may include sub-second coordination overhead.",
                *(() if collected.replay_verified else ("Private source replay failed.",)),
            )
        )
    )
    quality, allowed, forbidden = derive_runtime_lock_run_boundaries(
        adapter_id=collected.request.adapter_id,
        analysis_quality_status=collected.analysis.quality_status,
        analysis_allowed_conclusions=collected.analysis.allowed_conclusions,
        analysis_forbidden_conclusions=collected.analysis.forbidden_conclusions,
        warnings=warnings,
    )
    benchmark = (
        store.load_benchmark(collected.container_run.benchmark_id)
        if collected.container_run.benchmark_id is not None
        else None
    )
    correctness_status: Literal["passed", "failed", "unavailable"]
    if collected.container_run.exit_code != 0 or (
        benchmark is not None and benchmark.error_count not in {None, 0}
    ):
        correctness_status = "failed"
    elif benchmark is not None and benchmark.error_count == 0:
        correctness_status = "passed"
    else:
        correctness_status = "unavailable"
    operation_identity = hashlib.sha256(
        (
            "perflens-docker-runtime-lock-operation-v1\0"
            f"{session.session_id}\0{lease.lease_id}\0{build.content_sha256}\0"
            f"{collected.container_run.content_sha256}\0{collected.evidence.content_sha256}"
        ).encode()
    ).hexdigest()
    provisional = RuntimeLockRunArtifact(
        schema_version="1.1",
        perflens_version=__version__,
        run_id=derive_runtime_lock_run_id(
            session.session_id,
            collected.request.adapter_id,
            collected.evidence.content_sha256,
            collected.started_at,
        ),
        created_at=collected.finished_at,
        started_at=collected.started_at,
        finished_at=collected.finished_at,
        authorization_kind="docker_optimization",
        session_id=session.session_id,
        docker_optimization_binding=binding,
        target_scope="docker_optimization",
        operation_identity_sha256=operation_identity,
        target_identity_sha256=collected.target.identity_fingerprint,
        adapter_id=collected.request.adapter_id,
        adapter_execution_identity_sha256=(
            collected.request.execution_binding.execution_identity_sha256
        ),
        measurement_semantics=(collected.request.execution_binding.measurement_semantics),
        workload_identity_sha256=build.recipe_content_sha256,
        runtime_lock_evidence_id=collected.evidence.runtime_lock_evidence_id,
        runtime_lock_evidence_content_sha256=collected.evidence.content_sha256,
        runtime_lock_analysis_id=collected.analysis.runtime_lock_analysis_id,
        runtime_lock_analysis_content_sha256=collected.analysis.content_sha256,
        runtime_lock_verification_id=(collected.verification.runtime_lock_verification_id),
        runtime_lock_verification_content_sha256=collected.verification.content_sha256,
        duration_seconds=active_seconds,
        evidence_bytes=evidence_bytes,
        event_count=event_count,
        correctness_status=correctness_status,
        quality_status=quality,
        warnings=warnings,
        allowed_conclusions=allowed,
        forbidden_conclusions=forbidden,
        content_sha256="0" * 64,
    )
    runtime_run = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    # Publish the Run before its parent Session revision.  If Run persistence
    # fails, the outer failure path records a terminal/unavailable parent; if
    # Session persistence fails, the append-only Run remains unreachable until
    # its exact parent revision exists.  Reversing this order could expose an
    # active parent counter with no corresponding Runtime Lock Run.
    store.save(runtime_run, runtime_run.run_id, "runtime-lock-run")
    store.save(
        session,
        session.session_artifact_id,
        "docker-optimization-session",
    )
    optimization_runtime.mark_runtime_lock_published(session_id, lease)
    return session, runtime_run



def create_server(config: ServerConfig) -> MCPServer[None]:
    client_connection_identity_sha256 = hashlib.sha256(os.urandom(32)).hexdigest()
    if config.allow_pid_attach and not config.allow_active_collection:
        raise ValueError("PID attachment cannot be enabled while active collection is disabled")
    if config.allow_automatic_collection and (
        not config.allow_active_collection
        or config.collector_socket is None
        or not config.automatic_collection_policy.enabled
    ):
        raise ValueError(
            "Automatic collection requires active collection, a broker socket, and an enabled "
            "automatic policy"
        )
    if config.allow_project_execution and not config.allow_automatic_collection:
        raise ValueError("Project execution requires automatic collection to be enabled")
    if config.allow_docker_targets and (
        not config.allow_automatic_collection or config.docker_project_config is None
    ):
        raise ValueError("Docker targets require automatic collection and one project policy path")
    if not config.allow_docker_targets and config.docker_project_config is not None:
        raise ValueError("Docker project policy cannot be set while Docker targets are disabled")
    if not config.allow_docker_targets and config.docker_runtime_root is not None:
        raise ValueError("Docker runtime root cannot be set while Docker targets are disabled")
    if config.allow_docker_optimization and not config.allow_docker_targets:
        raise ValueError("Docker optimization requires Docker targets")
    if config.allow_docker_optimization and (
        not config.allow_writes or not config.allow_process_execution
    ):
        raise ValueError("Docker optimization requires writes and process execution")
    if not config.allow_docker_optimization and config.docker_builder_policy is not None:
        raise ValueError("Docker Builder policy requires Docker optimization")
    if (
        not config.allow_docker_optimization
        and config.docker_optimization_runtime_factory is not None
    ):
        raise ValueError("Docker optimization runtime factory requires Docker optimization")
    if config.allow_runtime_locks and (
        config.runtime_lock_project_config is None or not config.allow_writes
    ):
        raise ValueError("Runtime Lock sessions require writes and one project policy path")
    if not config.allow_runtime_locks and config.runtime_lock_project_config is not None:
        raise ValueError(
            "Runtime Lock project policy cannot be set while Runtime Lock sessions are disabled"
        )
    if not config.allow_runtime_locks and (
        config.runtime_lock_runtime_factory is not None
        or config.runtime_lock_capability_factory is not None
        or config.runtime_lock_native_launcher_factory is not None
        or config.runtime_lock_java_bridge_factory is not None
        or config.runtime_lock_java_launcher_factory is not None
        or config.runtime_lock_cpython_bridge_factory is not None
        or config.runtime_lock_cpython_launcher_factory is not None
        or config.runtime_lock_go_bridge_factory is not None
        or config.runtime_lock_go_launcher_factory is not None
    ):
        raise ValueError("Runtime Lock factories require Runtime Lock sessions")
    if (
        config.runtime_lock_native_launcher_factory is not None
        or config.runtime_lock_java_launcher_factory is not None
        or config.runtime_lock_cpython_launcher_factory is not None
        or config.runtime_lock_go_launcher_factory is not None
    ) and not config.allow_process_execution:
        raise ValueError("Runtime Lock workload launcher requires process execution")
    docker_policy = (
        load_docker_project_policy(
            config.docker_project_config,
            allowed_roots=config.allowed_roots,
        )
        if config.docker_project_config is not None
        else None
    )
    docker_runtime = (
        ExistingDockerRuntime(
            project=inspect_managed_project_root(docker_policy.path.parent.parent),
            project_policy=docker_policy,
            allowed_roots=config.allowed_roots,
            collection_policy=config.automatic_collection_policy,
            managed_runtime_root=config.docker_runtime_root,
            container_gate_path=config.docker_gate_path,
        )
        if docker_policy is not None
        else None
    )
    runtime_lock_policy = (
        load_runtime_lock_project_policy(
            config.runtime_lock_project_config,
            allowed_roots=config.allowed_roots,
        )
        if config.runtime_lock_project_config is not None
        else None
    )
    runtime_lock_project = (
        inspect_managed_project_root(runtime_lock_policy.path.parent.parent)
        if runtime_lock_policy is not None
        else None
    )
    policy = PathPolicy(config.allowed_roots)
    store = ArtifactStore(
        config.artifact_root,
        policy,
        allow_writes=config.allow_writes,
        max_artifact_bytes=config.max_artifact_bytes,
    )
    docker_optimization_runtime: DockerOptimizationRuntime | None = None
    runtime_lock_runtime: RuntimeLockSessionRuntime | None = None
    runtime_lock_native_launcher: NativePthreadLauncher | None = None
    runtime_lock_native_private_root: Path | None = None
    runtime_lock_java_bridge: JavaJfrAdapterBridge | None = None
    runtime_lock_java_launcher: JavaJfrLauncher | None = None
    runtime_lock_java_private_root: Path | None = None
    runtime_lock_java_artifact_lease: JavaJfrArtifactRootLease | None = None
    runtime_lock_java_retained_results: list[JavaJfrPrivateEvidence] = []
    runtime_lock_cpython_bridge: CpythonAdapterBridge | None = None
    runtime_lock_cpython_launcher: CpythonThreadingLauncher | None = None
    runtime_lock_cpython_private_root: Path | None = None
    runtime_lock_cpython_retained_results: list[CpythonLaunchResult] = []
    runtime_lock_go_bridge: GoPprofAdapterBridge | None = None
    runtime_lock_go_launcher: GoPprofLauncher | None = None
    runtime_lock_go_private_root: Path | None = None
    runtime_lock_go_retained_results: list[tuple[GoPprofLaunchResult, GoPprofRawResult | None]] = []
    runtime_lock_go_retained_loopback: list[
        tuple[GoPprofLoopbackCapture, GoPprofRawResult | None]
    ] = []
    managed_runtime_lock_requests: dict[str, _DockerRuntimeLockRequest] = {}
    managed_runtime_lock_results: dict[str, _DockerRuntimeLockCollected] = {}
    managed_collection_progress: dict[str, tuple[int, str]] = {}

    def runtime_lock_go_retained_bytes() -> int:
        launched = sum(
            launch.mutex_profile_size
            + launch.block_profile_size
            + (raw.raw_size if raw is not None else 0)
            for launch, raw in runtime_lock_go_retained_results
        )
        loopback = sum(
            capture.profile_size + (raw.raw_size if raw is not None else 0)
            for capture, raw in runtime_lock_go_retained_loopback
        )
        return launched + loopback

    @asynccontextmanager
    async def server_lifespan(_server: MCPServer[None]) -> AsyncGenerator[None]:
        try:
            yield None
        finally:
            if docker_optimization_runtime is not None:
                docker_optimization_runtime.close()
            if runtime_lock_runtime is not None:
                for terminal_session in runtime_lock_runtime.close():
                    store.save(
                        terminal_session,
                        terminal_session.session_artifact_id,
                        "runtime-lock-session",
                    )
            if runtime_lock_native_private_root is not None:
                with suppress(OSError, PerfLensError):
                    _cleanup_native_runtime_lock_retained_streams(runtime_lock_native_private_root)
                with suppress(OSError):
                    runtime_lock_native_private_root.rmdir()
            if runtime_lock_java_artifact_lease is not None:
                try:
                    if runtime_lock_java_private_root is not None:
                        with suppress(OSError, PerfLensError):
                            cleanup_java_jfr_empty_private_roots(config.artifact_root)
                finally:
                    with suppress(OSError, PerfLensError):
                        release_java_jfr_artifact_root_lease(runtime_lock_java_artifact_lease)
            if runtime_lock_cpython_private_root is not None:
                with suppress(OSError):
                    runtime_lock_cpython_private_root.rmdir()
            if runtime_lock_go_private_root is not None:
                for launch, raw in runtime_lock_go_retained_results:
                    with suppress(OSError, PerfLensError):
                        cleanup_go_pprof_result(launch, raw)
                for capture, raw in runtime_lock_go_retained_loopback:
                    with suppress(OSError, PerfLensError):
                        cleanup_go_pprof_loopback_capture(capture)
                    if raw is not None:
                        with suppress(OSError, PerfLensError):
                            cleanup_go_pprof_raw_result(raw)
                with suppress(OSError):
                    runtime_lock_go_private_root.rmdir()

    server: MCPServer[None] = MCPServer(
        "perflens",
        title="PerfLens Linux Performance Analysis",
        description="Deterministic profile analysis, evidence, and source-resolution tools.",
        instructions=(
            "Treat hotspots as observations and rule matches as candidates. "
            "Only equivalent-workload "
            "A/B validation is a verified improvement. State missing evidence and limitations. "
            "Active collection is disabled unless server policy authorizes it. Manual collection "
            "also requires per-call confirmation. Automatic collection requires a short-lived "
            "PID-bound plan and an independently policy-enforcing collector broker. Project "
            "workloads run unprivileged and require a separate per-call authorization. For an "
            "authorized project workload, collect_project_workload must receive the exact fixed "
            "authorization value I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION. A failed project "
            "workload call must not be replaced with a shell launch, direct perf, or existing-PID "
            "attachment. Docker tools require the project Docker policy and bounded-session "
            "authorization. Never substitute direct Docker CLI/Socket access, build/pull, "
            "arbitrary mounts, networking, capabilities, or host namespaces."
        ),
        version=__version__,
        lifespan=server_lifespan,
    )
    collection_plans: dict[str, CollectionPlanArtifact] = {}

    def get_docker_optimization_runtime() -> DockerOptimizationRuntime:
        nonlocal docker_optimization_runtime
        _require_docker_optimization(config)
        if docker_optimization_runtime is not None:
            return docker_optimization_runtime
        if config.docker_optimization_runtime_factory is not None:
            docker_optimization_runtime = config.docker_optimization_runtime_factory()
            return docker_optimization_runtime
        assert docker_policy is not None
        project = inspect_managed_project_root(docker_policy.path.parent.parent)
        administrator_policy = (
            load_docker_administrator_builder_policy(config.docker_builder_policy)
            if config.docker_builder_policy is not None
            else None
        )
        runtime_root = config.docker_runtime_root or prepare_default_managed_runtime_root(project)
        docker_optimization_runtime = DockerOptimizationRuntime(
            project=project,
            project_policy=docker_policy,
            allowed_roots=config.allowed_roots,
            private_root=runtime_root,
            runtime_capability_factory=discover_docker_capability,
            build_adapter_factory=lambda private_directory: open_local_docker_build_adapter(
                administrator_policy=administrator_policy,
                runtime_directory=private_directory,
            ),
            collector_available=lambda: (
                config.collector_socket is not None and config.collector_socket.exists()
            ),
            collector_modes=config.automatic_collection_policy.allowed_modes,
            client_connection_identity_sha256=client_connection_identity_sha256,
        )
        return docker_optimization_runtime

    def get_runtime_lock_java_bridge() -> JavaJfrAdapterBridge:
        nonlocal runtime_lock_java_bridge
        _require_runtime_locks(config)
        if runtime_lock_java_bridge is not None:
            return runtime_lock_java_bridge
        assert runtime_lock_policy is not None
        if config.runtime_lock_java_bridge_factory is not None:
            bridge = config.runtime_lock_java_bridge_factory()
        elif config.allow_process_execution:
            bridge = discover_java_jfr_adapter_bridge(runtime_lock_policy)
        else:
            bridge = discover_java_jfr_adapter_bridge(
                runtime_lock_policy,
                trusted_owner_uids=(),
            )
        runtime_lock_java_bridge = bridge
        return bridge

    def get_runtime_lock_cpython_bridge() -> CpythonAdapterBridge:
        nonlocal runtime_lock_cpython_bridge
        _require_runtime_locks(config)
        if runtime_lock_cpython_bridge is not None:
            return runtime_lock_cpython_bridge
        assert runtime_lock_policy is not None
        if config.runtime_lock_cpython_bridge_factory is not None:
            bridge = config.runtime_lock_cpython_bridge_factory()
        elif config.allow_process_execution:
            bridge = discover_cpython_adapter_bridge(runtime_lock_policy)
        else:
            bridge = build_cpython_adapter_bridge(
                runtime_lock_policy,
                inspect_cpython_installation(trusted_owner_uids=()),
                supervisor_available=False,
            )
        runtime_lock_cpython_bridge = bridge
        return bridge

    def get_runtime_lock_go_bridge() -> GoPprofAdapterBridge:
        nonlocal runtime_lock_go_bridge
        _require_runtime_locks(config)
        if runtime_lock_go_bridge is not None:
            return runtime_lock_go_bridge
        assert runtime_lock_policy is not None
        if config.runtime_lock_go_bridge_factory is not None:
            bridge = config.runtime_lock_go_bridge_factory()
        elif config.allow_process_execution:
            bridge = discover_go_pprof_adapter_bridge(runtime_lock_policy)
        else:
            bridge = build_go_pprof_adapter_bridge(
                runtime_lock_policy,
                inspect_go_pprof_installation(trusted_owner_uids=()),
                supervisor_available=False,
            )
        runtime_lock_go_bridge = bridge
        return bridge

    def inspect_runtime_lock_session_capability() -> RuntimeLockCapabilityInspection:
        _require_runtime_locks(config)
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        assert_runtime_lock_project_policy_current(
            runtime_lock_policy,
            allowed_roots=config.allowed_roots,
        )
        if config.runtime_lock_capability_factory is not None:
            return config.runtime_lock_capability_factory()
        native_capability: NativeLaunchCapability
        if config.allow_process_execution:
            discovery = discover_native_pthread_probe_policy()
            native_capability = inspect_native_pthread_installation(discovery.policy)
        else:
            native_capability = NativeLaunchCapability(
                target_scope="host_launched_workload",
                launch_backend="host_launcher",
                availability="unavailable",
                target_identity_sha256=None,
                target_label="native-pthread",
                probe_sha256=None,
                runtime_glibc_version=None,
                supported_semantics=(),
                supported_lock_surfaces=(),
                limitations=(
                    "Active Native pthread instrumentation is disabled by project MCP policy; "
                    "controlled import and deterministic analysis remain available.",
                ),
            )
        return inspect_runtime_lock_capability(
            runtime_lock_policy,
            project_identity_sha256=runtime_lock_project.identity_sha256,
            native_pthread_capability=native_capability,
            java_jfr_bridge=get_runtime_lock_java_bridge(),
            cpython_bridge=get_runtime_lock_cpython_bridge(),
            go_pprof_bridge=get_runtime_lock_go_bridge(),
        )

    def build_docker_runtime_lock_scope(
        adapter_ids: tuple[RuntimeLockAdapterId, ...],
    ) -> tuple[DockerRuntimeLockAuthorizationScope, RuntimeLockCapabilityInspection]:
        """Bind reviewed Adapter identities into the parent Docker consent.

        This helper performs discovery only.  It neither creates a second Runtime Lock
        Session nor launches a container, and it intentionally has no token parameter.
        """

        _require_runtime_locks(config)
        assert runtime_lock_policy is not None
        if (
            not adapter_ids
            or len(set(adapter_ids)) != len(adapter_ids)
            or tuple(sorted(adapter_ids)) != adapter_ids
            or "generic_ndjson_import" in adapter_ids
            or "docker_optimization" not in runtime_lock_policy.target_scopes
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Docker optimization Runtime Lock adapters must be a unique policy-enabled "
                "active Adapter scope",
                recoverable=True,
            )
        inspection = inspect_runtime_lock_session_capability()
        references = {item.adapter_id: item for item in inspection.capability.adapters}
        bindings: list[RuntimeLockAdapterExecutionBinding] = []
        for adapter_id in adapter_ids:
            reference = references.get(adapter_id)
            if reference is None or reference.availability not in {"available", "partial"}:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "A selected Docker Runtime Lock Adapter is unavailable",
                    recoverable=True,
                    details={"adapter_id": adapter_id},
                )
            if adapter_id == "java_jfr":
                binding = get_runtime_lock_java_bridge().execution_binding
            elif adapter_id == "cpython_threading":
                binding = get_runtime_lock_cpython_bridge().binding_for("thresholded")
                if binding is None:
                    binding = get_runtime_lock_cpython_bridge().binding_for("exact")
            elif adapter_id == "go_pprof":
                binding = get_runtime_lock_go_bridge().execution_binding
            else:
                native = next(
                    item
                    for item in inspection.adapter_capabilities
                    if item.adapter_id == "native_pthread"
                )
                probe = discover_native_pthread_probe_policy()
                adapter_policy = runtime_lock_policy.adapter_policy("native_pthread")
                semantics = (
                    "thresholded" if "thresholded" in adapter_policy.allowed_semantics else "exact"
                )
                threshold = (
                    adapter_policy.duration_threshold_ns if semantics == "thresholded" else None
                )
                if probe.policy is None or native.availability not in {"available", "partial"}:
                    binding = None
                else:
                    tools = ()
                    toolchain = derive_runtime_lock_toolchain_identity(tools)
                    metadata = hashlib.sha256(
                        (
                            "perflens-native-pthread-metadata-v1\0"
                            f"{NATIVE_PTHREAD_PROBE_ABI_VERSION}\0"
                            f"{NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION}"
                        ).encode()
                    ).hexdigest()
                    execution = derive_runtime_lock_adapter_execution_identity(
                        "native_pthread",
                        "native-pthread-adapter-v1",
                        "ld-preload",
                        "glibc-2.36-or-2.41",
                        semantics,
                        semantics,
                        threshold,
                        toolchain,
                        probe.policy.sha256,
                        metadata,
                        probe.policy.sha256,
                    )
                    binding = RuntimeLockAdapterExecutionBinding(
                        adapter_id="native_pthread",
                        adapter_version="native-pthread-adapter-v1",
                        backend_id="ld-preload",
                        runtime_version="glibc-2.36-or-2.41",
                        profile=semantics,
                        measurement_semantics=semantics,
                        duration_threshold_ns=threshold,
                        tools=tools,
                        toolchain_identity_sha256=toolchain,
                        configuration_sha256=probe.policy.sha256,
                        metadata_sha256=metadata,
                        runtime_payload_identity_sha256=probe.policy.sha256,
                        execution_identity_sha256=execution,
                        limitations=native.limitations,
                    )
            if (
                binding is None
                or binding.measurement_semantics not in reference.supported_semantics
            ):
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "A selected Docker Runtime Lock execution binding is unavailable",
                    recoverable=True,
                    details={"adapter_id": adapter_id},
                )
            bindings.append(binding)
        semantics = cast(
            tuple[MeasurementSemantics, ...],
            tuple(sorted({item.measurement_semantics for item in bindings})),
        )
        provisional = DockerRuntimeLockAuthorizationScope.model_construct(
            schema_version="1.1",
            runtime_lock_config_sha256=runtime_lock_policy.sha256,
            capability_id=inspection.capability.capability_id,
            capability_content_sha256=inspection.capability.content_sha256,
            allowed_adapters=adapter_ids,
            allowed_semantics=semantics,
            adapter_execution_bindings=tuple(bindings),
            runtime_version_constraints=docker_runtime_lock_version_constraints(tuple(bindings)),
            budget=runtime_lock_policy.budget,
            content_sha256="0" * 64,
        )
        scope = DockerRuntimeLockAuthorizationScope.model_validate(
            {
                **provisional.model_dump(mode="json"),
                "content_sha256": docker_runtime_lock_scope_sha256(provisional),
            }
        )
        return scope, inspection

    def build_docker_runtime_lock_launch(
        session: DockerOptimizationSessionArtifact,
        adapter_id: RuntimeLockAdapterId,
        *,
        max_events: int,
        go_profile_kind: GoProfileKind | None,
    ) -> tuple[RuntimeLockAdapterExecutionBinding, RuntimeLockDockerLaunch]:
        scope = session.runtime_lock_scope
        if (
            session.state != "active"
            or scope is None
            or adapter_id not in scope.allowed_adapters
            or isinstance(max_events, bool)
            or not 1 <= max_events <= scope.budget.max_exact_events
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Runtime Lock collection is outside the parent Docker authorization",
                recoverable=True,
            )
        _require_runtime_locks(config)
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        assert_runtime_lock_project_policy_current(
            runtime_lock_policy,
            allowed_roots=config.allowed_roots,
        )
        assert_managed_project_current(runtime_lock_project)
        binding = next(
            item for item in scope.adapter_execution_bindings if item.adapter_id == adapter_id
        )
        if (adapter_id == "go_pprof") != (go_profile_kind is not None):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "A Docker Go Runtime Lock run requires exactly one authorized profile kind",
                recoverable=True,
            )
        if adapter_id == "native_pthread":
            discovery = discover_native_pthread_probe_policy()
            if discovery.policy is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "The packaged Native pthread probe is unavailable",
                    recoverable=True,
                )
            current_execution_identity = derive_runtime_lock_adapter_execution_identity(
                "native_pthread",
                "native-pthread-adapter-v1",
                "ld-preload",
                "glibc-2.36-or-2.41",
                binding.measurement_semantics,
                binding.measurement_semantics,
                binding.duration_threshold_ns,
                binding.toolchain_identity_sha256,
                discovery.policy.sha256,
                binding.metadata_sha256,
                discovery.policy.sha256,
            )
            if (
                binding.configuration_sha256 != discovery.policy.sha256
                or binding.runtime_payload_identity_sha256 != discovery.policy.sha256
                or binding.execution_identity_sha256 != current_execution_identity
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The packaged Native pthread probe changed after Docker authorization",
                    recoverable=False,
                )
            launch: RuntimeLockDockerLaunch = NativePthreadDockerLaunch(
                probe_path=discovery.policy.path,
                probe_sha256=discovery.policy.sha256,
                semantics=cast(Literal["exact", "thresholded"], binding.measurement_semantics),
                duration_threshold_ns=binding.duration_threshold_ns,
                max_events=max_events,
            )
        elif adapter_id == "cpython_threading":
            policy_binding = get_runtime_lock_cpython_bridge().launch_policy
            if policy_binding is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "The packaged CPython bootstrap is unavailable",
                    recoverable=True,
                )
            assert_cpython_launch_policy_current(policy_binding)
            authorized_tools = {tool.name: tool for tool in binding.tools}
            if (
                binding.configuration_sha256 != policy_binding.bootstrap.sha256
                or binding.runtime_payload_identity_sha256
                != policy_binding.bootstrap.sha256
                or authorized_tools.get("python") is None
                or authorized_tools["python"].binary_sha256
                != policy_binding.interpreter.sha256
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The CPython Runtime Lock payload changed after Docker authorization",
                    recoverable=False,
                )
            launch = CpythonDockerLaunch(
                bootstrap_path=policy_binding.bootstrap.path,
                bootstrap_sha256=policy_binding.bootstrap.sha256,
                semantics=cast(Literal["exact", "thresholded"], binding.measurement_semantics),
                duration_threshold_ns=binding.duration_threshold_ns,
                max_events=max_events,
            )
        elif adapter_id == "java_jfr":
            java_policy = get_runtime_lock_java_bridge().launch_policy
            if java_policy is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "The packaged Java JFR configuration is unavailable",
                    recoverable=True,
                )
            assert_java_jfr_launch_policy_current(java_policy)
            current_jfr = inspect_java_jfr_tool_identity(java_policy.jfr_tool)
            authorized_tools = {tool.name: tool for tool in binding.tools}
            if (
                current_jfr.path != java_policy.jfr_tool.path
                or current_jfr.sha256 != java_policy.jfr_tool.sha256
                or current_jfr.owner_uid != java_policy.jfr_tool.owner_uid
                or current_jfr.mode != java_policy.jfr_tool.mode
                or binding.configuration_sha256 != java_policy.jfc_profile.sha256
                or binding.runtime_payload_identity_sha256
                != java_policy.runtime_payload.identity_sha256
                or "java" not in authorized_tools
                or "jfr" not in authorized_tools
                or authorized_tools["java"].binary_sha256
                != java_policy.java_tool.sha256
                or authorized_tools["jfr"].binary_sha256 != current_jfr.sha256
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The Java JFR tool changed after Docker authorization",
                    recoverable=False,
                )
            launch = JavaJfrDockerLaunch(
                configuration_path=java_policy.jfc_profile.path,
                configuration_sha256=java_policy.jfc_profile.sha256,
                profile=java_policy.profile,
            )
        else:
            go_bridge = get_runtime_lock_go_bridge()
            if go_bridge.tool is None or go_bridge.pprof_tool is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "The authorized Go pprof tools are unavailable",
                    recoverable=True,
                )
            assert_go_tool_identity(go_bridge.tool)
            assert_go_tool_identity(go_bridge.pprof_tool)
            authorized_tools = {tool.name: tool for tool in binding.tools}
            if (
                authorized_tools.get("go") is None
                or authorized_tools.get("pprof") is None
                or authorized_tools["go"].binary_sha256 != go_bridge.tool.sha256
                or authorized_tools["pprof"].binary_sha256 != go_bridge.pprof_tool.sha256
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The Go pprof tools changed after Docker authorization",
                    recoverable=False,
                )
            adapter_policy = runtime_lock_policy.adapter_policy("go_pprof")
            current_configuration_sha256 = hashlib.sha256(
                "\0".join(
                    (
                        "perflens-go-pprof-configuration-v1",
                        str(adapter_policy.mutex_profile_fraction or 0),
                        str(adapter_policy.block_profile_rate_ns or 0),
                        str(int(adapter_policy.file_backend_enabled)),
                        str(int(adapter_policy.loopback_backend_enabled)),
                    )
                ).encode("utf-8")
            ).hexdigest()
            assert go_profile_kind is not None
            enabled = (
                adapter_policy.block_profile_rate_ns is not None
                if go_profile_kind == "block"
                else adapter_policy.mutex_profile_fraction is not None
            )
            if binding.configuration_sha256 != current_configuration_sha256:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The Go pprof configuration changed after Docker authorization",
                    recoverable=False,
                )
            if not enabled:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The selected Go profile kind is disabled by project policy",
                    recoverable=True,
                )
            launch = GoPprofDockerLaunch(profile_kinds=(go_profile_kind,))
        return binding, launch

    def get_runtime_lock_session_runtime() -> RuntimeLockSessionRuntime:
        nonlocal runtime_lock_runtime
        _require_runtime_locks(config)
        if runtime_lock_runtime is not None:
            return runtime_lock_runtime
        if config.runtime_lock_runtime_factory is not None:
            runtime_lock_runtime = config.runtime_lock_runtime_factory()
            return runtime_lock_runtime
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime_lock_runtime = RuntimeLockSessionRuntime(
            project_identity_sha256=runtime_lock_project.identity_sha256,
            project_policy_sha256=runtime_lock_policy.sha256,
            runtime_lock_config_sha256=runtime_lock_policy.sha256,
            client_connection_identity_sha256=client_connection_identity_sha256,
        )
        return runtime_lock_runtime

    def get_runtime_lock_native_launcher() -> NativePthreadLauncher:
        nonlocal runtime_lock_native_launcher, runtime_lock_native_private_root
        _require_runtime_locks(config)
        if not config.allow_process_execution:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Native Runtime Lock workload execution is disabled by project MCP policy",
                recoverable=True,
            )
        if runtime_lock_native_launcher is not None:
            return runtime_lock_native_launcher
        assert runtime_lock_project is not None
        private_root = Path(
            tempfile.mkdtemp(
                prefix=".runtime-lock-native-",
                dir=config.artifact_root,
            )
        )
        private_root.chmod(0o700)
        try:
            if config.runtime_lock_native_launcher_factory is not None:
                launcher = config.runtime_lock_native_launcher_factory(
                    runtime_lock_project.path,
                    private_root,
                )
            else:
                discovery = discover_native_pthread_probe_policy()
                if discovery.policy is None:
                    raise PerfLensError(
                        ErrorCode.EXTERNAL_TOOL_FAILED,
                        "runtime_lock_capability",
                        "The packaged Native pthread probe is unavailable or unsafe",
                        recoverable=True,
                        details={"limitations": discovery.limitations},
                    )
                launcher = NativePthreadLauncher(
                    project_root=runtime_lock_project.path,
                    private_output_root=private_root,
                    probe_policy=discovery.policy,
                )
        except Exception:
            with suppress(OSError):
                private_root.rmdir()
            raise
        runtime_lock_native_private_root = private_root
        runtime_lock_native_launcher = launcher
        return launcher

    def get_runtime_lock_java_launcher() -> JavaJfrLauncher:
        nonlocal runtime_lock_java_artifact_lease
        nonlocal runtime_lock_java_launcher, runtime_lock_java_private_root
        _require_runtime_locks(config)
        if not config.allow_process_execution:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Java JFR workload execution is disabled by project MCP policy",
                recoverable=True,
            )
        if runtime_lock_java_launcher is not None:
            return runtime_lock_java_launcher
        assert runtime_lock_project is not None
        bridge = get_runtime_lock_java_bridge()
        if bridge.launch_policy is None or bridge.execution_binding is None:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "runtime_lock_capability",
                "The trusted Java JFR launch bridge is unavailable",
                recoverable=True,
                details={"limitations": bridge.capability.limitations},
            )
        assert runtime_lock_policy is not None
        artifact_lease = acquire_java_jfr_artifact_root_lease(config.artifact_root)
        private_root: Path | None = None
        try:
            recovered = inventory_java_jfr_retained_evidence(
                config.artifact_root,
                max_retained_bytes=runtime_lock_policy.budget.max_evidence_bytes,
            )
            runtime_lock_java_retained_results[:] = list(recovered.retained_evidence)
            private_root = Path(
                tempfile.mkdtemp(prefix=".runtime-lock-java-", dir=config.artifact_root)
            )
            private_root.chmod(0o700)
            if config.runtime_lock_java_launcher_factory is not None:
                launcher = config.runtime_lock_java_launcher_factory(
                    runtime_lock_project.path,
                    private_root,
                    bridge.launch_policy,
                )
            else:
                launcher = JavaJfrLauncher(
                    project_root=runtime_lock_project.path,
                    private_output_root=private_root,
                    policy=bridge.launch_policy,
                    json_runner=SubprocessJavaJfrJsonRunner(),
                )
        except Exception:
            if private_root is not None:
                with suppress(OSError):
                    private_root.rmdir()
            with suppress(OSError, PerfLensError):
                release_java_jfr_artifact_root_lease(artifact_lease)
            raise
        runtime_lock_java_artifact_lease = artifact_lease
        runtime_lock_java_private_root = private_root
        runtime_lock_java_launcher = launcher
        return launcher

    def get_runtime_lock_cpython_launcher() -> CpythonThreadingLauncher:
        nonlocal runtime_lock_cpython_launcher, runtime_lock_cpython_private_root
        _require_runtime_locks(config)
        if not config.allow_process_execution:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "CPython Runtime Lock workload execution is disabled by project MCP policy",
                recoverable=True,
            )
        if runtime_lock_cpython_launcher is not None:
            return runtime_lock_cpython_launcher
        assert runtime_lock_project is not None
        bridge = get_runtime_lock_cpython_bridge()
        if bridge.launch_policy is None:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "runtime_lock_capability",
                "The trusted CPython launch bridge is unavailable",
                recoverable=True,
                details={"limitations": bridge.capability.limitations},
            )
        private_root = Path(
            tempfile.mkdtemp(prefix=".runtime-lock-cpython-", dir=config.artifact_root)
        )
        private_root.chmod(0o700)
        try:
            if config.runtime_lock_cpython_launcher_factory is not None:
                launcher = config.runtime_lock_cpython_launcher_factory(
                    runtime_lock_project.path,
                    private_root,
                    bridge.launch_policy,
                )
            else:
                launcher = CpythonThreadingLauncher(
                    project_root=runtime_lock_project.path,
                    private_output_root=private_root,
                    policy=bridge.launch_policy,
                )
        except Exception:
            with suppress(OSError):
                private_root.rmdir()
            raise
        runtime_lock_cpython_private_root = private_root
        runtime_lock_cpython_launcher = launcher
        return launcher

    def get_runtime_lock_go_launcher() -> GoPprofLauncher:
        nonlocal runtime_lock_go_launcher, runtime_lock_go_private_root
        _require_runtime_locks(config)
        if not config.allow_process_execution:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Go pprof workload execution is disabled by project MCP policy",
                recoverable=True,
            )
        if runtime_lock_go_launcher is not None:
            return runtime_lock_go_launcher
        assert runtime_lock_project is not None
        bridge = get_runtime_lock_go_bridge()
        if bridge.execution_binding is None or bridge.tool is None or bridge.pprof_tool is None:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "runtime_lock_capability",
                "The trusted Go pprof launch bridge is unavailable",
                recoverable=True,
                details={"limitations": bridge.capability.limitations},
            )
        private_root = Path(tempfile.mkdtemp(prefix=".runtime-lock-go-", dir=config.artifact_root))
        private_root.chmod(0o700)
        try:
            if config.runtime_lock_go_launcher_factory is not None:
                launcher = config.runtime_lock_go_launcher_factory(
                    runtime_lock_project.path,
                    private_root,
                    bridge.tool,
                    bridge.pprof_tool,
                )
            else:
                launcher = GoPprofLauncher(
                    project_root=runtime_lock_project.path,
                    private_output_root=private_root,
                    go_tool=bridge.tool,
                    pprof_tool=bridge.pprof_tool,
                )
        except Exception:
            with suppress(OSError):
                private_root.rmdir()
            raise
        runtime_lock_go_private_root = private_root
        runtime_lock_go_launcher = launcher
        return launcher

    def capture_module_snapshot(
        executed: _ExecutedBrokerPlan,
        *,
        pinned_process_root: PinnedContainerProcessRoot | None = None,
    ) -> ContainerModuleSnapshotArtifact | None:
        collection = executed.collection
        if (
            collection is None
            or collection.mode != "record"
            or collection.target_runtime != "docker"
        ):
            return None
        existing = store.load_container_module_snapshot_for_collection(collection.collection_id)
        if existing is not None:
            return existing
        snapshot = capture_container_module_snapshot(
            collection,
            perf_path=config.perf_path,
            pinned_process_root=pinned_process_root,
        )
        store.save(
            snapshot,
            snapshot.module_snapshot_id,
            "container-module-snapshot",
        )
        return snapshot

    def execute_broker_plan(
        plan: CollectionPlanArtifact,
        *,
        ready_callback: Callable[[], None] | None = None,
        namespace_attestation: NamespaceIdentity | None = None,
    ) -> _ExecutedBrokerPlan:
        if namespace_attestation is None:
            assert_plan_current(plan)
        else:
            assert_plan_current(plan, namespace_attestation=namespace_attestation)
        assert config.collector_socket is not None
        client = CollectorBrokerClient(
            config.collector_socket,
            timeout_seconds=min(plan.duration_seconds + 15, 86_500),
        )
        started = time.monotonic()
        if plan.mode in {"sched", "off_cpu", "lock"}:
            trace_evidence = client.collect_trace(plan, ready_callback=ready_callback)
            active_seconds = time.monotonic() - started
            store.save(
                trace_evidence,
                trace_evidence.trace_evidence_id,
                "trace-evidence",
            )
            return _ExecutedBrokerPlan(
                reference=ArtifactReference(
                    artifact_id=trace_evidence.trace_evidence_id,
                    artifact_type="trace-evidence",
                    uri=store.uri(trace_evidence.trace_evidence_id, "trace-evidence"),
                    summary={
                        "mode": trace_evidence.mode,
                        "target_pid": trace_evidence.target.target_pid,
                        "target_uid": trace_evidence.target.target_uid,
                        "status": trace_evidence.status,
                        "quality": trace_evidence.quality.quality_status,
                        "event_count": len(trace_evidence.events),
                        "lost_event_count": trace_evidence.quality.lost_event_count,
                        "content_sha256": trace_evidence.content_sha256,
                        "source_output_sha256": trace_evidence.source.output_sha256,
                        "limitations": "; ".join(trace_evidence.quality.limitations),
                    },
                ),
                collection=None,
                collection_id=trace_evidence.source.collection_id,
                output_sha256=trace_evidence.source.output_sha256,
                evidence_bytes=trace_evidence.source.output_bytes,
                active_seconds=active_seconds,
            )
        artifact = client.collect(plan, ready_callback=ready_callback)
        active_seconds = time.monotonic() - started
        store.save(artifact, artifact.collection_id, "collection")
        return _ExecutedBrokerPlan(
            reference=ArtifactReference(
                artifact_id=artifact.collection_id,
                artifact_type="collection",
                uri=store.uri(artifact.collection_id, "collection"),
                summary={
                    "mode": artifact.mode,
                    "target_type": artifact.target_type,
                    "target_pid": artifact.target_pid,
                    "output_bytes": artifact.output_bytes,
                    "metric_count": len(artifact.metrics),
                    "record_event": artifact.record_event,
                    "requested_event_source": artifact.requested_event_source,
                    "actual_event_source": artifact.actual_event_source,
                    "fallback_used": artifact.fallback_used,
                    "fallback_reason": artifact.fallback_reason,
                    "evidence_limitations": "; ".join(artifact.evidence_limitations),
                    "warnings": "; ".join(artifact.warnings),
                },
            ),
            collection=artifact,
            collection_id=artifact.collection_id,
            output_sha256=artifact.output_sha256,
            evidence_bytes=artifact.output_bytes,
            active_seconds=active_seconds,
        )

    async def collect_cpython_runtime_lock_evidence(
        session_id: str,
        measurement_semantics: Literal["exact", "thresholded"],
        duration_seconds: int,
        max_events: int,
    ) -> ArtifactReference:
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime = get_runtime_lock_session_runtime()
        lease = None
        launch_result: CpythonLaunchResult | None = None
        actual_active_seconds = duration_seconds
        actual_evidence_bytes = 0
        actual_exact_events = 0
        run_finished = False
        retain_private_stream = False
        failure_reason: Literal[
            "adapter_output_invalid",
            "correctness_failed",
            "identity_or_policy_changed",
            "internal_collection_error",
            "resource_limit_exceeded",
            "target_exited",
            "target_identity_changed",
        ] = "internal_collection_error"
        try:
            assert_runtime_lock_project_policy_current(
                runtime_lock_policy, allowed_roots=config.allowed_roots
            )
            assert_managed_project_current(runtime_lock_project)
            session = runtime.snapshot(session_id)
            preview = store.load_runtime_lock_preview(session.preview_id)
            bridge = get_runtime_lock_cpython_bridge()
            binding = bridge.binding_for(measurement_semantics)
            if binding is None:
                raise _runtime_lock_native_error(
                    "CPython execution binding is unavailable for the selected semantics"
                )
            workload = _validate_cpython_runtime_lock_session(
                session,
                preview,
                runtime_lock_policy,
                execution_binding=binding,
                measurement_semantics=measurement_semantics,
                duration_seconds=duration_seconds,
                max_events=max_events,
            )
            launcher = get_runtime_lock_cpython_launcher()
            script_path = _runtime_lock_project_executable(
                runtime_lock_project.path, workload.program
            )
            target = launcher.inspect_target(script_path)
            if (
                target.project_relative_path != workload.program
                or target.script_sha256 != workload.program_sha256
                or target.size != workload.program_size
            ):
                failure_reason = "target_identity_changed"
                raise _runtime_lock_native_error(
                    "CPython workload differs from the authorized Preview"
                )
            threshold = 10_000 if measurement_semantics == "thresholded" else None
            operation_identity = _runtime_lock_cpython_operation_identity(
                session,
                target.identity_sha256,
                measurement_semantics,
                duration_seconds,
                max_events,
                binding.execution_identity_sha256,
            )
            lease = runtime.begin_run(
                session_id,
                adapter_id="cpython_threading",
                measurement_semantics=measurement_semantics,
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                workload_identity_sha256=workload.workload_identity_sha256,
                reserve_active_seconds=duration_seconds,
                reserve_evidence_bytes=session.budget.max_artifact_bytes,
                reserve_exact_events=(max_events if measurement_semantics == "exact" else 0),
            )
            reserved = runtime.snapshot(session_id)
            store.save(reserved, reserved.session_artifact_id, "runtime-lock-session")
            launch_result = launcher.launch(
                script_path,
                CpythonLaunchRequest(
                    arguments=workload.arguments,
                    semantics=measurement_semantics,
                    threshold_ns=threshold,
                    duration_seconds=duration_seconds,
                    max_events=max_events,
                ),
                expected_target_identity_sha256=target.identity_sha256,
            )
            actual_active_seconds = launch_result.accounted_active_seconds
            actual_evidence_bytes = launch_result.stream_size
            if launch_result.termination_reason == "duration_limit":
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "CPython workload exceeded its authorized duration",
                    recoverable=True,
                )
            if launch_result.exit_code is None:
                failure_reason = "target_exited"
                raise _runtime_lock_native_error("CPython workload exit status is unavailable")
            if launch_result.exit_code != 0:
                failure_reason = "correctness_failed"
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_collection",
                    "CPython workload exited unsuccessfully",
                    recoverable=True,
                    details={"exit_code": launch_result.exit_code},
                )
            failure_reason = "adapter_output_invalid"
            retain_private_stream = True
            source_fd = open_cpython_private_stream(launch_result)
            try:
                with os.fdopen(os.dup(source_fd), "rb") as source:
                    receipt = convert_cpython_threading_stream(
                        source,
                        execution_binding=binding,
                        limits=RuntimeLockResourceLimits(
                            max_source_bytes=session.budget.max_artifact_bytes,
                            max_input_records=max_events,
                            max_output_bytes=session.budget.max_artifact_bytes,
                        ),
                        created_at=launch_result.started_at,
                    )
            finally:
                os.close(source_fd)
            # Reopen and revalidate because ``dup`` shares the original
            # open-file offset and the first streaming conversion ends at EOF.
            replay_fd = open_cpython_private_stream(launch_result)
            try:
                with os.fdopen(os.dup(replay_fd), "rb") as replay:
                    if not verify_cpython_threading_replay(
                        receipt.evidence, replay, execution_binding=binding
                    ):
                        raise _runtime_lock_native_error(
                            "CPython private evidence replay differs from the public Artifact"
                        )
            finally:
                os.close(replay_fd)
            evidence = receipt.evidence
            identity_warnings = _assert_cpython_runtime_lock_evidence_identity(
                evidence,
                launch_result=launch_result,
                expected_target_identity_sha256=target.identity_sha256,
                execution_binding=binding,
                max_events=max_events,
            )
            analysis = build_runtime_lock_analysis(evidence)
            verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
            require_usable_runtime_lock_analysis(verification)
            actual_evidence_bytes = len(serialize_json(evidence))
            actual_exact_events = len(evidence.events) if measurement_semantics == "exact" else 0
            warnings = tuple(
                dict.fromkeys(
                    (*preview.warnings, *evidence.quality.limitations, *identity_warnings)
                )
            )
            quality, allowed, forbidden = derive_runtime_lock_run_boundaries(
                adapter_id="cpython_threading",
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=warnings,
            )
            provisional_run = RuntimeLockRunArtifact(
                schema_version=preview.schema_version,
                perflens_version=__version__,
                run_id=derive_runtime_lock_run_id(
                    session_id,
                    "cpython_threading",
                    evidence.content_sha256,
                    launch_result.started_at,
                ),
                created_at=launch_result.finished_at,
                started_at=launch_result.started_at,
                finished_at=launch_result.finished_at,
                authorization_kind="runtime_lock_session",
                session_id=session_id,
                session_artifact_id=lease.session_artifact_id,
                session_artifact_content_sha256=lease.session_artifact_content_sha256,
                session_revision=lease.session_revision,
                target_scope="host_launched_workload",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                adapter_id="cpython_threading",
                adapter_execution_identity_sha256=binding.execution_identity_sha256,
                measurement_semantics=measurement_semantics,
                workload_identity_sha256=workload.workload_identity_sha256,
                runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
                runtime_lock_evidence_content_sha256=evidence.content_sha256,
                runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
                runtime_lock_analysis_content_sha256=analysis.content_sha256,
                runtime_lock_verification_id=verification.runtime_lock_verification_id,
                runtime_lock_verification_content_sha256=verification.content_sha256,
                duration_seconds=actual_active_seconds,
                evidence_bytes=actual_evidence_bytes,
                event_count=len(evidence.events),
                correctness_status="passed",
                quality_status=quality,
                warnings=warnings,
                allowed_conclusions=allowed,
                forbidden_conclusions=forbidden,
                content_sha256="0" * 64,
            )
            run = provisional_run.model_copy(
                update={
                    "content_sha256": contract_content_sha256(
                        provisional_run, exclude={"content_sha256"}
                    )
                }
            )
            cleanup_cpython_launch_result(launch_result)
            retain_private_stream = False
            for artifact, artifact_id, artifact_type in (
                (evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence"),
                (analysis, analysis.runtime_lock_analysis_id, "runtime-lock-analysis"),
                (
                    verification,
                    verification.runtime_lock_verification_id,
                    "runtime-lock-verification",
                ),
                (run, run.run_id, "runtime-lock-run"),
            ):
                store.save(artifact, artifact_id, artifact_type)
            settlement = runtime.finish_run(session_id, lease, run)
            run_finished = True
            _persist_runtime_lock_settlement(runtime, session_id, store, settlement)
            return ArtifactReference(
                artifact_id=run.run_id,
                artifact_type="runtime-lock-run",
                uri=store.uri(run.run_id, "runtime-lock-run"),
                summary={
                    "session_id": session_id,
                    "adapter_id": "cpython_threading",
                    "runtime": analysis.runtime,
                    "measurement_semantics": measurement_semantics,
                    "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
                    "runtime_lock_analysis_id": analysis.runtime_lock_analysis_id,
                    "runtime_lock_verification_id": verification.runtime_lock_verification_id,
                    "private_source_replay_status": "passed",
                    "quality_status": run.quality_status,
                    "event_count": run.event_count,
                    "target_pid": launch_result.target_pid,
                    "exit_code": launch_result.exit_code,
                    "session_state": settlement.session.state,
                },
            )
        except Exception:
            if launch_result is not None:
                if retain_private_stream:
                    if launch_result not in runtime_lock_cpython_retained_results:
                        runtime_lock_cpython_retained_results.append(launch_result)
                else:
                    with suppress(OSError, PerfLensError):
                        cleanup_cpython_launch_result(launch_result)
            if lease is not None and not run_finished:
                with suppress(PerfLensError):
                    terminal = runtime.fail_run(
                        session_id,
                        lease,
                        actual_active_seconds=actual_active_seconds,
                        actual_evidence_bytes=actual_evidence_bytes,
                        actual_exact_events=actual_exact_events,
                        reason=failure_reason,
                    )
                    _persist_runtime_lock_settlement(runtime, session_id, store, terminal)
            elif lease is None:
                with suppress(PerfLensError):
                    terminal = runtime.revoke(session_id)
                    store.save(terminal, terminal.session_artifact_id, "runtime-lock-session")
            raise

    async def collect_go_pprof_runtime_lock_evidence(
        session_id: str,
        duration_seconds: int,
        max_events: int,
        profile_kind: GoProfileKind,
    ) -> ArtifactReference:
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime = get_runtime_lock_session_runtime()
        lease = None
        launch_result: GoPprofLaunchResult | None = None
        raw_result: GoPprofRawResult | None = None
        actual_active_seconds = duration_seconds
        actual_evidence_bytes = 0
        run_finished = False
        retain_private_evidence = False
        failure_reason: Literal[
            "adapter_output_invalid",
            "correctness_failed",
            "identity_or_policy_changed",
            "internal_collection_error",
            "resource_limit_exceeded",
            "target_exited",
            "target_identity_changed",
        ] = "internal_collection_error"
        try:
            assert_runtime_lock_project_policy_current(
                runtime_lock_policy, allowed_roots=config.allowed_roots
            )
            assert_managed_project_current(runtime_lock_project)
            session = runtime.snapshot(session_id)
            preview = store.load_runtime_lock_preview(session.preview_id)
            bridge = get_runtime_lock_go_bridge()
            binding = bridge.execution_binding
            if binding is None:
                raise _runtime_lock_native_error("Go pprof execution binding is unavailable")
            workload = _validate_go_runtime_lock_session(
                session,
                preview,
                runtime_lock_policy,
                execution_binding=binding,
                duration_seconds=duration_seconds,
                max_events=max_events,
                profile_kind=profile_kind,
            )
            launcher = get_runtime_lock_go_launcher()
            executable_path = _runtime_lock_project_executable(
                runtime_lock_project.path, workload.program
            )
            target = launcher.inspect_target(executable_path)
            if (
                target.project_relative_path != workload.program
                or target.binary_sha256 != workload.program_sha256
                or target.size != workload.program_size
            ):
                failure_reason = "target_identity_changed"
                raise _runtime_lock_native_error("Go workload differs from the authorized Preview")
            adapter_policy = runtime_lock_policy.adapter_policy("go_pprof")
            operation_identity = _runtime_lock_go_operation_identity(
                session,
                target.identity_sha256,
                profile_kind,
                duration_seconds,
                max_events,
                binding.execution_identity_sha256,
                adapter_policy.mutex_profile_fraction,
                adapter_policy.block_profile_rate_ns,
            )
            lease = runtime.begin_run(
                session_id,
                adapter_id="go_pprof",
                measurement_semantics="cumulative",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                workload_identity_sha256=workload.workload_identity_sha256,
                reserve_active_seconds=duration_seconds,
                reserve_evidence_bytes=min(
                    session.budget.max_evidence_bytes,
                    session.budget.max_artifact_bytes * 3,
                ),
                reserve_exact_events=0,
            )
            reserved = runtime.snapshot(session_id)
            store.save(reserved, reserved.session_artifact_id, "runtime-lock-session")
            launch_result = launcher.launch(
                executable_path,
                GoPprofLaunchRequest(
                    arguments=workload.arguments,
                    duration_seconds=duration_seconds,
                ),
                expected_target_identity_sha256=target.identity_sha256,
            )
            actual_active_seconds = launch_result.accounted_active_seconds
            actual_evidence_bytes = (
                launch_result.mutex_profile_size + launch_result.block_profile_size
            )
            if launch_result.termination_reason == "duration_limit":
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "Go workload exceeded its authorized duration",
                    recoverable=True,
                )
            if launch_result.exit_code is None:
                failure_reason = "target_exited"
                raise _runtime_lock_native_error("Go workload exit status is unavailable")
            if launch_result.exit_code != 0:
                failure_reason = "correctness_failed"
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_collection",
                    "Go workload exited unsuccessfully",
                    recoverable=True,
                    details={"exit_code": launch_result.exit_code},
                )
            failure_reason = "adapter_output_invalid"
            retain_private_evidence = True
            raw_result = launcher.render_raw(launch_result, profile_kind)
            actual_evidence_bytes += raw_result.raw_size
            source_fd = open_go_pprof_raw(raw_result)
            try:
                with os.fdopen(os.dup(source_fd), "rb") as source:
                    receipt = convert_go_pprof_raw(
                        source,
                        execution_binding=binding,
                        profile_kind=profile_kind,
                        target_pid=launch_result.target_pid,
                        target_uid=launch_result.target_uid,
                        target_start_time_ticks=launch_result.target_start_ticks,
                        mutex_profile_fraction=(
                            adapter_policy.mutex_profile_fraction
                            if profile_kind == "mutex"
                            else None
                        ),
                        block_profile_rate_ns=(
                            adapter_policy.block_profile_rate_ns
                            if profile_kind == "block"
                            else None
                        ),
                        limits=RuntimeLockResourceLimits(
                            max_source_bytes=session.budget.max_artifact_bytes,
                            max_input_records=max_events,
                            max_output_bytes=session.budget.max_artifact_bytes,
                        ),
                        created_at=launch_result.started_at,
                    )
            finally:
                os.close(source_fd)
            replay_fd = open_go_pprof_raw(raw_result)
            try:
                with os.fdopen(os.dup(replay_fd), "rb") as replay:
                    if (
                        verify_go_pprof_replay(
                            replay,
                            expected=receipt,
                            execution_binding=binding,
                            target_pid=launch_result.target_pid,
                            target_uid=launch_result.target_uid,
                            target_start_time_ticks=launch_result.target_start_ticks,
                            mutex_profile_fraction=(
                                adapter_policy.mutex_profile_fraction
                                if profile_kind == "mutex"
                                else None
                            ),
                            block_profile_rate_ns=(
                                adapter_policy.block_profile_rate_ns
                                if profile_kind == "block"
                                else None
                            ),
                        )
                        is None
                    ):
                        raise _runtime_lock_native_error(
                            "Go private profile replay differs from the public Artifact"
                        )
            finally:
                os.close(replay_fd)
            evidence = receipt.evidence
            identity_warnings = _assert_go_runtime_lock_evidence_identity(
                evidence,
                launch_result=launch_result,
                raw_result=raw_result,
                expected_target_identity_sha256=target.identity_sha256,
                execution_binding=binding,
                profile_kind=profile_kind,
                max_events=max_events,
            )
            analysis = build_runtime_lock_analysis(evidence)
            verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
            require_usable_runtime_lock_analysis(verification)
            public_evidence_bytes = len(serialize_json(evidence))
            warnings = tuple(
                dict.fromkeys(
                    (*preview.warnings, *evidence.quality.limitations, *identity_warnings)
                )
            )
            quality, allowed, forbidden = derive_runtime_lock_run_boundaries(
                adapter_id="go_pprof",
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=warnings,
            )
            provisional_run = RuntimeLockRunArtifact(
                schema_version=preview.schema_version,
                perflens_version=__version__,
                run_id=derive_runtime_lock_run_id(
                    session_id,
                    "go_pprof",
                    evidence.content_sha256,
                    launch_result.started_at,
                ),
                created_at=launch_result.finished_at,
                started_at=launch_result.started_at,
                finished_at=launch_result.finished_at,
                authorization_kind="runtime_lock_session",
                session_id=session_id,
                session_artifact_id=lease.session_artifact_id,
                session_artifact_content_sha256=lease.session_artifact_content_sha256,
                session_revision=lease.session_revision,
                target_scope="host_launched_workload",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                adapter_id="go_pprof",
                adapter_execution_identity_sha256=binding.execution_identity_sha256,
                measurement_semantics="cumulative",
                workload_identity_sha256=workload.workload_identity_sha256,
                runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
                runtime_lock_evidence_content_sha256=evidence.content_sha256,
                runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
                runtime_lock_analysis_content_sha256=analysis.content_sha256,
                runtime_lock_verification_id=verification.runtime_lock_verification_id,
                runtime_lock_verification_content_sha256=verification.content_sha256,
                duration_seconds=actual_active_seconds,
                evidence_bytes=public_evidence_bytes,
                event_count=len(evidence.events),
                correctness_status="passed",
                quality_status=quality,
                warnings=warnings,
                allowed_conclusions=allowed,
                forbidden_conclusions=forbidden,
                content_sha256="0" * 64,
            )
            run = provisional_run.model_copy(
                update={
                    "content_sha256": contract_content_sha256(
                        provisional_run, exclude={"content_sha256"}
                    )
                }
            )
            cleanup_go_pprof_result(launch_result, raw_result)
            retain_private_evidence = False
            actual_evidence_bytes = public_evidence_bytes
            for artifact, artifact_id, artifact_type in (
                (evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence"),
                (analysis, analysis.runtime_lock_analysis_id, "runtime-lock-analysis"),
                (
                    verification,
                    verification.runtime_lock_verification_id,
                    "runtime-lock-verification",
                ),
                (run, run.run_id, "runtime-lock-run"),
            ):
                store.save(artifact, artifact_id, artifact_type)
            settlement = runtime.finish_run(session_id, lease, run)
            run_finished = True
            _persist_runtime_lock_settlement(runtime, session_id, store, settlement)
            return ArtifactReference(
                artifact_id=run.run_id,
                artifact_type="runtime-lock-run",
                uri=store.uri(run.run_id, "runtime-lock-run"),
                summary={
                    "session_id": session_id,
                    "adapter_id": "go_pprof",
                    "profile_kind": profile_kind,
                    "runtime": analysis.runtime,
                    "measurement_semantics": "cumulative",
                    "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
                    "runtime_lock_analysis_id": analysis.runtime_lock_analysis_id,
                    "runtime_lock_verification_id": verification.runtime_lock_verification_id,
                    "private_source_replay_status": "passed",
                    "quality_status": run.quality_status,
                    "event_count": run.event_count,
                    "target_pid": launch_result.target_pid,
                    "exit_code": launch_result.exit_code,
                    "session_state": settlement.session.state,
                },
            )
        except Exception:
            if launch_result is not None:
                if retain_private_evidence:
                    retained = (launch_result, raw_result)
                    retained_bytes = (
                        launch_result.mutex_profile_size
                        + launch_result.block_profile_size
                        + (raw_result.raw_size if raw_result is not None else 0)
                    )
                    if (
                        retained not in runtime_lock_go_retained_results
                        and runtime_lock_go_retained_bytes() + retained_bytes
                        <= config.max_artifact_bytes
                    ):
                        runtime_lock_go_retained_results.append(retained)
                    else:
                        with suppress(OSError, PerfLensError):
                            cleanup_go_pprof_result(launch_result, raw_result)
                else:
                    with suppress(OSError, PerfLensError):
                        cleanup_go_pprof_result(launch_result, raw_result)
            if lease is not None and not run_finished:
                with suppress(PerfLensError):
                    terminal = runtime.fail_run(
                        session_id,
                        lease,
                        actual_active_seconds=actual_active_seconds,
                        actual_evidence_bytes=actual_evidence_bytes,
                        actual_exact_events=0,
                        reason=failure_reason,
                    )
                    _persist_runtime_lock_settlement(runtime, session_id, store, terminal)
            elif lease is None:
                with suppress(PerfLensError):
                    terminal = runtime.revoke(session_id)
                    store.save(terminal, terminal.session_artifact_id, "runtime-lock-session")
            raise

    async def collect_go_pprof_loopback_runtime_lock_evidence(
        session_id: str,
        duration_seconds: int,
        max_events: int,
        profile_kind: GoProfileKind,
    ) -> ArtifactReference:
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime = get_runtime_lock_session_runtime()
        lease = None
        capture: GoPprofLoopbackCapture | None = None
        raw_result: GoPprofRawResult | None = None
        actual_active_seconds = duration_seconds
        actual_evidence_bytes = 0
        run_finished = False
        retain_private_evidence = False
        failure_reason: Literal[
            "adapter_output_invalid",
            "identity_or_policy_changed",
            "internal_collection_error",
            "resource_limit_exceeded",
            "target_exited",
            "target_identity_changed",
        ] = "internal_collection_error"
        try:
            assert_runtime_lock_project_policy_current(
                runtime_lock_policy,
                allowed_roots=config.allowed_roots,
            )
            assert_managed_project_current(runtime_lock_project)
            session = runtime.snapshot(session_id)
            preview = store.load_runtime_lock_preview(session.preview_id)
            bridge = get_runtime_lock_go_bridge()
            binding = bridge.execution_binding
            if binding is None:
                raise _runtime_lock_native_error("Go pprof execution binding is unavailable")
            target = _validate_go_loopback_runtime_lock_session(
                session,
                preview,
                runtime_lock_policy,
                execution_binding=binding,
                duration_seconds=duration_seconds,
                max_events=max_events,
                profile_kind=profile_kind,
            )
            current_target = inspect_go_pprof_loopback_target(
                target.target_pid,
                target.loopback_port,
            )
            if current_target != target:
                failure_reason = "target_identity_changed"
                raise _runtime_lock_native_error(
                    "Go pprof loopback target differs from the authorized Preview"
                )
            adapter_policy = runtime_lock_policy.adapter_policy("go_pprof")
            operation_identity = _runtime_lock_go_operation_identity(
                session,
                target.target_identity_sha256,
                profile_kind,
                duration_seconds,
                max_events,
                binding.execution_identity_sha256,
                adapter_policy.mutex_profile_fraction,
                adapter_policy.block_profile_rate_ns,
            )
            lease = runtime.begin_run(
                session_id,
                adapter_id="go_pprof",
                measurement_semantics="cumulative",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.target_identity_sha256,
                workload_identity_sha256=target.target_identity_sha256,
                reserve_active_seconds=duration_seconds,
                reserve_evidence_bytes=min(
                    session.budget.max_evidence_bytes,
                    session.budget.max_artifact_bytes * 2,
                ),
                reserve_exact_events=0,
            )
            reserved = runtime.snapshot(session_id)
            store.save(reserved, reserved.session_artifact_id, "runtime-lock-session")
            launcher = get_runtime_lock_go_launcher()
            assert runtime_lock_go_private_root is not None
            capture = capture_go_pprof_loopback_profile(
                target,
                profile_kind,
                private_output_root=runtime_lock_go_private_root,
                maximum_bytes=session.budget.max_artifact_bytes,
                timeout_seconds=duration_seconds,
            )
            actual_active_seconds = capture.accounted_active_seconds
            actual_evidence_bytes = capture.profile_size
            if actual_active_seconds > duration_seconds:
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "Go pprof loopback fetch exceeded its authorized active time",
                    recoverable=True,
                )
            failure_reason = "adapter_output_invalid"
            retain_private_evidence = True
            profile_fd = open_go_pprof_loopback_capture(capture)
            try:
                raw_result = launcher.render_pinned_raw(profile_fd, profile_kind)
            finally:
                os.close(profile_fd)
            actual_evidence_bytes += raw_result.raw_size
            raw_fd = open_go_pprof_raw(raw_result)
            try:
                with os.fdopen(os.dup(raw_fd), "rb") as source:
                    receipt = convert_go_pprof_raw(
                        source,
                        execution_binding=binding,
                        profile_kind=profile_kind,
                        target_pid=target.target_pid,
                        target_uid=target.target_uid,
                        target_start_time_ticks=target.target_start_time_ticks,
                        mutex_profile_fraction=(
                            adapter_policy.mutex_profile_fraction
                            if profile_kind == "mutex"
                            else None
                        ),
                        block_profile_rate_ns=(
                            adapter_policy.block_profile_rate_ns
                            if profile_kind == "block"
                            else None
                        ),
                        limits=RuntimeLockResourceLimits(
                            max_source_bytes=session.budget.max_artifact_bytes,
                            max_input_records=max_events,
                            max_output_bytes=session.budget.max_artifact_bytes,
                        ),
                        created_at=capture.started_at,
                    )
            finally:
                os.close(raw_fd)
            replay_fd = open_go_pprof_raw(raw_result)
            try:
                with os.fdopen(os.dup(replay_fd), "rb") as replay:
                    if (
                        verify_go_pprof_replay(
                            replay,
                            expected=receipt,
                            execution_binding=binding,
                            target_pid=target.target_pid,
                            target_uid=target.target_uid,
                            target_start_time_ticks=target.target_start_time_ticks,
                            mutex_profile_fraction=(
                                adapter_policy.mutex_profile_fraction
                                if profile_kind == "mutex"
                                else None
                            ),
                            block_profile_rate_ns=(
                                adapter_policy.block_profile_rate_ns
                                if profile_kind == "block"
                                else None
                            ),
                        )
                        is None
                    ):
                        raise _runtime_lock_native_error(
                            "Go loopback private profile replay differs from the public Artifact"
                        )
            finally:
                os.close(replay_fd)
            if (
                inspect_go_pprof_loopback_target(
                    target.target_pid,
                    target.loopback_port,
                )
                != target
            ):
                failure_reason = "target_identity_changed"
                raise _runtime_lock_native_error(
                    "Go pprof loopback PID or socket identity changed after conversion"
                )
            evidence = receipt.evidence
            identity_warnings = _assert_go_loopback_runtime_lock_evidence_identity(
                evidence,
                capture=capture,
                raw_result=raw_result,
                execution_binding=binding,
                profile_kind=profile_kind,
                max_events=max_events,
            )
            analysis = build_runtime_lock_analysis(evidence)
            verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
            require_usable_runtime_lock_analysis(verification)
            public_evidence_bytes = len(serialize_json(evidence))
            warnings = tuple(
                dict.fromkeys(
                    (
                        *preview.warnings,
                        *evidence.quality.limitations,
                        *identity_warnings,
                        "A loopback pprof snapshot cannot independently prove workload "
                        "correctness.",
                    )
                )
            )
            quality, allowed, forbidden = derive_runtime_lock_run_boundaries(
                adapter_id="go_pprof",
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=warnings,
            )
            provisional_run = RuntimeLockRunArtifact(
                schema_version=preview.schema_version,
                perflens_version=__version__,
                run_id=derive_runtime_lock_run_id(
                    session_id,
                    "go_pprof",
                    evidence.content_sha256,
                    capture.started_at,
                ),
                created_at=capture.finished_at,
                started_at=capture.started_at,
                finished_at=capture.finished_at,
                authorization_kind="runtime_lock_session",
                session_id=session_id,
                session_artifact_id=lease.session_artifact_id,
                session_artifact_content_sha256=lease.session_artifact_content_sha256,
                session_revision=lease.session_revision,
                target_scope="host_bound_process",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.target_identity_sha256,
                adapter_id="go_pprof",
                adapter_execution_identity_sha256=binding.execution_identity_sha256,
                measurement_semantics="cumulative",
                workload_identity_sha256=target.target_identity_sha256,
                runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
                runtime_lock_evidence_content_sha256=evidence.content_sha256,
                runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
                runtime_lock_analysis_content_sha256=analysis.content_sha256,
                runtime_lock_verification_id=verification.runtime_lock_verification_id,
                runtime_lock_verification_content_sha256=verification.content_sha256,
                duration_seconds=actual_active_seconds,
                evidence_bytes=public_evidence_bytes,
                event_count=len(evidence.events),
                correctness_status="unavailable",
                quality_status=quality,
                warnings=warnings,
                allowed_conclusions=allowed,
                forbidden_conclusions=forbidden,
                content_sha256="0" * 64,
            )
            run = provisional_run.model_copy(
                update={
                    "content_sha256": contract_content_sha256(
                        provisional_run, exclude={"content_sha256"}
                    )
                }
            )
            cleanup_go_pprof_raw_result(raw_result)
            cleanup_go_pprof_loopback_capture(capture)
            retain_private_evidence = False
            actual_evidence_bytes = public_evidence_bytes
            for artifact, artifact_id, artifact_type in (
                (evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence"),
                (analysis, analysis.runtime_lock_analysis_id, "runtime-lock-analysis"),
                (
                    verification,
                    verification.runtime_lock_verification_id,
                    "runtime-lock-verification",
                ),
                (run, run.run_id, "runtime-lock-run"),
            ):
                store.save(artifact, artifact_id, artifact_type)
            settlement = runtime.finish_run(session_id, lease, run)
            run_finished = True
            _persist_runtime_lock_settlement(runtime, session_id, store, settlement)
            return ArtifactReference(
                artifact_id=run.run_id,
                artifact_type="runtime-lock-run",
                uri=store.uri(run.run_id, "runtime-lock-run"),
                summary={
                    "session_id": session_id,
                    "adapter_id": "go_pprof",
                    "backend": "same_uid_loopback",
                    "profile_kind": profile_kind,
                    "measurement_semantics": "cumulative",
                    "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
                    "runtime_lock_analysis_id": analysis.runtime_lock_analysis_id,
                    "runtime_lock_verification_id": verification.runtime_lock_verification_id,
                    "private_source_replay_status": "passed",
                    "quality_status": run.quality_status,
                    "event_count": run.event_count,
                    "target_pid": target.target_pid,
                    "session_state": settlement.session.state,
                },
            )
        except Exception:
            if capture is not None:
                if retain_private_evidence:
                    retained = (capture, raw_result)
                    retained_bytes = capture.profile_size + (
                        raw_result.raw_size if raw_result is not None else 0
                    )
                    if (
                        retained not in runtime_lock_go_retained_loopback
                        and runtime_lock_go_retained_bytes() + retained_bytes
                        <= config.max_artifact_bytes
                    ):
                        runtime_lock_go_retained_loopback.append(retained)
                    else:
                        if raw_result is not None:
                            with suppress(OSError, PerfLensError):
                                cleanup_go_pprof_raw_result(raw_result)
                        with suppress(OSError, PerfLensError):
                            cleanup_go_pprof_loopback_capture(capture)
                else:
                    if raw_result is not None:
                        with suppress(OSError, PerfLensError):
                            cleanup_go_pprof_raw_result(raw_result)
                    with suppress(OSError, PerfLensError):
                        cleanup_go_pprof_loopback_capture(capture)
            if lease is not None and not run_finished:
                with suppress(PerfLensError):
                    terminal = runtime.fail_run(
                        session_id,
                        lease,
                        actual_active_seconds=actual_active_seconds,
                        actual_evidence_bytes=actual_evidence_bytes,
                        actual_exact_events=0,
                        reason=failure_reason,
                    )
                    _persist_runtime_lock_settlement(runtime, session_id, store, terminal)
            elif lease is None:
                with suppress(PerfLensError):
                    terminal = runtime.revoke(session_id)
                    store.save(terminal, terminal.session_artifact_id, "runtime-lock-session")
            raise

    @server.tool(
        name="inspect_collection_capabilities",
        description=(
            "Inspect perf, kernel policy, capabilities, and collection-mode availability without "
            "sampling or attaching to a process."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def inspect_capabilities() -> CollectionCapabilityArtifact:
        return inspect_collection_capabilities(config.perf_path)

    @server.tool(
        name="inspect_runtime_lock_capability",
        description=(
            "Inspect project policy and implemented Runtime Lock adapters without importing, "
            "instrumenting, attaching to, or executing a target."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def inspect_runtime_lock_capability_tool() -> RuntimeLockCapabilityArtifact:
        return inspect_runtime_lock_session_capability().capability

    @server.tool(
        name="preview_runtime_lock_session",
        description=(
            "Create the exact content-bound Runtime Lock Session summary. This does not import, "
            "instrument, attach, launch, or collect; the user must confirm this exact Preview."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "READ_ONLY_CONTEXT_SNAPSHOT"},
        structured_output=True,
    )
    async def preview_runtime_lock_session(
        target_scope: RuntimeLockTargetScope,
        allowed_adapters: tuple[RuntimeLockAdapterId, ...],
        allowed_semantics: tuple[Literal["exact", "thresholded", "sampled", "cumulative"], ...],
        executable: str | None = None,
        arguments: tuple[str, ...] = (),
        target_pid: int | None = None,
        loopback_port: int | None = None,
    ) -> RuntimeLockSessionPreviewArtifact:
        _require_runtime_locks(config)
        if target_scope in {"managed_temporary_container", "docker_optimization"}:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Docker Runtime Lock scope must be content-bound by the parent Docker "
                "Preview and cannot be authorized through the standalone Runtime Lock entry "
                "point",
                recoverable=True,
            )
        assert runtime_lock_policy is not None
        _validate_runtime_lock_preview_policy(
            runtime_lock_policy,
            target_scope=target_scope,
            allowed_adapters=allowed_adapters,
            allowed_semantics=allowed_semantics,
        )
        inspection = inspect_runtime_lock_session_capability()
        runtime = get_runtime_lock_session_runtime()
        workload: RuntimeLockWorkloadBinding | None = None
        process_target: RuntimeLockProcessTargetBinding | None = None
        execution_bindings: tuple[RuntimeLockAdapterExecutionBinding, ...] = ()
        preview_warnings: tuple[str, ...] = ()
        if target_scope == "host_bound_process":
            if (
                allowed_adapters != ("go_pprof",)
                or allowed_semantics != ("cumulative",)
                or executable is not None
                or arguments
                or target_pid is None
                or loopback_port is None
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "Host-bound Go pprof Preview requires one PID, literal loopback port, and "
                    "cumulative semantics",
                    recoverable=True,
                )
            _require_runtime_lock_adapter_capability(
                inspection,
                adapter_id="go_pprof",
                allowed_semantics=allowed_semantics,
            )
            adapter_policy = runtime_lock_policy.adapter_policy("go_pprof")
            if not adapter_policy.loopback_backend_enabled:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "The same-UID Go pprof loopback backend is disabled by project policy",
                    recoverable=True,
                )
            bridge = get_runtime_lock_go_bridge()
            if bridge.execution_binding is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_capability",
                    "The Go pprof converter binding is unavailable",
                    recoverable=True,
                )
            process_target = inspect_go_pprof_loopback_target(target_pid, loopback_port)
            execution_bindings = (bridge.execution_binding,)
            preview_warnings = bridge.capability.limitations
        elif target_scope == "host_launched_workload":
            if target_pid is not None or loopback_port is not None:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "A launched workload Preview cannot also attach to a process",
                    recoverable=True,
                )
            if (
                len(allowed_adapters) != 1
                or allowed_adapters[0]
                not in {"native_pthread", "java_jfr", "cpython_threading", "go_pprof"}
                or executable is None
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "Host Runtime Lock Preview requires one exact executable and Adapter",
                    recoverable=True,
                )
            adapter_id = allowed_adapters[0]
            _require_runtime_lock_adapter_capability(
                inspection,
                adapter_id=adapter_id,
                allowed_semantics=allowed_semantics,
            )
            assert runtime_lock_project is not None
            executable_path = _runtime_lock_project_executable(
                runtime_lock_project.path,
                executable,
            )
            if adapter_id == "java_jfr":
                if allowed_semantics != ("thresholded",):
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "runtime_lock_authorization",
                        "Java JFR host collection requires thresholded semantics",
                        recoverable=True,
                    )
                launcher = get_runtime_lock_java_launcher()
                target = launcher.inspect_target(executable_path)
                workload_kind = "java_archive"
                bridge = get_runtime_lock_java_bridge()
                assert bridge.execution_binding is not None
                execution_bindings = (bridge.execution_binding,)
                preview_warnings = bridge.capability.limitations
                program_sha256 = target.binary_sha256
            elif adapter_id == "cpython_threading":
                if len(allowed_semantics) != 1 or allowed_semantics[0] not in {
                    "exact",
                    "thresholded",
                }:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "runtime_lock_authorization",
                        "CPython host collection requires one exact or thresholded semantics",
                        recoverable=True,
                    )
                launcher = get_runtime_lock_cpython_launcher()
                target = launcher.inspect_target(executable_path)
                workload_kind = "python_script"
                bridge = get_runtime_lock_cpython_bridge()
                binding = bridge.binding_for(
                    cast(Literal["exact", "thresholded"], allowed_semantics[0])
                )
                if binding is None:
                    raise PerfLensError(
                        ErrorCode.EXTERNAL_TOOL_FAILED,
                        "runtime_lock_capability",
                        "The selected CPython execution binding is unavailable",
                        recoverable=True,
                    )
                execution_bindings = (binding,)
                preview_warnings = bridge.capability.limitations
                program_sha256 = target.script_sha256
            elif adapter_id == "go_pprof":
                if allowed_semantics != ("cumulative",):
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "runtime_lock_authorization",
                        "Go pprof host collection requires cumulative semantics",
                        recoverable=True,
                    )
                launcher = get_runtime_lock_go_launcher()
                target = launcher.inspect_target(executable_path)
                workload_kind = "go_elf"
                bridge = get_runtime_lock_go_bridge()
                if bridge.execution_binding is None:
                    raise PerfLensError(
                        ErrorCode.EXTERNAL_TOOL_FAILED,
                        "runtime_lock_capability",
                        "The Go pprof execution binding is unavailable",
                        recoverable=True,
                    )
                execution_bindings = (bridge.execution_binding,)
                preview_warnings = bridge.capability.limitations
                program_sha256 = target.binary_sha256
            else:
                launcher = get_runtime_lock_native_launcher()
                target = launcher.inspect_target(executable_path)
                target_capability = launcher.capability(executable_path)
                if target_capability.availability == "unavailable" or any(
                    semantics not in target_capability.supported_semantics
                    for semantics in allowed_semantics
                ):
                    raise PerfLensError(
                        ErrorCode.EXTERNAL_TOOL_FAILED,
                        "runtime_lock_capability",
                        "The reviewed Native pthread workload does not support this "
                        "semantics scope",
                        recoverable=True,
                        details={"limitations": target_capability.limitations},
                    )
                workload_kind = "native_elf"
                program_sha256 = target.binary_sha256
                preview_warnings = tuple(
                    dict.fromkeys(
                        (*target_capability.limitations, NATIVE_PTHREAD_PROVENANCE_LIMITATION)
                    )
                )
            workload_identity = derive_runtime_lock_workload_identity(
                adapter_id,
                workload_kind,
                target.project_relative_path,
                program_sha256,
                target.size,
                ".",
                arguments,
            )
            workload = RuntimeLockWorkloadBinding(
                adapter_id=adapter_id,
                workload_kind=workload_kind,
                program=target.project_relative_path,
                program_sha256=program_sha256,
                program_size=target.size,
                working_directory=".",
                arguments=arguments,
                workload_identity_sha256=workload_identity,
            )
        elif target_scope == "controlled_import":
            if (
                executable is not None
                or arguments
                or target_pid is not None
                or loopback_port is not None
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "Controlled import cannot bind an executable workload",
                    recoverable=True,
                )
            if "go_pprof" in allowed_adapters:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "Raw Go pprof import cannot prove a target PID; use the startup-file or "
                    "same-UID PID/socket-bound loopback backend",
                    recoverable=True,
                )
        elif (
            executable is not None
            or arguments
            or target_pid is not None
            or loopback_port is not None
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Only a host-launched Runtime Lock Preview may bind an executable workload",
                recoverable=True,
            )
        preview = runtime.preview(
            inspection.capability,
            target_scope=target_scope,
            allowed_adapters=allowed_adapters,
            allowed_semantics=allowed_semantics,
            import_roots=(
                runtime_lock_policy.import_roots if target_scope == "controlled_import" else ()
            ),
            workload=workload,
            process_target=process_target,
            adapter_execution_bindings=execution_bindings,
            budget=runtime_lock_policy.budget,
            planned_actions=_runtime_lock_planned_actions(target_scope),
            warnings=(
                preview_warnings
                if target_scope in {"host_launched_workload", "host_bound_process"}
                or preview_warnings
                else (
                    ("This Runtime Lock launch entry point is not implemented yet.",)
                    if target_scope != "controlled_import"
                    else ()
                )
            ),
            expires_in_seconds=runtime_lock_policy.preview_ttl_seconds,
        )
        for adapter in inspection.adapter_capabilities:
            store.save(
                adapter,
                adapter.capability_id,
                "runtime-adapter-capability",
            )
        store.save(
            inspection.capability,
            inspection.capability.capability_id,
            "runtime-lock-capability",
        )
        store.save(preview, preview.preview_id, "runtime-lock-preview")
        return preview

    @server.tool(
        name="authorize_runtime_lock_session",
        description=(
            "Authorize one exact Runtime Lock Preview. The process-local token is never stored; "
            "this call itself does not import, instrument, attach, launch, or collect."
        ),
        annotations=AUTHORIZES_DOCKER,
        meta={"perflens/permission": "RUNTIME_LOCK_AUTHORIZATION"},
        structured_output=True,
    )
    async def authorize_runtime_lock_session(
        preview_id: str,
        preview_content_sha256: str,
        authorization_summary_sha256: str,
        authorization: Literal["I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"],
    ) -> RuntimeLockSessionArtifact:
        _require_runtime_locks(config)
        assert runtime_lock_policy is not None
        assert_runtime_lock_project_policy_current(
            runtime_lock_policy,
            allowed_roots=config.allowed_roots,
        )
        runtime = get_runtime_lock_session_runtime()
        session = runtime.authorize(
            preview_id=preview_id,
            preview_content_sha256=preview_content_sha256,
            authorization_summary_sha256=authorization_summary_sha256,
            explicit_authorization=authorization,
        )
        store.save(
            session,
            session.session_artifact_id,
            "runtime-lock-session",
        )
        return session

    async def collect_java_jfr_runtime_lock_evidence(
        session_id: str,
        duration_seconds: int,
        max_events: int,
    ) -> ArtifactReference:
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime = get_runtime_lock_session_runtime()
        lease = None
        launch_result: JavaJfrLaunchResult | None = None
        actual_active_seconds = duration_seconds
        actual_evidence_bytes = 0
        run_finished = False
        failure_reason: Literal[
            "adapter_output_invalid",
            "correctness_failed",
            "identity_or_policy_changed",
            "internal_collection_error",
            "resource_limit_exceeded",
            "target_exited",
            "target_identity_changed",
        ] = "internal_collection_error"
        try:
            assert_runtime_lock_project_policy_current(
                runtime_lock_policy,
                allowed_roots=config.allowed_roots,
            )
            assert_managed_project_current(runtime_lock_project)
            session = runtime.snapshot(session_id)
            preview = store.load_runtime_lock_preview(session.preview_id)
            bridge = get_runtime_lock_java_bridge()
            if bridge.execution_binding is None:
                raise _runtime_lock_native_error("Java JFR execution binding is unavailable")
            workload = _validate_java_runtime_lock_session(
                session,
                preview,
                runtime_lock_policy,
                execution_binding=bridge.execution_binding,
                duration_seconds=duration_seconds,
                max_events=max_events,
            )
            launcher = get_runtime_lock_java_launcher()
            executable_path = _runtime_lock_project_executable(
                runtime_lock_project.path,
                workload.program,
            )
            target = launcher.inspect_target(executable_path)
            if (
                target.project_relative_path != workload.program
                or target.binary_sha256 != workload.program_sha256
                or target.size != workload.program_size
            ):
                failure_reason = "target_identity_changed"
                raise _runtime_lock_native_error(
                    "Java JFR executable JAR differs from the authorized Preview"
                )
            operation_identity = _runtime_lock_java_operation_identity(
                session,
                target.identity_sha256,
                duration_seconds,
                max_events,
                bridge.execution_binding.execution_identity_sha256,
            )
            lease = runtime.begin_run(
                session_id,
                adapter_id="java_jfr",
                measurement_semantics="thresholded",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                workload_identity_sha256=workload.workload_identity_sha256,
                reserve_active_seconds=duration_seconds,
                # A failed JFR conversion may retain one bounded recording and
                # one bounded JSON transcript.  Reserve both honestly; each
                # individual file remains capped by max_artifact_bytes.
                reserve_evidence_bytes=min(
                    session.budget.max_evidence_bytes,
                    session.budget.max_artifact_bytes * 2,
                ),
                reserve_exact_events=0,
            )
            reserved_session = runtime.snapshot(session_id)
            store.save(
                reserved_session,
                reserved_session.session_artifact_id,
                "runtime-lock-session",
            )
            try:
                launch_result = launcher.launch(
                    executable_path,
                    JavaJfrLaunchRequest(
                        arguments=workload.arguments,
                        duration_seconds=duration_seconds,
                    ),
                    expected_target_identity_sha256=target.identity_sha256,
                    expected_arguments_sha256=java_jfr_arguments_sha256(workload.arguments),
                )
            except JavaJfrLaunchFailure as exc:
                if exc.accounted_active_seconds is not None:
                    actual_active_seconds = exc.accounted_active_seconds
                retained = exc.retained_evidence
                if retained is not None:
                    retained_size = retained.recording_size + retained.json_size
                    actual_evidence_bytes = retained_size
                    retained_total = sum(
                        item.recording_size + item.json_size
                        for item in runtime_lock_java_retained_results
                    )
                    if retained_total + retained_size > session.budget.max_evidence_bytes:
                        try:
                            cleanup_java_jfr_launch_result(retained)
                        except (OSError, PerfLensError):
                            runtime_lock_java_retained_results.append(retained)
                        failure_reason = "resource_limit_exceeded"
                        raise PerfLensError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "runtime_lock_collection",
                            "Retained Java JFR private evidence exceeds the Session bound",
                            recoverable=True,
                        ) from exc
                    runtime_lock_java_retained_results.append(retained)
                failure_reason = "adapter_output_invalid"
                raise
            retained_bytes = sum(
                item.recording_size + item.json_size for item in runtime_lock_java_retained_results
            )
            if (
                retained_bytes + launch_result.recording_size + launch_result.json_size
                > session.budget.max_evidence_bytes
            ):
                cleanup_java_jfr_launch_result(launch_result)
                launch_result = None
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "Retained Java JFR private evidence exceeds the Session bound",
                    recoverable=True,
                )
            runtime_lock_java_retained_results.append(launch_result)
            actual_active_seconds = launch_result.accounted_active_seconds
            actual_evidence_bytes = launch_result.json_size
            if launch_result.termination_reason == "duration_limit":
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "Java JFR workload exceeded its authorized duration",
                    recoverable=True,
                )
            if launch_result.termination_reason != "exited":
                failure_reason = "target_exited"
                raise _runtime_lock_native_error("Java JFR workload identity became unavailable")
            if launch_result.exit_code != 0:
                failure_reason = "correctness_failed"
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_collection",
                    "Java JFR workload exited unsuccessfully",
                    recoverable=True,
                    details={"exit_code": launch_result.exit_code},
                )
            failure_reason = "adapter_output_invalid"
            json_fd = open_java_jfr_private_file(launch_result, "json")
            try:
                with os.fdopen(os.dup(json_fd), "rb") as private_source:
                    receipt = convert_java_jfr_json(
                        private_source,
                        execution_binding=bridge.execution_binding,
                        target_pid=launch_result.target_pid,
                        target_uid=launch_result.target_uid,
                        target_start_time_ticks=launch_result.target_start_ticks,
                        created_at=launch_result.started_at,
                    )
                if (
                    receipt.raw_source_sha256 != launch_result.json_sha256
                    or receipt.raw_source_bytes != launch_result.json_size
                ):
                    raise _runtime_lock_native_error(
                        "Java JFR conversion source differs from the launched private JSON"
                    )
                evidence = receipt.evidence
                identity_warnings = _assert_java_runtime_lock_evidence_identity(
                    evidence,
                    launch_result=launch_result,
                    expected_target_identity_sha256=target.identity_sha256,
                    execution_binding=bridge.execution_binding,
                    max_events=max_events,
                )
            finally:
                os.close(json_fd)
            # Reopen and revalidate the private file for replay.  ``dup`` shares
            # the original open-file offset, so reusing the first descriptor
            # would deterministically start the replay at EOF.
            replay_fd = open_java_jfr_private_file(launch_result, "json")
            try:
                with os.fdopen(os.dup(replay_fd), "rb") as private_source:
                    replay_receipt = verify_java_jfr_replay(
                        private_source,
                        expected=receipt,
                        execution_binding=bridge.execution_binding,
                        target_pid=launch_result.target_pid,
                        target_uid=launch_result.target_uid,
                        target_start_time_ticks=launch_result.target_start_ticks,
                        created_at=launch_result.started_at,
                    )
                    if replay_receipt is None:
                        raise _runtime_lock_native_error(
                            "Java JFR private deterministic replay differs from its complete "
                            "conversion receipt"
                        )
            finally:
                os.close(replay_fd)
            analysis = build_runtime_lock_analysis(evidence)
            verification = verify_runtime_lock_analysis_artifact(
                analysis,
                evidence,
                source_replay_receipt=build_runtime_lock_source_replay_receipt(
                    evidence,
                    normalized_source_sha256=replay_receipt.normalized_source_sha256,
                    normalized_source_bytes=replay_receipt.normalized_source_bytes,
                ),
            )
            require_usable_runtime_lock_analysis(verification)
            actual_evidence_bytes = len(serialize_json(evidence))
            started_wall = datetime.fromisoformat(launch_result.started_at)
            finished_wall = datetime.fromisoformat(launch_result.finished_at)
            duration = launch_result.accounted_active_seconds
            if duration != math.ceil((finished_wall - started_wall).total_seconds()):
                failure_reason = "adapter_output_invalid"
                raise PerfLensError(
                    ErrorCode.PROFILE_PARSE_FAILED,
                    "runtime_lock_collection",
                    "Java JFR supervisor timing receipt is inconsistent",
                    recoverable=True,
                )
            if duration > duration_seconds:
                failure_reason = "resource_limit_exceeded"
                raise _runtime_lock_native_error(
                    "Java JFR evidence exceeded its active-time reservation"
                )
            run_warnings = tuple(
                dict.fromkeys(
                    (
                        *preview.warnings,
                        *launch_result.limitations,
                        *evidence.quality.limitations,
                        *identity_warnings,
                    )
                )
            )
            (
                run_quality_status,
                run_allowed_conclusions,
                run_forbidden_conclusions,
            ) = derive_runtime_lock_run_boundaries(
                adapter_id="java_jfr",
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=run_warnings,
            )
            provisional_run = RuntimeLockRunArtifact(
                schema_version=preview.schema_version,
                perflens_version=__version__,
                run_id=derive_runtime_lock_run_id(
                    session_id,
                    "java_jfr",
                    evidence.content_sha256,
                    launch_result.started_at,
                ),
                created_at=launch_result.finished_at,
                started_at=launch_result.started_at,
                finished_at=launch_result.finished_at,
                authorization_kind="runtime_lock_session",
                session_id=session_id,
                session_artifact_id=lease.session_artifact_id,
                session_artifact_content_sha256=lease.session_artifact_content_sha256,
                session_revision=lease.session_revision,
                target_scope="host_launched_workload",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                adapter_id="java_jfr",
                adapter_execution_identity_sha256=(
                    bridge.execution_binding.execution_identity_sha256
                ),
                measurement_semantics="thresholded",
                workload_identity_sha256=workload.workload_identity_sha256,
                runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
                runtime_lock_evidence_content_sha256=evidence.content_sha256,
                runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
                runtime_lock_analysis_content_sha256=analysis.content_sha256,
                runtime_lock_verification_id=verification.runtime_lock_verification_id,
                runtime_lock_verification_content_sha256=verification.content_sha256,
                duration_seconds=duration,
                evidence_bytes=actual_evidence_bytes,
                event_count=len(evidence.events),
                correctness_status="passed",
                quality_status=run_quality_status,
                warnings=run_warnings,
                allowed_conclusions=run_allowed_conclusions,
                forbidden_conclusions=run_forbidden_conclusions,
                content_sha256="0" * 64,
            )
            run = provisional_run.model_copy(
                update={
                    "content_sha256": contract_content_sha256(
                        provisional_run,
                        exclude={"content_sha256"},
                    )
                }
            )
            cleanup_java_jfr_launch_result(launch_result)
            runtime_lock_java_retained_results.remove(launch_result)
            for artifact, artifact_id, artifact_type in (
                (evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence"),
                (analysis, analysis.runtime_lock_analysis_id, "runtime-lock-analysis"),
                (
                    verification,
                    verification.runtime_lock_verification_id,
                    "runtime-lock-verification",
                ),
                (run, run.run_id, "runtime-lock-run"),
            ):
                store.save(artifact, artifact_id, artifact_type)
            settlement = runtime.finish_run(session_id, lease, run)
            run_finished = True
            _persist_runtime_lock_settlement(
                runtime,
                session_id,
                store,
                settlement,
            )
            return ArtifactReference(
                artifact_id=run.run_id,
                artifact_type="runtime-lock-run",
                uri=store.uri(run.run_id, "runtime-lock-run"),
                summary={
                    "session_id": session_id,
                    "adapter_id": "java_jfr",
                    "runtime": analysis.runtime,
                    "measurement_semantics": "thresholded",
                    "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
                    "runtime_lock_analysis_id": analysis.runtime_lock_analysis_id,
                    "runtime_lock_verification_id": verification.runtime_lock_verification_id,
                    "private_source_replay_status": "passed",
                    "quality_status": run.quality_status,
                    "event_count": run.event_count,
                    "evidence_bytes": run.evidence_bytes,
                    "target_pid": launch_result.target_pid,
                    "target_uid": launch_result.target_uid,
                    "exit_code": launch_result.exit_code,
                    "session_state": settlement.session.state,
                },
            )
        except Exception:
            if (
                launch_result is not None
                and launch_result in runtime_lock_java_retained_results
                and failure_reason == "adapter_output_invalid"
            ):
                # Conversion, replay, or identity-safe cleanup failures retain
                # both private files.  Account the bytes that actually remain,
                # not merely the JSON transcript or projected public Evidence.
                actual_evidence_bytes = max(
                    actual_evidence_bytes,
                    launch_result.recording_size + launch_result.json_size,
                )
            if (
                launch_result is not None
                and failure_reason != "adapter_output_invalid"
                and launch_result in runtime_lock_java_retained_results
            ):
                with suppress(PerfLensError, OSError):
                    cleanup_java_jfr_launch_result(launch_result)
                    runtime_lock_java_retained_results.remove(launch_result)
            if lease is not None and not run_finished:
                with suppress(PerfLensError):
                    terminal = runtime.fail_run(
                        session_id,
                        lease,
                        actual_active_seconds=actual_active_seconds,
                        actual_evidence_bytes=actual_evidence_bytes,
                        actual_exact_events=0,
                        reason=failure_reason,
                    )
                    _persist_runtime_lock_settlement(
                        runtime,
                        session_id,
                        store,
                        terminal,
                    )
            elif lease is None:
                with suppress(PerfLensError):
                    terminal = runtime.revoke(session_id)
                    store.save(terminal, terminal.session_artifact_id, "runtime-lock-session")
            raise

    @server.tool(
        name="collect_runtime_lock_evidence",
        description=(
            "Execute only the exact Native pthread, startup-time Java JFR, startup-time "
            "CPython threading, or startup-time Go pprof host workload "
            "bound into an authorized Runtime Lock Preview. The fixed Adapter, environment, "
            "private output, duration, event count, and one single-use lease remain "
            "independently bounded."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "RUNTIME_LOCK_WORKLOAD_EXECUTION"},
        structured_output=True,
    )
    async def collect_runtime_lock_evidence(
        session_id: str,
        measurement_semantics: Literal["exact", "thresholded", "cumulative"],
        duration_seconds: int,
        max_events: int = 20_000,
        profile_kind: GoProfileKind = "mutex",
    ) -> ArtifactReference:
        _require_runtime_locks(config)
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime = get_runtime_lock_session_runtime()
        candidate_session = runtime.snapshot(session_id)
        candidate_preview = store.load_runtime_lock_preview(candidate_session.preview_id)
        if candidate_preview.target_scope == "host_bound_process":
            if measurement_semantics != "cumulative":
                raise _runtime_lock_native_error(
                    "Go pprof loopback collection requires cumulative semantics"
                )
            return await collect_go_pprof_loopback_runtime_lock_evidence(
                session_id,
                duration_seconds,
                max_events,
                profile_kind,
            )
        if (
            candidate_preview.workload is not None
            and candidate_preview.workload.adapter_id == "java_jfr"
        ):
            if measurement_semantics != "thresholded":
                raise _runtime_lock_native_error(
                    "Java JFR collection requires thresholded semantics"
                )
            return await collect_java_jfr_runtime_lock_evidence(
                session_id,
                duration_seconds,
                max_events,
            )
        if (
            candidate_preview.workload is not None
            and candidate_preview.workload.adapter_id == "cpython_threading"
        ):
            if measurement_semantics == "cumulative":
                raise _runtime_lock_native_error(
                    "CPython collection requires exact or thresholded semantics"
                )
            return await collect_cpython_runtime_lock_evidence(
                session_id,
                measurement_semantics,
                duration_seconds,
                max_events,
            )
        if (
            candidate_preview.workload is not None
            and candidate_preview.workload.adapter_id == "go_pprof"
        ):
            if measurement_semantics != "cumulative":
                raise _runtime_lock_native_error(
                    "Go pprof collection requires cumulative semantics"
                )
            return await collect_go_pprof_runtime_lock_evidence(
                session_id,
                duration_seconds,
                max_events,
                profile_kind,
            )
        if measurement_semantics == "cumulative":
            raise _runtime_lock_native_error(
                "Cumulative collection is supported only by the Go pprof Adapter"
            )
        if profile_kind != "mutex":
            raise _runtime_lock_native_error("profile_kind is valid only for the Go pprof Adapter")
        lease = None
        launch_result: NativeLaunchResult | None = None
        pinned: _PinnedRuntimeLockImport | None = None
        actual_evidence_bytes = 0
        actual_exact_events = 0
        run_finished = False
        cleanup_attempted = False
        private_stream_removed = False
        private_stream_retained = False
        retain_private_stream_on_failure = False
        private_retention_quota_bytes = 0
        operation_failed = False
        failure_reason: Literal[
            "adapter_output_invalid",
            "correctness_failed",
            "identity_or_policy_changed",
            "internal_collection_error",
            "resource_limit_exceeded",
            "target_exited",
            "target_identity_changed",
        ] = "internal_collection_error"
        try:
            assert_runtime_lock_project_policy_current(
                runtime_lock_policy,
                allowed_roots=config.allowed_roots,
            )
            assert_managed_project_current(runtime_lock_project)
            session = runtime.snapshot(session_id)
            private_retention_quota_bytes = session.budget.max_evidence_bytes
            preview = store.load_runtime_lock_preview(session.preview_id)
            workload = _validate_native_runtime_lock_session(
                session,
                preview,
                runtime_lock_policy,
                measurement_semantics=measurement_semantics,
                duration_seconds=duration_seconds,
                max_events=max_events,
            )
            launcher = get_runtime_lock_native_launcher()
            assert runtime_lock_native_private_root is not None
            executable_path = _runtime_lock_project_executable(
                runtime_lock_project.path,
                workload.program,
            )
            target = launcher.inspect_target(executable_path)
            if (
                target.project_relative_path != workload.program
                or target.binary_sha256 != workload.program_sha256
                or target.size != workload.program_size
            ):
                failure_reason = "target_identity_changed"
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_collection",
                    "Native pthread workload differs from the authorized Preview",
                    recoverable=True,
                )
            threshold_ns = (
                None
                if measurement_semantics == "exact"
                else runtime_lock_policy.adapter_policy("native_pthread").duration_threshold_ns
            )
            request = NativeLaunchRequest(
                arguments=workload.arguments,
                semantics=measurement_semantics,
                threshold_ns=threshold_ns,
                duration_seconds=duration_seconds,
                max_events=max_events,
            )
            operation_identity = _runtime_lock_native_operation_identity(
                session,
                target.identity_sha256,
                measurement_semantics,
                duration_seconds,
                max_events,
            )
            lease = runtime.begin_run(
                session_id,
                adapter_id="native_pthread",
                measurement_semantics=measurement_semantics,
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                workload_identity_sha256=workload.workload_identity_sha256,
                reserve_active_seconds=duration_seconds,
                reserve_evidence_bytes=session.budget.max_artifact_bytes,
                reserve_exact_events=(max_events if measurement_semantics == "exact" else 0),
            )
            reserved_session = runtime.snapshot(session_id)
            store.save(
                reserved_session,
                reserved_session.session_artifact_id,
                "runtime-lock-session",
            )
            launch_result = launcher.launch(
                executable_path,
                request,
                expected_target_identity_sha256=target.identity_sha256,
            )
            actual_evidence_bytes = launch_result.stream_size
            actual_exact_events = (
                launch_result.declared_event_count or 0 if measurement_semantics == "exact" else 0
            )
            failure_reason = "adapter_output_invalid"
            if launch_result.termination_reason == "duration_limit":
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "Native pthread workload exceeded its authorized duration",
                    recoverable=True,
                )
            if launch_result.termination_reason != "exited" or launch_result.exit_code is None:
                failure_reason = "target_exited"
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_collection",
                    "Native pthread workload identity became unavailable",
                    recoverable=True,
                )
            if launch_result.exit_code != 0:
                failure_reason = "correctness_failed"
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_lock_collection",
                    "Native pthread workload exited unsuccessfully",
                    recoverable=True,
                    details={"exit_code": launch_result.exit_code},
                )
            pinned = _pin_native_runtime_lock_stream(
                launch_result,
                private_root=runtime_lock_native_private_root,
                max_source_bytes=session.budget.max_artifact_bytes,
            )
            # Once a bounded stream has passed the private-file identity gate, retain it
            # privately if conversion or deterministic verification fails. It is never
            # persisted as a public Artifact or exposed by an MCP resource.
            retain_private_stream_on_failure = True
            limits = RuntimeLockResourceLimits(
                max_source_bytes=session.budget.max_artifact_bytes,
                max_input_records=max_events,
                max_output_bytes=session.budget.max_artifact_bytes,
            )
            with os.fdopen(os.dup(pinned.descriptor), "rb") as private_source:
                os.lseek(private_source.fileno(), 0, os.SEEK_SET)
                receipt = convert_native_pthread_probe(
                    private_source,
                    limits=limits,
                    created_at=launch_result.started_at,
                )
            _assert_runtime_lock_import_unchanged(pinned)
            evidence = receipt.evidence
            try:
                identity_warnings = _assert_native_runtime_lock_evidence_identity(
                    evidence,
                    receipt_source_sha256=receipt.raw_source_sha256,
                    receipt_source_bytes=receipt.raw_source_bytes,
                    launch_result=launch_result,
                    expected_target_identity_sha256=target.identity_sha256,
                    measurement_semantics=measurement_semantics,
                    duration_threshold_ns=threshold_ns,
                    max_events=max_events,
                )
            except PerfLensError:
                failure_reason = "target_identity_changed"
                raise
            analysis = build_runtime_lock_analysis(evidence)
            with os.fdopen(os.dup(pinned.descriptor), "rb") as private_source:
                os.lseek(private_source.fileno(), 0, os.SEEK_SET)
                private_verification = verify_runtime_lock_analysis_artifact(
                    analysis,
                    evidence,
                    private_source_stream=private_source,
                    normalized_source_sha256=receipt.normalized_source_sha256,
                    normalized_source_bytes=receipt.normalized_source_bytes,
                )
            _assert_runtime_lock_import_unchanged(pinned)
            require_usable_runtime_lock_analysis(private_verification)
            verification = private_verification
            retain_private_stream_on_failure = False
            actual_evidence_bytes = len(serialize_json(evidence))
            actual_exact_events = len(evidence.events) if measurement_semantics == "exact" else 0
            started_wall = datetime.fromisoformat(launch_result.started_at)
            finished_wall = datetime.fromisoformat(launch_result.finished_at)
            duration = launch_result.accounted_active_seconds
            if duration != math.ceil((finished_wall - started_wall).total_seconds()):
                failure_reason = "adapter_output_invalid"
                raise PerfLensError(
                    ErrorCode.PROFILE_PARSE_FAILED,
                    "runtime_lock_collection",
                    "Native pthread supervisor timing receipt is inconsistent",
                    recoverable=True,
                )
            if duration > duration_seconds:
                failure_reason = "resource_limit_exceeded"
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_collection",
                    "Native pthread evidence exceeded its authorized active-time reservation",
                    recoverable=True,
                )
            run_warnings = tuple(
                dict.fromkeys(
                    (
                        *preview.warnings,
                        *launch_result.limitations,
                        *evidence.quality.limitations,
                        *identity_warnings,
                    )
                )
            )
            (
                run_quality_status,
                run_allowed_conclusions,
                run_forbidden_conclusions,
            ) = derive_runtime_lock_run_boundaries(
                adapter_id="native_pthread",
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=run_warnings,
            )
            provisional_run = RuntimeLockRunArtifact(
                schema_version=preview.schema_version,
                perflens_version=__version__,
                run_id=derive_runtime_lock_run_id(
                    session_id,
                    "native_pthread",
                    evidence.content_sha256,
                    launch_result.started_at,
                ),
                created_at=launch_result.finished_at,
                started_at=launch_result.started_at,
                finished_at=launch_result.finished_at,
                authorization_kind="runtime_lock_session",
                session_id=session_id,
                session_artifact_id=lease.session_artifact_id,
                session_artifact_content_sha256=lease.session_artifact_content_sha256,
                session_revision=lease.session_revision,
                target_scope="host_launched_workload",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target.identity_sha256,
                adapter_id="native_pthread",
                measurement_semantics=measurement_semantics,
                workload_identity_sha256=workload.workload_identity_sha256,
                runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
                runtime_lock_evidence_content_sha256=evidence.content_sha256,
                runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
                runtime_lock_analysis_content_sha256=analysis.content_sha256,
                runtime_lock_verification_id=verification.runtime_lock_verification_id,
                runtime_lock_verification_content_sha256=verification.content_sha256,
                duration_seconds=duration,
                evidence_bytes=actual_evidence_bytes,
                event_count=len(evidence.events),
                correctness_status="passed",
                quality_status=run_quality_status,
                warnings=run_warnings,
                allowed_conclusions=run_allowed_conclusions,
                forbidden_conclusions=run_forbidden_conclusions,
                content_sha256="0" * 64,
            )
            run = provisional_run.model_copy(
                update={
                    "content_sha256": contract_content_sha256(
                        provisional_run,
                        exclude={"content_sha256"},
                    )
                }
            )
            pinned_metadata = pinned.metadata
            os.close(pinned.descriptor)
            pinned = None
            cleanup_attempted = True
            _remove_native_runtime_lock_stream(
                launch_result.stream_path,
                private_root=runtime_lock_native_private_root,
                expected_metadata=pinned_metadata,
            )
            private_stream_removed = True
            for artifact, artifact_id, artifact_type in (
                (evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence"),
                (analysis, analysis.runtime_lock_analysis_id, "runtime-lock-analysis"),
                (
                    verification,
                    verification.runtime_lock_verification_id,
                    "runtime-lock-verification",
                ),
                (run, run.run_id, "runtime-lock-run"),
            ):
                store.save(artifact, artifact_id, artifact_type)
            settlement = runtime.finish_run(session_id, lease, run)
            run_finished = True
            _persist_runtime_lock_settlement(
                runtime,
                session_id,
                store,
                settlement,
            )
            return ArtifactReference(
                artifact_id=run.run_id,
                artifact_type="runtime-lock-run",
                uri=store.uri(run.run_id, "runtime-lock-run"),
                summary={
                    "session_id": session_id,
                    "adapter_id": run.adapter_id,
                    "runtime": analysis.runtime,
                    "measurement_semantics": run.measurement_semantics,
                    "runtime_lock_evidence_id": run.runtime_lock_evidence_id,
                    "runtime_lock_analysis_id": run.runtime_lock_analysis_id,
                    "runtime_lock_verification_id": run.runtime_lock_verification_id,
                    "private_source_replay_status": private_verification.verification_status,
                    "quality_status": run.quality_status,
                    "event_count": run.event_count,
                    "evidence_bytes": run.evidence_bytes,
                    "target_pid": launch_result.target_pid,
                    "target_uid": launch_result.target_uid,
                    "exit_code": launch_result.exit_code,
                    "session_state": settlement.session.state,
                },
            )
        except Exception:
            operation_failed = True
            if lease is not None and not run_finished:
                with suppress(PerfLensError):
                    terminal = runtime.fail_run(
                        session_id,
                        lease,
                        actual_active_seconds=(
                            launch_result.accounted_active_seconds
                            if launch_result is not None
                            else duration_seconds
                        ),
                        actual_evidence_bytes=actual_evidence_bytes,
                        actual_exact_events=actual_exact_events,
                        reason=failure_reason,
                    )
                    _persist_runtime_lock_settlement(
                        runtime,
                        session_id,
                        store,
                        terminal,
                    )
            elif lease is None:
                with suppress(PerfLensError):
                    terminal = runtime.revoke(session_id)
                    store.save(
                        terminal,
                        terminal.session_artifact_id,
                        "runtime-lock-session",
                    )
            raise
        finally:
            if (
                operation_failed
                and retain_private_stream_on_failure
                and pinned is not None
                and runtime_lock_native_private_root is not None
            ):
                try:
                    _retain_native_runtime_lock_stream(
                        pinned,
                        private_root=runtime_lock_native_private_root,
                        max_retained_bytes=private_retention_quota_bytes,
                    )
                    private_stream_retained = True
                    cleanup_attempted = True
                except PerfLensError:
                    # Preserve the original collection error. A rejected retention
                    # attempt falls through to identity-checked removal below so the
                    # private quota cannot grow without a bound.
                    pass
            if pinned is not None:
                os.close(pinned.descriptor)
            if (
                launch_result is not None
                and runtime_lock_native_private_root is not None
                and not cleanup_attempted
                and not private_stream_removed
                and not private_stream_retained
            ):
                try:
                    _remove_native_runtime_lock_stream(
                        launch_result.stream_path,
                        private_root=runtime_lock_native_private_root,
                        expected_metadata=(pinned.metadata if pinned is not None else None),
                    )
                except PerfLensError:
                    if not operation_failed:
                        raise

    @server.tool(
        name="import_runtime_lock_evidence",
        description=(
            "Consume one authorized, same-UID, immutable controlled-import NDJSON source; "
            "normalize, analyze, privately replay, persist only redacted Artifacts, and consume "
            "one single-use Runtime Lock lease. This never launches or attaches to a target."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "RUNTIME_LOCK_CONTROLLED_IMPORT"},
        structured_output=True,
    )
    async def import_runtime_lock_evidence_tool(
        session_id: str,
        source_path: str,
        measurement_semantics: Literal["exact", "thresholded", "sampled", "cumulative"],
    ) -> ArtifactReference:
        _require_runtime_locks(config)
        assert runtime_lock_policy is not None
        assert runtime_lock_project is not None
        runtime = get_runtime_lock_session_runtime()
        lease = None
        pinned: _PinnedRuntimeLockImport | None = None
        started_monotonic = time.monotonic()
        actual_evidence_bytes = 0
        actual_exact_events = 0
        run_finished = False
        try:
            assert_runtime_lock_project_policy_current(
                runtime_lock_policy,
                allowed_roots=config.allowed_roots,
            )
            assert_managed_project_current(runtime_lock_project)
            session = runtime.snapshot(session_id)
            preview = store.load_runtime_lock_preview(session.preview_id)
            _validate_runtime_lock_import_session(
                session,
                preview,
                runtime_lock_policy,
                measurement_semantics=measurement_semantics,
            )
            pinned = _pin_runtime_lock_import_source(
                runtime_lock_project.path,
                source_path,
                import_roots=preview.import_roots,
                max_source_bytes=session.budget.max_artifact_bytes,
            )
            operation_identity = _runtime_lock_import_identity(
                "operation",
                session.session_id,
                pinned.project_relative_path,
                pinned.source_sha256,
                str(pinned.metadata.st_dev),
                str(pinned.metadata.st_ino),
                str(pinned.metadata.st_size),
                str(pinned.metadata.st_mtime_ns),
            )
            target_identity = _runtime_lock_import_identity(
                "target",
                session.project_identity_sha256,
                pinned.source_sha256,
            )
            workload_identity = _runtime_lock_import_identity(
                "workload",
                session.project_identity_sha256,
                pinned.source_sha256,
                measurement_semantics,
            )
            reserve_active_seconds = (
                session.budget.max_exact_duration_seconds
                if measurement_semantics == "exact"
                else session.budget.max_collection_duration_seconds
            )
            reserve_exact_events = (
                session.budget.max_exact_events if measurement_semantics == "exact" else 0
            )
            lease = runtime.begin_run(
                session_id,
                adapter_id="generic_ndjson_import",
                measurement_semantics=measurement_semantics,
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target_identity,
                workload_identity_sha256=workload_identity,
                reserve_active_seconds=reserve_active_seconds,
                reserve_evidence_bytes=session.budget.max_artifact_bytes,
                reserve_exact_events=reserve_exact_events,
            )
            reserved_session = runtime.snapshot(session_id)
            store.save(
                reserved_session,
                reserved_session.session_artifact_id,
                "runtime-lock-session",
            )
            limits = RuntimeLockResourceLimits(
                max_source_bytes=session.budget.max_artifact_bytes,
                max_input_records=(
                    session.budget.max_exact_events if measurement_semantics == "exact" else 100_000
                ),
                max_output_bytes=session.budget.max_artifact_bytes,
            )
            started_wall = datetime.now(tz=UTC)
            started_at = started_wall.isoformat()
            with os.fdopen(os.dup(pinned.descriptor), "rb") as source:
                os.lseek(source.fileno(), 0, os.SEEK_SET)
                evidence = import_runtime_lock_ndjson(
                    source,
                    limits=limits,
                    created_at=started_at,
                )
            _assert_runtime_lock_import_unchanged(pinned)
            if (
                evidence.source.source_sha256 != pinned.source_sha256
                or evidence.source.source_bytes != pinned.metadata.st_size
                or evidence.source.measurement_semantics != measurement_semantics
                or evidence.target.target_kind != "host"
                or evidence.target.target_uid != os.geteuid()
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_import",
                    "Runtime Lock source identity, semantics, or same-UID host scope changed",
                    recoverable=True,
                )
            analysis = build_runtime_lock_analysis(evidence)
            with os.fdopen(os.dup(pinned.descriptor), "rb") as private_source:
                os.lseek(private_source.fileno(), 0, os.SEEK_SET)
                private_verification = verify_runtime_lock_analysis_artifact(
                    analysis,
                    evidence,
                    private_source_stream=private_source,
                )
            _assert_runtime_lock_import_unchanged(pinned)
            require_usable_runtime_lock_analysis(private_verification)
            verification = private_verification
            actual_evidence_bytes = len(serialize_json(evidence))
            actual_exact_events = len(evidence.events) if measurement_semantics == "exact" else 0
            finished_wall = datetime.now(tz=UTC)
            duration_seconds = math.ceil((finished_wall - started_wall).total_seconds())
            if duration_seconds > reserve_active_seconds:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_import",
                    "Runtime Lock controlled import exceeded its authorized active-time budget",
                    recoverable=True,
                )
            finished_at = finished_wall.isoformat()
            (
                run_quality_status,
                run_allowed_conclusions,
                run_forbidden_conclusions,
            ) = derive_runtime_lock_run_boundaries(
                adapter_id="generic_ndjson_import",
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=evidence.quality.limitations,
            )
            provisional_run = RuntimeLockRunArtifact(
                schema_version=preview.schema_version,
                perflens_version=__version__,
                run_id=derive_runtime_lock_run_id(
                    session_id,
                    "generic_ndjson_import",
                    evidence.content_sha256,
                    started_at,
                ),
                created_at=finished_at,
                started_at=started_at,
                finished_at=finished_at,
                authorization_kind="runtime_lock_session",
                session_id=session_id,
                session_artifact_id=lease.session_artifact_id,
                session_artifact_content_sha256=lease.session_artifact_content_sha256,
                session_revision=lease.session_revision,
                target_scope="controlled_import",
                operation_identity_sha256=operation_identity,
                target_identity_sha256=target_identity,
                adapter_id="generic_ndjson_import",
                measurement_semantics=measurement_semantics,
                workload_identity_sha256=workload_identity,
                runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
                runtime_lock_evidence_content_sha256=evidence.content_sha256,
                runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
                runtime_lock_analysis_content_sha256=analysis.content_sha256,
                runtime_lock_verification_id=verification.runtime_lock_verification_id,
                runtime_lock_verification_content_sha256=verification.content_sha256,
                duration_seconds=duration_seconds,
                evidence_bytes=actual_evidence_bytes,
                event_count=len(evidence.events),
                correctness_status="unavailable",
                quality_status=run_quality_status,
                warnings=evidence.quality.limitations,
                allowed_conclusions=run_allowed_conclusions,
                forbidden_conclusions=run_forbidden_conclusions,
                content_sha256="0" * 64,
            )
            run = provisional_run.model_copy(
                update={
                    "content_sha256": contract_content_sha256(
                        provisional_run,
                        exclude={"content_sha256"},
                    )
                }
            )
            for artifact, artifact_id, artifact_type in (
                (
                    evidence,
                    evidence.runtime_lock_evidence_id,
                    "runtime-lock-evidence",
                ),
                (
                    analysis,
                    analysis.runtime_lock_analysis_id,
                    "runtime-lock-analysis",
                ),
                (
                    verification,
                    verification.runtime_lock_verification_id,
                    "runtime-lock-verification",
                ),
                (run, run.run_id, "runtime-lock-run"),
            ):
                store.save(artifact, artifact_id, artifact_type)
            settlement = runtime.finish_run(session_id, lease, run)
            run_finished = True
            _persist_runtime_lock_settlement(
                runtime,
                session_id,
                store,
                settlement,
            )
            return ArtifactReference(
                artifact_id=run.run_id,
                artifact_type="runtime-lock-run",
                uri=store.uri(run.run_id, "runtime-lock-run"),
                summary={
                    "session_id": session_id,
                    "adapter_id": run.adapter_id,
                    "runtime": analysis.runtime,
                    "measurement_semantics": run.measurement_semantics,
                    "runtime_lock_evidence_id": run.runtime_lock_evidence_id,
                    "runtime_lock_analysis_id": run.runtime_lock_analysis_id,
                    "runtime_lock_verification_id": run.runtime_lock_verification_id,
                    "private_source_replay_status": private_verification.verification_status,
                    "quality_status": run.quality_status,
                    "event_count": run.event_count,
                    "evidence_bytes": run.evidence_bytes,
                    "session_state": settlement.session.state,
                },
            )
        except Exception:
            if lease is not None and not run_finished:
                with suppress(PerfLensError):
                    terminal = runtime.fail_run(
                        session_id,
                        lease,
                        actual_active_seconds=time.monotonic() - started_monotonic,
                        actual_evidence_bytes=actual_evidence_bytes,
                        actual_exact_events=actual_exact_events,
                        reason="internal_collection_error",
                    )
                    _persist_runtime_lock_settlement(
                        runtime,
                        session_id,
                        store,
                        terminal,
                    )
            elif lease is None:
                with suppress(PerfLensError):
                    terminal = runtime.revoke(session_id)
                    store.save(
                        terminal,
                        terminal.session_artifact_id,
                        "runtime-lock-session",
                    )
            raise
        finally:
            if pinned is not None:
                os.close(pinned.descriptor)

    @server.tool(
        name="revoke_runtime_lock_session",
        description=(
            "Revoke one Runtime Lock authorization held by this MCP connection and prevent all "
            "subsequent operations."
        ),
        annotations=REVOKES_DOCKER,
        meta={"perflens/permission": "RUNTIME_LOCK_AUTHORIZATION"},
        structured_output=True,
    )
    async def revoke_runtime_lock_session(
        session_id: str,
    ) -> RuntimeLockSessionArtifact:
        session = get_runtime_lock_session_runtime().revoke(session_id)
        store.save(
            session,
            session.session_artifact_id,
            "runtime-lock-session",
        )
        return session

    @server.tool(
        name="inspect_docker_capability",
        description=(
            "Inspect the fixed local Docker endpoint and cgroup-v2 support without starting, "
            "stopping, building, pulling, or profiling a container."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def inspect_docker_capability() -> DockerRuntimeCapabilityArtifact:
        _require_docker_targets(config)
        assert docker_policy is not None
        assert_docker_project_policy_current(
            docker_policy,
            allowed_roots=config.allowed_roots,
        )
        return discover_docker_capability()

    @server.tool(
        name="inspect_docker_optimization_capability",
        description=(
            "Inspect the fixed local Docker/Buildx/Builder identities, project build contract, "
            "Benchmark requirement, base-image presence, and Collector modes. This is read-only "
            "and never builds, pulls, runs, profiles, or modifies source."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def inspect_docker_optimization_capability() -> DockerBuildCapabilityArtifact:
        return get_docker_optimization_runtime().inspect_capability()

    @server.tool(
        name="preview_docker_optimization_session",
        description=(
            "Capture the exact authorized build context and return the complete content-bound "
            "one-confirmation optimization summary. This does not build or pull. The user must "
            "confirm this exact Preview before authorization."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "READ_ONLY_CONTEXT_SNAPSHOT"},
        structured_output=True,
    )
    async def preview_docker_optimization_session(
        allowed_modes: tuple[OptimizationCollectionMode, ...],
        runtime_lock_adapters: tuple[RuntimeLockAdapterId, ...] = (),
    ) -> DockerOptimizationPreviewArtifact:
        runtime = get_docker_optimization_runtime()
        runtime_lock_scope: DockerRuntimeLockAuthorizationScope | None = None
        runtime_lock_inspection: RuntimeLockCapabilityInspection | None = None
        if runtime_lock_adapters:
            runtime_lock_scope, runtime_lock_inspection = build_docker_runtime_lock_scope(
                runtime_lock_adapters
            )
        if runtime_lock_scope is None:
            result = runtime.preview(allowed_modes=allowed_modes)
        else:
            result = runtime.preview(
                allowed_modes=allowed_modes,
                runtime_lock_scope=runtime_lock_scope,
            )
        if runtime_lock_inspection is not None:
            for adapter in runtime_lock_inspection.adapter_capabilities:
                store.save(adapter, adapter.capability_id, "runtime-adapter-capability")
            store.save(
                runtime_lock_inspection.capability,
                runtime_lock_inspection.capability.capability_id,
                "runtime-lock-capability",
            )
        store.save(
            result.capability,
            result.capability.capability_id,
            "docker-build-capability",
        )
        store.save(result.recipe, result.recipe.recipe_id, "docker-build-recipe")
        store.save(result.context, result.context.context_id, "docker-build-context")
        store.save(
            result.preview,
            result.preview.preview_id,
            "docker-optimization-preview",
        )
        return result.preview

    @server.tool(
        name="authorize_docker_optimization_session",
        description=(
            "Authorize the exact Docker optimization Preview once. This stores a process-local "
            "secret and permits only its fixed paths, build recipe, modes, and budgets; it does "
            "not itself build, run, profile, modify source, commit, push, tag, or release."
        ),
        annotations=AUTHORIZES_DOCKER,
        meta={"perflens/permission": "DOCKER_OPTIMIZATION_AUTHORIZATION"},
        structured_output=True,
    )
    async def authorize_docker_optimization_session(
        preview_id: str,
        preview_content_sha256: str,
        authorization_summary_sha256: str,
        authorization: Literal["I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"],
    ) -> DockerOptimizationSessionArtifact:
        runtime = get_docker_optimization_runtime()
        session = runtime.authorize(
            preview_id=preview_id,
            preview_content_sha256=preview_content_sha256,
            authorization_summary_sha256=authorization_summary_sha256,
            explicit_authorization=authorization,
        )
        store.save(
            session,
            session.session_artifact_id,
            "docker-optimization-session",
        )
        return session

    @server.tool(
        name="build_docker_optimization_candidate",
        description=(
            "Build one baseline or next candidate from the already-authorized immutable context "
            "and mutable Treatment paths. It accepts no image, command, path, build argument, "
            "network option, or Docker flag from the caller."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "DOCKER_OPTIMIZATION_BUILD"},
        structured_output=True,
    )
    async def build_docker_optimization_candidate(
        session_id: str,
        build_kind: Literal["baseline", "candidate"],
        candidate_round: int,
    ) -> ArtifactReference:
        runtime = get_docker_optimization_runtime()
        result = runtime.build(
            session_id,
            build_kind=build_kind,
            candidate_round=candidate_round,
        )
        store.save(result.build, result.build.build_id, "docker-build")
        store.save(
            result.session,
            result.session.session_artifact_id,
            "docker-optimization-session",
        )
        return ArtifactReference(
            artifact_id=result.build.build_id,
            artifact_type="docker-build",
            uri=store.uri(result.build.build_id, "docker-build"),
            summary={
                "session_id": result.session.session_id,
                "session_artifact_id": result.session.session_artifact_id,
                "build_kind": result.build.build_kind,
                "candidate_round": result.build.candidate_round,
                "final_image_digest": result.build.final_image_digest,
                "image_size_bytes": result.build.image_size_bytes,
                "builds_used": result.session.builds_used,
                "candidate_rounds_used": result.session.candidate_rounds_used,
            },
        )

    @server.tool(
        name="revoke_docker_optimization_session",
        description=(
            "Revoke one in-memory Docker optimization authorization and conservatively clean "
            "only verified session-owned temporary image tags and private snapshots."
        ),
        annotations=REVOKES_DOCKER,
        meta={"perflens/permission": "DOCKER_OPTIMIZATION_AUTHORIZATION"},
        structured_output=True,
    )
    async def revoke_docker_optimization_session(
        session_id: str,
    ) -> DockerOptimizationSessionArtifact:
        runtime = get_docker_optimization_runtime()
        session = runtime.revoke(session_id)
        store.save(
            session,
            session.session_artifact_id,
            "docker-optimization-session",
        )
        return session

    @server.tool(
        name="discover_docker_processes",
        description=(
            "Observe bounded CPU deltas for one existing local container and return only "
            "container PID, host PID, executable name, and a safe recommendation."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def discover_docker_processes(
        container_reference: str,
        observation_duration_ms: int = 100,
    ) -> ContainerProcessInventoryArtifact:
        _require_docker_targets(config)
        assert docker_runtime is not None
        return docker_runtime.discover(
            container_reference,
            observation_duration_ms=observation_duration_ms,
        )

    @server.tool(
        name="resolve_docker_target",
        description=(
            "Re-resolve one container process against Docker, /proc, PID start time, "
            "namespaces, cgroup identity, and UID policy without profiling it."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def resolve_docker_target(
        container_reference: str,
        host_pid: int | None = None,
        container_pid: int | None = None,
    ) -> ContainerTargetArtifact:
        _require_docker_targets(config)
        assert docker_runtime is not None
        return docker_runtime.resolve(
            container_reference,
            host_pid=host_pid,
            container_pid=container_pid,
        )

    @server.tool(
        name="authorize_docker_session",
        description=(
            "Authorize one project-bound existing-container performance session. This stores "
            "only process-local authorization and does not execute or profile the target. A "
            "fresh user reply to the exact session summary is required; MCP tool permission is "
            "not workload consent. allowed_modes is required and must exactly equal the "
            "non-empty mode set shown in that summary; expanding it requires a new summary and "
            "fresh authorization."
        ),
        annotations=AUTHORIZES_DOCKER,
        meta={"perflens/permission": "DOCKER_AUTHORIZATION"},
        structured_output=True,
    )
    async def authorize_docker_session(
        container_reference: str,
        authorization: Literal["I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"],
        allowed_modes: tuple[CollectionMode, ...],
        host_pid: int | None = None,
        container_pid: int | None = None,
        authorization_mode: Literal["per_run", "bounded_session"] | None = None,
    ) -> ContainerOptimizationSessionArtifact:
        _require_docker_targets(config)
        assert docker_runtime is not None
        return docker_runtime.authorize(
            container_reference,
            host_pid=host_pid,
            container_pid=container_pid,
            allowed_modes=allowed_modes,
            authorization_mode=authorization_mode,
            explicit_authorization=authorization,
        )

    @server.tool(
        name="authorize_managed_docker_session",
        description=(
            "Authorize the exact immutable image, command, mounts, resource limits, modes, and "
            "budget pinned in this project's Docker policy. This never builds or pulls an image. "
            "A fresh user reply to that exact summary is required; MCP tool permission is not "
            "workload consent. allowed_modes is required and must exactly equal the non-empty "
            "mode set shown in that summary; expanding it requires a new summary and fresh "
            "authorization."
        ),
        annotations=AUTHORIZES_DOCKER,
        meta={"perflens/permission": "DOCKER_AUTHORIZATION"},
        structured_output=True,
    )
    async def authorize_managed_docker_session(
        authorization: Literal["I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"],
        allowed_modes: tuple[CollectionMode, ...],
    ) -> ContainerOptimizationSessionArtifact:
        _require_docker_targets(config)
        assert docker_runtime is not None
        return docker_runtime.authorize_managed(
            allowed_modes=allowed_modes,
            explicit_authorization=authorization,
        )

    @server.tool(
        name="revoke_docker_session",
        description=(
            "Revoke one Docker authorization held by this project MCP process without stopping "
            "or removing a user container."
        ),
        annotations=REVOKES_DOCKER,
        meta={"perflens/permission": "DOCKER_AUTHORIZATION"},
        structured_output=True,
    )
    async def revoke_docker_session(
        session_id: str,
    ) -> ContainerOptimizationSessionArtifact:
        _require_docker_targets(config)
        assert docker_runtime is not None
        return docker_runtime.revoke(session_id)

    @server.tool(
        name="collect_docker_target",
        description=(
            "Re-resolve one authorized existing-container process, consume one bounded session "
            "run, and collect it through the restricted Broker. The Docker adapter never enters "
            "the Collector or Helper."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "DOCKER_COLLECTION"},
        structured_output=True,
    )
    async def collect_docker_target(
        session_id: str,
        container_reference: str,
        host_pid: int | None = None,
        container_pid: int | None = None,
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "record",
        duration_seconds: float = 10.0,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = HARDWARE_STAT_EVENTS,
        event_source: Literal["auto", "hardware_required", "software_only"] = "auto",
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ArtifactReference:
        # Docker attachment has its own project opt-in, identity-bound session, and per-run
        # authorization. Do not require or implicitly enable the broader Host-PID attach switch.
        _require_automatic_collection(config, require_existing_pid_attach=False)
        _require_docker_targets(config)
        assert docker_runtime is not None
        resolved_target = docker_runtime.resolve_for_collection(
            container_reference,
            host_pid=host_pid,
            container_pid=container_pid,
        )
        target = resolved_target.artifact
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode=mode,
                pid=target.host_pid,
                duration_seconds=duration_seconds,
                frequency_hz=frequency_hz,
                call_graph=call_graph,
                events=events,
                event_source=event_source,
                max_output_bytes=max_output_bytes,
                container_target=target,
            ),
            policy=config.automatic_collection_policy,
            capabilities=inspect_collection_capabilities(config.perf_path),
        )
        if plan.policy_status != "allowed":
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_authorization",
                "Docker collection request is outside MCP automatic-collection policy",
                recoverable=True,
                details={"warnings": "; ".join(plan.warnings)},
            )
        resource_reader = CgroupV2ResourceReader(resolved_target)
        reserve_active_seconds = math.ceil(plan.duration_seconds)
        try:
            lease = docker_runtime.begin_existing_run(
                session_id,
                target,
                requested_modes=(mode,),
                reserve_active_seconds=reserve_active_seconds,
                reserve_evidence_bytes=plan.max_output_bytes,
            )
        except BaseException:
            resource_reader.close()
            raise
        started = time.monotonic()
        executed: _ExecutedBrokerPlan | None = None
        before_snapshot: CapturedCgroupSnapshot | None = None

        def capture_resource_baseline() -> None:
            nonlocal before_snapshot
            if before_snapshot is not None:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "docker_resource_context",
                    "Docker resource baseline callback was invoked more than once",
                )
            before_snapshot = resource_reader.capture()

        try:
            executed = execute_broker_plan(
                plan,
                ready_callback=capture_resource_baseline,
            )
            if before_snapshot is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "docker_resource_context",
                    "Collector completed without requesting the Docker resource baseline",
                )
            after_snapshot = resource_reader.capture()
            docker_runtime.assert_collection_target_current(
                container_reference,
                resolved_target,
                host_pid=host_pid,
                container_pid=container_pid,
            )
            module_snapshot = capture_module_snapshot(executed)
            resource_context = build_container_resource_context(
                resource_reader,
                before_snapshot,
                after_snapshot,
                source_collection_id=executed.collection_id,
                source_output_sha256=executed.output_sha256,
            )
            resource_reader.close()
            store.save(
                resource_context,
                resource_context.resource_context_id,
                "container-resource-context",
            )
            measurement = (
                build_container_measurement(executed.collection, resource_context)
                if executed.collection is not None
                else None
            )
            if measurement is not None:
                store.save(
                    measurement,
                    measurement.measurement_id,
                    "container-measurement",
                )
        except BaseException:
            resource_reader.close()
            with suppress(PerfLensError):
                docker_runtime.finish_existing_run(
                    session_id,
                    lease,
                    actual_active_seconds=min(
                        reserve_active_seconds,
                        max(0, math.ceil(time.monotonic() - started)),
                    ),
                    actual_evidence_bytes=(executed.evidence_bytes if executed is not None else 0),
                )
            raise
        session = docker_runtime.finish_existing_run(
            session_id,
            lease,
            actual_active_seconds=min(
                reserve_active_seconds,
                max(0, math.ceil(executed.active_seconds)),
            ),
            actual_evidence_bytes=executed.evidence_bytes,
        )
        return ArtifactReference.model_validate(
            {
                **executed.reference.model_dump(mode="json"),
                "summary": {
                    **executed.reference.summary,
                    "docker_session_id": session.session_id,
                    "docker_run_number": lease.run_number,
                    "docker_session_state": session.state,
                    "container_target_id": target.target_id,
                    "container_pid": target.container_pid,
                    **_container_resource_summary(
                        resource_context,
                        uri=store.uri(
                            resource_context.resource_context_id,
                            "container-resource-context",
                        ),
                    ),
                    **_container_module_summary(
                        module_snapshot,
                        uri=(
                            store.uri(
                                module_snapshot.module_snapshot_id,
                                "container-module-snapshot",
                            )
                            if module_snapshot is not None
                            else None
                        ),
                    ),
                    **_container_measurement_summary(
                        measurement,
                        uri=(
                            store.uri(
                                measurement.measurement_id,
                                "container-measurement",
                            )
                            if measurement is not None
                            else None
                        ),
                    ),
                },
            }
        )

    @server.tool(
        name="collect_managed_docker_workload",
        description=(
            "Create one fixed-policy temporary container from an already-local immutable image, "
            "hold its exact workload at the package Gate until Broker collection is ready, then "
            "run, collect, wait, and conservatively clean only that verified container."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "DOCKER_COLLECTION"},
        structured_output=True,
    )
    async def collect_managed_docker_workload(
        session_id: str,
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "record",
        duration_seconds: float = 10.0,
        workload_timeout_seconds: int = 60,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = HARDWARE_STAT_EVENTS,
        event_source: Literal["auto", "hardware_required", "software_only"] = "auto",
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ArtifactReference:
        _require_automatic_collection(config, require_existing_pid_attach=False)
        _require_docker_targets(config)
        assert docker_runtime is not None
        assert docker_policy is not None
        _preflight_managed_collection(
            config,
            mode=mode,
            duration_seconds=duration_seconds,
            workload_timeout_seconds=workload_timeout_seconds,
            frequency_hz=frequency_hz,
            max_output_bytes=max_output_bytes,
            trace_max_duration_seconds=docker_policy.trace_max_duration_seconds,
        )
        started = time.monotonic()
        executed: _ExecutedBrokerPlan | None = None
        resource_reader: CgroupV2ResourceReader | None = None
        resource_monitor: CgroupSnapshotMonitor | None = None
        pinned_process_root: PinnedContainerProcessRoot | None = None
        project_root = policy.workspace_root(docker_policy.path.parent.parent)
        treatment_snapshot = capture_treatment_snapshot(
            project_root,
            tuple(
                policy.input_file(project_root / relative_path)
                for relative_path in docker_policy.managed.treatment_paths
            ),
        )
        runtime_lock_request = managed_runtime_lock_requests.get(session_id)
        run = docker_runtime.prepare_managed_run(
            session_id,
            requested_modes=(mode,),
            reserve_active_seconds=workload_timeout_seconds,
            reserve_evidence_bytes=max_output_bytes,
            runtime_lock_launch=(
                runtime_lock_request.launch if runtime_lock_request is not None else None
            ),
        )
        try:
            captured_path_sha256 = tuple(
                sorted(item.relative_path_sha256 for item in treatment_snapshot.files)
            )
            if captured_path_sha256 != run.authorization.workload.treatment_path_sha256:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "docker_comparison",
                    "Managed Docker treatment files differ from the authorized workload",
                )
            target = run.prepared.target.artifact
            store.save(target, target.target_id, "container-target")
            namespace_attestation = namespace_attestation_from_target(target)
            plan = create_collection_plan(
                CollectionPlanRequest(
                    mode=mode,
                    pid=target.host_pid,
                    duration_seconds=duration_seconds,
                    frequency_hz=frequency_hz,
                    call_graph=call_graph,
                    events=events,
                    event_source=event_source,
                    max_output_bytes=max_output_bytes,
                    container_target=target,
                ),
                policy=config.automatic_collection_policy,
                capabilities=inspect_collection_capabilities(config.perf_path),
                namespace_attestation=namespace_attestation,
            )
            if plan.policy_status != "allowed":
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "docker_authorization",
                    "Managed Docker collection is outside MCP automatic-collection policy",
                    recoverable=True,
                    details={"warnings": "; ".join(plan.warnings)},
                )
            # Persist the immutable authorization recipe before starting collection. Its
            # per-authorization artifact ID is distinct from the stable workload fingerprint,
            # so repeated sessions remain auditable without colliding in append-only storage.
            store.save(
                run.authorization.workload,
                run.authorization.workload.workload_spec_id,
                "container-workload-spec",
            )
            requires_runtime_executable = (
                runtime_lock_request is not None and runtime_lock_request.adapter_id == "go_pprof"
            )
            if mode == "record" or requires_runtime_executable:
                # The Gate is still live here. Pin its already-verified container root
                # before release so short workloads cannot disappear before perf's
                # Build-ID hits are matched to exact module bytes.
                try:
                    pinned_process_root = pin_container_process_root(target)
                except PerfLensError as exc:
                    # Symbol capture is evidence enrichment, not a prerequisite for raw
                    # collection. A same-target root that is merely unreadable (for example,
                    # a cross-UID rootful container) keeps the previous truthful partial path.
                    # Identity failures from docker_identity still abort before Gate release.
                    if (
                        requires_runtime_executable
                        or exc.stage != "container_symbols"
                        or not exc.recoverable
                    ):
                        raise
            if requires_runtime_executable:
                if pinned_process_root is None:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "runtime_lock_docker_binding",
                        "Go target executable cannot be pinned before Gate release",
                        recoverable=False,
                    )
                executable_fd = -1
                try:
                    executable_fd, _executable_sha256, _executable_bytes = (
                        pinned_process_root.open_runtime_executable(
                            run.authorization.workload.entrypoint
                        )
                    )
                    go_tool = get_runtime_lock_go_bridge().tool
                    if go_tool is None:
                        raise PerfLensError(
                            ErrorCode.EXTERNAL_TOOL_FAILED,
                            "runtime_lock_capability",
                            "The fixed Go version tool is unavailable",
                            recoverable=True,
                        )
                    go_version = inspect_pinned_go_executable_version(
                        go_tool,
                        executable_fd,
                    )
                finally:
                    if executable_fd >= 0:
                        os.close(executable_fd)
                assert runtime_lock_request is not None
                runtime_lock_request = replace(
                    runtime_lock_request,
                    execution_binding=bind_observed_runtime_execution(
                        runtime_lock_request.execution_binding,
                        runtime_version=go_version,
                        runtime_characteristics="go-version-metadata",
                    ),
                    runtime_characteristics="go-version-metadata",
                )
            resource_reader = CgroupV2ResourceReader(run.prepared.target)
            before_snapshot = resource_reader.capture()
            resource_monitor = CgroupSnapshotMonitor(resource_reader, before_snapshot)
            workload_released = False
            workload_started_at: datetime | None = None

            def capture_and_release_workload() -> None:
                nonlocal workload_released, workload_started_at
                if workload_released:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "docker_resource_context",
                        "Managed Docker resource baseline callback was invoked more than once",
                    )
                assert resource_monitor is not None
                resource_monitor.start()
                try:
                    workload_started_at = datetime.now(tz=UTC)
                    run.coordinator.release(run.prepared)
                except BaseException:
                    with suppress(PerfLensError):
                        resource_monitor.stop()
                    raise
                workload_released = True

            executed = execute_broker_plan(
                plan,
                ready_callback=capture_and_release_workload,
                namespace_attestation=namespace_attestation,
            )
            if session_id in managed_collection_progress:
                managed_collection_progress[session_id] = (
                    executed.evidence_bytes,
                    executed.collection_id,
                )
            if not workload_released:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "docker_resource_context",
                    "Collector completed without releasing the managed Docker workload",
                )
            try:
                module_snapshot = capture_module_snapshot(
                    executed,
                    pinned_process_root=pinned_process_root,
                )
            finally:
                if pinned_process_root is not None:
                    pinned_process_root.close()
                    pinned_process_root = None
            elapsed = math.ceil(time.monotonic() - started)
            remaining = workload_timeout_seconds - elapsed
            if remaining <= 0:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "docker_workload",
                    "Managed Docker workload exhausted its bounded run timeout",
                    recoverable=True,
                )
            run.coordinator.wait(run.prepared, timeout_seconds=remaining)
            workload_finished_at = datetime.now(tz=UTC)
            if workload_started_at is None:
                raise PerfLensError(
                    ErrorCode.PROFILE_PARSE_FAILED,
                    "runtime_lock_docker_binding",
                    "Docker workload release time is unavailable",
                    recoverable=False,
                )
            assert_treatment_snapshot_current(treatment_snapshot)
            runtime_lock_capture: DockerRuntimeLockCapture | None = None
            if runtime_lock_request is not None:
                if target.container_uid is None:
                    raise PerfLensError(
                        ErrorCode.PROFILE_PARSE_FAILED,
                        "runtime_lock_docker_binding",
                        "Docker Runtime Lock target lacks container UID-map evidence",
                        recoverable=False,
                    )
                parent = get_docker_optimization_runtime().snapshot(
                    runtime_lock_request.docker_optimization_session_id
                )
                scope = parent.runtime_lock_scope
                if scope is None or runtime_lock_request.adapter_id not in scope.allowed_adapters:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "runtime_lock_authorization",
                        "Docker Runtime Lock scope changed during the managed workload",
                        recoverable=False,
                    )
                java_authority: JavaDockerJfrAuthority | None = None
                go_authority: GoDockerPprofAuthority | None = None
                if runtime_lock_request.adapter_id == "java_jfr":
                    java_policy = get_runtime_lock_java_bridge().launch_policy
                    if java_policy is None:
                        raise PerfLensError(
                            ErrorCode.EXTERNAL_TOOL_FAILED,
                            "runtime_lock_capability",
                            "The authorized Java JFR toolchain is unavailable",
                            recoverable=True,
                        )
                    java_authority = JavaDockerJfrAuthority(
                        runner=SubprocessJavaJfrJsonRunner(),
                        jfr_tool=inspect_java_jfr_tool_identity(java_policy.jfr_tool),
                        jdk_major=java_policy.jdk_major,
                    )
                elif runtime_lock_request.adapter_id == "go_pprof":
                    assert runtime_lock_policy is not None
                    profile_kind = runtime_lock_request.go_profile_kind
                    if profile_kind is None:
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            "runtime_lock_authorization",
                            "Docker Go Runtime Lock profile kind is unavailable",
                            recoverable=False,
                        )
                    adapter_policy = runtime_lock_policy.adapter_policy("go_pprof")
                    go_authority = GoDockerPprofAuthority(
                        renderer=get_runtime_lock_go_launcher(),
                        profile_kind=profile_kind,
                        mutex_profile_fraction=adapter_policy.mutex_profile_fraction,
                        block_profile_rate_ns=adapter_policy.block_profile_rate_ns,
                    )
                runtime_lock_capture = capture_docker_runtime_lock_evidence(
                    run.prepared.receipt.scratch_directory,
                    launch=runtime_lock_request.launch,
                    execution_binding=runtime_lock_request.execution_binding,
                    target_pid=target.container_pid,
                    target_uid=target.container_uid,
                    target_start_time_ticks=target.host_start_time_ticks,
                    created_at=workload_started_at.isoformat(),
                    scratch_owner_uid=os.geteuid(),
                    source_owner_uid=target.host_uid,
                    limits=RuntimeLockResourceLimits(
                        max_source_bytes=scope.budget.max_artifact_bytes,
                        max_input_records=scope.budget.max_exact_events,
                        max_output_bytes=scope.budget.max_artifact_bytes,
                    ),
                    go_profile_kind=runtime_lock_request.go_profile_kind,
                    java_authority=java_authority,
                    go_authority=go_authority,
                )
            benchmark = (
                load_managed_benchmark(
                    run.prepared.receipt.scratch_directory,
                    docker_policy.managed.benchmark_output,
                    source_format=docker_policy.managed.benchmark_format,
                    benchmark_name=docker_policy.managed.benchmark_name,
                )
                if docker_policy.managed.benchmark_output
                else None
            )
            # Keep the cgroup monitor alive through workload exit, Adapter conversion, and
            # correctness/Benchmark capture.  Runtime Lock totals cover the whole workload;
            # binding them to the shorter perf sampling window could hide a resource transfer.
            after_snapshot = resource_monitor.finish()
            resource_context = build_container_resource_context(
                resource_reader,
                before_snapshot,
                after_snapshot,
                source_collection_id=executed.collection_id,
                source_output_sha256=executed.output_sha256,
            )
            resource_reader.close()
            store.save(
                resource_context,
                resource_context.resource_context_id,
                "container-resource-context",
            )
            cleanup_status = run.coordinator.cleanup(run.prepared)
            finished_at = datetime.now(tz=UTC)
            container_run = build_container_run_artifact(
                prepared=run.prepared,
                workload=run.authorization.workload,
                finished_at=finished_at,
                status="exited",
                cleanup_status=cleanup_status,
                collection_ids=(executed.collection_id,),
                build_artifact_sha256=treatment_snapshot.treatment_sha256,
                benchmark=benchmark,
                resource_context_id=resource_context.resource_context_id,
                warnings=(
                    (
                        "Managed container identity could not be safely removed; "
                        "manual review is required.",
                    )
                    if cleanup_status == "preserved_for_manual_cleanup"
                    else ()
                ),
            )
            session = docker_runtime.finish_managed_run(
                run,
                actual_active_seconds=max(1, math.ceil(time.monotonic() - started)),
                actual_evidence_bytes=executed.evidence_bytes,
            )
            if benchmark is not None:
                store.save(benchmark, benchmark.benchmark_id, "benchmark")
            store.save(container_run, container_run.run_id, "container-run")
            measurement = (
                build_container_measurement(
                    executed.collection,
                    resource_context,
                    run=container_run,
                    workload=run.authorization.workload,
                )
                if executed.collection is not None
                else None
            )
            if measurement is not None:
                store.save(
                    measurement,
                    measurement.measurement_id,
                    "container-measurement",
                )
            if runtime_lock_request is not None:
                if runtime_lock_capture is None or measurement is None:
                    raise PerfLensError(
                        ErrorCode.PROFILE_PARSE_FAILED,
                        "runtime_lock_docker_binding",
                        "Docker Runtime Lock collection lacks its measurement evidence",
                        recoverable=False,
                    )
                evidence = bind_runtime_lock_evidence_to_container(
                    runtime_lock_capture.evidence,
                    execution_binding=runtime_lock_capture.execution_binding,
                    target=target,
                    run=container_run,
                )
                analysis = build_runtime_lock_analysis(evidence)
                replay_receipt = build_runtime_lock_source_replay_receipt(
                    evidence,
                    origin_source_sha256=runtime_lock_capture.private_source_sha256,
                    origin_source_bytes=runtime_lock_capture.private_source_bytes,
                    normalized_source_sha256=(runtime_lock_capture.normalized_source_sha256),
                    normalized_source_bytes=(runtime_lock_capture.normalized_source_bytes),
                )
                verification = verify_runtime_lock_analysis_artifact(
                    analysis,
                    evidence,
                    source_replay_receipt=replay_receipt,
                )
                require_usable_runtime_lock_analysis(verification)
                managed_runtime_lock_results[session_id] = _DockerRuntimeLockCollected(
                    request=replace(
                        runtime_lock_request,
                        execution_binding=runtime_lock_capture.execution_binding,
                        runtime_characteristics=(runtime_lock_capture.runtime_characteristics),
                    ),
                    evidence=evidence,
                    analysis=analysis,
                    verification=verification,
                    target=target,
                    container_run=container_run,
                    measurement=measurement,
                    started_at=workload_started_at.isoformat(),
                    finished_at=workload_finished_at.isoformat(),
                    replay_verified=runtime_lock_capture.replay_verified,
                )
            return _managed_run_reference(
                container_run,
                executed.reference,
                session,
                resource_context,
                module_snapshot,
                measurement,
                evidence_bytes=executed.evidence_bytes,
                uri=store.uri(container_run.run_id, "container-run"),
                resource_uri=store.uri(
                    resource_context.resource_context_id,
                    "container-resource-context",
                ),
                module_uri=(
                    store.uri(
                        module_snapshot.module_snapshot_id,
                        "container-module-snapshot",
                    )
                    if module_snapshot is not None
                    else None
                ),
                measurement_uri=(
                    store.uri(
                        measurement.measurement_id,
                        "container-measurement",
                    )
                    if measurement is not None
                    else None
                ),
            )
        except BaseException:
            if pinned_process_root is not None:
                pinned_process_root.close()
            resource_reader_can_close = True
            if resource_monitor is not None:
                try:
                    resource_monitor.stop()
                except PerfLensError:
                    # Preserve the original collection failure. A still-running bounded monitor
                    # owns its Reader until its daemon thread exits; closing descriptors under
                    # that thread would create a use-after-close race.
                    resource_reader_can_close = False
            if resource_reader is not None and resource_reader_can_close:
                resource_reader.close()
            with suppress(PerfLensError):
                run.coordinator.cleanup(run.prepared)
            with suppress(PerfLensError):
                docker_runtime.finish_managed_run(
                    run,
                    actual_active_seconds=max(1, math.ceil(time.monotonic() - started)),
                    actual_evidence_bytes=(executed.evidence_bytes if executed is not None else 0),
                )
            raise

    @server.tool(
        name="collect_docker_optimization_workload",
        description=(
            "Run and collect only a verified image Build produced by this one-confirmation "
            "optimization session. The caller selects bounded evidence, never an image, command, "
            "mount, network, Docker option, or host path. A failed attempt after workload-lease "
            "issuance is charged and stops further build/collection operations in that Session; "
            "it must not be retried unchanged."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "DOCKER_OPTIMIZATION_COLLECTION"},
        structured_output=True,
    )
    async def collect_docker_optimization_workload(
        session_id: str,
        build_id: str,
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "stat",
        duration_seconds: float = 2.0,
        workload_timeout_seconds: int = 60,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = HARDWARE_STAT_EVENTS,
        event_source: Literal["auto", "hardware_required", "software_only"] = "auto",
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        runtime_lock_adapter: RuntimeLockAdapterId | None = None,
        runtime_lock_max_events: int = 20_000,
        runtime_lock_go_profile_kind: GoProfileKind | None = None,
    ) -> ArtifactReference:
        _require_automatic_collection(config, require_existing_pid_attach=False)
        _require_docker_optimization(config)
        assert docker_runtime is not None
        assert docker_policy is not None
        optimization_runtime = get_docker_optimization_runtime()
        parent_session = optimization_runtime.snapshot(session_id)
        runtime_lock_binding: RuntimeLockAdapterExecutionBinding | None = None
        runtime_lock_launch: RuntimeLockDockerLaunch | None = None
        runtime_lock_reserved_bytes = 0
        if runtime_lock_adapter is not None:
            if mode not in {"stat", "record"}:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_authorization",
                    "Docker Runtime Lock collection must accompany stat or record evidence",
                    recoverable=True,
                )
            runtime_lock_binding, runtime_lock_launch = build_docker_runtime_lock_launch(
                parent_session,
                runtime_lock_adapter,
                max_events=runtime_lock_max_events,
                go_profile_kind=runtime_lock_go_profile_kind,
            )
            scope = parent_session.runtime_lock_scope
            assert scope is not None
            runtime_runs = parent_session.runtime_lock_runs_used
            runtime_active = parent_session.runtime_lock_active_seconds_used
            runtime_bytes = parent_session.runtime_lock_evidence_bytes_used
            runtime_exact = parent_session.runtime_lock_exact_events_used
            if (
                parent_session.runtime_lock_status in {"exhausted", "unavailable"}
                or runtime_runs is None
                or runtime_active is None
                or runtime_bytes is None
                or runtime_exact is None
            ):
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_authorization",
                    "Docker Runtime Lock collection is unavailable in this Session",
                    recoverable=False,
                )
            runtime_lock_duration_limit = (
                scope.budget.max_exact_duration_seconds
                if runtime_lock_binding.measurement_semantics == "exact"
                else scope.budget.max_collection_duration_seconds
            )
            if workload_timeout_seconds > runtime_lock_duration_limit:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_authorization",
                    "Docker workload timeout exceeds the selected Runtime Lock evidence window",
                    recoverable=True,
                )
            reserved_exact_events = (
                runtime_lock_max_events
                if runtime_lock_binding.measurement_semantics == "exact"
                else 0
            )
            if (
                runtime_runs + 1 > scope.budget.max_workload_runs
                or runtime_active + workload_timeout_seconds > scope.budget.max_active_seconds
                or runtime_bytes + 4 * scope.budget.max_artifact_bytes
                > scope.budget.max_evidence_bytes
                or runtime_exact + reserved_exact_events
                > scope.budget.max_workload_runs * scope.budget.max_exact_events
            ):
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "runtime_lock_authorization",
                    "Docker Runtime Lock reservation exceeds the remaining Session budget",
                    recoverable=False,
                )
            # Reserve all bounded representations before a container exists:
            # private adapter output, converted text, normalized records, and
            # public Evidence. Actual settlement charges their exact byte sum.
            runtime_lock_reserved_bytes = 4 * scope.budget.max_artifact_bytes
        elif runtime_lock_go_profile_kind is not None:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "A Go profile kind cannot be selected without the Go Runtime Lock Adapter",
                recoverable=True,
            )
        recipe = optimization_runtime.build_recipe(session_id)
        budget = recipe.budget
        if (
            (mode == "record" and duration_seconds > budget.record_max_duration_seconds)
            or (mode == "record" and frequency_hz > budget.record_frequency_hz)
            or (
                mode in {"sched", "off_cpu", "lock"}
                and duration_seconds > budget.trace_max_duration_seconds
            )
        ):
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "docker_optimization_collection",
                "Docker optimization collection exceeds its mode-specific budget",
                recoverable=True,
            )
        _preflight_managed_collection(
            config,
            mode=mode,
            duration_seconds=duration_seconds,
            workload_timeout_seconds=workload_timeout_seconds,
            frequency_hz=frequency_hz,
            max_output_bytes=max_output_bytes,
            trace_max_duration_seconds=budget.trace_max_duration_seconds,
        )
        build = optimization_runtime.build_result(session_id, build_id).artifact
        lease = optimization_runtime.begin_workload(
            session_id,
            build_id=build_id,
            mode=mode,
            reserve_active_seconds=workload_timeout_seconds,
            reserve_evidence_bytes=max_output_bytes + runtime_lock_reserved_bytes,
        )
        started = time.monotonic()
        internal_session: ContainerOptimizationSessionArtifact | None = None
        workload_completed = False
        try:
            internal_session = docker_runtime.authorize_optimization_build(
                build,
                recipe,
                allowed_modes=(mode,),
            )
            managed_collection_progress[internal_session.session_id] = (0, "")
            if runtime_lock_binding is not None and runtime_lock_launch is not None:
                managed_runtime_lock_requests[internal_session.session_id] = (
                    _DockerRuntimeLockRequest(
                        docker_optimization_session_id=session_id,
                        build_id=build_id,
                        adapter_id=cast(RuntimeLockAdapterId, runtime_lock_adapter),
                        execution_binding=runtime_lock_binding,
                        authorized_execution_identity_sha256=(
                            runtime_lock_binding.execution_identity_sha256
                        ),
                        launch=runtime_lock_launch,
                        observation_limit_seconds=workload_timeout_seconds,
                        go_profile_kind=runtime_lock_go_profile_kind,
                    )
                )
            collected = await collect_managed_docker_workload(
                session_id=internal_session.session_id,
                mode=mode,
                duration_seconds=duration_seconds,
                workload_timeout_seconds=workload_timeout_seconds,
                frequency_hz=frequency_hz,
                call_graph=call_graph,
                events=events,
                event_source=event_source,
                max_output_bytes=max_output_bytes,
            )
            runtime_lock_collected = managed_runtime_lock_results.pop(
                internal_session.session_id,
                None,
            )
            if (runtime_lock_binding is None) != (runtime_lock_collected is None):
                raise PerfLensError(
                    ErrorCode.PROFILE_PARSE_FAILED,
                    "runtime_lock_docker_binding",
                    "Docker Runtime Lock result differs from the authorized collection scope",
                    recoverable=False,
                )
            session = _finish_optimization_workload_with_evidence(
                optimization_runtime,
                session_id,
                lease,
                actual_active_seconds=min(
                    workload_timeout_seconds,
                    max(0, time.monotonic() - started),
                ),
                collected=collected,
                additional_evidence_bytes=(
                    _docker_runtime_lock_accounted_bytes(runtime_lock_collected)
                    if runtime_lock_collected is not None
                    else 0
                ),
            )
            workload_completed = True
            runtime_lock_run: RuntimeLockRunArtifact | None = None
            if runtime_lock_collected is not None:
                session, runtime_lock_run = _finalize_docker_runtime_lock_run(
                    store,
                    optimization_runtime,
                    session_id,
                    lease,
                    build,
                    runtime_lock_collected,
                )
        except BaseException as exc:
            failed_session: DockerOptimizationSessionArtifact | None = None
            persisted_evidence_bytes = 0
            if internal_session is not None:
                progress = managed_collection_progress.get(internal_session.session_id)
                if progress is not None:
                    persisted_evidence_bytes = progress[0]
            with suppress(PerfLensError):
                failure_reason = (
                    exc.message
                    if isinstance(exc, PerfLensError)
                    else "Docker optimization collection failed."
                )
                if workload_completed:
                    failed_session = optimization_runtime.fail_completed_runtime_lock_use(
                        session_id,
                        lease,
                        reason=failure_reason,
                    )
                else:
                    failed_session = optimization_runtime.fail_workload(
                        session_id,
                        lease,
                        actual_active_seconds=min(
                            workload_timeout_seconds,
                            max(0, time.monotonic() - started),
                        ),
                        actual_evidence_bytes=persisted_evidence_bytes,
                        reason=failure_reason,
                        runtime_lock_requested=runtime_lock_binding is not None,
                    )
            if failed_session is None:
                # Reservation overrun and expiry transitions can end the authority before the
                # ordinary failure reconciler runs.  Persist the resulting terminal snapshot so
                # disk evidence never presents the previous active state as current.
                with suppress(PerfLensError):
                    failed_session = optimization_runtime.snapshot(session_id)
            if failed_session is not None:
                with suppress(PerfLensError):
                    store.save(
                        failed_session,
                        failed_session.session_artifact_id,
                        "docker-optimization-session",
                    )
            if isinstance(exc, PerfLensError):
                details = dict(exc.details)
                details.update(
                    {
                        "docker_optimization_session_id": session_id,
                        "docker_optimization_workload_attempt_charged": True,
                        "docker_optimization_automatic_retry_allowed": False,
                        "docker_optimization_workload_runs_used": (
                            failed_session.workload_runs_used
                            if failed_session is not None
                            else None
                        ),
                    }
                )
                raise PerfLensError(
                    exc.code,
                    exc.stage,
                    exc.message,
                    recoverable=False,
                    retryable=False,
                    details=details,
                    suggested_actions=(
                        "Do not retry or switch evidence mode in this Session.",
                        "Finalize or revoke the Session, correct the infrastructure, then "
                        "authorize a new Session.",
                    ),
                ) from exc
            raise
        finally:
            if internal_session is not None:
                managed_runtime_lock_requests.pop(internal_session.session_id, None)
                managed_runtime_lock_results.pop(internal_session.session_id, None)
                managed_collection_progress.pop(internal_session.session_id, None)
                with suppress(PerfLensError):
                    docker_runtime.revoke(internal_session.session_id)
        # Runtime Lock finalization already publishes the exact charged parent
        # revision before sealing the completed lease.  A second save here could
        # report a false collection failure after publication if storage becomes
        # unavailable between the two writes.
        if runtime_lock_run is None:
            store.save(
                session,
                session.session_artifact_id,
                "docker-optimization-session",
            )
        return ArtifactReference.model_validate(
            {
                **collected.model_dump(mode="json"),
                "summary": {
                    **collected.summary,
                    "docker_optimization_session_id": session.session_id,
                    "docker_optimization_session_artifact_id": session.session_artifact_id,
                    "docker_optimization_build_id": build.build_id,
                    "docker_optimization_build_content_sha256": build.content_sha256,
                    "docker_optimization_candidate_round": build.candidate_round,
                    "docker_optimization_workload_runs_used": session.workload_runs_used,
                    "runtime_lock_run_id": (
                        runtime_lock_run.run_id if runtime_lock_run is not None else None
                    ),
                    "runtime_lock_adapter": (
                        runtime_lock_run.adapter_id if runtime_lock_run is not None else None
                    ),
                    "runtime_lock_quality_status": (
                        runtime_lock_run.quality_status if runtime_lock_run is not None else None
                    ),
                },
            }
        )

    @server.tool(
        name="plan_automatic_collection",
        description=(
            "Create a short-lived PID-bound collection plan. This does not sample or attach."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def plan_automatic_collection(
        pid: int,
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "record",
        duration_seconds: float = 10.0,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = HARDWARE_STAT_EVENTS,
        event_source: Literal["auto", "hardware_required", "software_only"] = "auto",
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> CollectionPlanArtifact:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode=mode,
                pid=pid,
                duration_seconds=duration_seconds,
                frequency_hz=frequency_hz,
                call_graph=call_graph,
                events=events,
                event_source=event_source,
                max_output_bytes=max_output_bytes,
            ),
            policy=config.automatic_collection_policy,
            capabilities=inspect_collection_capabilities(config.perf_path),
        )
        if plan.policy_status == "allowed":
            expired_plan_ids = [
                existing_id
                for existing_id, existing_plan in collection_plans.items()
                if datetime.fromisoformat(existing_plan.expires_at) <= datetime.now(tz=UTC)
            ]
            for expired_plan_id in expired_plan_ids:
                collection_plans.pop(expired_plan_id, None)
            if len(collection_plans) >= 128:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "collection_plan",
                    "Automatic collection plan store reached its bounded capacity",
                    recoverable=True,
                )
            collection_plans[plan.plan_id] = plan
        return plan

    @server.tool(
        name="execute_collection_plan",
        description=(
            "Execute one previously planned PID collection through the restricted collector "
            "broker. Plans are short-lived and single-use."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "AUTOMATIC_COLLECTION"},
        structured_output=True,
    )
    async def execute_collection_plan(plan_id: str) -> ArtifactReference:
        _require_automatic_collection(config, require_existing_pid_attach=True)
        try:
            plan = collection_plans.pop(plan_id)
        except KeyError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection_plan",
                "Collection plan was not found, was denied, or was already consumed",
                recoverable=True,
                details={"plan_id": plan_id},
            ) from exc
        return execute_broker_plan(plan).reference

    @server.tool(
        name="collect_project_workload",
        description=(
            "Run one explicitly authorized executable inside a project as the MCP user, bind its "
            "exact PID incarnation, and collect it through the restricted Collector broker. "
            "After the user approves the exact scope, authorization must be exactly "
            "I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION; do not substitute manual PID attachment."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "PROJECT_EXECUTION"},
        structured_output=True,
    )
    def collect_project_workload_tool(
        project_root: str,
        executable: str,
        authorization: Literal["I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION"],
        arguments: tuple[str, ...] = (),
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "record",
        duration_seconds: float = 10.0,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = HARDWARE_STAT_EVENTS,
        event_source: Literal["auto", "hardware_required", "software_only"] = "auto",
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ArtifactReference:
        _require_project_execution(config)
        safe_project = policy.workspace_root(project_root)
        executable_candidate = Path(executable).expanduser()
        if not executable_candidate.is_absolute():
            executable_candidate = safe_project / executable_candidate
        safe_executable = policy.input_file(str(executable_candidate))
        assert config.collector_socket is not None
        collection, project_run = collect_project_workload(
            ProjectWorkloadRequest(
                project_root=safe_project,
                executable=safe_executable,
                arguments=arguments,
                authorization=authorization,
                mode=mode,
                duration_seconds=duration_seconds,
                frequency_hz=frequency_hz,
                call_graph=call_graph,
                events=events,
                event_source=event_source,
                max_output_bytes=max_output_bytes,
            ),
            policy=config.automatic_collection_policy,
            capabilities=inspect_collection_capabilities(config.perf_path),
            collector_socket=config.collector_socket,
        )
        if isinstance(collection, TraceEvidenceArtifact):
            store.save(
                collection,
                collection.trace_evidence_id,
                "trace-evidence",
            )
            collection_summary: dict[str, str | int | float | bool | None] = {
                "actual_event_source": "kernel_trace",
                "record_event": None,
                "fallback_used": False,
                "fallback_reason": None,
                "evidence_limitations": "; ".join(collection.quality.limitations),
                "warnings": "",
                "trace_quality": collection.quality.quality_status,
                "trace_event_count": len(collection.events),
            }
        else:
            store.save(collection, collection.collection_id, "collection")
            collection_summary = {
                "actual_event_source": collection.actual_event_source,
                "record_event": collection.record_event,
                "fallback_used": collection.fallback_used,
                "fallback_reason": collection.fallback_reason,
                "evidence_limitations": "; ".join(collection.evidence_limitations),
                "warnings": "; ".join(collection.warnings),
            }
        store.save(project_run, project_run.project_run_id, "project-run")
        return ArtifactReference(
            artifact_id=project_run.project_run_id,
            artifact_type="project-run",
            uri=store.uri(project_run.project_run_id, "project-run"),
            summary={
                "collection_id": project_run.collection_id,
                "mode": project_run.mode,
                "target_pid": project_run.target_pid,
                "workload_status": project_run.workload_status,
                "workload_exit_code": project_run.workload_exit_code,
                **collection_summary,
            },
        )

    @server.tool(
        name="analyze_collection",
        description="Analyze a stored CPU record collection artifact.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "PROCESS_EXECUTION"},
        structured_output=True,
    )
    async def analyze_collection(collection_id: str) -> ArtifactReference:
        _require_process_execution(config)
        collection = store.load_collection(collection_id)
        if collection.mode in {"sched", "lock", "off_cpu"}:
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "trace_evidence",
                (
                    "Raw trace collections cannot use the on-CPU profile analyzer; "
                    "a verified target-scoped TraceEvidence artifact is required"
                ),
                recoverable=True,
                suggested_actions=(
                    "Use the dedicated Trace adapter and analyze_trace_evidence workflow.",
                    "Do not expose the private raw trace spool to the MCP process.",
                ),
            )
        if collection.output_format != "perf_data":
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "collection",
                "perf stat metrics are already stored in the collection artifact",
                recoverable=True,
            )
        safe_path = policy.input_file(collection.output_path)
        symbol_context: ContainerSymbolContextArtifact | None = None
        if collection.target_runtime == "docker":
            snapshot = store.load_container_module_snapshot_for_collection(collection_id)
            if snapshot is None:
                snapshot = capture_container_module_snapshot(
                    collection,
                    perf_path=config.perf_path,
                )
                store.save(
                    snapshot,
                    snapshot.module_snapshot_id,
                    "container-module-snapshot",
                )
            workspace_root = docker_policy.path.parent.parent if docker_policy is not None else None
            if workspace_root is None:
                analysis = analyze_perf_data(
                    safe_path,
                    perf_path=config.perf_path,
                    collection=build_collection_evidence_provenance(collection),
                )
            else:
                with materialize_container_workspace_symfs(
                    collection,
                    snapshot,
                    workspace_root=workspace_root,
                    perf_path=config.perf_path,
                ) as symfs:
                    analysis = analyze_perf_data(
                        safe_path,
                        perf_path=config.perf_path,
                        collection=build_collection_evidence_provenance(collection),
                        symfs_path=symfs.root if symfs is not None else None,
                        symfs_identity_sha256=(
                            symfs.identity_sha256 if symfs is not None else None
                        ),
                    )
            symbol_context = build_container_symbol_context(
                analysis,
                snapshot,
                workspace_root=workspace_root,
            )
            analysis, symbol_context = project_container_analysis(
                analysis,
                symbol_context,
            )
        else:
            analysis = analyze_perf_data(
                safe_path,
                perf_path=config.perf_path,
                collection=build_collection_evidence_provenance(collection),
            )
        store.save(analysis, analysis.analysis_id, "analysis")
        if symbol_context is not None:
            store.save(
                symbol_context,
                symbol_context.symbol_context_id,
                "container-symbol-context",
            )
        return ArtifactReference(
            artifact_id=analysis.analysis_id,
            artifact_type="analysis",
            uri=store.uri(analysis.analysis_id, "analysis"),
            summary={
                "status": analysis.status,
                "quality_status": analysis.evidence_quality.quality_status,
                "sample_count": analysis.metadata.sample_count,
                "total_weight": analysis.metadata.total_weight,
                "hotspot_count": len(analysis.hotspots),
                "unresolved_self_percent": (analysis.evidence_quality.unresolved_self_percent),
                "kernel_context_self_percent": (
                    analysis.evidence_quality.kernel_context_self_percent
                ),
                "user_context_self_percent": (analysis.evidence_quality.user_context_self_percent),
                "unknown_context_self_percent": (
                    analysis.evidence_quality.unknown_context_self_percent
                ),
                "unresolved_kernel_self_percent": (
                    analysis.evidence_quality.unresolved_kernel_self_percent
                ),
                "unresolved_user_self_percent": (
                    analysis.evidence_quality.unresolved_user_self_percent
                ),
                "warning_count": analysis.evidence_quality.warning_count,
                **_container_symbol_summary(
                    symbol_context,
                    uri=(
                        store.uri(
                            symbol_context.symbol_context_id,
                            "container-symbol-context",
                        )
                        if symbol_context is not None
                        else None
                    ),
                ),
            },
            evidence_quality=analysis.evidence_quality,
        )

    @server.tool(
        name="analyze_trace_evidence",
        description=(
            "Deterministically analyze a stored, normalized sched/off-CPU/lock TraceEvidence "
            "artifact and verify it before Agent use."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def analyze_trace_evidence(trace_evidence_id: str) -> ArtifactReference:
        evidence = store.load_trace_evidence(trace_evidence_id)
        analysis = build_trace_analysis(evidence)
        verification = verify_trace_analysis_artifact(analysis, evidence)
        require_usable_trace_analysis(verification)
        analysis_id, artifact_type = _trace_analysis_identity(analysis)
        store.save(analysis, analysis_id, artifact_type)
        summary: dict[str, str | int | float | bool | None] = {
            "mode": analysis.mode,
            "status": analysis.status,
            "quality_status": analysis.quality.quality_status,
            "trace_evidence_id": analysis.trace_evidence_id,
            "artifact_content_sha256": analysis.content_sha256,
            "verification_status": verification.verification_status,
            "observed_event_count": analysis.event_accounting.observed_event_count,
            "unpaired_event_count": analysis.event_accounting.unpaired.total_count,
            "limitation_count": len(analysis.quality.limitations),
        }
        summary["summary_sha256"] = canonical_trace_json_sha256(summary)
        return ArtifactReference(
            artifact_id=analysis_id,
            artifact_type=artifact_type,
            uri=store.uri(analysis_id, artifact_type),
            summary=summary,
        )

    @server.tool(
        name="analyze_runtime_lock_evidence",
        description=(
            "Deterministically analyze one stored, normalized Runtime Lock Evidence artifact, "
            "independently verify every projection, and persist both immutable results."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def analyze_runtime_lock_evidence(
        runtime_lock_evidence_id: str,
    ) -> ArtifactReference:
        evidence = store.load_runtime_lock_evidence(runtime_lock_evidence_id)
        analysis = build_runtime_lock_analysis(evidence)
        verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
        require_usable_runtime_lock_analysis(verification)
        store.save(
            analysis,
            analysis.runtime_lock_analysis_id,
            "runtime-lock-analysis",
        )
        store.save(
            verification,
            verification.runtime_lock_verification_id,
            "runtime-lock-verification",
        )
        return ArtifactReference(
            artifact_id=analysis.runtime_lock_analysis_id,
            artifact_type="runtime-lock-analysis",
            uri=store.uri(
                analysis.runtime_lock_analysis_id,
                "runtime-lock-analysis",
            ),
            summary={
                "runtime": analysis.runtime,
                "measurement_semantics": analysis.measurement_semantics,
                "quality_status": analysis.quality_status,
                "runtime_lock_evidence_id": analysis.runtime_lock_evidence_id,
                "verification_status": verification.verification_status,
                "verification_id": verification.runtime_lock_verification_id,
                "lock_hotspot_count": len(analysis.aggregates),
                "call_path_count": len(analysis.call_path_aggregates),
                "total_observed_or_estimated_wait_ns": (
                    analysis.total_observed_or_estimated_wait_ns
                ),
                "omitted_lock_count": analysis.omitted_lock_count,
            },
        )

    @server.tool(
        name="verify_runtime_lock_analysis",
        description=(
            "Independently replay a stored Runtime Lock Analysis from its bound Evidence before "
            "Agent interpretation."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def verify_runtime_lock_analysis(
        runtime_lock_analysis_id: str,
    ) -> RuntimeLockAnalysisVerificationArtifact:
        analysis, evidence, _ = store.load_runtime_lock_analysis(runtime_lock_analysis_id)
        return verify_runtime_lock_analysis_artifact(analysis, evidence)

    @server.tool(
        name="list_runtime_lock_hotspots",
        description=(
            "Return one bounded page from a verified Runtime Lock lock/context/path/outcome/kind "
            "projection without mixing measurement semantics."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def list_runtime_lock_hotspots(
        runtime_lock_analysis_id: str,
        projection: Literal[
            "lock",
            "execution_context",
            "call_path",
            "wait_outcome",
            "lock_kind",
        ] = "lock",
        sort_by: Literal[
            "observed_or_estimated_wait_ns",
            "exact_wait_count",
            "thresholded_wait_count",
            "sampled_observation_count",
            "cumulative_observation_count",
            "exact_hold_ns",
            "owner_observed_count",
        ] = "observed_or_estimated_wait_ns",
        cursor: int = 0,
        limit: int = 30,
    ) -> RuntimeLockHotspotPage:
        analysis, _, _ = store.load_runtime_lock_analysis(runtime_lock_analysis_id)
        return query_runtime_lock_hotspots(
            analysis,
            projection=projection,
            sort_by=sort_by,
            cursor=cursor,
            limit=limit,
        )

    @server.tool(
        name="get_runtime_lock_call_paths",
        description=(
            "Return a bounded verified Runtime Lock call-path page joined only to redacted "
            "public stack frames."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def get_runtime_lock_call_paths(
        runtime_lock_analysis_id: str,
        cursor: int = 0,
        limit: int = 20,
    ) -> RuntimeLockCallPathPage:
        analysis, evidence, _ = store.load_runtime_lock_analysis(runtime_lock_analysis_id)
        return query_runtime_lock_call_paths(
            analysis,
            evidence,
            cursor=cursor,
            limit=limit,
        )

    @server.tool(
        name="compare_runtime_lock_analyses",
        description=(
            "Deterministically compare two independently verified Runtime Lock Runs from the "
            "same bounded authority. Docker Runs require one stored matched-container "
            "comparison; standalone Runs remain resource-incomplete."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def compare_runtime_lock_analyses_tool(
        baseline_run_id: str,
        candidate_run_id: str,
        container_comparison_id: str | None = None,
    ) -> RuntimeLockComparisonArtifact:
        baseline_run = store.load_runtime_lock_run(baseline_run_id)
        candidate_run = store.load_runtime_lock_run(candidate_run_id)
        baseline_analysis, baseline_evidence, _ = store.load_runtime_lock_analysis(
            baseline_run.runtime_lock_analysis_id
        )
        candidate_analysis, candidate_evidence, _ = store.load_runtime_lock_analysis(
            candidate_run.runtime_lock_analysis_id
        )
        baseline_verification = store.load_runtime_lock_verification(
            baseline_run.runtime_lock_verification_id
        )
        candidate_verification = store.load_runtime_lock_verification(
            candidate_run.runtime_lock_verification_id
        )

        def resource_environment(
            run: RuntimeLockRunArtifact,
            evidence: RuntimeLockEvidenceArtifact,
        ) -> str:
            binding = run.docker_optimization_binding
            if run.authorization_kind == "docker_optimization":
                if binding is None:
                    raise PerfLensError(
                        ErrorCode.PROFILE_PARSE_FAILED,
                        "runtime_lock_comparison",
                        "Docker Runtime Lock Run lacks its resource binding",
                    )
                measurement = store.load_container_measurement(binding.container_measurement_id)
                return docker_runtime_lock_fixed_environment_sha256(measurement)
            return runtime_lock_resource_environment_sha256(run, evidence)

        resource_transfer_status: Literal["no_observed_regression", "regression", "incomplete"] = (
            "incomplete"
        )
        resource_comparison_content_sha256: str | None = None
        baseline_build: DockerBuildArtifact | None = None
        candidate_build: DockerBuildArtifact | None = None
        if baseline_run.authorization_kind == "docker_optimization":
            if container_comparison_id is None:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_comparison",
                    "Docker Runtime Lock comparison requires a bound container comparison",
                    recoverable=True,
                )
            resource_comparison = store.load_container_matched_comparison(container_comparison_id)
            baseline_binding = baseline_run.docker_optimization_binding
            candidate_binding = candidate_run.docker_optimization_binding
            if (
                baseline_binding is None
                or candidate_binding is None
                or resource_comparison.baseline_measurement_id
                != baseline_binding.container_measurement_id
                or resource_comparison.candidate_measurement_id
                != candidate_binding.container_measurement_id
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_comparison",
                    "Container comparison does not bind the selected Runtime Lock Runs",
                    recoverable=False,
                )
            resource_transfer_status = resource_comparison.resource_transfer_status
            resource_comparison_content_sha256 = resource_comparison.content_sha256
            baseline_build = store.load_docker_build(baseline_binding.build_id)
            candidate_build = store.load_docker_build(candidate_binding.build_id)
        elif container_comparison_id is not None:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_comparison",
                "Standalone Runtime Lock comparison cannot claim Docker resource evidence",
                recoverable=True,
            )

        comparison = compare_runtime_lock_artifacts(
            baseline_run=baseline_run,
            baseline_analysis=baseline_analysis,
            baseline_evidence=baseline_evidence,
            baseline_verification=baseline_verification,
            candidate_run=candidate_run,
            candidate_analysis=candidate_analysis,
            candidate_evidence=candidate_evidence,
            candidate_verification=candidate_verification,
            baseline_resource_environment_sha256=resource_environment(
                baseline_run, baseline_evidence
            ),
            candidate_resource_environment_sha256=resource_environment(
                candidate_run, candidate_evidence
            ),
            resource_transfer_status=resource_transfer_status,
            resource_comparison_id=container_comparison_id,
            resource_comparison_content_sha256=resource_comparison_content_sha256,
            baseline_build=baseline_build,
            candidate_build=candidate_build,
        )
        store.save(comparison, comparison.comparison_id, "runtime-lock-comparison")
        return comparison

    @server.tool(
        name="build_runtime_lock_diagnosis_bundle",
        description=(
            "Build and store one bounded evidence-constrained Runtime Lock diagnosis; it never "
            "upgrades an observation to a root cause or Verified Improvement."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def build_runtime_lock_diagnosis_bundle(
        runtime_lock_analysis_id: str,
    ) -> ArtifactReference:
        analysis, evidence, verification = store.load_runtime_lock_analysis(
            runtime_lock_analysis_id
        )
        diagnosis = create_runtime_lock_diagnosis(
            analysis,
            evidence,
            verification,
        )
        store.save(
            diagnosis,
            diagnosis.runtime_lock_diagnosis_id,
            "runtime-lock-diagnosis",
        )
        return ArtifactReference(
            artifact_id=diagnosis.runtime_lock_diagnosis_id,
            artifact_type="runtime-lock-diagnosis",
            uri=store.uri(
                diagnosis.runtime_lock_diagnosis_id,
                "runtime-lock-diagnosis",
            ),
            summary={
                "runtime_lock_analysis_id": diagnosis.runtime_lock_analysis_id,
                "runtime": diagnosis.runtime,
                "measurement_semantics": diagnosis.measurement_semantics,
                "quality_status": diagnosis.quality_status,
                "observation_count": len(diagnosis.observations),
                "limitation_count": len(diagnosis.limitations),
                "top_lock_count": len(diagnosis.top_lock_ids),
                "top_call_path_count": len(diagnosis.top_stack_ids),
            },
        )

    @server.tool(
        name="verify_trace_analysis",
        description=(
            "Replay and verify a stored sched/off-CPU/lock analysis before Agent interpretation."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def verify_trace_analysis(
        analysis_id: str,
    ) -> TraceAnalysisVerificationArtifact:
        analysis, evidence, _ = store.load_trace_analysis(analysis_id)
        return verify_trace_analysis_artifact(analysis, evidence)

    @server.tool(
        name="analyze_profile",
        description="Analyze an allowed folded, perf-script, or perf.data profile and store JSON.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def analyze_profile(
        path: str,
        source_type: Literal["auto", "folded", "perf_script", "perf_data"] = "auto",
    ) -> ArtifactReference:
        safe_path = policy.input_file(path)
        selected = _detect_source_type(safe_path) if source_type == "auto" else source_type
        if selected == "folded":
            analysis = analyze_folded(safe_path)
        elif selected == "perf_script":
            analysis = analyze_perf_script(safe_path)
        else:
            _require_process_execution(config)
            analysis = analyze_perf_data(safe_path, perf_path=config.perf_path)
        store.save(analysis, analysis.analysis_id, "analysis")
        return ArtifactReference(
            artifact_id=analysis.analysis_id,
            artifact_type="analysis",
            uri=store.uri(analysis.analysis_id, "analysis"),
            summary={
                "status": analysis.status,
                "quality_status": analysis.evidence_quality.quality_status,
                "sample_count": analysis.metadata.sample_count,
                "total_weight": analysis.metadata.total_weight,
                "hotspot_count": len(analysis.hotspots),
                "unresolved_self_percent": (analysis.evidence_quality.unresolved_self_percent),
                "kernel_context_self_percent": (
                    analysis.evidence_quality.kernel_context_self_percent
                ),
                "user_context_self_percent": (analysis.evidence_quality.user_context_self_percent),
                "unknown_context_self_percent": (
                    analysis.evidence_quality.unknown_context_self_percent
                ),
                "unresolved_kernel_self_percent": (
                    analysis.evidence_quality.unresolved_kernel_self_percent
                ),
                "unresolved_user_self_percent": (
                    analysis.evidence_quality.unresolved_user_self_percent
                ),
                "warning_count": analysis.evidence_quality.warning_count,
            },
            evidence_quality=analysis.evidence_quality,
        )

    @server.tool(
        name="verify_analysis",
        description=(
            "Independently verify a stored Analysis fingerprint, metadata consistency, and "
            "weight conservation before Agent interpretation."
        ),
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def verify_analysis(analysis_id: str) -> AnalysisVerificationArtifact:
        analysis = store.load_analysis(analysis_id)
        return verify_analysis_artifact(analysis, verify_source=False)

    @server.tool(
        name="list_hotspots",
        description="Return a bounded page of hotspots from a stored analysis.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def list_hotspots(
        analysis_id: str,
        sort_by: Literal["self_percent", "inclusive_percent"] = "self_percent",
        cursor: int = 0,
        limit: int = 30,
        category: str | None = None,
    ) -> HotspotPage:
        if cursor < 0 or limit < 1 or limit > 100:
            raise ValueError("cursor must be non-negative and limit must be between 1 and 100")
        analysis = store.load_analysis(analysis_id)
        diagnosis = create_diagnosis(analysis) if category is not None else None
        permitted_ids = (
            {item.hotspot_id for item in diagnosis.classifications if item.category == category}
            if diagnosis is not None
            else None
        )
        items = [
            hotspot
            for hotspot in analysis.hotspots
            if permitted_ids is None or hotspot.hotspot_id in permitted_ids
        ]
        items.sort(key=lambda item: (-getattr(item, sort_by), item.symbol, item.dso))
        page = tuple(items[cursor : cursor + limit])
        next_cursor = cursor + len(page) if cursor + len(page) < len(items) else None
        return HotspotPage(
            analysis_id=analysis_id,
            evidence_quality=analysis.evidence_quality,
            items=page,
            next_cursor=next_cursor,
            total_items=len(items),
        )

    @server.tool(
        name="get_hotspot_details",
        description="Return one hotspot with bounded dominant paths, classifications, and limits.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def get_hotspot_details(
        analysis_id: str,
        hotspot_id: str,
        call_path_limit: int = 10,
    ) -> HotspotDetails:
        if call_path_limit < 1 or call_path_limit > 50:
            raise ValueError("call_path_limit must be between 1 and 50")
        analysis = store.load_analysis(analysis_id)
        hotspot = next((item for item in analysis.hotspots if item.hotspot_id == hotspot_id), None)
        if hotspot is None:
            raise ValueError("hotspot_id was not found in the analysis")
        paths = tuple(
            path
            for path in analysis.call_paths
            if any(
                frame.symbol == hotspot.symbol and frame.dso == hotspot.dso for frame in path.frames
            )
        )[:call_path_limit]
        container_symbols = store.load_container_symbol_context_for_analysis(analysis_id)
        diagnosis = create_diagnosis(
            analysis,
            container_symbols=container_symbols,
        )
        classifications = tuple(
            item for item in diagnosis.classifications if item.hotspot_id == hotspot_id
        )
        return HotspotDetails(
            analysis_id=analysis_id,
            evidence_quality=analysis.evidence_quality,
            hotspot=hotspot,
            dominant_call_paths=paths,
            classifications=classifications,
            limitations=diagnosis.limitations,
        )

    @server.tool(
        name="get_call_paths",
        description="Return a bounded page of dominant call paths, optionally containing a symbol.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def get_call_paths(
        analysis_id: str,
        symbol: str | None = None,
        cursor: int = 0,
        limit: int = 20,
    ) -> CallPathPage:
        if cursor < 0 or limit < 1 or limit > 100:
            raise ValueError("cursor must be non-negative and limit must be between 1 and 100")
        analysis = store.load_analysis(analysis_id)
        items = [
            path
            for path in analysis.call_paths
            if symbol is None or any(frame.symbol == symbol for frame in path.frames)
        ]
        page = tuple(items[cursor : cursor + limit])
        next_cursor = cursor + len(page) if cursor + len(page) < len(items) else None
        return CallPathPage(
            analysis_id=analysis_id,
            evidence_quality=analysis.evidence_quality,
            symbol=symbol,
            items=page,
            next_cursor=next_cursor,
            total_items=len(items),
        )

    @server.tool(
        name="classify_hotspots",
        description="Apply generic candidate-only rules and return a bounded classification page.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def classify_hotspots(
        analysis_id: str,
        cursor: int = 0,
        limit: int = 30,
    ) -> ClassificationPage:
        if cursor < 0 or limit < 1 or limit > 100:
            raise ValueError("cursor must be non-negative and limit must be between 1 and 100")
        analysis = store.load_analysis(analysis_id)
        container_symbols = store.load_container_symbol_context_for_analysis(analysis_id)
        diagnosis = create_diagnosis(
            analysis,
            container_symbols=container_symbols,
        )
        items = diagnosis.classifications
        page = items[cursor : cursor + limit]
        next_cursor = cursor + len(page) if cursor + len(page) < len(items) else None
        return ClassificationPage(
            analysis_id=analysis_id,
            evidence_quality=analysis.evidence_quality,
            items=page,
            next_cursor=next_cursor,
            total_items=len(items),
        )

    @server.tool(
        name="build_diagnosis_bundle",
        description="Build and store the full evidence-constrained diagnosis artifact.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def build_diagnosis_bundle(analysis_id: str) -> ArtifactReference:
        analysis = store.load_analysis(analysis_id)
        container_symbols = store.load_container_symbol_context_for_analysis(analysis_id)
        artifact_id = f"diagnosis-{analysis_id}"
        diagnosis = store.load_diagnosis(analysis_id)
        if diagnosis is None:
            candidate = create_diagnosis(
                analysis,
                container_symbols=container_symbols,
            )
            try:
                store.save(candidate, artifact_id, "diagnosis")
                diagnosis = candidate
            except PerfLensError as exc:
                # Another request may have published the immutable diagnosis
                # after the initial lookup. Reuse only a fully verified bundle
                # for this exact Analysis; unrelated storage failures remain
                # visible to the caller.
                diagnosis = store.load_diagnosis(analysis_id)
                if diagnosis is None:
                    raise exc
        return ArtifactReference(
            artifact_id=artifact_id,
            artifact_type="diagnosis",
            uri=store.uri(artifact_id, "diagnosis"),
            summary={
                "status": diagnosis.status,
                "classification_count": len(diagnosis.classifications),
                "missing_evidence_count": len(diagnosis.missing_evidence),
                "container_symbol_quality": diagnosis.container_symbol_quality_status,
            },
            evidence_quality=analysis.evidence_quality,
        )

    @server.tool(
        name="read_artifact_page",
        description="Read at most 64 KiB from a stored JSON artifact.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def read_artifact_page(
        artifact_id: str,
        artifact_type: Literal[
            "analysis",
            "benchmark",
            "benchmark-comparison",
            "collection",
            "diagnosis",
            "profile-comparison",
            "project-run",
            "trace-evidence",
            "scheduler-analysis",
            "off-cpu-analysis",
            "lock-analysis",
            "runtime-lock-capability",
            "runtime-lock-preview",
            "runtime-lock-evidence",
            "runtime-lock-analysis",
            "runtime-lock-verification",
            "runtime-lock-diagnosis",
            "runtime-lock-session",
            "runtime-lock-run",
            "runtime-lock-comparison",
            "container-resource-context",
            "container-run",
            "container-workload-spec",
            "container-measurement",
            "container-matched-comparison",
            "container-module-snapshot",
            "container-symbol-context",
        ],
        offset: int = 0,
        limit: int = 65_536,
    ) -> ArtifactTextPage:
        text, next_offset, total = store.read_page(
            artifact_id,
            artifact_type,
            offset=offset,
            limit=limit,
        )
        return ArtifactTextPage(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            text=text,
            next_offset=next_offset,
            total_bytes=total,
        )

    @server.tool(
        name="resolve_source",
        description="Resolve a verified module offset using an allowed ELF/debug file.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "PROCESS_EXECUTION"},
        structured_output=True,
    )
    async def resolve_source(
        binary_path: str,
        module_offset: int,
        runtime_address: int | None = None,
    ) -> SourceResolutionArtifact:
        _require_process_execution(config)
        safe_binary = policy.input_file(binary_path)
        return resolve_module_source(
            safe_binary,
            module_offset,
            runtime_address=runtime_address,
        )

    @server.tool(
        name="get_source_context",
        description="Read bounded source lines within one configured allowed workspace.",
        annotations=READ_ONLY,
        meta={"perflens/permission": "READ_ONLY"},
        structured_output=True,
    )
    async def get_source_context(
        file: str,
        line: int,
        workspace_root: str,
        before: int = 20,
        after: int = 20,
    ) -> SourceContextArtifact:
        safe_file = policy.input_file(file)
        safe_workspace = policy.workspace_root(workspace_root)
        return resolve_source_context(
            safe_file,
            line,
            workspace_root=safe_workspace,
            before=before,
            after=after,
        )

    @server.tool(
        name="analyze_benchmark",
        description="Normalize a supported benchmark JSON file and store the typed artifact.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def analyze_benchmark(
        path: str,
        source_format: Literal[
            "auto", "perflens", "pyperf", "google_benchmark", "hyperfine"
        ] = "auto",
        benchmark_name: str | None = None,
    ) -> ArtifactReference:
        benchmark = load_benchmark(
            policy.input_file(path),
            source_format=source_format,
            benchmark_name=benchmark_name,
        )
        store.save(benchmark, benchmark.benchmark_id, "benchmark")
        return ArtifactReference(
            artifact_id=benchmark.benchmark_id,
            artifact_type="benchmark",
            uri=store.uri(benchmark.benchmark_id, "benchmark"),
            summary={
                "name": benchmark.name,
                "repetitions": benchmark.repetitions,
                "metric_count": len(benchmark.metrics),
                "source_format": benchmark.source_format,
            },
        )

    @server.tool(
        name="compare_profiles",
        description="Compare two stored analyses and store bounded profile-difference evidence.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def compare_profiles(
        baseline_analysis_id: str,
        candidate_analysis_id: str,
        minimum_delta_percent: float = 1.0,
    ) -> ArtifactReference:
        comparison = compare_profile_artifacts(
            store.load_analysis(baseline_analysis_id),
            store.load_analysis(candidate_analysis_id),
            minimum_delta_percent=minimum_delta_percent,
        )
        store.save(comparison, comparison.comparison_id, "profile-comparison")
        return ArtifactReference(
            artifact_id=comparison.comparison_id,
            artifact_type="profile-comparison",
            uri=store.uri(comparison.comparison_id, "profile-comparison"),
            summary={
                "comparable": comparison.comparable,
                "hotspot_delta_count": len(comparison.hotspot_deltas),
                "call_path_delta_count": len(comparison.call_path_deltas),
            },
        )

    @server.tool(
        name="compare_benchmarks",
        description="Compare repeated benchmark values with condition and impact checks.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def compare_benchmarks(
        baseline_benchmark_id: str,
        candidate_benchmark_id: str,
        minimum_practical_impact_percent: float = 1.0,
    ) -> ArtifactReference:
        comparison = compare_benchmark_artifacts(
            store.load_benchmark(baseline_benchmark_id),
            store.load_benchmark(candidate_benchmark_id),
            minimum_practical_impact_percent=minimum_practical_impact_percent,
        )
        store.save(comparison, comparison.comparison_id, "benchmark-comparison")
        return ArtifactReference(
            artifact_id=comparison.comparison_id,
            artifact_type="benchmark-comparison",
            uri=store.uri(comparison.comparison_id, "benchmark-comparison"),
            summary={
                "comparable": comparison.comparable,
                "metric_count": len(comparison.metrics),
                "insufficient_metric_count": sum(
                    item.status == "insufficient_data" for item in comparison.metrics
                ),
            },
        )

    @server.tool(
        name="compare_container_measurements",
        description=(
            "Compare two Docker measurements using bound profile, absolute benchmark, "
            "correctness, treatment, and whole-container resource evidence."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def compare_container_measurement_artifacts(
        baseline_measurement_id: str,
        candidate_measurement_id: str,
        baseline_analysis_id: str,
        candidate_analysis_id: str,
        baseline_benchmark_id: str,
        candidate_benchmark_id: str,
        minimum_delta_percent: float = 1.0,
        minimum_practical_impact_percent: float = 1.0,
    ) -> ArtifactReference:
        baseline_measurement = store.load_container_measurement(baseline_measurement_id)
        candidate_measurement = store.load_container_measurement(candidate_measurement_id)
        baseline_analysis = store.load_analysis(baseline_analysis_id)
        candidate_analysis = store.load_analysis(candidate_analysis_id)
        baseline_benchmark = store.load_benchmark(baseline_benchmark_id)
        candidate_benchmark = store.load_benchmark(candidate_benchmark_id)
        profile_comparison = compare_profile_artifacts(
            baseline_analysis,
            candidate_analysis,
            minimum_delta_percent=minimum_delta_percent,
        )
        benchmark_comparison = compare_benchmark_artifacts(
            baseline_benchmark,
            candidate_benchmark,
            minimum_practical_impact_percent=minimum_practical_impact_percent,
        )
        comparison: ContainerMatchedComparisonArtifact = compare_container_measurements(
            baseline_measurement,
            candidate_measurement,
            baseline_analysis=baseline_analysis,
            candidate_analysis=candidate_analysis,
            profile_comparison=profile_comparison,
            baseline_benchmark=baseline_benchmark,
            candidate_benchmark=candidate_benchmark,
            benchmark_comparison=benchmark_comparison,
        )
        store.save(
            profile_comparison,
            profile_comparison.comparison_id,
            "profile-comparison",
        )
        store.save(
            benchmark_comparison,
            benchmark_comparison.comparison_id,
            "benchmark-comparison",
        )
        store.save(
            comparison,
            comparison.comparison_id,
            "container-matched-comparison",
        )
        return ArtifactReference(
            artifact_id=comparison.comparison_id,
            artifact_type="container-matched-comparison",
            uri=store.uri(
                comparison.comparison_id,
                "container-matched-comparison",
            ),
            summary={
                "comparable": comparison.comparable,
                "environment_match": comparison.environment_match,
                "treatment_changed": comparison.treatment_changed,
                "correctness_status": comparison.correctness_status,
                "resource_transfer_status": comparison.resource_transfer_status,
                "conclusion": comparison.conclusion,
                "improved_metrics": "; ".join(comparison.improved_metrics),
                "regressed_metrics": "; ".join(comparison.regressed_metrics),
                "warnings": "; ".join(comparison.warnings),
            },
        )

    @server.tool(
        name="compare_docker_optimization_iterations",
        description=(
            "Deterministically compare one authorized baseline/candidate Build pair using "
            "bound container measurements, profiles, Benchmark correctness, resource deltas, "
            "and fixed-environment invariants. Different final image digests are accepted only "
            "as session-bound Treatment evidence."
        ),
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "WRITES_ARTIFACTS"},
        structured_output=True,
    )
    async def compare_docker_optimization_iterations(
        session_id: str,
        baseline_build_id: str,
        candidate_build_id: str,
        baseline_measurement_id: str,
        candidate_measurement_id: str,
        baseline_analysis_id: str,
        candidate_analysis_id: str,
        baseline_benchmark_id: str,
        candidate_benchmark_id: str,
        runtime_lock_comparison_id: str | None = None,
        minimum_delta_percent: float = 1.0,
        minimum_practical_impact_percent: float = 1.0,
    ) -> ArtifactReference:
        runtime = get_docker_optimization_runtime()
        session = runtime.snapshot(session_id)
        baseline_build = runtime.build_result(session_id, baseline_build_id).artifact
        candidate_build = runtime.build_result(session_id, candidate_build_id).artifact
        baseline_measurement = store.load_container_measurement(baseline_measurement_id)
        candidate_measurement = store.load_container_measurement(candidate_measurement_id)
        baseline_analysis = store.load_analysis(baseline_analysis_id)
        candidate_analysis = store.load_analysis(candidate_analysis_id)
        baseline_benchmark = store.load_benchmark(baseline_benchmark_id)
        candidate_benchmark = store.load_benchmark(candidate_benchmark_id)
        runtime_lock_comparison = (
            store.load_runtime_lock_comparison(runtime_lock_comparison_id)
            if runtime_lock_comparison_id is not None
            else None
        )
        profile_comparison = compare_profile_artifacts(
            baseline_analysis,
            candidate_analysis,
            minimum_delta_percent=minimum_delta_percent,
        )
        benchmark_comparison = compare_benchmark_artifacts(
            baseline_benchmark,
            candidate_benchmark,
            minimum_practical_impact_percent=minimum_practical_impact_percent,
        )
        source_comparison = compare_container_measurements(
            baseline_measurement,
            candidate_measurement,
            baseline_analysis=baseline_analysis,
            candidate_analysis=candidate_analysis,
            profile_comparison=profile_comparison,
            baseline_benchmark=baseline_benchmark,
            candidate_benchmark=candidate_benchmark,
            benchmark_comparison=benchmark_comparison,
        )
        iteration: DockerOptimizationIterationArtifact = compare_docker_optimization_iteration(
            session=session,
            baseline_build=baseline_build,
            candidate_build=candidate_build,
            baseline_measurement=baseline_measurement,
            candidate_measurement=candidate_measurement,
            baseline_analysis=baseline_analysis,
            candidate_analysis=candidate_analysis,
            profile_comparison=profile_comparison,
            baseline_benchmark=baseline_benchmark,
            candidate_benchmark=candidate_benchmark,
            benchmark_comparison=benchmark_comparison,
            source_container_comparison=source_comparison,
            runtime_lock_comparison=runtime_lock_comparison,
        )
        store.save(profile_comparison, profile_comparison.comparison_id, "profile-comparison")
        store.save(
            benchmark_comparison,
            benchmark_comparison.comparison_id,
            "benchmark-comparison",
        )
        store.save(
            source_comparison,
            source_comparison.comparison_id,
            "container-matched-comparison",
        )
        store.save(
            iteration,
            iteration.iteration_id,
            "docker-optimization-iteration",
        )
        return ArtifactReference(
            artifact_id=iteration.iteration_id,
            artifact_type="docker-optimization-iteration",
            uri=store.uri(iteration.iteration_id, "docker-optimization-iteration"),
            summary=_docker_optimization_iteration_summary(
                iteration,
                profile_comparable=profile_comparison.comparable,
                benchmark_comparable=benchmark_comparison.comparable,
                source_environment_match=source_comparison.environment_match,
                baseline_profile_quality_status=(baseline_analysis.evidence_quality.quality_status),
                candidate_profile_quality_status=(
                    candidate_analysis.evidence_quality.quality_status
                ),
                baseline_profile_sample_count=baseline_analysis.metadata.sample_count,
                candidate_profile_sample_count=candidate_analysis.metadata.sample_count,
                profile_metadata_differences=profile_comparison.metadata_differences,
            ),
        )

    @server.tool(
        name="finalize_docker_optimization_candidate",
        description=(
            "Finalize the source-workspace choice for either one replay-verified Iteration or "
            "a stopped Session whose latest candidate could not be evaluated, revoke the bounded "
            "optimization Session, and clean only verified session resources. "
            "Retaining a non-verified candidate requires a fresh explicit user decision and "
            "never creates or upgrades an A/B conclusion."
        ),
        annotations=REVOKES_DOCKER,
        meta={"perflens/permission": "DOCKER_OPTIMIZATION_DISPOSITION"},
        structured_output=True,
    )
    async def finalize_docker_optimization_candidate(
        session_id: str,
        disposition: Literal["retain_candidate", "restore_baseline"],
        iteration_id: str | None = None,
        candidate_build_id: str | None = None,
        evaluation_reason: OptimizationEvaluationReason | None = None,
        authorization: Literal["I_EXPLICITLY_ACCEPT_THIS_UNVERIFIED_DOCKER_CANDIDATE"]
        | None = None,
    ) -> ArtifactReference:
        iteration = (
            store.load_docker_optimization_iteration(iteration_id)
            if iteration_id is not None
            else None
        )
        result = get_docker_optimization_runtime().finalize_candidate(
            session_id,
            iteration=iteration,
            candidate_build_id=candidate_build_id,
            evaluation_reason=evaluation_reason,
            disposition=disposition,
            explicit_unverified_acceptance=authorization,
        )
        store.save(
            result.session,
            result.session.session_artifact_id,
            "docker-optimization-session",
        )
        store.save(
            result.disposition,
            result.disposition.disposition_id,
            "docker-optimization-disposition",
        )
        return ArtifactReference(
            artifact_id=result.disposition.disposition_id,
            artifact_type="docker-optimization-disposition",
            uri=store.uri(
                result.disposition.disposition_id,
                "docker-optimization-disposition",
            ),
            summary={
                "session_id": result.disposition.session_id,
                "iteration_id": result.disposition.iteration_id,
                "iteration_conclusion": result.disposition.iteration_conclusion,
                "evaluation_reason": result.disposition.evaluation_reason,
                "disposition": result.disposition.disposition,
                "selected_build_id": result.disposition.selected_build_id,
                "workspace_matches_selected_build": (
                    result.disposition.workspace_matches_selected_build
                ),
                "explicit_unverified_acceptance": (
                    result.disposition.explicit_unverified_acceptance
                ),
                "final_session_state": result.disposition.final_session_state,
                "warnings": "; ".join(result.disposition.warnings),
            },
        )

    @server.tool(
        name="collect_profile",
        description=(
            "Run bounded perf record/stat/sched/lock/off-CPU collection only after explicit "
            "server and per-call authorization."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "ACTIVE_COLLECTION"},
        structured_output=True,
    )
    async def collect_profile(
        output_path: str,
        authorization: str,
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "record",
        executable: str | None = None,
        target_arguments: tuple[str, ...] = (),
        pid: int | None = None,
        duration_seconds: float | None = None,
        pid_authorization: str | None = None,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = DEFAULT_STAT_EVENTS,
        timeout_seconds: float = 300.0,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ArtifactReference:
        _require_active_collection(config, pid=pid)
        safe_output = policy.new_output_file(output_path)
        safe_executable = policy.input_file(executable) if executable is not None else None
        artifact = run_collection(
            CollectionRequest(
                mode=mode,
                target=CollectionTarget(
                    executable=safe_executable,
                    arguments=target_arguments,
                    pid=pid,
                    duration_seconds=duration_seconds,
                ),
                output_path=safe_output,
                authorization=authorization,
                pid_authorization=pid_authorization,
                perf_path=config.perf_path,
                frequency_hz=frequency_hz,
                call_graph=call_graph,
                events=events,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        )
        store.save(artifact, artifact.collection_id, "collection")
        return ArtifactReference(
            artifact_id=artifact.collection_id,
            artifact_type="collection",
            uri=store.uri(artifact.collection_id, "collection"),
            summary={
                "mode": artifact.mode,
                "target_type": artifact.target_type,
                "output_bytes": artifact.output_bytes,
                "metric_count": len(artifact.metrics),
            },
        )

    return server


def _trace_analysis_identity(
    analysis: SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact,
) -> tuple[str, str]:
    if isinstance(analysis, SchedulerAnalysisArtifact):
        return analysis.scheduler_analysis_id, "scheduler-analysis"
    if isinstance(analysis, OffCpuAnalysisArtifact):
        return analysis.off_cpu_analysis_id, "off-cpu-analysis"
    return analysis.lock_analysis_id, "lock-analysis"


def _preflight_managed_collection(
    config: ServerConfig,
    *,
    mode: CollectionMode,
    duration_seconds: float,
    workload_timeout_seconds: int,
    frequency_hz: int,
    max_output_bytes: int,
    trace_max_duration_seconds: int,
) -> None:
    policy = config.automatic_collection_policy
    invalid = (
        mode not in policy.allowed_modes
        or not math.isfinite(duration_seconds)
        or duration_seconds <= 0
        or duration_seconds > policy.max_duration_seconds
        or type(workload_timeout_seconds) is not int
        or workload_timeout_seconds < math.ceil(duration_seconds)
        or workload_timeout_seconds > 1200
        or frequency_hz < 1
        or frequency_hz > policy.max_frequency_hz
        or max_output_bytes < 1
        or max_output_bytes > policy.max_output_bytes
        or (mode in {"sched", "off_cpu", "lock"} and duration_seconds > trace_max_duration_seconds)
    )
    if invalid:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_authorization",
            "Managed Docker collection exceeds its fixed project or MCP bounds",
            recoverable=True,
        )


def _managed_run_reference(
    run: ContainerRunArtifact,
    collection: ArtifactReference,
    session: ContainerOptimizationSessionArtifact,
    resource_context: ContainerResourceContextArtifact,
    module_snapshot: ContainerModuleSnapshotArtifact | None,
    measurement: ContainerMeasurementArtifact | None,
    *,
    evidence_bytes: int,
    uri: str,
    resource_uri: str,
    module_uri: str | None,
    measurement_uri: str | None,
) -> ArtifactReference:
    if isinstance(evidence_bytes, bool) or evidence_bytes <= 0:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "docker_evidence",
            "Managed Docker evidence byte count is invalid",
            recoverable=False,
        )
    return ArtifactReference(
        artifact_id=run.run_id,
        artifact_type="container-run",
        uri=uri,
        summary={
            "docker_session_id": run.session_id,
            "docker_session_state": session.state,
            "container_target_identity_sha256": run.target_identity_sha256,
            "container_pid": run.container_pid,
            "host_pid": run.host_pid,
            "workload_status": run.status,
            "workload_exit_code": run.exit_code,
            "cleanup_status": run.cleanup_status,
            "collection_id": collection.artifact_id,
            "collection_artifact_type": collection.artifact_type,
            "evidence_bytes": evidence_bytes,
            **_container_resource_summary(resource_context, uri=resource_uri),
            **_container_module_summary(module_snapshot, uri=module_uri),
            **_container_measurement_summary(measurement, uri=measurement_uri),
        },
    )


def _managed_evidence_bytes(reference: ArtifactReference) -> int:
    value = reference.summary.get("evidence_bytes")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "docker_optimization_evidence",
            "Managed Docker result does not carry a valid evidence byte count",
            recoverable=False,
        )
    return value


def _docker_optimization_iteration_summary(
    iteration: DockerOptimizationIterationArtifact,
    *,
    profile_comparable: bool,
    benchmark_comparable: bool,
    source_environment_match: bool,
    baseline_profile_quality_status: str,
    candidate_profile_quality_status: str,
    baseline_profile_sample_count: int,
    candidate_profile_sample_count: int,
    profile_metadata_differences: dict[str, tuple[str, str]],
) -> dict[str, str | int | float | bool | None]:
    """Expose the exact comparison chain used by the final Iteration verdict."""
    return {
        "session_id": iteration.session_id,
        "candidate_round": iteration.candidate_round,
        "comparable": iteration.comparable,
        "baseline_build_id": iteration.baseline_build_id,
        "candidate_build_id": iteration.candidate_build_id,
        "baseline_measurement_id": iteration.baseline_measurement_id,
        "candidate_measurement_id": iteration.candidate_measurement_id,
        "baseline_analysis_id": iteration.baseline_analysis_id,
        "candidate_analysis_id": iteration.candidate_analysis_id,
        "profile_comparison_id": iteration.profile_comparison_id,
        "profile_comparable": profile_comparable,
        "baseline_profile_quality_status": baseline_profile_quality_status,
        "candidate_profile_quality_status": candidate_profile_quality_status,
        "baseline_profile_sample_count": baseline_profile_sample_count,
        "candidate_profile_sample_count": candidate_profile_sample_count,
        "profile_sample_count_warning": (
            baseline_profile_sample_count < 100 or candidate_profile_sample_count < 100
        ),
        "profile_sample_count_is_advisory": True,
        "profile_noncomparability_reasons": "; ".join(
            f"{key}: {before} -> {after}"
            for key, (before, after) in sorted(profile_metadata_differences.items())
        ),
        "baseline_benchmark_id": iteration.baseline_benchmark_id,
        "candidate_benchmark_id": iteration.candidate_benchmark_id,
        "benchmark_comparison_id": iteration.benchmark_comparison_id,
        "benchmark_comparable": benchmark_comparable,
        "source_container_comparison_id": iteration.source_container_comparison_id,
        "source_generic_environment_match": source_environment_match,
        "source_comparison_includes_authorized_treatment": True,
        "fixed_environment_match": iteration.fixed_environment_match,
        "treatment_changed": iteration.treatment_changed,
        "correctness_status": iteration.correctness_status,
        "actual_event_source_match": iteration.actual_event_source_match,
        "resource_transfer_status": iteration.resource_transfer_status,
        "deterministic_replay_passed": iteration.deterministic_replay_passed,
        "conclusion": iteration.conclusion,
        "improved_metrics": "; ".join(iteration.improved_metrics),
        "regressed_metrics": "; ".join(iteration.regressed_metrics),
        "warnings": "; ".join(iteration.warnings),
    }


def _finish_optimization_workload_with_evidence(
    runtime: DockerOptimizationRuntime,
    session_id: str,
    lease: DockerOptimizationWorkloadLease,
    *,
    actual_active_seconds: float,
    collected: ArtifactReference,
    additional_evidence_bytes: int = 0,
) -> DockerOptimizationSessionArtifact:
    return runtime.finish_workload(
        session_id,
        lease,
        actual_active_seconds=actual_active_seconds,
        actual_evidence_bytes=(_managed_evidence_bytes(collected) + additional_evidence_bytes),
    )


def _container_resource_summary(
    context: ContainerResourceContextArtifact,
    *,
    uri: str,
) -> dict[str, str | int | float | bool | None]:
    """Project the bounded whole-container context without implying process ownership."""
    return {
        "container_resource_context_id": context.resource_context_id,
        "container_resource_context_uri": uri,
        "container_resource_collection_id": context.source_collection_id,
        "container_resource_output_sha256": context.source_output_sha256,
        "container_resource_quality": context.quality_status,
        "container_cpu_usage_usec": context.delta.cpu_usage_usec,
        "container_cpu_throttled_usec": context.delta.cpu_throttled_usec,
        "container_memory_current_bytes_after": context.after.memory_current_bytes,
        "container_io_read_bytes": context.delta.io_read_bytes,
        "container_io_write_bytes": context.delta.io_write_bytes,
        "container_pids_current_after": context.after.pids_current,
        "container_resource_scope": context.scope,
        "container_resource_limitations": "; ".join(context.limitations),
    }


def _container_module_summary(
    snapshot: ContainerModuleSnapshotArtifact | None,
    *,
    uri: str | None,
) -> dict[str, str | int | float | bool | None]:
    if snapshot is None:
        return {}
    return {
        "container_module_snapshot_id": snapshot.module_snapshot_id,
        "container_module_snapshot_uri": uri,
        "container_module_quality": snapshot.status,
        "container_referenced_module_count": snapshot.referenced_module_count,
        "container_verified_module_count": sum(
            1 for item in snapshot.modules if item.status == "verified"
        ),
        "container_module_limitations": "; ".join(snapshot.limitations),
    }


def _container_measurement_summary(
    measurement: ContainerMeasurementArtifact | None,
    *,
    uri: str | None,
) -> dict[str, str | int | float | bool | None]:
    if measurement is None:
        return {}
    return {
        "container_measurement_id": measurement.measurement_id,
        "container_measurement_uri": uri,
        "container_measurement_quality": measurement.quality_status,
        "container_environment_fingerprint_sha256": (
            measurement.environment.environment_fingerprint_sha256
        ),
        "container_treatment_count": len(measurement.treatment_sha256),
        "container_benchmark_id": measurement.source_benchmark_id,
        "container_measurement_limitations": "; ".join(measurement.limitations),
    }


def _container_symbol_summary(
    context: ContainerSymbolContextArtifact | None,
    *,
    uri: str | None,
) -> dict[str, str | int | float | bool | None]:
    if context is None:
        return {}
    return {
        "container_symbol_context_id": context.symbol_context_id,
        "container_symbol_context_uri": uri,
        "container_symbol_quality": context.quality_status,
        "container_module_count": context.module_count,
        "container_source_location_count": context.source_location_count,
        "container_mapped_source_count": sum(
            1 for item in context.source_mappings if item.status == "mapped"
        ),
        "container_symbol_limitations": "; ".join(context.limitations),
    }


def _detect_source_type(path: Path) -> Literal["folded", "perf_script", "perf_data"]:
    if path.name.endswith("perf.data") or path.suffix == ".data":
        return "perf_data"
    if path.suffix in {".perf-script", ".script"}:
        return "perf_script"
    if path.suffix in {".folded", ".txt"}:
        return "folded"
    raise PerfLensError(
        ErrorCode.UNSUPPORTED_FORMAT,
        "mcp",
        "Unable to auto-detect profile type from its filename",
        recoverable=True,
        suggested_actions=("Pass source_type explicitly.",),
    )


def _require_process_execution(config: ServerConfig) -> None:
    if not config.allow_process_execution:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "External process execution is disabled by server policy",
            recoverable=True,
        )


def _require_active_collection(config: ServerConfig, *, pid: int | None) -> None:
    if not config.allow_writes:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Active collection requires artifact writes to be enabled by server policy",
            recoverable=True,
        )
    if not config.allow_process_execution or not config.allow_active_collection:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Active collection is disabled by server policy",
            recoverable=True,
        )
    if pid is not None and not config.allow_pid_attach:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "PID attachment is disabled by server policy",
            recoverable=True,
        )


def _require_automatic_collection(
    config: ServerConfig,
    *,
    require_existing_pid_attach: bool,
) -> None:
    _require_active_collection(
        config,
        pid=1 if require_existing_pid_attach else None,
    )
    if (
        not config.allow_automatic_collection
        or config.collector_socket is None
        or not config.automatic_collection_policy.enabled
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Automatic collection through the privileged broker is disabled by server policy",
            recoverable=True,
        )


def _require_project_execution(config: ServerConfig) -> None:
    _require_automatic_collection(config, require_existing_pid_attach=False)
    if not config.allow_project_execution:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Unprivileged project workload execution is disabled by server policy",
            recoverable=True,
            suggested_actions=(
                "Enable it only for a trusted project and require per-call authorization.",
            ),
        )


def _require_docker_targets(config: ServerConfig) -> None:
    if not config.allow_docker_targets or config.docker_project_config is None:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Docker target runtime is disabled by project MCP policy",
            recoverable=True,
            suggested_actions=(
                "Run perflens init --docker in this project and restart the client.",
            ),
        )


def _require_docker_optimization(config: ServerConfig) -> None:
    _require_docker_targets(config)
    if not config.allow_docker_optimization:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Docker optimization sessions are disabled by project MCP policy",
            recoverable=True,
            suggested_actions=(
                "Enable the schema 1.1 optimization contract and regenerate project integration.",
            ),
        )


def _persist_runtime_lock_settlement(
    runtime: RuntimeLockSessionRuntime,
    session_id: str,
    store: ArtifactStore,
    settlement: RuntimeLockRunSettlement,
) -> None:
    """Publish marker-last or destroy the process-local authorization.

    Once the authority reconciles a lease, the returned Session revision may
    only be used as a parent after both the Session and its finalization marker
    are durable.  A partial write therefore poisons the in-memory capability;
    leaving it active would permit a later run to extend an unverifiable chain.
    """

    try:
        store.save_runtime_lock_settlement(
            settlement.session,
            settlement.finalization,
        )
    except Exception:
        with suppress(PerfLensError):
            runtime.abandon_unpublished(session_id)
        raise


def _validate_runtime_lock_preview_policy(
    policy: RuntimeLockProjectPolicy,
    *,
    target_scope: RuntimeLockTargetScope,
    allowed_adapters: tuple[RuntimeLockAdapterId, ...],
    allowed_semantics: tuple[Literal["exact", "thresholded", "sampled", "cumulative"], ...],
) -> None:
    if not policy.enabled:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "runtime_lock_authorization",
            "Runtime Lock sessions are disabled by project policy",
            recoverable=True,
        )
    if target_scope not in policy.target_scopes:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "runtime_lock_authorization",
            "Runtime Lock target scope is outside project policy",
            recoverable=True,
        )
    if (
        not allowed_adapters
        or len(allowed_adapters) != len(set(allowed_adapters))
        or any(adapter not in policy.allowed_adapters for adapter in allowed_adapters)
        or not allowed_semantics
        or len(allowed_semantics) != len(set(allowed_semantics))
        or any(semantics not in policy.allowed_semantics for semantics in allowed_semantics)
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "runtime_lock_authorization",
            "Runtime Lock Adapter or semantics scope exceeds project policy",
            recoverable=True,
        )
    covered_semantics: set[str] = set()
    for adapter_id in allowed_adapters:
        adapter = policy.adapter_policy(adapter_id)
        selected_semantics = set(adapter.allowed_semantics) & set(allowed_semantics)
        entry_point_allowed = (
            adapter.controlled_import_allowed
            if target_scope == "controlled_import"
            else (
                adapter.loopback_backend_enabled
                if target_scope == "host_bound_process" and adapter_id == "go_pprof"
                else adapter.launch_instrumentation_allowed
            )
        )
        if not adapter.enabled or not selected_semantics or not entry_point_allowed:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "runtime_lock_authorization",
                "Runtime Lock Adapter entry point or semantics is outside project policy",
                recoverable=True,
            )
        covered_semantics.update(selected_semantics)
    if covered_semantics != set(allowed_semantics):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "runtime_lock_authorization",
            "Runtime Lock semantics are not covered by the selected Adapter policies",
            recoverable=True,
        )


def _require_runtime_lock_adapter_capability(
    inspection: RuntimeLockCapabilityInspection,
    *,
    adapter_id: RuntimeLockAdapterId,
    allowed_semantics: tuple[Literal["exact", "thresholded", "sampled", "cumulative"], ...],
) -> None:
    reference = next(
        (item for item in inspection.capability.adapters if item.adapter_id == adapter_id),
        None,
    )
    if (
        reference is None
        or reference.availability not in {"available", "partial"}
        or any(item not in reference.supported_semantics for item in allowed_semantics)
    ):
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "runtime_lock_capability",
            "The selected Runtime Lock Adapter is unavailable for this semantics scope",
            recoverable=True,
            details={"adapter_id": adapter_id},
        )


def _runtime_lock_project_executable(project_root: Path, value: str) -> Path:
    if not value or "\x00" in value or "\\" in value or len(value.encode("utf-8")) > 4096:
        raise _runtime_lock_native_error("Native pthread executable path is invalid")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or str(relative) != value
        or relative in {PurePosixPath("."), PurePosixPath("..")}
        or ".." in relative.parts
    ):
        raise _runtime_lock_native_error(
            "Native pthread executable must be one normalized project-relative path"
        )
    return project_root.joinpath(*relative.parts)


def _validate_native_runtime_lock_session(
    session: RuntimeLockSessionArtifact,
    preview: RuntimeLockSessionPreviewArtifact,
    policy: RuntimeLockProjectPolicy,
    *,
    measurement_semantics: Literal["exact", "thresholded"],
    duration_seconds: int,
    max_events: int,
) -> RuntimeLockWorkloadBinding:
    workload = preview.workload
    if (
        session.state != "active"
        or session.target_scope != "host_launched_workload"
        or preview.target_scope != session.target_scope
        or preview.content_sha256 != session.preview_content_sha256
        or preview.runtime_lock_config_sha256 != policy.sha256
        or session.runtime_lock_config_sha256 != policy.sha256
        or session.allowed_adapters != ("native_pthread",)
        or workload is None
        or workload.adapter_id != "native_pthread"
        or workload.workload_kind != "native_elf"
        or measurement_semantics not in session.allowed_semantics
        or isinstance(duration_seconds, bool)
        or not 1 <= duration_seconds <= session.budget.max_collection_duration_seconds
        or isinstance(max_events, bool)
        or not 1 <= max_events <= session.budget.max_exact_events
        or (
            measurement_semantics == "exact"
            and duration_seconds > session.budget.max_exact_duration_seconds
        )
    ):
        raise _runtime_lock_native_error(
            "Native pthread collection is outside the authorized Runtime Lock Session"
        )
    _validate_runtime_lock_preview_policy(
        policy,
        target_scope="host_launched_workload",
        allowed_adapters=("native_pthread",),
        allowed_semantics=(measurement_semantics,),
    )
    adapter_policy = policy.adapter_policy("native_pthread")
    if measurement_semantics == "exact" and not adapter_policy.exact_enabled:
        raise _runtime_lock_native_error("Native pthread exact collection is disabled by policy")
    return workload


def _runtime_lock_native_operation_identity(
    session: RuntimeLockSessionArtifact,
    target_identity_sha256: str,
    measurement_semantics: str,
    duration_seconds: int,
    max_events: int,
) -> str:
    material = "\0".join(
        (
            "perflens-runtime-lock-native-operation-v1",
            session.session_id,
            str(session.revision),
            str(session.workload_runs_used + 1),
            target_identity_sha256,
            measurement_semantics,
            str(duration_seconds),
            str(max_events),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validate_java_runtime_lock_session(
    session: RuntimeLockSessionArtifact,
    preview: RuntimeLockSessionPreviewArtifact,
    policy: RuntimeLockProjectPolicy,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    duration_seconds: int,
    max_events: int,
) -> RuntimeLockWorkloadBinding:
    workload = preview.workload
    if (
        session.state != "active"
        or session.target_scope != "host_launched_workload"
        or preview.target_scope != session.target_scope
        or preview.content_sha256 != session.preview_content_sha256
        or preview.runtime_lock_config_sha256 != policy.sha256
        or session.runtime_lock_config_sha256 != policy.sha256
        or session.allowed_adapters != ("java_jfr",)
        or session.allowed_semantics != ("thresholded",)
        or workload is None
        or workload.adapter_id != "java_jfr"
        or workload.workload_kind != "java_archive"
        or preview.adapter_execution_bindings != (execution_binding,)
        or isinstance(duration_seconds, bool)
        or not 1 <= duration_seconds <= session.budget.max_collection_duration_seconds
        or isinstance(max_events, bool)
        or not 1 <= max_events <= 20_000
    ):
        raise _runtime_lock_native_error(
            "Java JFR collection is outside the authorized Runtime Lock Session"
        )
    _validate_runtime_lock_preview_policy(
        policy,
        target_scope="host_launched_workload",
        allowed_adapters=("java_jfr",),
        allowed_semantics=("thresholded",),
    )
    adapter_policy = policy.adapter_policy("java_jfr")
    if (
        execution_binding.profile != adapter_policy.profile
        or execution_binding.duration_threshold_ns != adapter_policy.duration_threshold_ns
    ):
        raise _runtime_lock_native_error(
            "Java JFR execution binding differs from the current project policy"
        )
    return workload


def _runtime_lock_java_operation_identity(
    session: RuntimeLockSessionArtifact,
    target_identity_sha256: str,
    duration_seconds: int,
    max_events: int,
    execution_identity_sha256: str,
) -> str:
    material = "\0".join(
        (
            "perflens-runtime-lock-java-operation-v1",
            session.session_id,
            str(session.revision),
            str(session.workload_runs_used + 1),
            target_identity_sha256,
            str(duration_seconds),
            str(max_events),
            execution_identity_sha256,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validate_cpython_runtime_lock_session(
    session: RuntimeLockSessionArtifact,
    preview: RuntimeLockSessionPreviewArtifact,
    policy: RuntimeLockProjectPolicy,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    measurement_semantics: Literal["exact", "thresholded"],
    duration_seconds: int,
    max_events: int,
) -> RuntimeLockWorkloadBinding:
    workload = preview.workload
    if (
        session.state != "active"
        or session.target_scope != "host_launched_workload"
        or preview.target_scope != session.target_scope
        or preview.content_sha256 != session.preview_content_sha256
        or preview.runtime_lock_config_sha256 != policy.sha256
        or session.runtime_lock_config_sha256 != policy.sha256
        or session.allowed_adapters != ("cpython_threading",)
        or session.allowed_semantics != (measurement_semantics,)
        or workload is None
        or workload.adapter_id != "cpython_threading"
        or workload.workload_kind != "python_script"
        or preview.adapter_execution_bindings != (execution_binding,)
        or isinstance(duration_seconds, bool)
        or not 1 <= duration_seconds <= session.budget.max_collection_duration_seconds
        or isinstance(max_events, bool)
        or not 1 <= max_events <= session.budget.max_exact_events
        or (
            measurement_semantics == "exact"
            and duration_seconds > session.budget.max_exact_duration_seconds
        )
    ):
        raise _runtime_lock_native_error(
            "CPython collection is outside the authorized Runtime Lock Session"
        )
    _validate_runtime_lock_preview_policy(
        policy,
        target_scope="host_launched_workload",
        allowed_adapters=("cpython_threading",),
        allowed_semantics=(measurement_semantics,),
    )
    adapter_policy = policy.adapter_policy("cpython_threading")
    if (
        measurement_semantics == "exact" and not adapter_policy.exact_enabled
    ) or execution_binding.duration_threshold_ns != (
        10_000 if measurement_semantics == "thresholded" else None
    ):
        raise _runtime_lock_native_error(
            "CPython execution binding differs from the current project policy"
        )
    return workload


def _runtime_lock_cpython_operation_identity(
    session: RuntimeLockSessionArtifact,
    target_identity_sha256: str,
    measurement_semantics: str,
    duration_seconds: int,
    max_events: int,
    execution_identity_sha256: str,
) -> str:
    material = "\0".join(
        (
            "perflens-runtime-lock-cpython-operation-v1",
            session.session_id,
            str(session.revision),
            str(session.workload_runs_used + 1),
            target_identity_sha256,
            measurement_semantics,
            str(duration_seconds),
            str(max_events),
            execution_identity_sha256,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validate_go_runtime_lock_session(
    session: RuntimeLockSessionArtifact,
    preview: RuntimeLockSessionPreviewArtifact,
    policy: RuntimeLockProjectPolicy,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    duration_seconds: int,
    max_events: int,
    profile_kind: GoProfileKind,
) -> RuntimeLockWorkloadBinding:
    workload = preview.workload
    adapter_policy = policy.adapter_policy("go_pprof")
    selected_rate = (
        adapter_policy.mutex_profile_fraction
        if profile_kind == "mutex"
        else adapter_policy.block_profile_rate_ns
    )
    if (
        session.state != "active"
        or session.target_scope != "host_launched_workload"
        or preview.target_scope != session.target_scope
        or preview.content_sha256 != session.preview_content_sha256
        or preview.runtime_lock_config_sha256 != policy.sha256
        or session.runtime_lock_config_sha256 != policy.sha256
        or session.allowed_adapters != ("go_pprof",)
        or session.allowed_semantics != ("cumulative",)
        or workload is None
        or workload.adapter_id != "go_pprof"
        or workload.workload_kind != "go_elf"
        or preview.adapter_execution_bindings != (execution_binding,)
        or not adapter_policy.file_backend_enabled
        or selected_rate is None
        or isinstance(duration_seconds, bool)
        or not 1 <= duration_seconds <= session.budget.max_collection_duration_seconds
        or isinstance(max_events, bool)
        or not 1 <= max_events <= session.budget.max_exact_events
    ):
        raise _runtime_lock_native_error(
            "Go pprof collection is outside the authorized Runtime Lock Session"
        )
    _validate_runtime_lock_preview_policy(
        policy,
        target_scope="host_launched_workload",
        allowed_adapters=("go_pprof",),
        allowed_semantics=("cumulative",),
    )
    return workload


def _validate_go_loopback_runtime_lock_session(
    session: RuntimeLockSessionArtifact,
    preview: RuntimeLockSessionPreviewArtifact,
    policy: RuntimeLockProjectPolicy,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    duration_seconds: int,
    max_events: int,
    profile_kind: GoProfileKind,
) -> RuntimeLockProcessTargetBinding:
    target = preview.process_target
    adapter_policy = policy.adapter_policy("go_pprof")
    selected_rate = (
        adapter_policy.mutex_profile_fraction
        if profile_kind == "mutex"
        else adapter_policy.block_profile_rate_ns
    )
    if (
        session.state != "active"
        or session.target_scope != "host_bound_process"
        or preview.target_scope != session.target_scope
        or preview.content_sha256 != session.preview_content_sha256
        or preview.runtime_lock_config_sha256 != policy.sha256
        or session.runtime_lock_config_sha256 != policy.sha256
        or session.allowed_adapters != ("go_pprof",)
        or session.allowed_semantics != ("cumulative",)
        or target is None
        or preview.workload is not None
        or preview.adapter_execution_bindings != (execution_binding,)
        or not adapter_policy.loopback_backend_enabled
        or selected_rate is None
        or isinstance(duration_seconds, bool)
        or not 1 <= duration_seconds <= session.budget.max_collection_duration_seconds
        or isinstance(max_events, bool)
        or not 1 <= max_events <= session.budget.max_exact_events
    ):
        raise _runtime_lock_native_error(
            "Go pprof loopback collection is outside the authorized Runtime Lock Session"
        )
    _validate_runtime_lock_preview_policy(
        policy,
        target_scope="host_bound_process",
        allowed_adapters=("go_pprof",),
        allowed_semantics=("cumulative",),
    )
    return target


def _runtime_lock_go_operation_identity(
    session: RuntimeLockSessionArtifact,
    target_identity_sha256: str,
    profile_kind: GoProfileKind,
    duration_seconds: int,
    max_events: int,
    execution_identity_sha256: str,
    mutex_profile_fraction: int | None,
    block_profile_rate_ns: int | None,
) -> str:
    material = "\0".join(
        (
            "perflens-runtime-lock-go-operation-v1",
            session.session_id,
            str(session.revision),
            str(session.workload_runs_used + 1),
            target_identity_sha256,
            profile_kind,
            str(duration_seconds),
            str(max_events),
            execution_identity_sha256,
            str(mutex_profile_fraction or 0),
            str(block_profile_rate_ns or 0),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _assert_go_runtime_lock_evidence_identity(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    launch_result: GoPprofLaunchResult,
    raw_result: GoPprofRawResult,
    expected_target_identity_sha256: str,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    profile_kind: GoProfileKind,
    max_events: int,
) -> tuple[str, ...]:
    source = evidence.source
    target = evidence.target
    bound_tools = {tool.name: tool for tool in execution_binding.tools}
    bound_go = bound_tools.get("go")
    bound_pprof = bound_tools.get("pprof")
    if (
        launch_result.target_identity_sha256 != expected_target_identity_sha256
        or target.target_kind != "host"
        or target.target_pid != launch_result.target_pid
        or target.target_uid != launch_result.target_uid
        or target.target_start_time_ticks != launch_result.target_start_ticks
        or target.observed_target_tids
        or launch_result.target_uid != os.geteuid()
        or source.runtime != "go"
        or source.adapter_id != "go_pprof"
        or source.backend_id != f"pprof-{profile_kind}"
        or source.source_format != "pprof_text_v1"
        or source.target_scope != "bound_pid"
        or source.source_sha256 != raw_result.raw_sha256
        or source.source_bytes != raw_result.raw_size
        or source.adapter_execution_identity_sha256 != execution_binding.execution_identity_sha256
        or source.configuration_sha256 != execution_binding.configuration_sha256
        or source.metadata_sha256 != execution_binding.metadata_sha256
        or bound_go is None
        or bound_pprof is None
        or bound_go.binary_sha256 != launch_result.go_tool_sha256
        or bound_pprof.binary_sha256 != launch_result.pprof_tool_sha256
        or source.tool is None
        or source.tool.name != "pprof"
        or source.tool.path != "pprof"
        or source.tool.binary_sha256 != launch_result.pprof_tool_sha256
        or len(evidence.events) > max_events
        or any(context.kind != "process_aggregate" for context in evidence.execution_contexts)
        or any(event.lock_id is not None for event in evidence.events)
    ):
        raise _runtime_lock_native_error(
            "Go pprof Evidence differs from its authorized workload or toolchain identity"
        )
    return (
        "Go pprof profile controls are application-declared and not independently attested by "
        "the profile payload.",
    )


def _assert_go_loopback_runtime_lock_evidence_identity(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    capture: GoPprofLoopbackCapture,
    raw_result: GoPprofRawResult,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    profile_kind: GoProfileKind,
    max_events: int,
) -> tuple[str, ...]:
    source = evidence.source
    target = evidence.target
    bound_pprof = next(
        (tool for tool in execution_binding.tools if tool.name == "pprof"),
        None,
    )
    if (
        target.target_kind != "host"
        or target.target_pid != capture.target.target_pid
        or target.target_uid != capture.target.target_uid
        or target.target_start_time_ticks != capture.target.target_start_time_ticks
        or target.observed_target_tids
        or target.target_uid != os.geteuid()
        or source.runtime != "go"
        or source.adapter_id != "go_pprof"
        or source.backend_id != f"pprof-{profile_kind}"
        or source.source_format != "pprof_text_v1"
        or source.target_scope != "bound_pid"
        or source.source_sha256 != raw_result.raw_sha256
        or source.source_bytes != raw_result.raw_size
        or source.adapter_execution_identity_sha256 != execution_binding.execution_identity_sha256
        or source.configuration_sha256 != execution_binding.configuration_sha256
        or source.metadata_sha256 != execution_binding.metadata_sha256
        or bound_pprof is None
        or source.tool is None
        or source.tool.name != "pprof"
        or source.tool.path != "pprof"
        or source.tool.binary_sha256 != bound_pprof.binary_sha256
        or len(evidence.events) > max_events
        or any(context.kind != "process_aggregate" for context in evidence.execution_contexts)
        or any(event.lock_id is not None for event in evidence.events)
    ):
        raise _runtime_lock_native_error(
            "Go pprof loopback Evidence differs from its PID/socket or toolchain identity"
        )
    return (
        "Go pprof profile controls are application-declared and not independently attested by "
        "the profile payload.",
        "Loopback collection binds PID, UID, start time, port, and socket inode but does not "
        "attach to or modify the target process.",
    )


def _assert_cpython_runtime_lock_evidence_identity(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    launch_result: CpythonLaunchResult,
    expected_target_identity_sha256: str,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    max_events: int,
) -> tuple[str, ...]:
    source = evidence.source
    target = evidence.target
    bound_python = execution_binding.tools[0] if execution_binding.tools else None
    evidence_tids = set(target.observed_target_tids)
    if (
        launch_result.target_identity_sha256 != expected_target_identity_sha256
        or target.target_kind != "host"
        or target.target_pid != launch_result.target_pid
        or target.target_uid != launch_result.target_uid
        or target.target_start_time_ticks != launch_result.target_start_ticks
        or launch_result.target_uid != os.geteuid()
        or launch_result.target_pid not in evidence_tids
        or source.runtime != "python"
        or source.adapter_id != "cpython_threading"
        or source.backend_id != "threading-bootstrap"
        or source.source_format != "cpython_threading_ndjson_v1"
        or source.target_scope != "bound_pid"
        or source.source_sha256 != launch_result.stream_sha256
        or source.source_bytes != launch_result.stream_size
        or source.configuration_sha256 != launch_result.bootstrap_sha256
        or source.adapter_execution_identity_sha256 != execution_binding.execution_identity_sha256
        or source.metadata_sha256 != execution_binding.metadata_sha256
        or bound_python is None
        or bound_python.binary_sha256 != launch_result.interpreter_sha256
        or source.tool is None
        or source.tool.name != "python"
        or source.tool.path != "python"
        or source.tool.binary_sha256 != launch_result.interpreter_sha256
        or len(evidence.events) > max_events
    ):
        raise _runtime_lock_native_error(
            "CPython target, source, tool, or execution identity changed during collection"
        )
    if any(
        context.target_pid != launch_result.target_pid
        or (context.target_tid is not None and context.target_tid not in evidence_tids)
        for context in evidence.execution_contexts
    ):
        raise _runtime_lock_native_error(
            "CPython execution context escaped the bound target process"
        )
    return ()


def _assert_java_runtime_lock_evidence_identity(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    launch_result: JavaJfrLaunchResult,
    expected_target_identity_sha256: str,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    max_events: int,
) -> tuple[str, ...]:
    target = evidence.target
    source = evidence.source
    evidence_tids = set(target.observed_target_tids)
    launch_tids = set(launch_result.observed_tids)
    bound_tools = {tool.name: tool for tool in execution_binding.tools}
    bound_java = bound_tools.get("java")
    bound_jfr = bound_tools.get("jfr")
    if (
        launch_result.target_identity_sha256 != expected_target_identity_sha256
        or target.target_kind != "host"
        or target.target_pid != launch_result.target_pid
        or target.target_uid != launch_result.target_uid
        or target.target_start_time_ticks != launch_result.target_start_ticks
        or launch_result.target_uid != os.geteuid()
        or launch_result.target_pid not in evidence_tids
        or launch_result.target_pid not in launch_tids
        or source.runtime != "java"
        or source.adapter_id != "java_jfr"
        or source.backend_id != "jfr"
        or source.source_format != "jfr_json_v1"
        or source.target_scope != "bound_pid"
        or source.source_sha256 != launch_result.json_sha256
        or source.source_bytes != launch_result.json_size
        or source.configuration_sha256 != launch_result.jfc_sha256
        or source.adapter_execution_identity_sha256 != execution_binding.execution_identity_sha256
        or source.metadata_sha256 != execution_binding.metadata_sha256
        or bound_java is None
        or bound_jfr is None
        or bound_java.binary_sha256 != launch_result.java_tool_sha256
        or bound_jfr.binary_sha256 != launch_result.jfr_tool_sha256
        or source.tool is None
        or source.tool.name != "jfr"
        or source.tool.path != "jfr"
        or source.tool.binary_sha256 != bound_jfr.binary_sha256
        or len(evidence.events) > max_events
    ):
        raise _runtime_lock_native_error(
            "Java JFR target, source, tool, or execution identity changed during collection"
        )
    context_ids = {context.context_id for context in evidence.execution_contexts}
    if any(
        context.target_pid != launch_result.target_pid
        or (context.target_tid is not None and context.target_tid not in evidence_tids)
        for context in evidence.execution_contexts
    ) or any(
        event.execution_context_id is not None and event.execution_context_id not in context_ids
        for event in evidence.events
    ):
        raise _runtime_lock_native_error(
            "Java JFR execution context escaped the bound target process"
        )
    transient_tids = evidence_tids - launch_tids
    if transient_tids:
        return (
            "Independent Java thread polling was partial: some evidence TIDs were shorter-lived "
            "than the procfs polling window; PID, UID, start time, JFR source, and execution "
            "binding passed.",
        )
    return ()


def _pin_native_runtime_lock_stream(
    result: NativeLaunchResult,
    *,
    private_root: Path,
    max_source_bytes: int,
) -> _PinnedRuntimeLockImport:
    root = private_root.resolve(strict=True)
    path = result.stream_path
    name = path.name
    token = name.removeprefix("native-pthread-").removesuffix(".ndjson")
    if (
        not path.is_absolute()
        or path.parent != root
        or not name.startswith("native-pthread-")
        or not name.endswith(".ndjson")
        or len(token) != 20
        or any(character not in "0123456789abcdef" for character in token)
        or path.is_symlink()
    ):
        raise _runtime_lock_native_error(
            "Native pthread private stream path is outside its fixed private root"
        )
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        metadata = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 1 <= metadata.st_size <= max_source_bytes
            or metadata.st_size != result.stream_size
            or _runtime_lock_file_identity(metadata) != _runtime_lock_file_identity(current)
        ):
            raise _runtime_lock_native_error(
                "Native pthread private stream owner, type, mode, size, or identity is unsafe"
            )
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1 << 20):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            _runtime_lock_file_identity(metadata) != _runtime_lock_file_identity(after)
            or digest.hexdigest() != result.stream_sha256
        ):
            raise _runtime_lock_native_error(
                "Native pthread private stream differs from its launcher receipt"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _PinnedRuntimeLockImport(
            descriptor=descriptor,
            path=path,
            project_relative_path=name,
            source_sha256=digest.hexdigest(),
            metadata=metadata,
        )
    except PerfLensError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise _runtime_lock_native_error(
            "Native pthread private stream cannot be opened safely"
        ) from exc


def _assert_native_runtime_lock_evidence_identity(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    receipt_source_sha256: str,
    receipt_source_bytes: int,
    launch_result: NativeLaunchResult,
    expected_target_identity_sha256: str,
    measurement_semantics: Literal["exact", "thresholded"],
    duration_threshold_ns: int | None,
    max_events: int,
) -> tuple[str, ...]:
    target = evidence.target
    source = evidence.source
    events = evidence.events
    evidence_tids = set(target.observed_target_tids)
    launch_tids = set(launch_result.observed_tids)
    if (
        launch_result.target_identity_sha256 != expected_target_identity_sha256
        or launch_result.target_start_ticks is None
        or target.target_kind != "host"
        or target.target_pid != launch_result.target_pid
        or target.target_uid != launch_result.target_uid
        or target.target_start_time_ticks != launch_result.target_start_ticks
        or launch_result.target_uid != os.geteuid()
        or launch_result.target_pid not in evidence_tids
        or launch_result.target_pid not in launch_tids
        or source.adapter_id != "native-pthread"
        or source.measurement_semantics != measurement_semantics
        or source.duration_threshold_ns != duration_threshold_ns
        or source.source_sha256 != receipt_source_sha256
        or source.source_bytes != receipt_source_bytes
        or receipt_source_sha256 != launch_result.stream_sha256
        or receipt_source_bytes != launch_result.stream_size
        or len(events) > max_events
    ):
        raise _runtime_lock_native_error(
            "Native pthread target, stream, semantics, or TID identity changed during collection"
        )
    context_ids = {context.context_id for context in evidence.execution_contexts}
    if any(
        context.target_pid != launch_result.target_pid
        or (context.target_tid is not None and context.target_tid not in evidence_tids)
        for context in evidence.execution_contexts
    ) or any(event.execution_context_id not in context_ids for event in evidence.events):
        raise _runtime_lock_native_error(
            "Native pthread execution context escaped the bound target process"
        )
    transient_tids = evidence_tids - launch_tids
    if transient_tids:
        return (
            "Independent TID polling was partial: some evidence TIDs were shorter-lived than "
            "the procfs polling window; "
            "PID, UID, start time, probe stream, and execution-context binding passed, but the "
            "independent TID coverage check is partial.",
        )
    return ()


def _remove_native_runtime_lock_stream(
    path: Path,
    *,
    private_root: Path,
    expected_metadata: os.stat_result | None,
) -> None:
    root = private_root.resolve(strict=True)
    if not path.is_absolute() or path.parent != root:
        raise _runtime_lock_native_error(
            "Native pthread cleanup refused a stream outside its fixed private root"
        )
    try:
        current = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread private stream cannot be inspected for cleanup"
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) != 0o600
        or (
            expected_metadata is not None
            and _runtime_lock_file_identity(current)
            != _runtime_lock_file_identity(expected_metadata)
        )
    ):
        raise _runtime_lock_native_error(
            "Native pthread private stream identity changed before cleanup"
        )
    try:
        root_descriptor = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            os.unlink(path.name, dir_fd=root_descriptor)
        finally:
            os.close(root_descriptor)
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread private stream could not be removed safely"
        ) from exc


def _retain_native_runtime_lock_stream(
    pinned: _PinnedRuntimeLockImport,
    *,
    private_root: Path,
    max_retained_bytes: int,
) -> Path:
    """Quarantine one verified failed stream under a hash-bound private name."""

    root = _validated_native_runtime_lock_private_root(private_root)
    if max_retained_bytes <= 0:
        raise _runtime_lock_native_retention_limit("Native pthread retention quota is invalid")
    path = pinned.path
    if not path.is_absolute() or path.parent != root or path.is_symlink():
        raise _runtime_lock_native_error(
            "Native pthread retention refused a stream outside its fixed private root"
        )
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread retained stream cannot be inspected safely"
        ) from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) != 0o600
        or _runtime_lock_file_identity(current) != _runtime_lock_file_identity(pinned.metadata)
        or len(pinned.source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in pinned.source_sha256)
    ):
        raise _runtime_lock_native_error(
            "Native pthread retained stream identity or hash binding is unsafe"
        )
    retained_bytes = _native_runtime_lock_retained_bytes(root, current_path=path)
    if retained_bytes + current.st_size > max_retained_bytes:
        raise _runtime_lock_native_retention_limit(
            "Native pthread retained diagnostics exceed the private Session quota"
        )

    root_descriptor = -1
    retained_name = ""
    try:
        root_descriptor = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        for _ in range(8):
            retained_name = (
                f".retained-native-pthread-{pinned.source_sha256}-{os.urandom(8).hex()}.ndjson"
            )
            try:
                os.link(
                    path.name,
                    retained_name,
                    src_dir_fd=root_descriptor,
                    dst_dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                break
            except FileExistsError:
                continue
        else:
            raise _runtime_lock_native_error(
                "Native pthread retained diagnostic name capacity is exhausted"
            )
        try:
            os.unlink(path.name, dir_fd=root_descriptor)
        except OSError:
            with suppress(OSError):
                os.unlink(retained_name, dir_fd=root_descriptor)
            raise
        retained = os.stat(retained_name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(retained.st_mode)
            or retained.st_uid != os.geteuid()
            or retained.st_nlink != 1
            or retained.st_dev != current.st_dev
            or retained.st_ino != current.st_ino
            or retained.st_size != current.st_size
            or stat.S_IMODE(retained.st_mode) != 0o600
        ):
            raise _runtime_lock_native_error(
                "Native pthread retained diagnostic changed during quarantine"
            )
        return root / retained_name
    except PerfLensError:
        raise
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread diagnostic could not be retained safely"
        ) from exc
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)


def _native_runtime_lock_retained_bytes(root: Path, *, current_path: Path) -> int:
    total = 0
    try:
        entries = tuple(os.scandir(root))
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread retained diagnostic quota cannot be inspected"
        ) from exc
    for entry in entries:
        path = Path(entry.path)
        if path == current_path:
            continue
        if not _is_native_runtime_lock_retained_name(entry.name):
            raise _runtime_lock_native_error(
                "Native pthread private root contains an unexpected diagnostic entry"
            )
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise _runtime_lock_native_error(
                "Native pthread retained diagnostic cannot be inspected"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise _runtime_lock_native_error(
                "Native pthread retained diagnostic identity is unsafe"
            )
        total += metadata.st_size
    return total


def _cleanup_native_runtime_lock_retained_streams(private_root: Path) -> None:
    """Remove only verified retained diagnostics during an orderly server shutdown."""

    root = _validated_native_runtime_lock_private_root(private_root)
    root_descriptor = -1
    try:
        root_descriptor = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        for entry in tuple(os.scandir(root)):
            if not _is_native_runtime_lock_retained_name(entry.name):
                raise _runtime_lock_native_error(
                    "Native pthread private root contains an unexpected cleanup entry"
                )
            metadata = entry.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise _runtime_lock_native_error(
                    "Native pthread retained diagnostic is unsafe for cleanup"
                )
            os.unlink(entry.name, dir_fd=root_descriptor)
    except PerfLensError:
        raise
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread retained diagnostics could not be cleaned safely"
        ) from exc
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)


def _validated_native_runtime_lock_private_root(private_root: Path) -> Path:
    try:
        root = private_root.resolve(strict=True)
        metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise _runtime_lock_native_error(
            "Native pthread private diagnostic root is unavailable"
        ) from exc
    if (
        root != private_root
        or private_root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _runtime_lock_native_error(
            "Native pthread private diagnostic root identity is unsafe"
        )
    return root


def _is_native_runtime_lock_retained_name(name: str) -> bool:
    prefix = ".retained-native-pthread-"
    suffix = ".ndjson"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return False
    payload = name[len(prefix) : -len(suffix)]
    digest, separator, nonce = payload.partition("-")
    return bool(
        separator
        and len(digest) == 64
        and len(nonce) == 16
        and all(character in "0123456789abcdef" for character in digest + nonce)
    )


def _runtime_lock_native_retention_limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "runtime_lock_collection",
        message,
        recoverable=True,
    )


def _runtime_lock_native_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_collection",
        message,
        recoverable=True,
    )


def _validate_runtime_lock_import_session(
    session: RuntimeLockSessionArtifact,
    preview: RuntimeLockSessionPreviewArtifact,
    policy: RuntimeLockProjectPolicy,
    *,
    measurement_semantics: Literal["exact", "thresholded", "sampled", "cumulative"],
) -> None:
    if (
        session.state != "active"
        or session.target_scope != "controlled_import"
        or preview.target_scope != session.target_scope
        or preview.content_sha256 != session.preview_content_sha256
        or preview.runtime_lock_config_sha256 != policy.sha256
        or session.runtime_lock_config_sha256 != policy.sha256
        or "generic_ndjson_import" not in session.allowed_adapters
        or measurement_semantics not in session.allowed_semantics
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "runtime_lock_import",
            "Runtime Lock controlled import is outside the authorized Session",
            recoverable=True,
        )
    _validate_runtime_lock_preview_policy(
        policy,
        target_scope="controlled_import",
        allowed_adapters=("generic_ndjson_import",),
        allowed_semantics=(measurement_semantics,),
    )


def _pin_runtime_lock_import_source(
    project_root: Path,
    source_path: str,
    *,
    import_roots: tuple[str, ...],
    max_source_bytes: int,
) -> _PinnedRuntimeLockImport:
    if (
        not source_path
        or "\x00" in source_path
        or "\\" in source_path
        or len(source_path.encode("utf-8")) > 4096
    ):
        raise _runtime_lock_import_error("Runtime Lock import path is invalid")
    relative = PurePosixPath(source_path)
    if (
        relative.is_absolute()
        or str(relative) != source_path
        or relative in {PurePosixPath("."), PurePosixPath("..")}
        or ".." in relative.parts
        or not any(relative.is_relative_to(PurePosixPath(root)) for root in import_roots)
    ):
        raise _runtime_lock_import_error(
            "Runtime Lock source is outside the authorized project import roots"
        )
    candidate = project_root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise _runtime_lock_import_error("Runtime Lock source cannot be resolved safely") from exc
    if resolved != candidate or not resolved.is_relative_to(project_root):
        raise _runtime_lock_import_error(
            "Runtime Lock source path contains a symlink or escapes the project"
        )
    descriptor = -1
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        metadata = os.fstat(descriptor)
        current = resolved.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 1 <= metadata.st_size <= max_source_bytes
            or _runtime_lock_file_identity(metadata) != _runtime_lock_file_identity(current)
        ):
            raise _runtime_lock_import_error(
                "Runtime Lock source owner, type, links, mode, size, or identity is unsafe"
            )
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1 << 20):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _runtime_lock_file_identity(metadata) != _runtime_lock_file_identity(after):
            raise _runtime_lock_import_error("Runtime Lock source changed while it was hashed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _PinnedRuntimeLockImport(
            descriptor=descriptor,
            path=resolved,
            project_relative_path=source_path,
            source_sha256=digest.hexdigest(),
            metadata=metadata,
        )
    except PerfLensError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise _runtime_lock_import_error("Runtime Lock source cannot be opened safely") from exc


def _assert_runtime_lock_import_unchanged(source: _PinnedRuntimeLockImport) -> None:
    try:
        descriptor = os.fstat(source.descriptor)
        current = source.path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _runtime_lock_import_error("Runtime Lock source identity became unavailable") from exc
    if _runtime_lock_file_identity(source.metadata) != _runtime_lock_file_identity(
        descriptor
    ) or _runtime_lock_file_identity(descriptor) != _runtime_lock_file_identity(current):
        raise _runtime_lock_import_error("Runtime Lock source changed during controlled import")


def _runtime_lock_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
    )


def _runtime_lock_import_identity(domain: str, *values: str) -> str:
    material = "\0".join((f"perflens-runtime-lock-import-{domain}-v1", *values))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _runtime_lock_import_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_import",
        message,
        recoverable=True,
    )


def _require_runtime_locks(config: ServerConfig) -> None:
    if not config.allow_runtime_locks or config.runtime_lock_project_config is None:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Runtime Lock sessions are disabled by project MCP policy",
            recoverable=True,
            suggested_actions=(
                "Run perflens init --runtime-locks in this project and restart the client.",
            ),
        )


def _runtime_lock_planned_actions(
    target_scope: RuntimeLockTargetScope,
) -> tuple[str, ...]:
    if target_scope == "controlled_import":
        return (
            "Authorize this exact bounded Runtime Lock Session Preview.",
            "Import only a versioned source inside one reviewed project-relative import root.",
            "Normalize, analyze, and independently verify the redacted Runtime Lock evidence.",
            "Expose only bounded verified hotspots, call paths, and evidence limitations.",
            "Revoke the in-memory Session authorization when the evidence workflow ends.",
        )
    if target_scope == "host_bound_process":
        return (
            "Authorize this exact same-UID PID, start time, and literal-loopback socket.",
            "Fetch only one fixed Go mutex or block pprof endpoint without redirects or proxies.",
            "Convert with the content-bound pprof tool and revalidate PID/socket identity.",
            "Analyze and independently verify the cumulative, redacted Runtime Lock evidence.",
            "Revoke the in-memory Session authorization when the evidence workflow ends.",
        )
    return (
        "Authorize this exact bounded Runtime Lock Session Preview.",
        "Launch only the fixed project workload through its reviewed Runtime Lock Adapter.",
        "Capture one bounded Runtime Lock evidence stream without attaching to an existing PID.",
        "Analyze and independently verify the redacted Runtime Lock evidence.",
        "Revoke the in-memory Session authorization when the evidence workflow ends.",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PerfLens MCP server over stdio")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--allowed-root", action="append", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--allow-writes", action="store_true")
    parser.add_argument("--allow-process-execution", action="store_true")
    parser.add_argument("--allow-active-collection", action="store_true")
    parser.add_argument("--allow-pid-attach", action="store_true")
    parser.add_argument("--allow-automatic-collection", action="store_true")
    parser.add_argument("--allow-project-execution", action="store_true")
    parser.add_argument("--allow-docker-targets", action="store_true")
    parser.add_argument("--allow-docker-optimization", action="store_true")
    parser.add_argument("--allow-runtime-locks", action="store_true")
    parser.add_argument("--docker-project-config", type=Path)
    parser.add_argument("--runtime-lock-project-config", type=Path)
    parser.add_argument("--docker-runtime-root", type=Path)
    parser.add_argument("--docker-builder-policy", type=Path)
    parser.add_argument(
        "--docker-gate-path",
        type=Path,
        default=Path("/usr/lib/perflens/perflens-container-gate"),
    )
    parser.add_argument("--collector-socket", type=Path)
    parser.add_argument(
        "--automatic-mode",
        action="append",
        choices=("record", "stat", "sched", "lock", "off_cpu"),
    )
    parser.add_argument("--automatic-max-duration-seconds", type=float, default=30.0)
    parser.add_argument("--automatic-max-frequency-hz", type=int, default=99)
    parser.add_argument("--automatic-max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    parser.add_argument("--automatic-plan-ttl-seconds", type=int, default=120)
    parser.add_argument(
        "--disable-automatic-software-fallback",
        action="store_true",
        help="Require hardware PMU evidence instead of continuing with software events.",
    )
    parser.add_argument("--perf-path", type=Path)
    parser.add_argument("--max-artifact-bytes", type=int, default=128 << 20)
    arguments = parser.parse_args()
    server = create_server(
        ServerConfig(
            allowed_roots=tuple(arguments.allowed_root),
            artifact_root=arguments.artifact_root,
            allow_writes=arguments.allow_writes,
            allow_process_execution=arguments.allow_process_execution,
            allow_active_collection=arguments.allow_active_collection,
            allow_pid_attach=arguments.allow_pid_attach,
            allow_automatic_collection=arguments.allow_automatic_collection,
            allow_project_execution=arguments.allow_project_execution,
            allow_docker_targets=arguments.allow_docker_targets,
            allow_docker_optimization=arguments.allow_docker_optimization,
            allow_runtime_locks=arguments.allow_runtime_locks,
            docker_project_config=arguments.docker_project_config,
            runtime_lock_project_config=arguments.runtime_lock_project_config,
            docker_runtime_root=arguments.docker_runtime_root,
            docker_builder_policy=arguments.docker_builder_policy,
            docker_gate_path=arguments.docker_gate_path,
            collector_socket=arguments.collector_socket,
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=arguments.allow_automatic_collection,
                allowed_modes=tuple(arguments.automatic_mode or ("record", "stat")),
                max_duration_seconds=arguments.automatic_max_duration_seconds,
                max_frequency_hz=arguments.automatic_max_frequency_hz,
                max_output_bytes=arguments.automatic_max_output_bytes,
                plan_ttl_seconds=arguments.automatic_plan_ttl_seconds,
                allow_software_fallback=not arguments.disable_automatic_software_fallback,
            ),
            perf_path=arguments.perf_path,
            max_artifact_bytes=arguments.max_artifact_bytes,
        )
    )
    server.run("stdio")


if __name__ == "__main__":
    main()
