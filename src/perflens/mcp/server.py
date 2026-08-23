"""PerfLens MCP server built on the official Python SDK."""
# pyright: reportUnusedFunction=false

from __future__ import annotations

import argparse
import math
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from perflens import __version__
from perflens.application.analyze import analyze_folded, analyze_perf_data, analyze_perf_script
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.evidence import build_collection_evidence_provenance
from perflens.application.symbols import get_source_context as resolve_source_context
from perflens.application.symbols import resolve_source as resolve_module_source
from perflens.application.trace_evidence import canonical_trace_json_sha256
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.application.verify_trace import (
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
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
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceAnalysisVerificationArtifact,
    TraceEvidenceArtifact,
)
from perflens.docker.benchmark import load_managed_benchmark
from perflens.docker.capability import discover_docker_capability
from perflens.docker.cgroup import (
    CapturedCgroupSnapshot,
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
from perflens.docker.project_config import (
    assert_docker_project_policy_current,
    load_docker_project_policy,
)
from perflens.docker.runtime import ExistingDockerRuntime
from perflens.docker.symbols import (
    build_container_symbol_context,
    capture_container_module_snapshot,
    materialize_container_workspace_symfs,
    project_container_analysis,
)
from perflens.docker.treatment import (
    assert_treatment_snapshot_current,
    capture_treatment_snapshot,
)
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy
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
    docker_project_config: Path | None = None
    docker_runtime_root: Path | None = None
    docker_gate_path: Path = Path("/usr/lib/perflens/perflens-container-gate")
    collector_socket: Path | None = None
    automatic_collection_policy: AutomaticCollectionPolicy = field(
        default_factory=AutomaticCollectionPolicy
    )
    perf_path: Path | None = None
    max_artifact_bytes: int = 128 << 20


@dataclass(frozen=True, slots=True)
class _ExecutedBrokerPlan:
    reference: ArtifactReference
    collection: CollectionArtifact | None
    collection_id: str
    output_sha256: str
    evidence_bytes: int
    active_seconds: float


def create_server(config: ServerConfig) -> MCPServer[None]:
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
    policy = PathPolicy(config.allowed_roots)
    store = ArtifactStore(
        config.artifact_root,
        policy,
        allow_writes=config.allow_writes,
        max_artifact_bytes=config.max_artifact_bytes,
    )
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
    )
    collection_plans: dict[str, CollectionPlanArtifact] = {}

    def capture_module_snapshot(
        executed: _ExecutedBrokerPlan,
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
        resource_reader = CgroupV2ResourceReader(resolved_target)
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
        reserve_active_seconds = math.ceil(plan.duration_seconds)
        lease = docker_runtime.begin_existing_run(
            session_id,
            target,
            requested_modes=(mode,),
            reserve_active_seconds=reserve_active_seconds,
            reserve_evidence_bytes=plan.max_output_bytes,
        )
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
        project_root = policy.workspace_root(docker_policy.path.parent.parent)
        treatment_snapshot = capture_treatment_snapshot(
            project_root,
            tuple(
                policy.input_file(project_root / relative_path)
                for relative_path in docker_policy.managed.treatment_paths
            ),
        )
        run = docker_runtime.prepare_managed_run(
            session_id,
            requested_modes=(mode,),
            reserve_active_seconds=workload_timeout_seconds,
            reserve_evidence_bytes=max_output_bytes,
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
            namespace_attestation = namespace_attestation_from_target(target)
            resource_reader = CgroupV2ResourceReader(run.prepared.target)
            before_snapshot: CapturedCgroupSnapshot | None = None

            def capture_and_release_workload() -> None:
                nonlocal before_snapshot
                if before_snapshot is not None:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        "docker_resource_context",
                        "Managed Docker resource baseline callback was invoked more than once",
                    )
                before_snapshot = resource_reader.capture()
                run.coordinator.release(run.prepared)

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
            executed = execute_broker_plan(
                plan,
                ready_callback=capture_and_release_workload,
                namespace_attestation=namespace_attestation,
            )
            if before_snapshot is None:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "docker_resource_context",
                    "Collector completed without releasing the managed Docker workload",
                )
            after_snapshot = resource_reader.capture()
            resource_context = build_container_resource_context(
                resource_reader,
                before_snapshot,
                after_snapshot,
                source_collection_id=executed.collection_id,
                source_output_sha256=executed.output_sha256,
            )
            store.save(
                resource_context,
                resource_context.resource_context_id,
                "container-resource-context",
            )
            module_snapshot = capture_module_snapshot(executed)
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
            assert_treatment_snapshot_current(treatment_snapshot)
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
            store.save(
                run.authorization.workload,
                run.authorization.workload.workload_spec_id,
                "container-workload-spec",
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
            return _managed_run_reference(
                container_run,
                executed.reference,
                session,
                resource_context,
                module_snapshot,
                measurement,
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
    uri: str,
    resource_uri: str,
    module_uri: str | None,
    measurement_uri: str | None,
) -> ArtifactReference:
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
            **_container_resource_summary(resource_context, uri=resource_uri),
            **_container_module_summary(module_snapshot, uri=module_uri),
            **_container_measurement_summary(measurement, uri=measurement_uri),
        },
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
    parser.add_argument("--docker-project-config", type=Path)
    parser.add_argument("--docker-runtime-root", type=Path)
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
            docker_project_config=arguments.docker_project_config,
            docker_runtime_root=arguments.docker_runtime_root,
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
