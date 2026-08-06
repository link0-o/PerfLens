"""PerfLens MCP server built on the official Python SDK."""
# pyright: reportUnusedFunction=false

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from perflens import __version__
from perflens.application.analyze import analyze_folded, analyze_perf_data, analyze_perf_script
from perflens.application.symbols import get_source_context as resolve_source_context
from perflens.application.symbols import resolve_source as resolve_module_source
from perflens.benchmarks.adapters import load_benchmark
from perflens.classification.engine import build_diagnosis_bundle as create_diagnosis
from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.collection.collector import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_STAT_EVENTS,
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
    ArtifactReference,
    ArtifactTextPage,
    CallPathPage,
    ClassificationPage,
    CollectionCapabilityArtifact,
    CollectionPlanArtifact,
    HotspotDetails,
    HotspotPage,
    SourceContextArtifact,
    SourceResolutionArtifact,
)
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
    collector_socket: Path | None = None
    automatic_collection_policy: AutomaticCollectionPolicy = field(
        default_factory=AutomaticCollectionPolicy
    )
    perf_path: Path | None = None
    max_artifact_bytes: int = 128 << 20


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
            "workloads run unprivileged and require a separate per-call authorization."
        ),
        version=__version__,
    )
    collection_plans: dict[str, CollectionPlanArtifact] = {}

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
        events: tuple[str, ...] = DEFAULT_STAT_EVENTS,
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
        assert_plan_current(plan)
        assert config.collector_socket is not None
        artifact = CollectorBrokerClient(
            config.collector_socket,
            timeout_seconds=min(plan.duration_seconds + 15, 86_500),
        ).collect(plan)
        store.save(artifact, artifact.collection_id, "collection")
        return ArtifactReference(
            artifact_id=artifact.collection_id,
            artifact_type="collection",
            uri=store.uri(artifact.collection_id, "collection"),
            summary={
                "mode": artifact.mode,
                "target_type": artifact.target_type,
                "target_pid": artifact.target_pid,
                "output_bytes": artifact.output_bytes,
                "metric_count": len(artifact.metrics),
            },
        )

    @server.tool(
        name="collect_project_workload",
        description=(
            "Run one explicitly authorized executable inside a project as the MCP user, bind its "
            "exact PID incarnation, and collect it through the restricted Collector broker."
        ),
        annotations=EXECUTES_TARGET,
        meta={"perflens/permission": "PROJECT_EXECUTION"},
        structured_output=True,
    )
    async def collect_project_workload_tool(
        project_root: str,
        executable: str,
        authorization: str,
        arguments: tuple[str, ...] = (),
        mode: Literal["record", "stat", "sched", "lock", "off_cpu"] = "record",
        duration_seconds: float = 10.0,
        frequency_hz: int = 99,
        call_graph: Literal["fp", "dwarf", "lbr"] = "dwarf",
        events: tuple[str, ...] = DEFAULT_STAT_EVENTS,
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
                max_output_bytes=max_output_bytes,
            ),
            policy=config.automatic_collection_policy,
            capabilities=inspect_collection_capabilities(config.perf_path),
            collector_socket=config.collector_socket,
        )
        store.save(collection, collection.collection_id, "collection")
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
            },
        )

    @server.tool(
        name="analyze_collection",
        description="Analyze a stored record/sched/lock/off-CPU collection artifact.",
        annotations=WRITES_ARTIFACTS,
        meta={"perflens/permission": "PROCESS_EXECUTION"},
        structured_output=True,
    )
    async def analyze_collection(collection_id: str) -> ArtifactReference:
        _require_process_execution(config)
        collection = store.load_collection(collection_id)
        if collection.output_format != "perf_data":
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "collection",
                "perf stat metrics are already stored in the collection artifact",
                recoverable=True,
            )
        safe_path = policy.input_file(collection.output_path)
        analysis = analyze_perf_data(safe_path, perf_path=config.perf_path)
        store.save(analysis, analysis.analysis_id, "analysis")
        return ArtifactReference(
            artifact_id=analysis.analysis_id,
            artifact_type="analysis",
            uri=store.uri(analysis.analysis_id, "analysis"),
            summary={
                "status": analysis.status,
                "sample_count": analysis.metadata.sample_count,
                "total_weight": analysis.metadata.total_weight,
                "hotspot_count": len(analysis.hotspots),
            },
        )

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
            analysis = analyze_perf_data(safe_path)
        store.save(analysis, analysis.analysis_id, "analysis")
        return ArtifactReference(
            artifact_id=analysis.analysis_id,
            artifact_type="analysis",
            uri=store.uri(analysis.analysis_id, "analysis"),
            summary={
                "status": analysis.status,
                "sample_count": analysis.metadata.sample_count,
                "total_weight": analysis.metadata.total_weight,
                "hotspot_count": len(analysis.hotspots),
            },
        )

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
        diagnosis = create_diagnosis(analysis)
        classifications = tuple(
            item for item in diagnosis.classifications if item.hotspot_id == hotspot_id
        )
        return HotspotDetails(
            analysis_id=analysis_id,
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
        diagnosis = create_diagnosis(store.load_analysis(analysis_id))
        items = diagnosis.classifications
        page = items[cursor : cursor + limit]
        next_cursor = cursor + len(page) if cursor + len(page) < len(items) else None
        return ClassificationPage(
            analysis_id=analysis_id,
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
        diagnosis = create_diagnosis(store.load_analysis(analysis_id))
        artifact_id = f"diagnosis-{analysis_id}"
        store.save(diagnosis, artifact_id, "diagnosis")
        return ArtifactReference(
            artifact_id=artifact_id,
            artifact_type="diagnosis",
            uri=store.uri(artifact_id, "diagnosis"),
            summary={
                "status": diagnosis.status,
                "classification_count": len(diagnosis.classifications),
                "missing_evidence_count": len(diagnosis.missing_evidence),
            },
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
        artifact_type: str,
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
            collector_socket=arguments.collector_socket,
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=arguments.allow_automatic_collection,
                allowed_modes=tuple(arguments.automatic_mode or ("record", "stat")),
                max_duration_seconds=arguments.automatic_max_duration_seconds,
                max_frequency_hz=arguments.automatic_max_frequency_hz,
                max_output_bytes=arguments.automatic_max_output_bytes,
                plan_ttl_seconds=arguments.automatic_plan_ttl_seconds,
            ),
            perf_path=arguments.perf_path,
            max_artifact_bytes=arguments.max_artifact_bytes,
        )
    )
    server.run("stdio")


if __name__ == "__main__":
    main()
