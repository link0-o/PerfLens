"""Versioned public artifact contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ParseStatistics(ContractModel):
    parsed_records: int = Field(ge=0)
    skipped_records: int = Field(ge=0)
    malformed_records: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    warnings_truncated: bool
    bytes_read: int = Field(ge=0)


class Warning(ContractModel):
    code: str
    message: str
    line_number: int | None = Field(default=None, ge=1)
    preview: str | None = None


class ProfileMetadata(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    profile_id: str
    source_type: Literal["folded", "perf_script", "perf_data"]
    input_path: str
    input_sha256: str
    created_at: str
    sample_count: int = Field(ge=0)
    total_weight: int = Field(ge=0)
    weight_unit: str
    weight_source: str
    event: str
    has_call_graph: bool
    has_source_lines: bool
    aggregation_semantics: Literal["unique_symbol_dso_per_sample"]
    parse_statistics: ParseStatistics
    warnings: tuple[str, ...] = ()


class Frame(ContractModel):
    ip: str | None = None
    address_kind: Literal["unknown"] = "unknown"
    symbol: str
    raw_symbol: str
    normalized_symbol: str
    dso: str
    dso_path: str | None = None
    source_file: str | None = None
    source_line: int | None = Field(default=None, ge=1)
    source_column: int | None = Field(default=None, ge=1)
    is_kernel: bool = False
    is_inline: bool = False
    is_unknown: bool = False


class StackSample(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    sample_id: int | None = Field(default=None, ge=0)
    process_id: int | None = Field(default=None, ge=0)
    thread_id: int | None = Field(default=None, ge=0)
    thread_name: str
    cpu: int | None = Field(default=None, ge=0)
    timestamp: float | None = None
    event: str
    weight: int = Field(gt=0)
    weight_unit: str
    weight_source: str
    frames: tuple[Frame, ...]


class Hotspot(ContractModel):
    hotspot_id: str
    symbol: str
    dso: str
    self_weight: int = Field(ge=0)
    inclusive_weight: int = Field(ge=0)
    sample_count: int = Field(ge=0)
    stack_occurrence_count: int = Field(ge=0)
    self_percent: float = Field(ge=0, le=100)
    inclusive_percent: float = Field(ge=0, le=100)
    thread_count: int = Field(ge=0)
    source_locations: tuple[str, ...] = ()
    top_callers: tuple[str, ...] = ()
    top_callees: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()


class CallPathFrame(ContractModel):
    symbol: str
    dso: str


class CallPath(ContractModel):
    path_id: str
    frames: tuple[CallPathFrame, ...]
    weight: int = Field(gt=0)
    record_count: int = Field(gt=0)
    percent: float = Field(ge=0, le=100)


class ResourceLimitsContract(ContractModel):
    max_input_bytes: int = Field(gt=0)
    max_records: int = Field(gt=0)
    max_line_chars: int = Field(gt=0)
    max_stack_depth: int = Field(gt=0)
    max_unique_frames: int = Field(gt=0)
    max_unique_call_paths: int = Field(gt=0)
    max_warnings: int = Field(ge=0)
    max_hotspots_output: int = Field(gt=0)
    max_call_paths_output: int = Field(gt=0)
    max_output_bytes: int = Field(gt=0)


class AnalysisArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    analysis_id: str
    analysis_fingerprint: str
    status: Literal["complete", "partial", "failed"]
    aggregation_semantics: Literal["unique_symbol_dso_per_sample"]
    metadata: ProfileMetadata
    hotspots: tuple[Hotspot, ...]
    call_paths: tuple[CallPath, ...]
    warnings: tuple[Warning, ...]
    limits: ResourceLimitsContract


class ErrorBody(ContractModel):
    error_id: str
    code: str
    stage: str
    message: str
    recoverable: bool
    retryable: bool
    details: dict[str, Any]
    suggested_actions: tuple[str, ...]


class ErrorArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    error: ErrorBody


class ElfMetadataArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    path: str
    build_id: str | None
    architecture: str
    elf_type: str
    is_pie: bool
    is_stripped: bool
    has_debug_info: bool
    debug_link: str | None
    debug_file_candidates: tuple[str, ...]


class ResolvedSourceFrame(ContractModel):
    symbol: str
    file: str | None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    is_inline: bool


class SourceResolutionArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    resolver_version: str
    status: Literal["complete", "partial"]
    build_id: str
    binary_path: str
    module_offset: str
    runtime_address: str | None = None
    frames: tuple[ResolvedSourceFrame, ...]
    warnings: tuple[str, ...] = ()


class SourceContextArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    file: str
    line: int = Field(ge=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    lines: tuple[str, ...]


class Evidence(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    evidence_id: str
    level: Literal["L0", "L1", "L2", "L3", "L4"]
    kind: str
    statement: str
    artifact_id: str
    hotspot_id: str | None = None


class Classification(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    classification_id: str
    rule_id: str
    rule_version: int = Field(ge=1)
    hotspot_id: str
    symbol: str
    dso: str
    category: str
    conclusion_status: Literal["candidate"] = "candidate"
    confidence: Literal["low", "medium"]
    evidence_level: Literal["L1", "L2"]
    observation: str
    supporting_evidence: tuple[Evidence, ...]
    counter_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    next_steps: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]


class DiagnosisBundle(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    analysis_id: str
    status: Literal["complete", "partial"]
    generated_at: str
    classifications: tuple[Classification, ...]
    observations: tuple[str, ...]
    limitations: tuple[str, ...]
    missing_evidence: tuple[str, ...]


class ArtifactReference(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    artifact_id: str
    artifact_type: str
    uri: str
    summary: dict[str, str | int | float | bool | None]


class HotspotPage(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    analysis_id: str
    items: tuple[Hotspot, ...]
    next_cursor: int | None = Field(default=None, ge=0)
    total_items: int = Field(ge=0)


class CallPathPage(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    analysis_id: str
    symbol: str | None
    items: tuple[CallPath, ...]
    next_cursor: int | None = Field(default=None, ge=0)
    total_items: int = Field(ge=0)


class HotspotDetails(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    analysis_id: str
    hotspot: Hotspot
    dominant_call_paths: tuple[CallPath, ...]
    classifications: tuple[Classification, ...]
    limitations: tuple[str, ...]


class ClassificationPage(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    analysis_id: str
    items: tuple[Classification, ...]
    next_cursor: int | None = Field(default=None, ge=0)
    total_items: int = Field(ge=0)


class ArtifactTextPage(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    artifact_id: str
    artifact_type: str
    text: str
    next_offset: int | None = Field(default=None, ge=0)
    total_bytes: int = Field(ge=0)


class BenchmarkMetric(ContractModel):
    unit: str
    higher_is_better: bool
    values: tuple[float, ...]
    median: float
    mean: float
    standard_deviation: float = Field(ge=0)


class BenchmarkEnvironment(ContractModel):
    cpu_model: str | None = None
    cpu_count: int | None = Field(default=None, ge=1)
    kernel: str | None = None
    compiler: str | None = None
    compiler_flags: tuple[str, ...] = ()
    cpu_governor: str | None = None
    turbo: bool | None = None
    cpu_affinity: str | None = None
    numa_policy: str | None = None
    background_load: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    git_dirty: bool | None = None
    containerized: bool | None = None


class BenchmarkArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    benchmark_id: str
    name: str
    commit: str | None = None
    build_type: str | None = None
    duration_seconds: float | None = Field(default=None, gt=0)
    warmup_seconds: float | None = Field(default=None, ge=0)
    repetitions: int = Field(ge=1)
    concurrency: int | None = Field(default=None, ge=1)
    payload_bytes: int | None = Field(default=None, ge=0)
    operations: int | None = Field(default=None, ge=0)
    metrics: dict[str, BenchmarkMetric]
    environment: BenchmarkEnvironment
    error_count: int | None = Field(default=None, ge=0)
    source_format: Literal["perflens", "pyperf", "google_benchmark", "hyperfine"]
    warnings: tuple[str, ...] = ()


class ProfileHotspotDelta(ContractModel):
    symbol: str
    dso: str
    status: Literal["added", "removed", "changed"]
    baseline_self_percent: float = Field(ge=0, le=100)
    candidate_self_percent: float = Field(ge=0, le=100)
    self_delta_percent: float
    baseline_inclusive_percent: float = Field(ge=0, le=100)
    candidate_inclusive_percent: float = Field(ge=0, le=100)
    inclusive_delta_percent: float
    baseline_rank: int | None = Field(default=None, ge=1)
    candidate_rank: int | None = Field(default=None, ge=1)
    rank_delta: int | None = None


class CallPathDelta(ContractModel):
    frames: tuple[CallPathFrame, ...]
    status: Literal["added", "removed", "changed"]
    baseline_percent: float = Field(ge=0, le=100)
    candidate_percent: float = Field(ge=0, le=100)
    delta_percent: float


class ProfileComparison(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    comparison_id: str
    baseline_analysis_id: str
    candidate_analysis_id: str
    comparable: bool
    metadata_differences: dict[str, tuple[str, str]]
    hotspot_deltas: tuple[ProfileHotspotDelta, ...]
    call_path_deltas: tuple[CallPathDelta, ...]
    dso_changes: dict[str, tuple[tuple[str, ...], tuple[str, ...]]]
    baseline_unresolved_percent: float = Field(ge=0, le=100)
    candidate_unresolved_percent: float = Field(ge=0, le=100)
    unresolved_delta_percent: float
    warnings: tuple[str, ...]


class BenchmarkMetricComparison(ContractModel):
    metric: str
    unit: str
    baseline_samples: int = Field(ge=1)
    candidate_samples: int = Field(ge=1)
    baseline_median: float
    candidate_median: float
    raw_delta_percent: float | None
    improvement_percent: float | None
    confidence_interval_95: tuple[float, float] | None
    statistically_significant: bool | None
    practically_significant: bool
    status: Literal[
        "insufficient_data",
        "not_comparable",
        "no_material_change",
        "candidate_improvement",
        "candidate_regression",
    ]


class BenchmarkComparison(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    comparison_id: str
    baseline_benchmark_id: str
    candidate_benchmark_id: str
    comparable: bool
    condition_differences: dict[str, tuple[str, str]]
    expected_variables: dict[str, tuple[str, str]]
    minimum_practical_impact_percent: float = Field(ge=0)
    metrics: tuple[BenchmarkMetricComparison, ...]
    warnings: tuple[str, ...]


class PerfStatMetric(ContractModel):
    event: str
    value: float | None
    unit: str
    run_time_ns: int | None = Field(default=None, ge=0)
    running_percent: float | None = Field(default=None, ge=0, le=100)
    derived: bool = False
    status: Literal["measured", "not_counted", "not_supported", "derived"]


class CollectionModeCapability(ContractModel):
    mode: Literal["record", "stat", "sched", "lock", "off_cpu"]
    status: Literal["available", "conditional", "blocked"]
    required_privilege: Literal[
        "none",
        "cap_perfmon",
        "cap_sys_admin_or_policy_change",
    ]
    reason: str


class CollectionCapabilityArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    capability_id: str
    platform: str
    kernel_release: str
    effective_uid: int = Field(ge=0)
    perf_executable: str | None = None
    perf_version: str | None = None
    perf_event_paranoid: int | None = None
    kptr_restrict: int | None = None
    ptrace_scope: int | None = None
    effective_capabilities: tuple[str, ...] = ()
    perf_file_capabilities: tuple[str, ...] = ()
    tracefs_accessible: bool
    modes: tuple[CollectionModeCapability, ...]
    warnings: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()


class CollectionPlanArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    plan_id: str = Field(pattern=r"^plan-[a-f0-9]{20}$")
    mode: Literal["record", "stat", "sched", "lock", "off_cpu"]
    target_type: Literal["pid"]
    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    backend: Literal["privileged_broker"]
    duration_seconds: float = Field(gt=0, le=86_400)
    frequency_hz: int | None = Field(default=None, ge=1, le=10_000)
    call_graph: Literal["fp", "dwarf", "lbr"] | None = None
    events: tuple[str, ...] = ()
    max_output_bytes: int = Field(gt=0)
    expires_at: str
    policy_status: Literal["allowed", "denied"]
    required_privilege: Literal[
        "none",
        "cap_perfmon",
        "cap_sys_admin_or_policy_change",
    ]
    warnings: tuple[str, ...] = ()


class CollectionArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    collection_id: str
    mode: Literal["record", "stat", "sched", "lock", "off_cpu"]
    status: Literal["complete"] = "complete"
    target_type: Literal["command", "pid"]
    target_executable: str | None = None
    target_argument_count: int = Field(ge=0)
    target_argv_sha256: str | None = None
    target_pid: int | None = Field(default=None, gt=0)
    output_path: str
    output_sha256: str
    output_bytes: int = Field(gt=0)
    output_format: Literal["perf_data", "perf_stat_delimited"]
    perf_executable: str
    started_at: str
    finished_at: str
    duration_seconds: float = Field(ge=0)
    frequency_hz: int | None = Field(default=None, ge=1)
    call_graph: Literal["fp", "dwarf", "lbr"] | None = None
    events: tuple[str, ...] = ()
    metrics: tuple[PerfStatMetric, ...] = ()
    authorization: Literal["explicit"] = "explicit"
    diagnostics: tuple[str, ...] = ()
    diagnostics_truncated: bool = False
    warnings: tuple[str, ...] = ()


class ProjectRunArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    project_run_id: str = Field(pattern=r"^project-run-[a-f0-9]{20}$")
    project_root: str
    executable: str
    arguments: tuple[str, ...] = ()
    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    mode: Literal["record", "stat", "sched", "lock", "off_cpu"]
    requested_duration_seconds: float = Field(gt=0, le=86_400)
    collection_id: str
    workload_status: Literal["exited", "terminated_after_collection"]
    workload_exit_code: int | None = None
    started_at: str
    finished_at: str
    warnings: tuple[str, ...] = ()


class CollectorAcceptanceArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    acceptance_id: str = Field(pattern=r"^acceptance-[a-f0-9]{20}$")
    status: Literal["passed"] = "passed"
    socket_path: str
    probe_kind: Literal["built_in_cpu"] = "built_in_cpu"
    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    requested_duration_seconds: float = Field(gt=0, le=5)
    collection_id: str
    output_path: str
    output_sha256: str
    output_bytes: int = Field(gt=0)
    metric_count: int = Field(ge=0)
    started_at: str
    finished_at: str
    warnings: tuple[str, ...] = ()


class CollectorHealthArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["ready"] = "ready"
    policy_version: int = Field(gt=0)
    service_pid: int = Field(gt=0)
    service_uid: int = Field(ge=0)
    peer_uid: int = Field(ge=0)
    allowed_modes: tuple[str, ...]
    spool_root: str


class CollectorDeploymentArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["dry_run", "deployed"]
    config_source: str
    config_path: str
    service_path: str
    collector_command: str
    allowed_uids: tuple[int, ...]
    planned_commands: tuple[tuple[str, ...], ...]
    warnings: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


class CollectorUpgradeArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["dry_run", "restarted", "upgraded"]
    config_path: str
    service_path: str
    collector_command: str
    previous_service_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_service_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    service_update_required: bool
    service_updated: bool
    planned_commands: tuple[tuple[str, ...], ...]
    config_preserved: bool = True
    state_preserved: bool = True
    warnings: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


class CollectorPolicyUpdateArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["dry_run", "unchanged", "updated"]
    candidate_source: str
    config_path: str
    previous_policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_change_required: bool
    policy_updated: bool
    service_restarted: bool
    allowed_uid: int = Field(gt=0)
    allowed_modes: tuple[str, ...]
    planned_commands: tuple[tuple[str, ...], ...]
    service_unit_preserved: bool = True
    state_preserved: bool = True
    warnings: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


class CollectorUndeploymentArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["dry_run", "removed", "already_absent"]
    service_path: str
    config_path: str
    state_directory: str
    planned_commands: tuple[tuple[str, ...], ...]
    config_preserved: bool = True
    state_preserved: bool = True
    warnings: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


class CollectorSpoolStatusArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status_id: str = Field(pattern=r"^spool-status-[a-f0-9]{16}$")
    checked_at: str
    status: Literal["ready", "warning", "exhausted", "unsafe", "unavailable"]
    config_path: str
    spool_root: str
    scan_complete: bool
    observed_artifact_count: int = Field(ge=0)
    observed_logical_bytes: int = Field(ge=0)
    filesystem_free_bytes: int | None = Field(default=None, ge=0)
    max_output_bytes: int = Field(gt=0)
    max_spool_bytes: int = Field(gt=0)
    max_spool_artifacts: int = Field(gt=0)
    min_free_bytes: int = Field(ge=0)
    remaining_spool_bytes: int | None = Field(default=None, ge=0)
    remaining_artifact_slots: int | None = Field(default=None, ge=0)
    free_bytes_above_reserve: int | None = Field(default=None, ge=0)
    max_collectable_output_bytes: int | None = Field(default=None, ge=0)
    issues: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


class CollectorSpoolArchiveEntry(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    name: str = Field(pattern=r"^plan-[a-f0-9]{20}\.(?:stat\.csv|perf\.data)$")
    logical_bytes: int = Field(ge=0)
    modified_time_ns: int = Field(ge=0)
    source_device: int = Field(ge=0)
    source_inode: int = Field(gt=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class CollectorSpoolArchiveManifest(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    archive_id: str = Field(pattern=r"^spool-archive-[a-f0-9]{16}$")
    created_at: str
    config_path: str
    spool_root: str
    allowed_uid: int = Field(gt=0)
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    older_than_days: int = Field(ge=0, le=36_500)
    keep_latest: int = Field(ge=0, le=10_000)
    max_artifacts: int = Field(gt=0, le=10_000)
    max_total_bytes: int = Field(gt=0, le=1 << 40)
    eligible_artifact_count: int = Field(ge=0)
    selection_truncated: bool
    artifact_count: int = Field(ge=0, le=10_000)
    total_logical_bytes: int = Field(ge=0, le=1 << 40)
    entries: tuple[CollectorSpoolArchiveEntry, ...]


class CollectorSpoolArchiveArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["dry_run", "archived", "nothing_to_archive"]
    archive_path: str
    archive_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    archive_created: bool
    manifest: CollectorSpoolArchiveManifest
    source_artifacts_preserved: bool = True
    next_steps: tuple[str, ...] = ()


class CollectorSpoolArchiveVerificationArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    verification_id: str = Field(pattern=r"^archive-verification-[a-f0-9]{16}$")
    checked_at: str
    status: Literal["verified"] = "verified"
    archive_path: str
    archive_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    archive_id: str = Field(pattern=r"^spool-archive-[a-f0-9]{16}$")
    archive_created_at: str
    config_path: str
    spool_root: str
    artifact_count: int = Field(ge=0, le=10_000)
    total_logical_bytes: int = Field(ge=0, le=1 << 40)
    source_artifacts_checked: bool
    present_source_artifact_count: int | None = Field(default=None, ge=0)
    absent_source_artifact_count: int | None = Field(default=None, ge=0)
    archive_preserved: bool = True
    next_steps: tuple[str, ...] = ()


class CollectorSpoolPruneArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status: Literal["dry_run", "pruned", "nothing_to_prune"]
    archive_path: str
    archive_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    archive_id: str = Field(pattern=r"^spool-archive-[a-f0-9]{16}$")
    config_path: str
    spool_root: str
    planned_artifact_names: tuple[str, ...]
    planned_logical_bytes: int = Field(ge=0)
    already_absent_artifact_count: int = Field(ge=0)
    removed_artifact_count: int = Field(ge=0)
    removed_logical_bytes: int = Field(ge=0)
    authorization_required: Literal[
        "I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE"
    ] = "I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE"
    archive_preserved: bool = True
    next_steps: tuple[str, ...] = ()


class RuntimeStatusArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    status_id: str = Field(pattern=r"^status-[a-f0-9]{16}$")
    checked_at: str
    project_root: str
    setup_directory: str
    setup_status: Literal["missing", "incomplete", "ready"]
    skill_status: Literal["missing", "incomplete", "ready"]
    mcp_config_status: Literal["missing", "ready"]
    automatic_collection_requested: bool
    collector_assets_status: Literal["not_requested", "missing", "incomplete", "ready"]
    collector_socket: str
    collector_socket_status: Literal["missing", "invalid", "inaccessible", "ready"]
    collector_group_status: Literal["missing", "not_member", "member"]
    collector_health_status: Literal[
        "not_checked", "ready", "unreachable", "rejected"
    ] = "not_checked"
    collector_health_error_code: str | None = None
    collector_service_pid: int | None = Field(default=None, gt=0)
    collector_service_uid: int | None = Field(default=None, ge=0)
    collector_policy_version: int | None = Field(default=None, gt=0)
    collector_allowed_modes: tuple[str, ...] = ()
    collector_spool_root: str | None = None
    capability_id: str
    host_collection_status: Literal["available", "conditional", "blocked"]
    automatic_collection_status: Literal[
        "not_configured",
        "configuration_incomplete",
        "collector_unavailable",
        "access_denied",
        "ready_for_verification",
    ]
    issues: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()


class SetupArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    project_root: str
    output_directory: str
    skill_status: Literal["installed", "existing", "skipped"]
    skill_path: str | None = None
    mcp_config_path: str
    capability_report_path: str
    collector_assets_path: str | None = None
    automatic_collection_enabled: bool = False
    collection_status: Literal["available", "conditional", "blocked"]
    blocked_modes: tuple[str, ...] = ()
    generated_files: tuple[str, ...]
    next_steps: tuple[str, ...]
