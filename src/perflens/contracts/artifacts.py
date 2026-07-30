"""Versioned public artifact contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


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
