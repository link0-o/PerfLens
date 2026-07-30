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
    source_type: Literal["folded"]
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
