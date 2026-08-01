"""Deterministic profile analysis application service."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from perflens import __version__
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CallPath,
    CallPathFrame,
    Hotspot,
    ParseStatistics,
    ProfileMetadata,
    ResourceLimitsContract,
    Warning,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.domain.ports import ProfileAdapter
from perflens.hotspots.aggregate import HotspotAggregator
from perflens.profiles.base import FileProfileSource
from perflens.profiles.folded import FoldedStackAdapter
from perflens.profiles.perf_data import PerfDataAdapter
from perflens.profiles.perf_script import PerfScriptAdapter
from perflens.security.paths import validate_input_file

AGGREGATION_SEMANTICS = "unique_symbol_dso_per_sample"
ProfileSourceType = Literal["folded", "perf_script", "perf_data"]


def analyze_folded(path: Path, *, limits: ResourceLimits | None = None) -> AnalysisArtifact:
    return _analyze_profile(path, "folded", FoldedStackAdapter(), limits=limits)


def analyze_perf_script(path: Path, *, limits: ResourceLimits | None = None) -> AnalysisArtifact:
    return _analyze_profile(path, "perf_script", PerfScriptAdapter(), limits=limits)


def analyze_perf_data(
    path: Path,
    *,
    limits: ResourceLimits | None = None,
    perf_path: Path | None = None,
    timeout_seconds: float = 300.0,
) -> AnalysisArtifact:
    adapter = PerfDataAdapter(perf_path, timeout_seconds=timeout_seconds)
    return _analyze_profile(path, "perf_data", adapter, limits=limits)


def _analyze_profile(
    path: Path,
    source_type: ProfileSourceType,
    adapter: ProfileAdapter,
    *,
    limits: ResourceLimits | None = None,
) -> AnalysisArtifact:
    effective_limits = limits or ResourceLimits()
    input_path = validate_input_file(path)
    input_size = input_path.stat().st_size
    if input_size > effective_limits.max_input_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "input",
            "Input file exceeds max_input_bytes",
            recoverable=True,
            details={
                "actual_bytes": input_size,
                "max_input_bytes": effective_limits.max_input_bytes,
            },
            suggested_actions=("Increase the explicit input limit if the file is trusted.",),
        )
    input_sha256 = _sha256_file(input_path, max_bytes=effective_limits.max_input_bytes)
    fingerprint = _fingerprint(input_sha256, source_type, effective_limits)
    source = FileProfileSource(path=input_path, source_type=source_type)
    with adapter.open(source, effective_limits) as stream:
        aggregator = HotspotAggregator(effective_limits, stream.frame_table)
        for sample in stream:
            aggregator.add(sample)
        result = aggregator.finish()
        diagnostics = stream.diagnostics()
        frame_table = stream.frame_table

    warnings = tuple(
        Warning(
            code=warning.code,
            message=warning.message,
            line_number=warning.line_number,
            preview=warning.preview,
        )
        for warning in diagnostics.warnings
    )
    metadata_warning_messages = tuple(warning.message for warning in warnings)
    if diagnostics.warnings_truncated:
        metadata_warning_messages += ("Additional parse warnings were truncated.",)

    total = result.total_weight
    hotspots = tuple(
        Hotspot(
            hotspot_id=f"H-{index:03d}",
            symbol=item.symbol,
            dso=item.dso,
            self_weight=item.self_weight,
            inclusive_weight=item.inclusive_weight,
            sample_count=item.sample_count,
            stack_occurrence_count=item.stack_occurrence_count,
            self_percent=_percent(item.self_weight, total),
            inclusive_percent=_percent(item.inclusive_weight, total),
            thread_count=item.thread_count,
        )
        for index, item in enumerate(
            result.hotspots[: effective_limits.max_hotspots_output],
            start=1,
        )
    )
    call_paths = tuple(
        CallPath(
            path_id=f"P-{index:03d}",
            frames=tuple(
                CallPathFrame(
                    symbol=frame_table.resolve(frame_id).symbol,
                    dso=frame_table.resolve(frame_id).dso,
                )
                for frame_id in item.frame_ids
            ),
            weight=item.weight,
            record_count=item.record_count,
            percent=_percent(item.weight, total),
        )
        for index, item in enumerate(
            result.call_paths[: effective_limits.max_call_paths_output],
            start=1,
        )
    )
    created_at = datetime.fromtimestamp(input_path.stat().st_mtime, tz=UTC).isoformat()
    metadata = ProfileMetadata(
        profile_id=f"profile-{input_sha256[:16]}",
        source_type=source_type,
        input_path=str(input_path),
        input_sha256=input_sha256,
        created_at=created_at,
        sample_count=result.record_count,
        total_weight=total,
        weight_unit=result.weight_unit,
        weight_source=result.weight_source,
        event=result.event,
        has_call_graph=result.has_call_graph,
        has_source_lines=any(
            frame_table.resolve(frame_id).source_file is not None
            for frame_id in range(len(frame_table))
        ),
        aggregation_semantics=AGGREGATION_SEMANTICS,
        parse_statistics=ParseStatistics(
            parsed_records=diagnostics.parsed_records,
            skipped_records=diagnostics.skipped_records,
            malformed_records=diagnostics.malformed_records,
            warning_count=diagnostics.warning_count,
            warnings_truncated=diagnostics.warnings_truncated,
            bytes_read=diagnostics.bytes_read,
        ),
        warnings=metadata_warning_messages,
    )
    status = "partial" if diagnostics.malformed_records else "complete"
    return AnalysisArtifact(
        perflens_version=__version__,
        analysis_id=f"analysis-{fingerprint[:16]}",
        analysis_fingerprint=fingerprint,
        status=status,
        aggregation_semantics=AGGREGATION_SEMANTICS,
        metadata=metadata,
        hotspots=hotspots,
        call_paths=call_paths,
        warnings=warnings,
        limits=ResourceLimitsContract(**_limits_dict(effective_limits)),
    )


def _sha256_file(path: Path, *, max_bytes: int, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "input",
                    "Input file grew beyond max_input_bytes while being read",
                    recoverable=True,
                    details={"actual_bytes": bytes_read, "max_input_bytes": max_bytes},
                )
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint(input_sha256: str, source_type: str, limits: ResourceLimits) -> str:
    digest = hashlib.sha256()
    components = (
        "perflens-analysis-v1",
        source_type,
        input_sha256,
        AGGREGATION_SEMANTICS,
        *[f"{key}={value}" for key, value in sorted(_limits_dict(limits).items())],
    )
    digest.update("\0".join(components).encode())
    return digest.hexdigest()


def _limits_dict(limits: ResourceLimits) -> dict[str, int]:
    return {
        "max_input_bytes": limits.max_input_bytes,
        "max_records": limits.max_records,
        "max_line_chars": limits.max_line_chars,
        "max_stack_depth": limits.max_stack_depth,
        "max_unique_frames": limits.max_unique_frames,
        "max_unique_call_paths": limits.max_unique_call_paths,
        "max_warnings": limits.max_warnings,
        "max_hotspots_output": limits.max_hotspots_output,
        "max_call_paths_output": limits.max_call_paths_output,
        "max_output_bytes": limits.max_output_bytes,
    }


def _percent(value: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(value * 100.0 / total, 6)
