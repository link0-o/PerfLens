"""Deterministic profile analysis application service."""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from perflens import __version__
from perflens.application.evidence import (
    build_conversion_provenance,
    build_evidence_quality,
    compute_analysis_content_sha256,
    compute_analysis_fingerprint,
    validate_aggregation_invariants,
)
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CallPath,
    CallPathFrame,
    CollectionEvidenceProvenance,
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
    collection: CollectionEvidenceProvenance | None = None,
    symfs_path: Path | None = None,
    symfs_identity_sha256: str | None = None,
) -> AnalysisArtifact:
    adapter = PerfDataAdapter(
        perf_path,
        timeout_seconds=timeout_seconds,
        symfs_path=symfs_path,
        symfs_identity_sha256=symfs_identity_sha256,
    )
    return _analyze_profile(
        path,
        "perf_data",
        adapter,
        limits=limits,
        collection=collection,
    )


def _analyze_profile(
    path: Path,
    source_type: ProfileSourceType,
    adapter: ProfileAdapter,
    *,
    limits: ResourceLimits | None = None,
    collection: CollectionEvidenceProvenance | None = None,
) -> AnalysisArtifact:
    effective_limits = limits or ResourceLimits()
    input_path = validate_input_file(path)
    input_stat = input_path.stat()
    input_identity = _file_identity(input_stat)
    input_size = input_stat.st_size
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
    if collection is not None and (
        collection.output_bytes != input_size or collection.output_sha256 != input_sha256
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "evidence_validation",
            "Collection output does not match the profile selected for analysis",
            details={
                "collection_id": collection.collection_id,
                "expected_bytes": collection.output_bytes,
                "actual_bytes": input_size,
                "expected_sha256": collection.output_sha256,
                "actual_sha256": input_sha256,
            },
            suggested_actions=(
                "Do not analyze this file as that Collection; preserve both artifacts for review.",
            ),
        )
    source = FileProfileSource(path=input_path, source_type=source_type)
    with adapter.open(source, effective_limits) as stream:
        aggregator = HotspotAggregator(effective_limits, stream.frame_table)
        for sample in stream:
            aggregator.add(sample)
        result = aggregator.finish()
        if source_type != "folded" and result.record_count == 0:
            # An empty perf transcript does not expose an observed event or period.
            # Preserve that distinction from the Collection's requested/selected
            # record event: the latter remains available through provenance, while
            # the Analysis truthfully reports that it contains no sampled event.
            result = replace(
                result,
                event="unknown",
                weight_unit="sample_count",
                weight_source="sample_count_fallback",
            )
        diagnostics = stream.diagnostics()
        frame_table = stream.frame_table
        conversion = build_conversion_provenance(
            source_type=source_type,
            input_sha256=input_sha256,
            input_bytes=input_size,
            stream=stream,
        )

    _assert_input_unchanged(
        input_path,
        before_identity=input_identity,
        before_sha256=input_sha256,
        max_bytes=effective_limits.max_input_bytes,
    )

    validate_aggregation_invariants(result, diagnostics, source_type=source_type)
    fingerprint = compute_analysis_fingerprint(
        input_sha256=input_sha256,
        source_type=source_type,
        aggregation_semantics=AGGREGATION_SEMANTICS,
        limits=_limits_dict(effective_limits),
        conversion=conversion,
        collection=collection,
    )

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
    hotspot_identities = {(item.symbol, item.dso): item for item in result.hotspots}
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
            symbol_variants=item.symbol_variants,
            symbol_variant_count=item.symbol_variant_count,
            symbol_variants_truncated=item.symbol_variants_truncated,
            normalization_merged=item.normalization_merged,
            source_locations=item.source_locations,
            source_locations_truncated=item.source_locations_truncated,
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
                    symbol_variant_count=hotspot_identities[
                        (
                            frame_table.resolve(frame_id).symbol,
                            frame_table.resolve(frame_id).dso,
                        )
                    ].symbol_variant_count,
                    symbol_variants_truncated=hotspot_identities[
                        (
                            frame_table.resolve(frame_id).symbol,
                            frame_table.resolve(frame_id).dso,
                        )
                    ].symbol_variants_truncated,
                    normalization_merged=hotspot_identities[
                        (
                            frame_table.resolve(frame_id).symbol,
                            frame_table.resolve(frame_id).dso,
                        )
                    ].normalization_merged,
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
    evidence_quality = build_evidence_quality(
        result,
        diagnostics,
        conversion,
        exported_hotspot_count=len(hotspots),
        exported_hotspot_self_weight=sum(item.self_weight for item in hotspots),
        exported_call_path_count=len(call_paths),
        exported_call_path_weight=sum(item.weight for item in call_paths),
        input_sha256=input_sha256,
        input_bytes=input_size,
        collection=collection,
    )
    created_at = datetime.fromtimestamp(input_stat.st_mtime, tz=UTC).isoformat()
    metadata = ProfileMetadata(
        profile_id=f"profile-{input_sha256[:16]}",
        source_type=source_type,
        input_path=str(input_path),
        input_sha256=input_sha256,
        input_bytes=input_size,
        created_at=created_at,
        sample_count=result.record_count,
        total_weight=total,
        weight_unit=result.weight_unit,
        weight_source=result.weight_source,
        event=result.event,
        has_call_graph=result.has_call_graph,
        has_source_lines=result.source_line_frame_count > 0,
        aggregation_semantics=AGGREGATION_SEMANTICS,
        conversion=conversion,
        collection=collection,
        parse_statistics=ParseStatistics(
            parsed_records=diagnostics.parsed_records,
            skipped_records=diagnostics.skipped_records,
            malformed_records=diagnostics.malformed_records,
            warning_count=diagnostics.warning_count,
            warnings_truncated=diagnostics.warnings_truncated,
            bytes_read=diagnostics.bytes_read,
            frame_lines=diagnostics.frame_lines,
            duplicate_frame_lines=diagnostics.duplicate_frame_lines,
            address_annotation_lines=diagnostics.address_annotation_lines,
            source_annotation_lines=diagnostics.source_annotation_lines,
            unicode_replacement_count=diagnostics.unicode_replacement_count,
        ),
        warnings=metadata_warning_messages,
    )
    status = "partial" if evidence_quality.quality_status == "partial" else "complete"
    artifact = AnalysisArtifact(
        perflens_version=__version__,
        analysis_id=f"analysis-{fingerprint[:16]}",
        analysis_fingerprint=fingerprint,
        content_sha256="0" * 64,
        status=status,
        aggregation_semantics=AGGREGATION_SEMANTICS,
        metadata=metadata,
        evidence_quality=evidence_quality,
        hotspots=hotspots,
        call_paths=call_paths,
        warnings=warnings,
        limits=ResourceLimitsContract(**_limits_dict(effective_limits)),
    )
    completed = artifact.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(artifact)}
    )
    # Keep construction and independent verification separate. This catches a projection bug in
    # PerfLens itself before an otherwise self-consistent JSON artifact reaches the Agent.
    verify_analysis_artifact(completed, verify_source=False)
    return completed


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


def _file_identity(stat_result: os.stat_result) -> tuple[int, ...]:
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_mode,
        stat_result.st_nlink,
        stat_result.st_uid,
        stat_result.st_gid,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )


def _assert_input_unchanged(
    path: Path,
    *,
    before_identity: tuple[int, ...],
    before_sha256: str,
    max_bytes: int,
) -> None:
    try:
        after_identity = _file_identity(path.stat())
        after_sha256 = _sha256_file(path, max_bytes=max_bytes)
    except (OSError, PerfLensError) as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "evidence_validation",
            "Profile input could not be verified after analysis",
            details={"path": str(path)},
        ) from exc
    if after_identity != before_identity or after_sha256 != before_sha256:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "evidence_validation",
            "Profile input changed while it was being analyzed",
            details={"path": str(path)},
            suggested_actions=("Freeze or copy the raw profile, then repeat the analysis.",),
        )


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
