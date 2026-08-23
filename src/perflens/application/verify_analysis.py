"""Independent structural verification for stored profile analyses."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path
from typing import cast

from perflens.application.evidence import (
    compute_analysis_content_sha256,
    compute_analysis_fingerprint,
    is_on_cpu_sampling_event,
)
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    AnalysisVerificationArtifact,
    EvidenceQuality,
    Hotspot,
    VerificationCheck,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.profiles.events import canonical_perf_event, perf_period_unit

_PERF_MAP = re.compile(r"^perf-\d+\.map$")


def verify_analysis_artifact(
    analysis: AnalysisArtifact,
    *,
    verify_source: bool,
) -> AnalysisVerificationArtifact:
    checks: list[VerificationCheck] = []
    warnings: list[str] = []

    _require(
        analysis.content_sha256 == compute_analysis_content_sha256(analysis),
        "analysis content SHA-256 does not match its Agent-visible fields",
    )
    checks.append(
        VerificationCheck(
            name="analysis_content_sha256",
            status="passed",
            detail="Every Agent-visible Analysis field matches the canonical content digest.",
        )
    )

    expected_fingerprint = compute_analysis_fingerprint(
        input_sha256=analysis.metadata.input_sha256,
        source_type=analysis.metadata.source_type,
        aggregation_semantics=analysis.aggregation_semantics,
        limits={key: int(value) for key, value in analysis.limits.model_dump().items()},
        conversion=analysis.metadata.conversion,
        collection=analysis.metadata.collection,
    )
    _require(
        analysis.analysis_fingerprint == expected_fingerprint,
        "analysis fingerprint does not match its input, conversion, and limits",
    )
    _require(
        analysis.analysis_id == f"analysis-{expected_fingerprint[:16]}",
        "analysis identifier does not match its fingerprint",
    )
    checks.append(
        VerificationCheck(
            name="analysis_fingerprint",
            status="passed",
            detail="Analysis ID and fingerprint bind the input, converter manifest, and limits.",
        )
    )

    quality = analysis.evidence_quality
    metadata = analysis.metadata
    _require(quality.parser_invariants_passed, "analysis does not claim parser invariants passed")
    _require(
        metadata.aggregation_semantics == analysis.aggregation_semantics,
        "metadata and Analysis aggregation semantics differ",
    )
    _require(quality.sample_count == metadata.sample_count, "quality sample count mismatch")
    _require(quality.total_weight == metadata.total_weight, "quality total weight mismatch")
    _require(quality.input_sha256 == metadata.input_sha256, "quality input hash mismatch")
    _require(quality.input_bytes == metadata.input_bytes, "quality input byte count mismatch")
    _require(
        metadata.conversion.transcript_bytes == metadata.parse_statistics.bytes_read,
        "conversion transcript and parser byte counts differ",
    )
    _require(quality.event == metadata.event, "quality event mismatch")
    _require(quality.weight_unit == metadata.weight_unit, "quality weight unit mismatch")
    _require(quality.weight_source == metadata.weight_source, "quality weight source mismatch")
    _require(
        quality.malformed_record_count == metadata.parse_statistics.malformed_records,
        "quality malformed count mismatch",
    )
    _require(
        quality.warning_count == metadata.parse_statistics.warning_count,
        "quality warning count mismatch",
    )
    _require(
        quality.warnings_truncated == metadata.parse_statistics.warnings_truncated,
        "quality warning-truncation state mismatch",
    )
    _require(
        quality.unicode_replacement_count == metadata.parse_statistics.unicode_replacement_count,
        "quality Unicode replacement count mismatch",
    )
    _require(
        quality.frame_line_count == metadata.parse_statistics.frame_lines,
        "quality Frame-line count mismatch",
    )
    _require(
        quality.duplicate_frame_line_count == metadata.parse_statistics.duplicate_frame_lines,
        "quality duplicate Frame-line count mismatch",
    )
    _require(
        quality.address_annotation_line_count == metadata.parse_statistics.address_annotation_lines,
        "quality address-annotation count mismatch",
    )
    _require(
        quality.source_annotation_line_count == metadata.parse_statistics.source_annotation_lines,
        "quality source-annotation count mismatch",
    )
    _require(
        metadata.parse_statistics.parsed_records == metadata.sample_count,
        "parsed record count does not match sample count",
    )
    _require(
        quality.aggregated_frame_occurrence_count >= metadata.sample_count,
        "aggregated Frame count is smaller than the sample count",
    )
    _require(
        quality.source_line_frame_count <= quality.aggregated_frame_occurrence_count,
        "source-line Frame count exceeds aggregated Frames",
    )
    _require(
        quality.inline_frame_count <= quality.aggregated_frame_occurrence_count,
        "inline Frame count exceeds aggregated Frames",
    )
    if metadata.source_type in {"perf_script", "perf_data"} and quality.malformed_record_count == 0:
        _require(
            quality.frame_line_count
            == quality.aggregated_frame_occurrence_count + quality.duplicate_frame_line_count,
            "clean Frame-line accounting does not match aggregated Frames",
        )
    _require(
        metadata.parse_statistics.warning_count >= len(analysis.warnings),
        "retained warning count exceeds total warning count",
    )
    if not metadata.parse_statistics.warnings_truncated:
        _require(
            metadata.parse_statistics.warning_count == len(analysis.warnings),
            "non-truncated warning count does not match retained warnings",
        )
    _require(quality.unresolved_self_weight <= metadata.total_weight, "unresolved weight overflow")
    has_sample_context = _has_complete_sample_context(quality)
    if has_sample_context:
        _require(
            cast(int, quality.kernel_context_self_weight)
            + cast(int, quality.user_context_self_weight)
            + cast(int, quality.unknown_context_self_weight)
            == metadata.total_weight,
            "sample-context Self weights do not sum to total weight",
        )
        _require(
            cast(int, quality.unresolved_kernel_self_weight)
            + cast(int, quality.unresolved_user_self_weight)
            + cast(int, quality.unresolved_unknown_context_self_weight)
            == quality.unresolved_self_weight,
            "unresolved sample-context weights do not sum to unresolved Self weight",
        )
    _require(quality.call_graph_weight <= metadata.total_weight, "call-graph weight overflow")
    _require(
        quality.source_line_self_weight <= metadata.total_weight,
        "source-line weight overflow",
    )
    _require(
        quality.unresolved_self_percent
        == _percent(quality.unresolved_self_weight, metadata.total_weight),
        "unresolved Self percentage mismatch",
    )
    if has_sample_context:
        for weight, percent, label in (
            (
                quality.kernel_context_self_weight,
                quality.kernel_context_self_percent,
                "kernel-context Self",
            ),
            (
                quality.user_context_self_weight,
                quality.user_context_self_percent,
                "user-context Self",
            ),
            (
                quality.unknown_context_self_weight,
                quality.unknown_context_self_percent,
                "unknown-context Self",
            ),
            (
                quality.unresolved_kernel_self_weight,
                quality.unresolved_kernel_self_percent,
                "unresolved kernel-context Self",
            ),
            (
                quality.unresolved_user_self_weight,
                quality.unresolved_user_self_percent,
                "unresolved user-context Self",
            ),
            (
                quality.unresolved_unknown_context_self_weight,
                quality.unresolved_unknown_context_self_percent,
                "unresolved unknown-context Self",
            ),
        ):
            _require(
                cast(float, percent)
                == _percent(cast(int, weight), metadata.total_weight),
                f"{label} percentage mismatch",
            )
    _require(
        quality.call_graph_weight_percent
        == _percent(quality.call_graph_weight, metadata.total_weight),
        "call-graph coverage percentage mismatch",
    )
    _require(
        quality.source_line_self_percent
        == _percent(quality.source_line_self_weight, metadata.total_weight),
        "source-line coverage percentage mismatch",
    )
    _require(
        metadata.has_call_graph == (quality.call_graph_weight > 0),
        "call-graph availability mismatch",
    )
    _require(
        metadata.has_source_lines == (quality.source_line_frame_count > 0),
        "source-line availability mismatch",
    )
    expected_quality_status = (
        "partial"
        if (
            quality.malformed_record_count
            or metadata.total_weight == 0
            or quality.warning_count
            or quality.unicode_replacement_count
            or quality.unresolved_self_weight
            or metadata.conversion.diagnostics
            or quality.omitted_hotspot_self_weight
            or quality.omitted_call_path_weight
            or quality.source_locations_truncated_hotspot_count
        )
        else "verified"
    )
    _require(
        quality.quality_status == expected_quality_status,
        "evidence-quality status does not match diagnostics and omissions",
    )
    expected_status = "partial" if expected_quality_status == "partial" else "complete"
    _require(analysis.status == expected_status, "analysis and evidence-quality status mismatch")
    _verify_collection_provenance(analysis)
    _verify_event_semantics(analysis)
    _verify_conclusion_gate(analysis)
    checks.append(
        VerificationCheck(
            name="metadata_quality_consistency",
            status="passed",
            detail="Profile metadata and EvidenceQuality agree on scope and diagnostics.",
        )
    )

    hotspot_keys: set[tuple[str, str]] = set()
    hotspots_by_key: dict[tuple[str, str], Hotspot] = {}
    hotspot_ids: set[str] = set()
    for index, hotspot in enumerate(analysis.hotspots, start=1):
        _require(hotspot.hotspot_id not in hotspot_ids, "duplicate hotspot identifier")
        _require(
            hotspot.hotspot_id == f"H-{index:03d}",
            "hotspot identifier is not canonical for its deterministic order",
        )
        hotspot_ids.add(hotspot.hotspot_id)
        key = (hotspot.symbol, hotspot.dso)
        _require(key not in hotspot_keys, "duplicate public hotspot identity")
        hotspot_keys.add(key)
        hotspots_by_key[key] = hotspot
        _require(hotspot.self_weight <= hotspot.inclusive_weight, "hotspot Self exceeds Inclusive")
        _require(hotspot.inclusive_weight <= metadata.total_weight, "hotspot Inclusive overflow")
        _require(hotspot.sample_count <= metadata.sample_count, "hotspot sample-count overflow")
        _require(
            hotspot.stack_occurrence_count >= hotspot.sample_count,
            "hotspot occurrence count is smaller than sample count",
        )
        _require(hotspot.thread_count <= hotspot.sample_count, "hotspot thread-count overflow")
        _require(
            hotspot.self_percent == _percent(hotspot.self_weight, metadata.total_weight),
            "hotspot Self percentage mismatch",
        )
        _require(
            hotspot.inclusive_percent == _percent(hotspot.inclusive_weight, metadata.total_weight),
            "hotspot Inclusive percentage mismatch",
        )
        _require(hotspot.symbol_variant_count >= 1, "hotspot has no symbol identity")
        _require(
            hotspot.symbol_variant_count >= len(hotspot.symbol_variants),
            "hotspot symbol-variant count is too small",
        )
        if not hotspot.symbol_variants_truncated:
            _require(
                hotspot.symbol_variant_count == len(hotspot.symbol_variants),
                "complete hotspot symbol-variant count mismatch",
            )
        _require(
            hotspot.normalization_merged == (hotspot.symbol_variant_count > 1),
            "hotspot normalization-merge flag mismatch",
        )
    _require(
        list(analysis.hotspots)
        == sorted(
            analysis.hotspots,
            key=lambda item: (
                -item.self_weight,
                -item.inclusive_weight,
                item.symbol,
                item.dso,
            ),
        ),
        "hotspots are not in deterministic aggregation order",
    )
    _require(
        quality.normalization_merge_count
        >= sum(1 for item in analysis.hotspots if item.normalization_merged),
        "normalization merge count is smaller than exported merged hotspots",
    )
    _require(
        quality.source_locations_truncated_hotspot_count
        >= sum(1 for item in analysis.hotspots if item.source_locations_truncated),
        "source-location truncation count is smaller than exported truncated hotspots",
    )

    exported_self = sum(item.self_weight for item in analysis.hotspots)
    _require(
        exported_self + quality.omitted_hotspot_self_weight == metadata.total_weight,
        "exported and omitted hotspot Self weight do not conserve total weight",
    )
    _require(
        quality.exported_hotspot_count == len(analysis.hotspots),
        "exported hotspot count mismatch",
    )
    _require(
        quality.total_hotspot_count >= quality.exported_hotspot_count,
        "total hotspot count is smaller than exported hotspot count",
    )
    _require(
        quality.exported_hotspot_count <= analysis.limits.max_hotspots_output,
        "exported hotspot count exceeds the recorded limit",
    )
    _require(
        quality.normalization_merge_count <= quality.total_hotspot_count,
        "normalization merge count exceeds total hotspots",
    )
    _require(
        quality.source_locations_truncated_hotspot_count <= quality.total_hotspot_count,
        "source-location truncation count exceeds total hotspots",
    )
    checks.append(
        VerificationCheck(
            name="hotspot_weight_conservation",
            status="passed",
            detail="Exported plus omitted Self weight equals total profile weight.",
        )
    )

    path_keys: set[tuple[tuple[str, str], ...]] = set()
    path_ids: set[str] = set()
    for index, path in enumerate(analysis.call_paths, start=1):
        _require(path.path_id not in path_ids, "duplicate call-path identifier")
        _require(
            path.path_id == f"P-{index:03d}",
            "call-path identifier is not canonical for its deterministic order",
        )
        path_ids.add(path.path_id)
        _require(bool(path.frames), "call path has no frames")
        key = tuple((frame.symbol, frame.dso) for frame in path.frames)
        _require(key not in path_keys, "duplicate public call path")
        path_keys.add(key)
        _require(path.weight <= metadata.total_weight, "call-path weight overflow")
        _require(path.record_count <= metadata.sample_count, "call-path record-count overflow")
        for frame in path.frames:
            _require(frame.symbol_variant_count >= 1, "call-path Frame has no symbol identity")
            _require(
                frame.normalization_merged == (frame.symbol_variant_count > 1),
                "call-path Frame normalization-merge flag mismatch",
            )
            exported_hotspot = hotspots_by_key.get((frame.symbol, frame.dso))
            if exported_hotspot is not None:
                _require(
                    frame.symbol_variant_count == exported_hotspot.symbol_variant_count
                    and frame.symbol_variants_truncated
                    == exported_hotspot.symbol_variants_truncated
                    and frame.normalization_merged == exported_hotspot.normalization_merged,
                    "call-path Frame and hotspot symbol identity differ",
                )
        _require(
            path.percent == _percent(path.weight, metadata.total_weight),
            "call-path percentage mismatch",
        )
    _require(
        list(analysis.call_paths)
        == sorted(
            analysis.call_paths,
            key=lambda item: (
                -item.weight,
                tuple((frame.symbol, frame.dso) for frame in item.frames),
            ),
        ),
        "call paths are not in deterministic aggregation order",
    )
    exported_paths = sum(item.weight for item in analysis.call_paths)
    _require(
        exported_paths + quality.omitted_call_path_weight == metadata.total_weight,
        "exported and omitted call-path weight do not conserve total weight",
    )
    _require(
        quality.exported_call_path_count == len(analysis.call_paths),
        "exported call-path count mismatch",
    )
    _require(
        quality.total_call_path_count >= quality.exported_call_path_count,
        "total call-path count is smaller than exported call-path count",
    )
    _require(
        quality.total_call_path_count <= metadata.sample_count,
        "unique call-path count exceeds sample count",
    )
    _require(
        quality.exported_call_path_count <= analysis.limits.max_call_paths_output,
        "exported call-path count exceeds the recorded limit",
    )
    checks.append(
        VerificationCheck(
            name="call_path_weight_conservation",
            status="passed",
            detail="Exported plus omitted call-path weight equals total profile weight.",
        )
    )
    _verify_complete_export_projection(analysis, hotspots_by_key)

    if metadata.source_type in {"folded", "perf_script"}:
        _require(
            metadata.conversion.transcript_sha256 == metadata.input_sha256,
            "text input and transcript hashes differ",
        )
        checks.append(
            VerificationCheck(
                name="text_transcript_identity",
                status="passed",
                detail="The analyzed text transcript is the hashed source input.",
            )
        )
    else:
        checks.append(
            VerificationCheck(
                name="text_transcript_identity",
                status="skipped",
                detail="perf.data transcript is hash-bound but not retained in this artifact.",
            )
        )
        warnings.append(
            "The perf-script transcript is hash-bound but not retained; full replay requires the "
            "original perf.data and compatible symbol context."
        )

    if verify_source:
        source_path = Path(metadata.input_path)
        try:
            resolved = source_path.expanduser().resolve(strict=True)
        except OSError:
            checks.append(
                VerificationCheck(
                    name="source_input_sha256",
                    status="skipped",
                    detail="The original source input is no longer available.",
                )
            )
            warnings.append("The original source input could not be re-hashed.")
        else:
            _require(resolved.is_file(), "recorded source input is not a regular file")
            actual_sha256 = _sha256_file(resolved, maximum=analysis.limits.max_input_bytes)
            _require(actual_sha256 == metadata.input_sha256, "source input SHA-256 mismatch")
            checks.append(
                VerificationCheck(
                    name="source_input_sha256",
                    status="passed",
                    detail="The current source input matches the recorded SHA-256.",
                )
            )
            replayed = _replay_source_analysis(analysis, resolved)
            _require(
                replayed.content_sha256 == analysis.content_sha256,
                "deterministic source replay differs from the stored Analysis",
            )
            checks.append(
                VerificationCheck(
                    name="deterministic_source_replay",
                    status="passed",
                    detail=(
                        "The frozen source reproduced the same complete Agent-visible Analysis."
                    ),
                )
            )
    else:
        checks.append(
            VerificationCheck(
                name="source_input_sha256",
                status="skipped",
                detail="Source re-hashing was not requested.",
            )
        )

    status = (
        "partial"
        if quality.quality_status == "partial"
        or warnings
        or any(item.status == "skipped" for item in checks)
        else "verified"
    )
    return AnalysisVerificationArtifact(
        analysis_id=analysis.analysis_id,
        status=status,
        checks=tuple(checks),
        warnings=tuple(warnings),
    )


def _require(condition: bool, failure: str) -> None:
    if condition:
        return
    raise PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "evidence_validation",
        "Stored analysis failed deterministic verification",
        details={"failure": failure},
        suggested_actions=(
            "Do not use this analysis for Agent conclusions; re-analyze the preserved raw input.",
        ),
    )


def _verify_collection_provenance(analysis: AnalysisArtifact) -> None:
    quality = analysis.evidence_quality
    collection = analysis.metadata.collection
    if collection is None:
        _require(quality.source_collection_id is None, "unexpected source Collection ID")
        _require(
            quality.source_collection_artifact_sha256 is None,
            "unexpected source Collection digest",
        )
        _require(quality.actual_event_source == "unknown", "unproven event source is not unknown")
        _require(quality.fallback_used is None, "unproven fallback state is not unknown")
        _require(quality.fallback_reason is None, "unexpected fallback reason")
        _require(not quality.collection_limitations, "unexpected Collection limitations")
        return
    _require(
        analysis.metadata.source_type == "perf_data",
        "Collection provenance is attached to a non-perf.data input",
    )
    _require(
        collection.output_sha256 == analysis.metadata.input_sha256,
        "Collection output hash does not match Analysis input",
    )
    _require(
        collection.output_bytes == quality.input_bytes,
        "Collection output size does not match Analysis input",
    )
    _require(
        quality.source_collection_id == collection.collection_id,
        "source Collection ID mismatch",
    )
    _require(
        quality.source_collection_artifact_sha256 == collection.collection_artifact_sha256,
        "source Collection digest mismatch",
    )
    _require(
        quality.actual_event_source == collection.actual_event_source,
        "Collection event-source provenance mismatch",
    )
    _require(quality.fallback_used == collection.fallback_used, "Collection fallback mismatch")
    _require(
        quality.fallback_reason == collection.fallback_reason,
        "Collection fallback reason mismatch",
    )
    _require(
        quality.collection_limitations == collection.evidence_limitations,
        "Collection evidence limitations mismatch",
    )
    _require(
        all(item in quality.limitations for item in collection.evidence_limitations),
        "Collection limitation was omitted from the quality gate",
    )
    if collection.mode == "record":
        _require(collection.frequency_hz is not None, "record Collection frequency is missing")
        _require(collection.call_graph is not None, "record Collection call graph is missing")
        _require(collection.record_event is not None, "record Collection event is missing")
        if quality.sample_count == 0:
            _require(quality.total_weight == 0, "empty profile contains weighted evidence")
            _require(
                quality.event == "unknown",
                "empty profile claims an observed source Collection event",
            )
        else:
            _require(
                canonical_perf_event(quality.event) == collection.record_event,
                "parsed profile event differs from the source Collection event",
            )
        _require(
            (collection.record_event == "cycles")
            == (collection.actual_event_source == "hardware"),
            "record Collection event and event-source provenance differ",
        )


def _verify_conclusion_gate(analysis: AnalysisArtifact) -> None:
    quality = analysis.evidence_quality
    forbidden = set(quality.forbidden_conclusions)
    allowed = set(quality.allowed_conclusions)
    expected_allowed: set[str] = set()
    if quality.total_weight:
        expected_allowed.add("sampled_event_hotspot_distribution")
    if quality.call_graph_weight:
        expected_allowed.add("call_path_distribution")
    if quality.source_line_self_weight:
        expected_allowed.add("source_line_observation")
    if quality.total_weight and is_on_cpu_sampling_event(quality.event):
        expected_allowed.add("on_cpu_hotspot_distribution")
    if _has_complete_sample_context(quality) and (
        quality.kernel_context_self_weight or quality.user_context_self_weight
    ):
        expected_allowed.add("sample_privilege_distribution")
    _require(allowed == expected_allowed, "allowed conclusions do not match the evidence fields")
    _require(not allowed.intersection(forbidden), "a conclusion is both allowed and forbidden")
    _require("performance_root_cause" in forbidden, "root-cause claim is not gated")
    _require("verified_improvement" in forbidden, "improvement claim is not gated")
    if quality.actual_event_source != "hardware":
        _require(
            {
                "instructions_per_cycle",
                "hardware_cache_miss_rate",
                "hardware_branch_miss_rate",
                "microarchitectural_bottleneck",
            }.issubset(forbidden),
            "software/unknown evidence does not gate hardware conclusions",
        )
    if quality.quality_status == "partial":
        _require(
            "unqualified_profile_conclusion" in forbidden,
            "partial evidence does not gate unqualified conclusions",
        )
    if quality.call_graph_weight == 0:
        _require(
            "caller_callee_relationship" in forbidden,
            "missing call graph does not gate caller/callee claims",
        )
    if quality.source_line_self_weight == 0:
        _require(
            "exact_source_line_attribution" in forbidden,
            "missing source lines do not gate exact line attribution",
        )
    if quality.source_locations_truncated_hotspot_count:
        _require(
            "complete_source_location_distribution" in forbidden,
            "truncated source locations do not gate completeness claims",
        )
    if quality.normalization_merge_count:
        _require(
            "unique_machine_code_identity_from_normalized_symbol" in forbidden,
            "normalized symbol merges do not gate unique-code identity claims",
        )
    if quality.omitted_hotspot_self_weight or quality.omitted_call_path_weight:
        _require(
            "complete_profile_distribution" in forbidden,
            "bounded output omissions do not gate complete-distribution claims",
        )
    if analysis.metadata.conversion.adapter == "perf_data" and any(
        _PERF_MAP.fullmatch(item.dso.rsplit("/", 1)[-1]) is not None
        for item in analysis.hotspots
    ):
        _require(
            "cross_time_jit_symbol_replay" in forbidden,
            "unretained JIT symbol context does not gate cross-time replay claims",
        )


def _has_complete_sample_context(quality: EvidenceQuality) -> bool:
    values = (
        quality.kernel_context_self_weight,
        quality.kernel_context_self_percent,
        quality.user_context_self_weight,
        quality.user_context_self_percent,
        quality.unknown_context_self_weight,
        quality.unknown_context_self_percent,
        quality.unresolved_kernel_self_weight,
        quality.unresolved_kernel_self_percent,
        quality.unresolved_user_self_weight,
        quality.unresolved_user_self_percent,
        quality.unresolved_unknown_context_self_weight,
        quality.unresolved_unknown_context_self_percent,
    )
    present = tuple(value is not None for value in values)
    _require(
        not any(present) or all(present),
        "sample-context metrics are only partially present",
    )
    return all(present)


def _verify_event_semantics(analysis: AnalysisArtifact) -> None:
    metadata = analysis.metadata
    quality = analysis.evidence_quality
    _require(
        metadata.conversion.adapter == metadata.source_type,
        "profile source type and conversion adapter differ",
    )
    if metadata.source_type == "folded":
        _require(metadata.event == "unknown", "folded profile has a non-generic event")
        _require(metadata.weight_unit == "sample_count", "folded profile has a non-count unit")
        _require(metadata.weight_source == "folded_weight", "folded weight source is invalid")
        return
    if metadata.weight_source == "perf_period":
        _require(
            metadata.weight_unit == perf_period_unit(metadata.event),
            "perf event and period weight unit differ",
        )
    elif metadata.weight_source == "sample_count_fallback":
        _require(
            metadata.weight_unit == "sample_count",
            "period-less perf sample has a non-count unit",
        )
    else:
        _require(False, "perf profile has an unsupported weight source")
    _require(quality.event == metadata.event, "quality event semantics differ")


def _verify_complete_export_projection(
    analysis: AnalysisArtifact,
    hotspots_by_key: dict[tuple[str, str], Hotspot],
) -> None:
    """Recompute exported hotspot facts from complete public call paths."""
    quality = analysis.evidence_quality
    if (
        quality.total_hotspot_count != quality.exported_hotspot_count
        or quality.total_call_path_count != quality.exported_call_path_count
    ):
        return

    self_weights: defaultdict[tuple[str, str], int] = defaultdict(int)
    inclusive_weights: defaultdict[tuple[str, str], int] = defaultdict(int)
    sample_counts: defaultdict[tuple[str, str], int] = defaultdict(int)
    occurrence_counts: defaultdict[tuple[str, str], int] = defaultdict(int)
    record_count = 0
    frame_occurrence_count = 0
    call_graph_weight = 0
    unresolved_self_weight = 0
    for path in analysis.call_paths:
        if not path.frames:
            continue  # Already rejected above; keeps static narrowing explicit.
        record_count += path.record_count
        frame_occurrence_count += len(path.frames) * path.record_count
        if len(path.frames) > 1:
            call_graph_weight += path.weight
        leaf = next(reversed(path.frames))
        self_weights[(leaf.symbol, leaf.dso)] += path.weight
        if leaf.symbol in {"unknown", "[unknown]", "??", "0x0"} or (
            analysis.metadata.source_type != "folded"
            and leaf.dso in {"unknown", "[unknown]"}
        ):
            unresolved_self_weight += path.weight
        seen: set[tuple[str, str]] = set()
        for frame in path.frames:
            key = (frame.symbol, frame.dso)
            occurrence_counts[key] += path.record_count
            if key in seen:
                continue
            seen.add(key)
            inclusive_weights[key] += path.weight
            sample_counts[key] += path.record_count

    _require(record_count == analysis.metadata.sample_count, "call paths do not conserve records")
    _require(
        frame_occurrence_count == quality.aggregated_frame_occurrence_count,
        "call paths do not conserve Frame occurrences",
    )
    _require(
        call_graph_weight == quality.call_graph_weight,
        "call paths do not conserve call-graph weight",
    )
    _require(
        unresolved_self_weight == quality.unresolved_self_weight,
        "call paths do not conserve unresolved Self weight",
    )
    _require(
        set(hotspots_by_key) == set(inclusive_weights),
        "complete hotspot and call-path identities differ",
    )
    for key, hotspot in hotspots_by_key.items():
        _require(hotspot.self_weight == self_weights[key], "hotspot Self differs from call paths")
        _require(
            hotspot.inclusive_weight == inclusive_weights[key],
            "hotspot Inclusive differs from call paths",
        )
        _require(
            hotspot.sample_count == sample_counts[key],
            "hotspot sample count differs from call paths",
        )
        _require(
            hotspot.stack_occurrence_count == occurrence_counts[key],
            "hotspot occurrence count differs from call paths",
        )


def _percent(value: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(value * 100.0 / total, 6)


def _sha256_file(path: Path, *, maximum: int, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            total += len(chunk)
            if total > maximum:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "evidence_validation",
                    "Source input exceeds the recorded verification limit",
                    details={"maximum": maximum, "actual": total},
                )
            digest.update(chunk)
    return digest.hexdigest()


def _replay_source_analysis(analysis: AnalysisArtifact, source: Path) -> AnalysisArtifact:
    from perflens.application.analyze import (
        analyze_folded,
        analyze_perf_data,
        analyze_perf_script,
    )

    limits = ResourceLimits(**analysis.limits.model_dump())
    source_type = analysis.metadata.source_type
    if source_type == "folded":
        return analyze_folded(source, limits=limits)
    if source_type == "perf_script":
        return analyze_perf_script(source, limits=limits)
    converter_path = analysis.metadata.conversion.converter_path
    _require(converter_path is not None, "perf.data replay has no recorded converter path")
    assert converter_path is not None
    return analyze_perf_data(
        source,
        limits=limits,
        perf_path=Path(converter_path),
        collection=analysis.metadata.collection,
    )
