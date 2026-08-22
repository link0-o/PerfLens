"""Relative profile comparison without claiming absolute CPU-time changes."""

from __future__ import annotations

import hashlib

from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CallPathDelta,
    CallPathFrame,
    ProfileComparison,
    ProfileHotspotDelta,
)


def compare_profiles(
    baseline: AnalysisArtifact,
    candidate: AnalysisArtifact,
    *,
    minimum_delta_percent: float = 1.0,
) -> ProfileComparison:
    if minimum_delta_percent < 0:
        raise ValueError("minimum_delta_percent must be non-negative")
    metadata_fields = ("event", "weight_unit", "weight_source", "source_type")
    metadata_differences = {
        field: (str(getattr(baseline.metadata, field)), str(getattr(candidate.metadata, field)))
        for field in metadata_fields
        if getattr(baseline.metadata, field) != getattr(candidate.metadata, field)
    }
    provenance_fields: dict[str, tuple[object, object]] = {
        "actual_event_source": (
            baseline.evidence_quality.actual_event_source,
            candidate.evidence_quality.actual_event_source,
        ),
        "parser_version": (
            baseline.metadata.conversion.parser_version,
            candidate.metadata.conversion.parser_version,
        ),
        "normalization_version": (
            baseline.metadata.conversion.normalization_version,
            candidate.metadata.conversion.normalization_version,
        ),
        "converter_version": (
            baseline.metadata.conversion.converter_version or "unknown",
            candidate.metadata.conversion.converter_version or "unknown",
        ),
        "converter_sha256": (
            baseline.metadata.conversion.converter_sha256 or "none",
            candidate.metadata.conversion.converter_sha256 or "none",
        ),
        "converter_argv": (
            _semantic_converter_argv(baseline),
            _semantic_converter_argv(candidate),
        ),
        "converter_locale": (
            baseline.metadata.conversion.locale,
            candidate.metadata.conversion.locale,
        ),
        "compatibility_fallbacks": (
            baseline.metadata.conversion.compatibility_fallbacks,
            candidate.metadata.conversion.compatibility_fallbacks,
        ),
    }
    provenance_fields.update(_collection_setting_fields(baseline, candidate))
    metadata_differences.update(
        {
            field: (str(before), str(after))
            for field, (before, after) in provenance_fields.items()
            if before != after
        }
    )
    if baseline.evidence_quality.quality_status != "verified":
        metadata_differences["baseline_quality_status"] = (
            baseline.evidence_quality.quality_status,
            "verified",
        )
    if candidate.evidence_quality.quality_status != "verified":
        metadata_differences["candidate_quality_status"] = (
            candidate.evidence_quality.quality_status,
            "verified",
        )
    comparable = not metadata_differences
    baseline_hotspots = {(item.symbol, item.dso): item for item in baseline.hotspots}
    candidate_hotspots = {(item.symbol, item.dso): item for item in candidate.hotspots}
    baseline_ranks = {key: index for index, key in enumerate(baseline_hotspots, start=1)}
    candidate_ranks = {key: index for index, key in enumerate(candidate_hotspots, start=1)}
    hotspot_deltas: list[ProfileHotspotDelta] = []
    for key in sorted(baseline_hotspots.keys() | candidate_hotspots.keys()):
        before = baseline_hotspots.get(key)
        after = candidate_hotspots.get(key)
        self_delta = (after.self_percent if after else 0.0) - (
            before.self_percent if before else 0.0
        )
        inclusive_delta = (after.inclusive_percent if after else 0.0) - (
            before.inclusive_percent if before else 0.0
        )
        if (
            before is not None
            and after is not None
            and max(abs(self_delta), abs(inclusive_delta)) < minimum_delta_percent
        ):
            continue
        status = "added" if before is None else "removed" if after is None else "changed"
        baseline_rank = baseline_ranks.get(key)
        candidate_rank = candidate_ranks.get(key)
        hotspot_deltas.append(
            ProfileHotspotDelta(
                symbol=key[0],
                dso=key[1],
                status=status,
                baseline_self_percent=before.self_percent if before else 0.0,
                candidate_self_percent=after.self_percent if after else 0.0,
                self_delta_percent=round(self_delta, 6),
                baseline_inclusive_percent=before.inclusive_percent if before else 0.0,
                candidate_inclusive_percent=after.inclusive_percent if after else 0.0,
                inclusive_delta_percent=round(inclusive_delta, 6),
                baseline_rank=baseline_rank,
                candidate_rank=candidate_rank,
                rank_delta=(
                    baseline_rank - candidate_rank
                    if baseline_rank is not None and candidate_rank is not None
                    else None
                ),
            )
        )
    hotspot_deltas.sort(
        key=lambda item: (
            -max(abs(item.self_delta_percent), abs(item.inclusive_delta_percent)),
            item.symbol,
            item.dso,
        )
    )

    call_path_deltas = _call_path_deltas(baseline, candidate, minimum_delta_percent)
    dso_changes = _dso_changes(baseline, candidate)
    baseline_unresolved = _unresolved_percent(baseline)
    candidate_unresolved = _unresolved_percent(candidate)
    warnings = [
        "Profile percentages are relative distributions and do not prove an absolute "
        "CPU-time change.",
        "Compare workload, duration, total CPU time, and benchmark metrics before "
        "attributing a change.",
    ]
    if not comparable:
        warnings.append(
            "Profile acquisition, conversion, event, weight, or evidence-quality semantics "
            "differ; the profiles are not directly comparable."
        )
    if baseline.metadata.sample_count < 100 or candidate.metadata.sample_count < 100:
        warnings.append(
            "At least one profile has fewer than 100 logical records; small deltas may be noisy."
        )
    material = "\0".join(
        (baseline.analysis_id, candidate.analysis_id, f"{minimum_delta_percent:.6f}")
    )
    comparison_id = f"profile-comparison-{hashlib.sha256(material.encode()).hexdigest()[:16]}"
    return ProfileComparison(
        comparison_id=comparison_id,
        baseline_analysis_id=baseline.analysis_id,
        candidate_analysis_id=candidate.analysis_id,
        minimum_delta_percent=minimum_delta_percent,
        comparable=comparable,
        metadata_differences=metadata_differences,
        hotspot_deltas=tuple(hotspot_deltas),
        call_path_deltas=call_path_deltas,
        dso_changes=dso_changes,
        baseline_unresolved_percent=baseline_unresolved,
        candidate_unresolved_percent=candidate_unresolved,
        unresolved_delta_percent=round(candidate_unresolved - baseline_unresolved, 6),
        warnings=tuple(warnings),
    )


def _call_path_deltas(
    baseline: AnalysisArtifact,
    candidate: AnalysisArtifact,
    minimum_delta_percent: float,
) -> tuple[CallPathDelta, ...]:
    def key(path_frames: tuple[CallPathFrame, ...]) -> tuple[tuple[str, str], ...]:
        return tuple((frame.symbol, frame.dso) for frame in path_frames)

    before = {key(path.frames): path for path in baseline.call_paths}
    after = {key(path.frames): path for path in candidate.call_paths}
    deltas: list[CallPathDelta] = []
    for path_key in sorted(before.keys() | after.keys()):
        baseline_path = before.get(path_key)
        candidate_path = after.get(path_key)
        baseline_percent = baseline_path.percent if baseline_path else 0.0
        candidate_percent = candidate_path.percent if candidate_path else 0.0
        delta = candidate_percent - baseline_percent
        if (
            baseline_path is not None
            and candidate_path is not None
            and abs(delta) < minimum_delta_percent
        ):
            continue
        status = (
            "added" if baseline_path is None else "removed" if candidate_path is None else "changed"
        )
        if candidate_path is not None:
            frames = candidate_path.frames
        elif baseline_path is not None:
            frames = baseline_path.frames
        else:
            raise RuntimeError("call-path delta key has no corresponding profile path")
        deltas.append(
            CallPathDelta(
                frames=frames,
                status=status,
                baseline_percent=baseline_percent,
                candidate_percent=candidate_percent,
                delta_percent=round(delta, 6),
            )
        )
    deltas.sort(
        key=lambda item: (-abs(item.delta_percent), tuple(frame.symbol for frame in item.frames))
    )
    return tuple(deltas)


def _dso_changes(
    baseline: AnalysisArtifact,
    candidate: AnalysisArtifact,
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    before: dict[str, set[str]] = {}
    after: dict[str, set[str]] = {}
    for hotspot in baseline.hotspots:
        before.setdefault(hotspot.symbol, set()).add(hotspot.dso)
    for hotspot in candidate.hotspots:
        after.setdefault(hotspot.symbol, set()).add(hotspot.dso)
    return {
        symbol: (tuple(sorted(before.get(symbol, set()))), tuple(sorted(after.get(symbol, set()))))
        for symbol in sorted(before.keys() | after.keys())
        if before.get(symbol, set()) != after.get(symbol, set())
    }


def _unresolved_percent(analysis: AnalysisArtifact) -> float:
    return analysis.evidence_quality.unresolved_self_percent


def _semantic_converter_argv(analysis: AnalysisArtifact) -> tuple[str, ...]:
    """Remove only executable/input paths while retaining conversion behavior."""
    argv = analysis.metadata.conversion.argv
    if not argv:
        return ()
    normalized: list[str] = []
    index = 1  # converter identity is compared by SHA/version, not installation path
    while index < len(argv):
        argument = argv[index]
        normalized.append(argument)
        if argument == "-i" and index + 1 < len(argv):
            normalized.append("<profile-input>")
            index += 2
        else:
            index += 1
    return tuple(normalized)


def _collection_setting_fields(
    baseline: AnalysisArtifact,
    candidate: AnalysisArtifact,
) -> dict[str, tuple[object, object]]:
    before = baseline.metadata.collection
    after = candidate.metadata.collection
    if before is None or after is None:
        return {"collection_provenance": (before is not None, after is not None)}
    return {
        "collection_mode": (before.mode, after.mode),
        "collection_frequency_hz": (before.frequency_hz, after.frequency_hz),
        "collection_call_graph": (before.call_graph, after.call_graph),
        "collection_record_event": (before.record_event, after.record_event),
        "collection_requested_event_source": (
            before.requested_event_source,
            after.requested_event_source,
        ),
        "collection_fallback_used": (before.fallback_used, after.fallback_used),
        "collection_fallback_reason": (before.fallback_reason, after.fallback_reason),
        "collection_evidence_limitations": (
            before.evidence_limitations,
            after.evidence_limitations,
        ),
        "collection_collector_config_sha256": (
            before.collector_config_sha256,
            after.collector_config_sha256,
        ),
        "collection_collector_privilege_mode": (
            before.collector_privilege_mode,
            after.collector_privilege_mode,
        ),
        "collection_collector_feature_profile": (
            before.collector_feature_profile,
            after.collector_feature_profile,
        ),
        "collection_host_kernel_release": (
            before.host_kernel_release,
            after.host_kernel_release,
        ),
        "collection_perf_executable_sha256": (
            before.perf_executable_sha256,
            after.perf_executable_sha256,
        ),
    }
