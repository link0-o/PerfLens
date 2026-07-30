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
            "Profile event or weight semantics differ; the profiles are not directly comparable."
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
        frames = candidate_path.frames if candidate_path is not None else baseline_path.frames  # type: ignore[union-attr]
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
    unresolved = sum(
        item.self_weight
        for item in analysis.hotspots
        if item.symbol in {"unknown", "[unknown]", "??"} or item.dso in {"unknown", "[unknown]"}
    )
    return (
        round(unresolved * 100 / analysis.metadata.total_weight, 6)
        if analysis.metadata.total_weight
        else 0.0
    )
