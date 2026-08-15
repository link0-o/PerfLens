"""Exact, bounded self/inclusive and call-path aggregation."""

from __future__ import annotations

from dataclasses import dataclass

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    AggregationResult,
    CallPathResult,
    FrameKey,
    FrameTable,
    HotspotAccumulator,
    HotspotResult,
    ResourceLimits,
    StackSample,
)
from perflens.stacks.normalize import strip_address_offset

_MAX_SYMBOL_VARIANTS_PER_HOTSPOT = 32
_MAX_SOURCE_LOCATIONS_PER_HOTSPOT = 16


@dataclass(slots=True)
class _CallPathAccumulator:
    frame_ids: tuple[int, ...]
    weight: int
    record_count: int


class HotspotAggregator:
    __slots__ = (
        "_call_graph_weight",
        "_call_paths",
        "_event",
        "_frame_identities",
        "_frame_table",
        "_has_call_graph",
        "_hotspots",
        "_inline_frame_count",
        "_limits",
        "_record_count",
        "_source_line_frame_count",
        "_source_line_self_weight",
        "_total_frame_count",
        "_total_weight",
        "_unknown_self_weight",
        "_weight_source",
        "_weight_unit",
    )

    def __init__(self, limits: ResourceLimits, frame_table: FrameTable) -> None:
        self._limits = limits
        self._frame_table = frame_table
        self._hotspots: dict[tuple[str, str], HotspotAccumulator] = {}
        self._frame_identities: dict[tuple[str, str], int] = {}
        self._call_paths: dict[tuple[int, ...], _CallPathAccumulator] = {}
        self._total_weight = 0
        self._record_count = 0
        self._has_call_graph = False
        self._call_graph_weight = 0
        self._unknown_self_weight = 0
        self._source_line_frame_count = 0
        self._source_line_self_weight = 0
        self._inline_frame_count = 0
        self._total_frame_count = 0
        self._event: str | None = None
        self._weight_unit: str | None = None
        self._weight_source: str | None = None

    def add(self, sample: StackSample) -> None:
        frames = sample.frames
        if not frames:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "aggregation",
                "A stack sample has no frames",
                details={},
            )
        self._check_scope(sample)
        self._record_count += 1
        self._total_weight += sample.weight
        self._has_call_graph = self._has_call_graph or len(frames) > 1
        if len(frames) > 1:
            self._call_graph_weight += sample.weight

        leaf_frame = self._frame_table.resolve(next(reversed(frames)))
        leaf_key = (leaf_frame.symbol, leaf_frame.dso)
        leaf = self._hotspots.setdefault(leaf_key, HotspotAccumulator())
        leaf.self_weight += sample.weight
        if leaf_frame.is_unknown:
            self._unknown_self_weight += sample.weight
        if leaf_frame.source_line is not None:
            self._source_line_self_weight += sample.weight

        seen: set[tuple[str, str]] = set()
        semantic_path: list[int] = []
        for frame_id in frames:
            frame = self._frame_table.resolve(frame_id)
            self._total_frame_count += 1
            if frame.source_line is not None:
                self._source_line_frame_count += 1
            if frame.is_inline:
                self._inline_frame_count += 1
            hotspot_key = (frame.symbol, frame.dso)
            semantic_frame_id = self._frame_identities.get(hotspot_key)
            if semantic_frame_id is None:
                semantic_frame_id = len(self._frame_identities)
                self._frame_identities[hotspot_key] = semantic_frame_id
            semantic_path.append(semantic_frame_id)
            accumulator = self._hotspots.setdefault(hotspot_key, HotspotAccumulator())
            variant = strip_address_offset(frame.raw_symbol or frame.symbol)
            if variant not in accumulator.symbol_variants:
                if len(accumulator.symbol_variants) < _MAX_SYMBOL_VARIANTS_PER_HOTSPOT:
                    accumulator.symbol_variants.add(variant)
                else:
                    accumulator.symbol_variants_truncated = True
            source_location = _source_location(frame)
            if source_location is not None and source_location not in accumulator.source_locations:
                if len(accumulator.source_locations) < _MAX_SOURCE_LOCATIONS_PER_HOTSPOT:
                    accumulator.source_locations.add(source_location)
                else:
                    accumulator.source_locations_truncated = True
            accumulator.stack_occurrence_count += 1
            if sample.thread_id is not None:
                accumulator.thread_ids.add(sample.thread_id)
            if hotspot_key not in seen:
                accumulator.inclusive_weight += sample.weight
                accumulator.sample_count += 1
                seen.add(hotspot_key)

        path_key = tuple(semantic_path)
        path_state = self._call_paths.get(path_key)
        if path_state is None:
            if len(self._call_paths) >= self._limits.max_unique_call_paths:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "aggregation",
                    "Input exceeds max_unique_call_paths",
                    recoverable=True,
                    details={"max_unique_call_paths": self._limits.max_unique_call_paths},
                )
            self._call_paths[path_key] = _CallPathAccumulator(
                frame_ids=frames,
                weight=sample.weight,
                record_count=1,
            )
        else:
            path_state.weight += sample.weight
            path_state.record_count += 1

    def finish(self) -> AggregationResult:
        hotspots = tuple(
            HotspotResult(
                symbol=hotspot_key[0],
                dso=hotspot_key[1],
                self_weight=state.self_weight,
                inclusive_weight=state.inclusive_weight,
                sample_count=state.sample_count,
                stack_occurrence_count=state.stack_occurrence_count,
                thread_count=len(state.thread_ids),
                symbol_variants=tuple(sorted(state.symbol_variants)),
                symbol_variant_count=(
                    len(state.symbol_variants) + (1 if state.symbol_variants_truncated else 0)
                ),
                symbol_variants_truncated=state.symbol_variants_truncated,
                normalization_merged=(
                    len(state.symbol_variants) > 1 or state.symbol_variants_truncated
                ),
                source_locations=tuple(sorted(state.source_locations)),
                source_locations_truncated=state.source_locations_truncated,
            )
            for hotspot_key, state in sorted(
                self._hotspots.items(),
                key=lambda item: (
                    -item[1].self_weight,
                    -item[1].inclusive_weight,
                    item[0],
                ),
            )
        )
        call_paths = tuple(
            CallPathResult(
                frame_ids=state.frame_ids,
                weight=state.weight,
                record_count=state.record_count,
            )
            for _path, state in sorted(
                self._call_paths.items(),
                key=lambda item: (
                    -item[1].weight,
                    tuple(
                        (
                            self._frame_table.resolve(frame_id).symbol,
                            self._frame_table.resolve(frame_id).dso,
                        )
                        for frame_id in item[1].frame_ids
                    ),
                ),
            )
        )
        return AggregationResult(
            total_weight=self._total_weight,
            record_count=self._record_count,
            has_call_graph=self._has_call_graph,
            event=self._event or "unknown",
            weight_unit=self._weight_unit or "sample_count",
            weight_source=self._weight_source or "folded_weight",
            call_graph_weight=self._call_graph_weight,
            unknown_self_weight=self._unknown_self_weight,
            source_line_frame_count=self._source_line_frame_count,
            source_line_self_weight=self._source_line_self_weight,
            inline_frame_count=self._inline_frame_count,
            total_frame_count=self._total_frame_count,
            normalization_merge_count=sum(1 for item in hotspots if item.normalization_merged),
            hotspots=hotspots,
            call_paths=call_paths,
        )

    def _check_scope(self, sample: StackSample) -> None:
        scope = (sample.event, sample.weight_unit, sample.weight_source)
        if self._event is None:
            self._event, self._weight_unit, self._weight_source = scope
            return
        expected = (self._event, self._weight_unit, self._weight_source)
        if scope != expected:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "aggregation",
                "Profiles with different events or weight units cannot be merged",
                details={"expected_scope": expected, "actual_scope": scope},
                suggested_actions=("Analyze each event and weight unit separately.",),
            )


def _source_location(frame: FrameKey) -> str | None:
    if frame.source_file is None:
        return None
    if frame.source_line is None:
        return frame.source_file
    if frame.source_column is not None:
        return f"{frame.source_file}:{frame.source_line}:{frame.source_column}"
    return f"{frame.source_file}:{frame.source_line}"
