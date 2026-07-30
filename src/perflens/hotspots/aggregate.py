"""Exact, bounded self/inclusive and call-path aggregation."""

from __future__ import annotations

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    AggregationResult,
    CallPathResult,
    FrameTable,
    HotspotAccumulator,
    HotspotResult,
    ResourceLimits,
    StackSample,
)


class HotspotAggregator:
    __slots__ = (
        "_call_paths",
        "_event",
        "_has_call_graph",
        "_hotspots",
        "_limits",
        "_record_count",
        "_total_weight",
        "_weight_source",
        "_weight_unit",
    )

    def __init__(self, limits: ResourceLimits) -> None:
        self._limits = limits
        self._hotspots: dict[int, HotspotAccumulator] = {}
        self._call_paths: dict[tuple[int, ...], list[int]] = {}
        self._total_weight = 0
        self._record_count = 0
        self._has_call_graph = False
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

        leaf_frame = next(reversed(frames))
        leaf = self._hotspots.setdefault(leaf_frame, HotspotAccumulator())
        leaf.self_weight += sample.weight

        seen: set[int] = set()
        for frame_id in frames:
            accumulator = self._hotspots.setdefault(frame_id, HotspotAccumulator())
            accumulator.stack_occurrence_count += 1
            if sample.thread_id is not None:
                accumulator.thread_ids.add(sample.thread_id)
            if frame_id not in seen:
                accumulator.inclusive_weight += sample.weight
                accumulator.sample_count += 1
                seen.add(frame_id)

        path_state = self._call_paths.get(frames)
        if path_state is None:
            if len(self._call_paths) >= self._limits.max_unique_call_paths:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "aggregation",
                    "Input exceeds max_unique_call_paths",
                    recoverable=True,
                    details={"max_unique_call_paths": self._limits.max_unique_call_paths},
                )
            self._call_paths[frames] = [sample.weight, 1]
        else:
            path_state[0] += sample.weight
            path_state[1] += 1

    def finish(self, frame_table: FrameTable) -> AggregationResult:
        hotspots = tuple(
            HotspotResult(
                frame_id=frame_id,
                self_weight=state.self_weight,
                inclusive_weight=state.inclusive_weight,
                sample_count=state.sample_count,
                stack_occurrence_count=state.stack_occurrence_count,
                thread_count=len(state.thread_ids),
            )
            for frame_id, state in sorted(
                self._hotspots.items(),
                key=lambda item: (
                    -item[1].self_weight,
                    -item[1].inclusive_weight,
                    frame_table.resolve(item[0]).symbol,
                    frame_table.resolve(item[0]).dso,
                ),
            )
        )
        call_paths = tuple(
            CallPathResult(frame_ids=path, weight=state[0], record_count=state[1])
            for path, state in sorted(
                self._call_paths.items(),
                key=lambda item: (
                    -item[1][0],
                    tuple(
                        (
                            frame_table.resolve(frame_id).symbol,
                            frame_table.resolve(frame_id).dso,
                        )
                        for frame_id in item[0]
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
