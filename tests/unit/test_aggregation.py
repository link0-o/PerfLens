from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from perflens.domain.errors import PerfLensError
from perflens.domain.models import FrameTable, ResourceLimits, StackSample
from perflens.hotspots.aggregate import HotspotAggregator


def _result(
    table: FrameTable,
    samples: list[StackSample],
):  # type: ignore[no-untyped-def]
    aggregator = HotspotAggregator(ResourceLimits(), table)
    for sample in samples:
        aggregator.add(sample)
    return aggregator.finish()


def test_self_and_recursive_inclusive_are_distinct() -> None:
    table = FrameTable()
    main = table.intern("main")
    walk = table.intern("walk")
    leaf = table.intern("leaf")
    result = _result(table, [StackSample((main, walk, walk, leaf), weight=10)])
    by_symbol = {item.symbol: item for item in result.hotspots}

    assert by_symbol["leaf"].self_weight == 10
    assert by_symbol["walk"].self_weight == 0
    assert by_symbol["walk"].inclusive_weight == 10
    assert by_symbol["walk"].stack_occurrence_count == 2
    assert by_symbol["walk"].sample_count == 1


def test_same_symbol_in_different_dsos_is_not_merged() -> None:
    table = FrameTable()
    first = table.intern("work", dso="app")
    second = table.intern("work", dso="plugin.so")
    result = _result(
        table,
        [
            StackSample((first,), weight=4, thread_id=1),
            StackSample((second,), weight=6, thread_id=2),
        ],
    )
    assert len(result.hotspots) == 2
    assert {item.dso for item in result.hotspots} == {
        "app",
        "plugin.so",
    }


def test_same_symbol_and_dso_at_different_ips_is_merged() -> None:
    table = FrameTable()
    first = table.intern("work", dso="app", ip="0x10")
    second = table.intern("work", dso="app", ip="0x20")
    result = _result(
        table,
        [StackSample((first,), weight=4), StackSample((second,), weight=6)],
    )
    assert len(result.hotspots) == 1
    assert result.hotspots[0].self_weight == 10


def test_multiple_threads_are_counted_without_merging_frame_identity() -> None:
    table = FrameTable()
    frame = table.intern("work", dso="app")
    result = _result(
        table,
        [
            StackSample((frame,), weight=1, thread_id=10),
            StackSample((frame,), weight=1, thread_id=11),
            StackSample((frame,), weight=1, thread_id=10),
        ],
    )
    assert result.hotspots[0].thread_count == 2


def test_different_event_or_weight_unit_is_rejected() -> None:
    table = FrameTable()
    frame = table.intern("work")
    aggregator = HotspotAggregator(ResourceLimits(), table)
    aggregator.add(StackSample((frame,), 1, event="cycles"))
    with pytest.raises(PerfLensError, match="cannot be merged"):
        aggregator.add(StackSample((frame,), 1, event="instructions"))


def test_self_weight_is_conserved_by_sample_privilege_context() -> None:
    table = FrameTable()
    unknown = table.intern("[unknown]", dso="[unknown]", is_unknown=True)
    resolved = table.intern("work", dso="app")
    result = _result(
        table,
        [
            StackSample((unknown,), weight=7, sample_context="kernel"),
            StackSample((unknown,), weight=3, sample_context="user"),
            StackSample((resolved,), weight=5, sample_context="user"),
            StackSample((resolved,), weight=2),
        ],
    )

    assert result.kernel_context_self_weight == 7
    assert result.user_context_self_weight == 8
    assert result.unknown_context_self_weight == 2
    assert result.unresolved_kernel_self_weight == 7
    assert result.unresolved_user_self_weight == 3
    assert result.unresolved_unknown_context_self_weight == 0


def test_call_paths_are_aggregated_and_deterministic() -> None:
    table = FrameTable()
    root = table.intern("root")
    a = table.intern("a")
    b = table.intern("b")
    result = _result(
        table,
        [
            StackSample((root, a), 2),
            StackSample((root, b), 5),
            StackSample((root, a), 3),
        ],
    )
    assert result.call_paths[0].frame_ids == (root, a)
    assert result.call_paths[0].weight == 5
    assert result.call_paths[0].record_count == 2
    assert result.call_paths[1].frame_ids == (root, b)
    assert result.has_call_graph


def test_call_paths_merge_address_variants_with_the_same_public_identity() -> None:
    table = FrameTable()
    root_first = table.intern("root", dso="/app", ip="0x100")
    leaf_first = table.intern("leaf", dso="/app", ip="0x200")
    root_second = table.intern("root", dso="/app", ip="0x101")
    leaf_second = table.intern("leaf", dso="/app", ip="0x201")
    aggregator = HotspotAggregator(ResourceLimits(max_unique_call_paths=1), table)

    aggregator.add(StackSample(frames=(root_first, leaf_first), weight=3))
    aggregator.add(StackSample(frames=(root_second, leaf_second), weight=7))
    result = aggregator.finish()

    assert len(result.call_paths) == 1
    assert result.call_paths[0].frame_ids == (root_first, leaf_first)
    assert result.call_paths[0].weight == 10
    assert result.call_paths[0].record_count == 2
    assert result.has_call_graph


def test_single_frame_samples_do_not_claim_a_call_graph() -> None:
    table = FrameTable()
    frame = table.intern("leaf")
    result = _result(table, [StackSample((frame,), 1)])
    assert not result.has_call_graph


def test_symbol_variant_output_is_bounded_and_count_is_a_visible_lower_bound() -> None:
    table = FrameTable()
    frames = [
        table.intern("work", dso="app", raw_symbol=f"work.clone.{index}")
        for index in range(40)
    ]

    result = _result(table, [StackSample((frame,), 1) for frame in frames])
    hotspot = result.hotspots[0]

    assert len(hotspot.symbol_variants) == 32
    assert hotspot.symbol_variant_count == 33
    assert hotspot.symbol_variants_truncated
    assert hotspot.normalization_merged


@given(
    stacks=st.lists(
        st.lists(st.integers(min_value=0, max_value=8), min_size=1, max_size=20),
        min_size=1,
        max_size=30,
    ),
    weights=st.lists(st.integers(min_value=1, max_value=100), min_size=1, max_size=30),
)
def test_aggregation_invariants(stacks: list[list[int]], weights: list[int]) -> None:
    table = FrameTable()
    frame_ids = [table.intern(f"f-{index}") for index in range(9)]
    samples = [
        StackSample(tuple(frame_ids[value] for value in stack), weight)
        for stack, weight in zip(stacks, weights, strict=False)
    ]
    result = _result(table, samples)
    for hotspot in result.hotspots:
        assert hotspot.self_weight <= hotspot.inclusive_weight
        assert hotspot.inclusive_weight <= result.total_weight
