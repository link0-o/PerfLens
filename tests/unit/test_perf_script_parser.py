from __future__ import annotations

from pathlib import Path

import pytest

from perflens.application.analyze import analyze_perf_script
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.profiles.base import FileProfileSource
from perflens.profiles.events import canonical_perf_event
from perflens.profiles.perf_script import PerfScriptAdapter


def _open(path: Path, limits: ResourceLimits | None = None):  # type: ignore[no-untyped-def]
    source = FileProfileSource(path=path, source_type="perf_script")
    return PerfScriptAdapter().open(source, limits or ResourceLimits())


def test_parses_supported_header_variants_and_reverses_callchains(fixture_root: Path) -> None:
    with _open(fixture_root / "perf_script" / "normal.perf-script") as stream:
        samples = list(stream)
        first_frames = [stream.frame_table.resolve(frame_id) for frame_id in samples[0].frames]
        second_leaf = stream.frame_table.resolve(samples[1].frames[-1])

    assert len(samples) == 3
    assert [frame.symbol for frame in first_frames] == [
        "main",
        "worker_loop",
        "do_work<int>(item const&)",
    ]
    assert samples[0].process_id == 101
    assert samples[0].thread_id == 102
    assert samples[0].thread_name == "worker pool"
    assert samples[0].cpu == 3
    assert samples[0].timestamp == 100.123456789
    assert samples[0].event == "cycles:u"
    assert samples[0].weight == 50
    assert samples[0].weight_unit == "cycles"
    assert second_leaf.ip == "0x7f1009"
    assert second_leaf.raw_symbol == "do_work<int>(item const&)+0x19"
    assert second_leaf.source_file == "/src/demo.cc"
    assert second_leaf.source_line == 45


def test_marks_kernel_frames_and_period_fallback(fixture_root: Path) -> None:
    with _open(fixture_root / "perf_script" / "normal.perf-script") as stream:
        samples = list(stream)
        kernel_leaf = stream.frame_table.resolve(samples[2].frames[-1])

    assert kernel_leaf.is_kernel
    assert samples[2].weight == 20
    assert samples[2].weight_source == "perf_period"


def test_parses_perf_script_without_sample_cpu_identity(fixture_root: Path) -> None:
    with _open(fixture_root / "perf_script" / "missing-cpu.perf-script") as stream:
        samples = list(stream)
        frames = [stream.frame_table.resolve(frame_id) for frame_id in samples[0].frames]

    assert len(samples) == 1
    assert samples[0].cpu is None
    assert samples[0].process_id == 101
    assert samples[0].thread_id == 102
    assert samples[0].event == "cpu-clock"
    assert samples[0].weight_unit == "nanoseconds"
    assert [frame.symbol for frame in frames] == ["main", "worker_loop", "leaf"]


def test_perf_period_units_are_event_specific_and_unknown_events_are_not_guessed(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "event-units.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 11 task-clock:u:\n"
        "        400001 task_leaf (/app)\n\n"
        "app 1/1 [000] 2.0: 13 instructions:u:\n"
        "        400002 instruction_leaf (/app)\n\n"
        "app 1/1 [000] 3.0: 17 vendor/event=0x1/:\n"
        "        400003 vendor_leaf (/app)\n\n"
        "app 1/1 [000] 4.0: 19 cpu_core/cycles/:u:\n"
        "        400004 pmu_cycle_leaf (/app)\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)

    assert [(sample.event, sample.weight_unit) for sample in samples] == [
        ("task-clock:u", "nanoseconds"),
        ("instructions:u", "instructions"),
        ("vendor/event=0x1/", "event_count"),
        ("cpu_core/cycles/:u", "cycles"),
    ]
    assert canonical_perf_event("cpu_core/cycles/:u") == "cycles"
    assert canonical_perf_event("cpu_atom/instructions/:k") == "instructions"
    assert canonical_perf_event("cpu-cycles") == "cycles"
    assert canonical_perf_event("cpu_core/cache-misses/") == "cache-misses"
    assert canonical_perf_event("branches:u") == "branches"
    assert canonical_perf_event("cycles:untrusted-alias") == "cycles:untrusted-alias"


def test_parses_python_perf_map_source_and_ignores_redundant_annotations(
    fixture_root: Path,
) -> None:
    with _open(fixture_root / "perf_script" / "python-perf-map.perf-script") as stream:
        samples = list(stream)
        diagnostics = stream.diagnostics()
        root_frame = stream.frame_table.resolve(samples[0].frames[0])
        python_frame = stream.frame_table.resolve(samples[0].frames[1])
        interpreter_frame = stream.frame_table.resolve(samples[0].frames[-1])

    assert len(samples) == 2
    assert [len(sample.frames) for sample in samples] == [3, 3]
    assert python_frame.symbol == "py::locate_bucket_linear"
    assert python_frame.raw_symbol == "py::locate_bucket_linear:/workspace/workload.py"
    assert python_frame.source_file == "/workspace/workload.py"
    assert python_frame.source_line is None
    assert interpreter_frame.symbol == "_PyEval_EvalFrameDefault"
    assert root_frame.symbol == "__libc_start_call_main"
    assert root_frame.source_file == "libc_start_call_main.h"
    assert root_frame.source_line == 58
    assert diagnostics.warning_count == 0
    assert diagnostics.malformed_records == 0


def test_mismatched_address_annotation_remains_a_visible_warning(tmp_path: Path) -> None:
    profile = tmp_path / "mismatched-annotation.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 1 cycles:\n        400001 leaf (/app)\n  app[400002]\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)
        diagnostics = stream.diagnostics()

    assert len(samples) == 1
    assert len(samples[0].frames) == 1
    assert diagnostics.warning_count == 1
    assert diagnostics.warnings[0].code == "UNMATCHED_FRAME_ANNOTATION"
    assert diagnostics.warnings[0].preview == "app[400002]"


def test_unparsed_frame_body_is_retained_with_a_visible_warning(tmp_path: Path) -> None:
    profile = tmp_path / "unparsed-body.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 1 cycles:\n"
        "        400001 symbol-without-a-dso\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)
        frame = stream.frame_table.resolve(samples[0].frames[0])
        diagnostics = stream.diagnostics()

    assert frame.raw_symbol == "symbol-without-a-dso"
    assert frame.dso == "unknown"
    assert diagnostics.warning_count == 1
    assert diagnostics.warnings[0].code == "UNPARSED_FRAME_BODY"


def test_native_parent_frame_is_not_consumed_as_a_source_annotation(tmp_path: Path) -> None:
    profile = tmp_path / "native-parent.perf-script"
    profile.write_text(
        "native 1/1 [000] 1.0: 17 cpu-clock:\n"
        "        400101 leaf_without_source (/opt/native/app)\n"
        "        400000 parent_with_source (/opt/native/app) /src/parent.c:9\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)
        frames = [stream.frame_table.resolve(frame_id) for frame_id in samples[0].frames]
        diagnostics = stream.diagnostics()

    assert [frame.symbol for frame in frames] == [
        "parent_with_source",
        "leaf_without_source",
    ]
    assert frames[0].source_file == "/src/parent.c"
    assert frames[0].source_line == 9
    assert frames[1].source_file is None
    assert diagnostics.frame_lines == 2
    assert diagnostics.source_annotation_lines == 0
    assert diagnostics.warning_count == 0


def test_source_column_is_preserved_in_frames_and_hotspot_locations(tmp_path: Path) -> None:
    profile = tmp_path / "source-column.perf-script"
    profile.write_text(
        "native 1/1 [000] 1.0: 17 cpu-clock:\n"
        "        400101 leaf (/opt/native/app) /src/leaf.c:9:27\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)
        leaf = stream.frame_table.resolve(samples[0].frames[-1])
    artifact = analyze_perf_script(profile)

    assert leaf.source_file == "/src/leaf.c"
    assert leaf.source_line == 9
    assert leaf.source_column == 27
    assert artifact.hotspots[0].source_locations == ("/src/leaf.c:9:27",)


def test_header_tail_duplicate_is_removed_after_callchain_source_enrichment(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "header-tail-annotation.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 7 cpu-clock: 400101 leaf (/opt/app)\n"
        "        400101 leaf (/opt/app)\n"
        "  /src/leaf.c:17\n"
        "        400000 parent (/opt/app) /src/main.c:4\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)
        frames = [stream.frame_table.resolve(frame_id) for frame_id in samples[0].frames]
        diagnostics = stream.diagnostics()

    assert [frame.symbol for frame in frames] == ["parent", "leaf"]
    assert frames[-1].source_file == "/src/leaf.c"
    assert frames[-1].source_line == 17
    assert diagnostics.duplicate_frame_lines == 1
    assert diagnostics.frame_lines == 3
    assert diagnostics.source_annotation_lines == 1


def test_recursive_identical_frames_without_header_tail_are_not_deduplicated(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "recursive.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 7 cpu-clock:\n"
        "        400101 recurse (/opt/app)\n"
        "        400101 recurse (/opt/app)\n",
        encoding="utf-8",
    )

    with _open(profile) as stream:
        samples = list(stream)
        diagnostics = stream.diagnostics()

    assert len(samples[0].frames) == 2
    assert diagnostics.duplicate_frame_lines == 0
    assert diagnostics.frame_lines == 2


def test_cross_language_frames_preserve_inline_and_parenthesized_dso(
    fixture_root: Path,
) -> None:
    with _open(fixture_root / "perf_script" / "cross-language.perf-script") as stream:
        samples = list(stream)
        frames = [
            stream.frame_table.resolve(frame_id) for sample in samples for frame_id in sample.frames
        ]
        diagnostics = stream.diagnostics()

    odd = next(frame for frame in frames if frame.symbol == "odd_path_leaf")
    inline = next(frame for frame in frames if frame.symbol == "inline_leaf")
    assert odd.dso == "/opt/My App (test)/bin"
    assert odd.source_file == "/src/odd.cc"
    assert inline.is_inline
    assert inline.source_file == "/src/inline.hpp"
    assert diagnostics.frame_lines == 16
    assert diagnostics.source_annotation_lines == 1
    assert diagnostics.warning_count == 0


def test_unknown_and_malformed_input_has_bounded_diagnostics(fixture_root: Path) -> None:
    limits = ResourceLimits(max_warnings=2)
    with _open(
        fixture_root / "perf_script" / "unknown-and-malformed.perf-script", limits
    ) as stream:
        samples = list(stream)
        diagnostics = stream.diagnostics()
        unknown = stream.frame_table.resolve(samples[0].frames[-1])

    assert len(samples) == 2
    assert unknown.is_unknown
    assert samples[0].weight == 1
    assert samples[0].weight_unit == "sample_count"
    assert diagnostics.warning_count == 2
    assert len(diagnostics.warnings) == 2
    assert diagnostics.malformed_records == 1


def test_overlong_frame_is_drained_and_next_record_survives(tmp_path: Path) -> None:
    profile = tmp_path / "long.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 1 cycles:\n"
        f"        400000 {'x' * 200} (/app)\n\n"
        "app 1/1 [000] 2.0: 2 cycles: 400001 leaf (/app)\n"
    )
    with _open(profile, ResourceLimits(max_line_chars=80)) as stream:
        samples = list(stream)
        retained_unknown = stream.frame_table.resolve(samples[0].frames[-1])
        diagnostics = stream.diagnostics()

    assert len(samples) == 2
    assert [sample.weight for sample in samples] == [1, 2]
    assert retained_unknown.is_unknown
    assert diagnostics.malformed_records == 0
    assert diagnostics.warnings[0].code == "LINE_TOO_LONG"


def test_malformed_header_tail_is_retained_as_unknown_self(tmp_path: Path) -> None:
    profile = tmp_path / "malformed-header-tail.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 7 cpu-clock: unreadable-jit-frame\n",
        encoding="utf-8",
    )

    artifact = analyze_perf_script(profile)

    assert artifact.status == "partial"
    assert artifact.hotspots[0].symbol == "unknown"
    assert artifact.hotspots[0].self_weight == 7
    assert artifact.evidence_quality.unresolved_self_weight == 7
    assert artifact.evidence_quality.frame_line_count == 1


def test_unknown_placeholder_respects_unique_frame_limit(tmp_path: Path) -> None:
    profile = tmp_path / "unknown-frame-limit.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 1 cycles:\n"
        "        400001 valid (/app)\n\n"
        "app 1/1 [000] 2.0: 1 cycles:\n"
        "        unreadable-frame\n",
        encoding="utf-8",
    )

    with (
        pytest.raises(PerfLensError) as captured,
        _open(profile, ResourceLimits(max_unique_frames=1)) as stream,
    ):
        list(stream)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
