from __future__ import annotations

from pathlib import Path

from perflens.domain.models import ResourceLimits
from perflens.profiles.base import FileProfileSource
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
    assert samples[0].weight_unit == "event_count"
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
    assert [frame.symbol for frame in frames] == ["main", "worker_loop", "leaf"]


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

    assert len(samples) == 1
    assert samples[0].weight == 2
