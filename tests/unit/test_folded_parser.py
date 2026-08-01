from __future__ import annotations

from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.profiles.base import FileProfileSource
from perflens.profiles.folded import FoldedStackAdapter


def _open(path: Path, limits: ResourceLimits | None = None):  # type: ignore[no-untyped-def]
    source = FileProfileSource(path=path, source_type="folded")
    return FoldedStackAdapter().open(source, limits or ResourceLimits())


def test_parses_root_to_leaf_and_marks_folded_metadata_unknown(fixture_root: Path) -> None:
    with _open(fixture_root / "folded" / "flamegraph-compatible.folded") as stream:
        samples = list(stream)
        frames = [stream.frame_table.resolve(frame_id) for frame_id in samples[0].frames]

    assert [frame.symbol for frame in frames] == ["all", "function with spaces", "leaf"]
    assert all(frame.dso == "unknown" for frame in frames)
    assert samples[0].thread_id is None
    assert samples[0].cpu is None
    assert samples[0].event == "unknown"
    assert samples[0].weight == 1


def test_stream_is_single_pass(fixture_root: Path) -> None:
    with _open(fixture_root / "folded" / "normal.folded") as stream:
        list(stream)
        with pytest.raises(RuntimeError, match="single-pass"):
            list(stream)


def test_empty_input_is_valid(fixture_root: Path) -> None:
    with _open(fixture_root / "folded" / "empty.folded") as stream:
        assert list(stream) == []
        assert stream.diagnostics().parsed_records == 0


def test_malformed_records_are_skipped_with_bounded_diagnostics(fixture_root: Path) -> None:
    limits = ResourceLimits(max_warnings=2)
    with _open(fixture_root / "folded" / "malformed.folded", limits) as stream:
        samples = list(stream)
        diagnostics = stream.diagnostics()

    assert [sample.weight for sample in samples] == [7, 3]
    assert diagnostics.parsed_records == 2
    assert diagnostics.malformed_records == 5
    assert diagnostics.warning_count == 5
    assert len(diagnostics.warnings) == 2
    assert diagnostics.warnings_truncated
    assert diagnostics.warnings[0].line_number == 3


def test_overlong_line_is_drained_without_losing_next_record(tmp_path: Path) -> None:
    profile = tmp_path / "long.folded"
    profile.write_text(f"main;{'x' * 100} 1\nmain;leaf 2\n")
    limits = ResourceLimits(max_line_chars=32)
    with _open(profile, limits) as stream:
        samples = list(stream)
        diagnostics = stream.diagnostics()
        leaf = stream.frame_table.resolve(samples[0].frames[-1])

    assert leaf.symbol == "leaf"
    assert samples[0].weight == 2
    assert diagnostics.malformed_records == 1


def test_input_size_limit_fails_before_parsing(tmp_path: Path) -> None:
    profile = tmp_path / "large.folded"
    profile.write_text("main;leaf 10\n")
    with (
        pytest.raises(PerfLensError) as captured,
        _open(profile, ResourceLimits(max_input_bytes=1)),
    ):
        pass
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_high_cardinality_frame_limit_is_explicit(tmp_path: Path) -> None:
    profile = tmp_path / "cardinality.folded"
    profile.write_text("a;b 1\na;c 1\n")
    with (
        pytest.raises(PerfLensError, match="max_unique_frames"),
        _open(profile, ResourceLimits(max_unique_frames=2)) as stream,
    ):
        list(stream)


def test_deep_stack_limit_is_diagnostic(tmp_path: Path) -> None:
    profile = tmp_path / "deep.folded"
    profile.write_text("a;b;c;d 1\n")
    with _open(profile, ResourceLimits(max_stack_depth=3)) as stream:
        assert list(stream) == []
        assert stream.diagnostics().warnings[0].code == "STACK_TOO_DEEP"


def test_resource_limits_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="ResourceLimits"):
        ResourceLimits(max_records=0)
    with pytest.raises(ValueError, match="ResourceLimits"):
        ResourceLimits(max_warnings=-1)
