from __future__ import annotations

import json
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.metrics.perf_stat import PerfStatMetricAdapter


def test_perf_stat_fixture_matches_golden(fixture_root: Path) -> None:
    metrics, warnings = PerfStatMetricAdapter().parse(fixture_root / "perf_stat" / "linux-6.12.csv")
    actual = {
        "events": [metric.event for metric in metrics],
        "ipc": next(metric.value for metric in metrics if metric.event == "instructions-per-cycle"),
        "not_supported": [metric.event for metric in metrics if metric.status == "not_supported"],
        "warning_count": len(warnings),
    }
    expected = json.loads(
        (fixture_root / "golden" / "perf-stat.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected


def test_perf_stat_adapter_is_bounded(tmp_path: Path) -> None:
    source = tmp_path / "stat.csv"
    source.write_text("1;;cycles\n2;;instructions\n", encoding="utf-8")
    with pytest.raises(PerfLensError) as captured:
        PerfStatMetricAdapter(max_metrics=1).parse(source)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_perf_stat_adapter_rejects_empty_metrics(tmp_path: Path) -> None:
    source = tmp_path / "stat.csv"
    source.write_text("# no metrics\n", encoding="utf-8")
    with pytest.raises(PerfLensError) as captured:
        PerfStatMetricAdapter().parse(source)
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_perf_stat_adapter_skips_non_finite_and_overlong_lines(tmp_path: Path) -> None:
    source = tmp_path / "stat.csv"
    source.write_text(f"Infinity;;cycles\n{'1' * 30};;ignored\n2;;instructions\n")
    metrics, warnings = PerfStatMetricAdapter(max_line_chars=24).parse(source)

    assert [metric.event for metric in metrics] == ["instructions"]
    assert len(warnings) == 2


def test_perf_stat_adapter_rejects_invalid_utf8_without_mutating_event_name(
    tmp_path: Path,
) -> None:
    source = tmp_path / "stat.csv"
    source.write_bytes(b"1;;cycl\xffes\n2;;instructions\n")

    with pytest.raises(PerfLensError) as captured:
        PerfStatMetricAdapter().parse(source)

    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert captured.value.details == {"line_number": 1, "invalid_bytes": 1}


def test_perf_stat_adapter_rejects_invalid_utf8_in_drained_overlong_line(
    tmp_path: Path,
) -> None:
    source = tmp_path / "stat.csv"
    source.write_bytes(b"123456789\xff\n2;;instructions\n")

    with pytest.raises(PerfLensError) as captured:
        PerfStatMetricAdapter(max_line_chars=8).parse(source)

    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert captured.value.details == {"line_number": 1, "invalid_bytes": 1}


def test_perf_stat_adapter_skips_malformed_csv_and_keeps_later_metric(tmp_path: Path) -> None:
    source = tmp_path / "stat.csv"
    source.write_text('"unterminated;;cycles\n2;;instructions\n', encoding="utf-8")

    metrics, warnings = PerfStatMetricAdapter().parse(source)

    assert [metric.event for metric in metrics] == ["instructions"]
    assert warnings == ("Line 1 is not valid delimited perf stat output and was skipped.",)


def test_perf_stat_adapter_marks_truncated_warnings(tmp_path: Path) -> None:
    source = tmp_path / "stat.csv"
    source.write_text("bad\ninvalid\nalso-invalid\n2;;instructions\n", encoding="utf-8")

    metrics, warnings = PerfStatMetricAdapter(max_warnings=2).parse(source)

    assert [metric.event for metric in metrics] == ["instructions"]
    assert warnings == (
        "Line 1 has fewer than three fields and was skipped.",
        "Additional perf stat parse warnings were truncated.",
    )


def test_perf_stat_adapter_does_not_mix_counter_scopes_when_deriving_ipc(
    tmp_path: Path,
) -> None:
    source = tmp_path / "stat.csv"
    source.write_text("100;;cycles:u\n200;;instructions:k\n", encoding="utf-8")

    metrics, _warnings = PerfStatMetricAdapter().parse(source)

    assert [metric.event for metric in metrics] == ["cycles:u", "instructions:k"]


def test_perf_stat_adapter_rejects_invalid_resource_limits() -> None:
    with pytest.raises(ValueError, match="resource limits"):
        PerfStatMetricAdapter(max_line_chars=0)
    with pytest.raises(ValueError, match="resource limits"):
        PerfStatMetricAdapter(max_warnings=0)
