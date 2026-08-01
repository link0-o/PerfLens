from __future__ import annotations

import json
from pathlib import Path

import pytest

from perflens.benchmarks.adapters import load_benchmark
from perflens.domain.errors import ErrorCode, PerfLensError


def test_normalizes_supported_benchmark_formats_against_golden(fixture_root: Path) -> None:
    benchmark_root = fixture_root / "benchmarks"
    hyperfine = load_benchmark(benchmark_root / "hyperfine.json")
    pyperf = load_benchmark(benchmark_root / "pyperf.json")
    google = load_benchmark(benchmark_root / "google-benchmark.json")
    actual = {
        "hyperfine": {
            "name": hyperfine.name,
            "repetitions": hyperfine.repetitions,
            "unit": hyperfine.metrics["wall_time"].unit,
            "median": hyperfine.metrics["wall_time"].median,
        },
        "pyperf": {
            "name": pyperf.name,
            "repetitions": pyperf.repetitions,
            "cpu_count": pyperf.environment.cpu_count,
        },
        "google_benchmark": {
            "name": google.name,
            "repetitions": google.repetitions,
            "metrics": sorted(google.metrics),
        },
    }
    expected = json.loads(
        (fixture_root / "golden" / "benchmark-adapters.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected


def test_rejects_unknown_or_oversized_benchmark_json(tmp_path: Path) -> None:
    unknown = tmp_path / "unknown.json"
    unknown.write_text('{"value": 1}')
    with pytest.raises(PerfLensError) as captured:
        load_benchmark(unknown)
    assert captured.value.code is ErrorCode.UNSUPPORTED_FORMAT
    with pytest.raises(PerfLensError) as captured:
        load_benchmark(unknown, max_input_bytes=1)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_rejects_invalid_limits_and_non_finite_benchmark_values(tmp_path: Path) -> None:
    profile = tmp_path / "benchmark.json"
    profile.write_text('{"results":[{"command":"bench","times":[Infinity]}]}')
    with pytest.raises(PerfLensError, match="finite numbers"):
        load_benchmark(profile)
    with pytest.raises(PerfLensError, match="must be positive"):
        load_benchmark(profile, max_input_bytes=0)


def test_oversized_benchmark_is_rejected_before_unbounded_json_loading(tmp_path: Path) -> None:
    profile = tmp_path / "large.json"
    with profile.open("wb") as handle:
        handle.truncate(1 << 20)
    with pytest.raises(PerfLensError) as captured:
        load_benchmark(profile, max_input_bytes=1024)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_multiple_benchmarks_require_explicit_selection(tmp_path: Path) -> None:
    profile = tmp_path / "multi.json"
    profile.write_text(
        '{"results": ['
        '{"command":"a","times":[1,2,3],"exit_codes":[0,0,0]},'
        '{"command":"b","times":[2,3,4],"exit_codes":[0,0,0]}]}'
    )
    with pytest.raises(PerfLensError, match="select one explicitly"):
        load_benchmark(profile)
    selected = load_benchmark(profile, benchmark_name="b")
    assert selected.name == "b"
