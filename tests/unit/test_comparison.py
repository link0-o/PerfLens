from __future__ import annotations

from pathlib import Path

from perflens.application.analyze import analyze_folded
from perflens.comparison.benchmarks import compare_benchmarks
from perflens.comparison.profiles import compare_profiles
from perflens.contracts.artifacts import (
    BenchmarkArtifact,
    BenchmarkEnvironment,
    BenchmarkMetric,
)
from perflens.reporting.diff import render_benchmark_comparison, render_profile_comparison


def _benchmark(
    benchmark_id: str,
    values: tuple[float, ...],
    *,
    commit: str,
    cpu_model: str = "same-cpu",
    error_count: int = 0,
) -> BenchmarkArtifact:
    import statistics

    metric = BenchmarkMetric(
        unit="operations/second",
        higher_is_better=True,
        values=values,
        median=statistics.median(values),
        mean=statistics.fmean(values),
        standard_deviation=statistics.stdev(values) if len(values) > 1 else 0,
    )
    return BenchmarkArtifact(
        benchmark_id=benchmark_id,
        name="throughput",
        commit=commit,
        build_type="release",
        duration_seconds=60,
        warmup_seconds=10,
        repetitions=len(values),
        concurrency=8,
        payload_bytes=256,
        operations=100_000,
        metrics={"throughput": metric},
        environment=BenchmarkEnvironment(cpu_model=cpu_model, cpu_count=8),
        error_count=error_count,
        source_format="perflens",
    )


def test_profile_comparison_finds_added_removed_rank_and_path_changes(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.folded"
    candidate_file = tmp_path / "candidate.folded"
    baseline_file.write_text("main;old 60\nmain;shared 40\n")
    candidate_file.write_text("main;new 50\nmain;shared 50\n")
    comparison = compare_profiles(
        analyze_folded(baseline_file),
        analyze_folded(candidate_file),
        minimum_delta_percent=1,
    )
    by_symbol = {item.symbol: item for item in comparison.hotspot_deltas}
    assert by_symbol["new"].status == "added"
    assert by_symbol["old"].status == "removed"
    assert by_symbol["shared"].self_delta_percent == 10
    assert comparison.call_path_deltas
    assert comparison.comparable
    assert any("do not prove an absolute" in warning for warning in comparison.warnings)
    markdown = render_profile_comparison(comparison)
    assert "Hotspot distribution changes" in markdown
    assert "do not establish an absolute CPU-time" in markdown


def test_profile_comparison_reports_dso_and_metadata_differences(tmp_path: Path) -> None:
    profile = tmp_path / "profile.folded"
    profile.write_text("main;work 10\n")
    baseline = analyze_folded(profile)
    changed_hotspots = tuple(
        item.model_copy(update={"dso": "libnew.so"}) if item.symbol == "work" else item
        for item in baseline.hotspots
    )
    candidate = baseline.model_copy(
        update={
            "metadata": baseline.metadata.model_copy(update={"event": "cycles"}),
            "hotspots": changed_hotspots,
        }
    )
    comparison = compare_profiles(baseline, candidate)
    assert not comparison.comparable
    assert "event" in comparison.metadata_differences
    assert "work" in comparison.dso_changes


def test_commit_is_expected_variable_and_repeated_gain_stays_candidate() -> None:
    baseline = _benchmark("b1", (100, 101, 99, 100, 100), commit="old")
    candidate = _benchmark("b2", (120, 121, 119, 120, 120), commit="new")
    comparison = compare_benchmarks(baseline, candidate, minimum_practical_impact_percent=5)
    metric = comparison.metrics[0]
    assert comparison.comparable
    assert "commit" in comparison.expected_variables
    assert "commit" not in comparison.condition_differences
    assert metric.statistically_significant
    assert metric.practically_significant
    assert metric.status == "candidate_improvement"
    assert any("does not establish a Verified Improvement" in item for item in comparison.warnings)
    markdown = render_benchmark_comparison(comparison)
    assert "Metric changes" in markdown
    assert "No metric in this report is a Verified Improvement" in markdown


def test_environment_mismatch_and_single_run_are_not_confirmed() -> None:
    baseline = _benchmark("b1", (100,), commit="old")
    candidate = _benchmark("b2", (80,), commit="new", cpu_model="different-cpu")
    comparison = compare_benchmarks(baseline, candidate)
    assert not comparison.comparable
    assert "environment.cpu_model" in comparison.condition_differences
    assert comparison.metrics[0].status == "insufficient_data"
    assert comparison.metrics[0].statistically_significant is None


def test_error_regression_is_explicit() -> None:
    baseline = _benchmark("b1", (100, 101, 99), commit="old", error_count=0)
    candidate = _benchmark("b2", (110, 111, 109), commit="new", error_count=2)
    comparison = compare_benchmarks(baseline, candidate)
    assert any("error_count increased" in item for item in comparison.warnings)
