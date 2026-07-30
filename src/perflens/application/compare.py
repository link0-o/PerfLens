"""Application services for normalized benchmark and profile comparisons."""

from __future__ import annotations

from pathlib import Path

from perflens.application.diagnose import load_analysis
from perflens.benchmarks.adapters import BenchmarkFormat, load_benchmark
from perflens.comparison.benchmarks import compare_benchmarks
from perflens.comparison.profiles import compare_profiles
from perflens.contracts.artifacts import (
    BenchmarkArtifact,
    BenchmarkComparison,
    ProfileComparison,
)


def normalize_benchmark(
    path: Path,
    *,
    source_format: BenchmarkFormat = "auto",
    benchmark_name: str | None = None,
    max_input_bytes: int = 64 << 20,
) -> BenchmarkArtifact:
    return load_benchmark(
        path,
        source_format=source_format,
        benchmark_name=benchmark_name,
        max_input_bytes=max_input_bytes,
    )


def compare_analysis_files(
    baseline_path: Path,
    candidate_path: Path,
    *,
    minimum_delta_percent: float = 1.0,
    max_input_bytes: int = 128 << 20,
) -> ProfileComparison:
    return compare_profiles(
        load_analysis(baseline_path, max_input_bytes=max_input_bytes),
        load_analysis(candidate_path, max_input_bytes=max_input_bytes),
        minimum_delta_percent=minimum_delta_percent,
    )


def compare_benchmark_files(
    baseline_path: Path,
    candidate_path: Path,
    *,
    source_format: BenchmarkFormat = "auto",
    benchmark_name: str | None = None,
    minimum_practical_impact_percent: float = 1.0,
    max_input_bytes: int = 64 << 20,
) -> BenchmarkComparison:
    baseline = load_benchmark(
        baseline_path,
        source_format=source_format,
        benchmark_name=benchmark_name,
        max_input_bytes=max_input_bytes,
    )
    candidate = load_benchmark(
        candidate_path,
        source_format=source_format,
        benchmark_name=benchmark_name,
        max_input_bytes=max_input_bytes,
    )
    return compare_benchmarks(
        baseline,
        candidate,
        minimum_practical_impact_percent=minimum_practical_impact_percent,
    )
