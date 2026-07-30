"""Condition-aware benchmark comparison with conservative statistical claims."""

from __future__ import annotations

import hashlib
import math

from perflens.contracts.artifacts import (
    BenchmarkArtifact,
    BenchmarkComparison,
    BenchmarkMetric,
    BenchmarkMetricComparison,
)


def compare_benchmarks(
    baseline: BenchmarkArtifact,
    candidate: BenchmarkArtifact,
    *,
    minimum_practical_impact_percent: float = 1.0,
) -> BenchmarkComparison:
    if minimum_practical_impact_percent < 0:
        raise ValueError("minimum_practical_impact_percent must be non-negative")
    conditions = _conditions(baseline, candidate)
    expected_variables: dict[str, tuple[str, str]] = {}
    if baseline.commit != candidate.commit:
        expected_variables["commit"] = (str(baseline.commit), str(candidate.commit))
    comparable = not conditions
    warnings = list(dict.fromkeys((*baseline.warnings, *candidate.warnings)))
    if not comparable:
        warnings.append(
            "Benchmark conditions differ. The metric change cannot be attributed solely "
            "to the code change."
        )
    if (
        baseline.error_count is not None
        and candidate.error_count is not None
        and candidate.error_count > baseline.error_count
    ):
        warnings.append(
            "Candidate error_count increased; performance gains cannot be accepted as valid."
        )
    metric_results: list[BenchmarkMetricComparison] = []
    common_metrics = sorted(baseline.metrics.keys() & candidate.metrics.keys())
    for name in common_metrics:
        before = baseline.metrics[name]
        after = candidate.metrics[name]
        metric_comparable = (
            comparable
            and before.unit == after.unit
            and before.higher_is_better == after.higher_is_better
        )
        raw_delta = (
            (after.median - before.median) * 100 / abs(before.median)
            if before.median != 0
            else None
        )
        improvement = (
            (raw_delta if before.higher_is_better else -raw_delta)
            if raw_delta is not None
            else None
        )
        enough = len(before.values) >= 3 and len(after.values) >= 3
        interval = _difference_interval(before, after) if enough else None
        significant = interval[0] > 0 or interval[1] < 0 if interval is not None else None
        practical = improvement is not None and abs(improvement) >= minimum_practical_impact_percent
        if not enough:
            status = "insufficient_data"
        elif not metric_comparable:
            status = "not_comparable"
        elif not practical or not significant:
            status = "no_material_change"
        elif improvement is not None and improvement > 0:
            status = "candidate_improvement"
        else:
            status = "candidate_regression"
        metric_results.append(
            BenchmarkMetricComparison(
                metric=name,
                unit=before.unit,
                baseline_samples=len(before.values),
                candidate_samples=len(after.values),
                baseline_median=before.median,
                candidate_median=after.median,
                raw_delta_percent=round(raw_delta, 6) if raw_delta is not None else None,
                improvement_percent=round(improvement, 6) if improvement is not None else None,
                confidence_interval_95=interval,
                statistically_significant=significant,
                practically_significant=practical,
                status=status,
            )
        )
    missing_baseline = sorted(candidate.metrics.keys() - baseline.metrics.keys())
    missing_candidate = sorted(baseline.metrics.keys() - candidate.metrics.keys())
    if missing_baseline or missing_candidate:
        warnings.append(
            f"Metric sets differ; candidate-only={missing_baseline}, "
            f"baseline-only={missing_candidate}."
        )
    if any(item.status == "insufficient_data" for item in metric_results):
        warnings.append(
            "At least three repeated values per side are required for a confidence assessment."
        )
    warnings.append("Benchmark comparison alone does not establish a Verified Improvement.")
    material = "\0".join(
        (
            baseline.benchmark_id,
            candidate.benchmark_id,
            f"{minimum_practical_impact_percent:.6f}",
        )
    )
    return BenchmarkComparison(
        comparison_id=f"benchmark-comparison-{hashlib.sha256(material.encode()).hexdigest()[:16]}",
        baseline_benchmark_id=baseline.benchmark_id,
        candidate_benchmark_id=candidate.benchmark_id,
        comparable=comparable,
        condition_differences=conditions,
        expected_variables=expected_variables,
        minimum_practical_impact_percent=minimum_practical_impact_percent,
        metrics=tuple(metric_results),
        warnings=tuple(warnings),
    )


def _conditions(
    baseline: BenchmarkArtifact,
    candidate: BenchmarkArtifact,
) -> dict[str, tuple[str, str]]:
    differences: dict[str, tuple[str, str]] = {}
    direct_fields = (
        "name",
        "build_type",
        "duration_seconds",
        "warmup_seconds",
        "concurrency",
        "payload_bytes",
        "operations",
    )
    for field in direct_fields:
        before = getattr(baseline, field)
        after = getattr(candidate, field)
        if before != after:
            differences[field] = (str(before), str(after))
    before_environment = baseline.environment.model_dump(mode="json")
    after_environment = candidate.environment.model_dump(mode="json")
    for field in sorted(before_environment.keys() | after_environment.keys()):
        before = before_environment.get(field)
        after = after_environment.get(field)
        if before != after:
            differences[f"environment.{field}"] = (str(before), str(after))
    return differences


def _difference_interval(
    baseline: BenchmarkMetric,
    candidate: BenchmarkMetric,
) -> tuple[float, float]:
    standard_error = math.sqrt(
        baseline.standard_deviation**2 / len(baseline.values)
        + candidate.standard_deviation**2 / len(candidate.values)
    )
    difference = candidate.mean - baseline.mean
    return (
        round(difference - 1.96 * standard_error, 9),
        round(difference + 1.96 * standard_error, 9),
    )
