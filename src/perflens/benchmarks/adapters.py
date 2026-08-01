"""Normalize pyperf, Google Benchmark, hyperfine, and PerfLens JSON."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections.abc import Callable
from pathlib import Path
from typing import Literal, cast

from pydantic import ValidationError

from perflens.contracts.artifacts import (
    BenchmarkArtifact,
    BenchmarkEnvironment,
    BenchmarkMetric,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.security.paths import validate_input_file

BenchmarkFormat = Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"]


def load_benchmark(
    path: Path,
    *,
    source_format: BenchmarkFormat = "auto",
    benchmark_name: str | None = None,
    max_input_bytes: int = 64 << 20,
) -> BenchmarkArtifact:
    safe_path = validate_input_file(path)
    if max_input_bytes < 1:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            "max_input_bytes must be positive",
        )
    try:
        size = safe_path.stat().st_size
        with safe_path.open("rb") as handle:
            raw_bytes = handle.read(max_input_bytes + 1)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            "Benchmark input cannot be read",
            details={"path": str(safe_path)},
        ) from exc
    if size > max_input_bytes or len(raw_bytes) > max_input_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "benchmark",
            "Benchmark JSON exceeds max_input_bytes",
            recoverable=True,
            details={"actual_bytes": max(size, len(raw_bytes)), "max_input_bytes": max_input_bytes},
        )
    try:
        raw: object = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            "Benchmark input is not valid JSON",
            details={"path": str(safe_path)},
        ) from exc
    selected_format = _detect_format(raw) if source_format == "auto" else source_format
    if selected_format == "perflens":
        try:
            return BenchmarkArtifact.model_validate(raw)
        except ValidationError as exc:
            raise _invalid_format("perflens", exc) from exc
    fingerprint = hashlib.sha256(raw_bytes).hexdigest()[:16]
    if selected_format == "hyperfine":
        return _parse_hyperfine(raw, fingerprint, benchmark_name)
    if selected_format == "pyperf":
        return _parse_pyperf(raw, fingerprint, benchmark_name)
    if selected_format == "google_benchmark":
        return _parse_google_benchmark(raw, fingerprint, benchmark_name)
    raise PerfLensError(ErrorCode.UNSUPPORTED_FORMAT, "benchmark", "Unsupported benchmark format")


def _parse_hyperfine(raw: object, fingerprint: str, name: str | None) -> BenchmarkArtifact:
    root = _mapping(raw, "hyperfine")
    raw_results = _sequence(root.get("results"), "hyperfine results")
    selected = _select_named(
        raw_results,
        name,
        lambda item: str(_mapping(item, "hyperfine result").get("command", "unknown")),
    )
    result = _mapping(selected, "hyperfine result")
    command = str(result.get("command", "unknown"))
    values = _numbers(result.get("times"), "hyperfine times")
    exit_codes = _integer_sequence(result.get("exit_codes", []), "hyperfine exit_codes")
    return BenchmarkArtifact(
        benchmark_id=f"benchmark-{fingerprint}",
        name=command,
        repetitions=len(values),
        metrics={"wall_time": _metric(values, "seconds", higher_is_better=False)},
        environment=BenchmarkEnvironment(),
        error_count=sum(code != 0 for code in exit_codes),
        source_format="hyperfine",
        warnings=("Hyperfine JSON does not contain complete build and host comparability data.",),
    )


def _parse_pyperf(raw: object, fingerprint: str, name: str | None) -> BenchmarkArtifact:
    root = _mapping(raw, "pyperf")
    raw_benchmarks = _sequence(root.get("benchmarks"), "pyperf benchmarks")
    selected = _select_named(raw_benchmarks, name, _pyperf_name)
    benchmark = _mapping(selected, "pyperf benchmark")
    metadata = _mapping_or_empty(benchmark.get("metadata"))
    values: list[float] = []
    for raw_run in _sequence(benchmark.get("runs"), "pyperf runs"):
        run = _mapping(raw_run, "pyperf run")
        values.extend(_numbers(run.get("values"), "pyperf values"))
    benchmark_name = _pyperf_name(selected)
    unit = str(metadata.get("unit") or "seconds")
    root_metadata = _mapping_or_empty(root.get("metadata"))
    return BenchmarkArtifact(
        benchmark_id=f"benchmark-{fingerprint}",
        name=benchmark_name,
        repetitions=len(values),
        metrics={"value": _metric(tuple(values), unit, higher_is_better=False)},
        environment=BenchmarkEnvironment(
            cpu_model=_optional_string(root_metadata.get("cpu_model_name")),
            cpu_count=_optional_positive_int(root_metadata.get("cpu_count")),
            cpu_affinity=_optional_string(root_metadata.get("cpu_affinity")),
        ),
        source_format="pyperf",
        warnings=(
            "pyperf adapter preserves raw values; workload/build metadata may be incomplete.",
        ),
    )


def _parse_google_benchmark(raw: object, fingerprint: str, name: str | None) -> BenchmarkArtifact:
    root = _mapping(raw, "Google Benchmark")
    raw_benchmarks = [
        item
        for item in _sequence(root.get("benchmarks"), "Google Benchmark results")
        if _mapping(item, "Google Benchmark result").get("run_type", "iteration") == "iteration"
    ]
    selected_name = _select_name(raw_benchmarks, name, _google_name)
    selected = [item for item in raw_benchmarks if _google_name(item) == selected_name]
    entries = [_mapping(item, "Google Benchmark result") for item in selected]
    real_times = tuple(_float_field(item, "real_time") for item in entries)
    cpu_times = tuple(_float_field(item, "cpu_time") for item in entries if "cpu_time" in item)
    unit = str(entries[0].get("time_unit", "nanoseconds"))
    metrics = {"real_time": _metric(real_times, unit, higher_is_better=False)}
    if len(cpu_times) == len(real_times):
        metrics["cpu_time"] = _metric(cpu_times, unit, higher_is_better=False)
    throughput = tuple(
        _float_field(item, "items_per_second") for item in entries if "items_per_second" in item
    )
    if len(throughput) == len(real_times):
        metrics["items_per_second"] = _metric(throughput, "items/second", higher_is_better=True)
    context = _mapping_or_empty(root.get("context"))
    return BenchmarkArtifact(
        benchmark_id=f"benchmark-{fingerprint}",
        name=selected_name,
        build_type=_optional_string(context.get("library_build_type")),
        repetitions=len(real_times),
        metrics=metrics,
        environment=BenchmarkEnvironment(
            cpu_count=_optional_positive_int(context.get("num_cpus")),
            cpu_model=_optional_string(context.get("cpu_info")),
        ),
        error_count=sum(bool(item.get("error_occurred", False)) for item in entries),
        source_format="google_benchmark",
        warnings=(
            "Google Benchmark context may omit compiler, affinity, governor, and NUMA data.",
        ),
    )


def _metric(values: tuple[float, ...], unit: str, *, higher_is_better: bool) -> BenchmarkMetric:
    if not values:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            "Benchmark metric contains no repeated values",
        )
    return BenchmarkMetric(
        unit=unit,
        higher_is_better=higher_is_better,
        values=values,
        median=statistics.median(values),
        mean=statistics.fmean(values),
        standard_deviation=statistics.stdev(values) if len(values) > 1 else 0.0,
    )


def _detect_format(raw: object) -> Literal["perflens", "pyperf", "google_benchmark", "hyperfine"]:
    root = _mapping(raw, "benchmark")
    if root.get("schema_version") == "1.0" and "benchmark_id" in root:
        return "perflens"
    if "results" in root:
        return "hyperfine"
    if "benchmarks" in root and "context" in root:
        return "google_benchmark"
    if "benchmarks" in root and "version" in root:
        return "pyperf"
    raise PerfLensError(
        ErrorCode.UNSUPPORTED_FORMAT,
        "benchmark",
        "Unable to detect benchmark JSON format",
        recoverable=True,
    )


def _mapping(raw: object, label: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise PerfLensError(ErrorCode.INVALID_INPUT, "benchmark", f"{label} must be an object")
    return cast(dict[str, object], raw)


def _mapping_or_empty(raw: object) -> dict[str, object]:
    return cast(dict[str, object], raw) if isinstance(raw, dict) else {}


def _sequence(raw: object, label: str) -> list[object]:
    if not isinstance(raw, list) or not raw:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT, "benchmark", f"{label} must be a non-empty list"
        )
    return cast(list[object], raw)


def _numbers(raw: object, label: str) -> tuple[float, ...]:
    values = _sequence(raw, label)
    if any(not isinstance(value, (int, float)) or isinstance(value, bool) for value in values):
        raise PerfLensError(ErrorCode.INVALID_INPUT, "benchmark", f"{label} must contain numbers")
    numbers = tuple(float(cast(int | float, value)) for value in values)
    if not all(math.isfinite(value) for value in numbers):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            f"{label} must contain only finite numbers",
        )
    return numbers


def _integer_sequence(raw: object, label: str) -> tuple[int, ...]:
    if raw == []:
        return ()
    values = _sequence(raw, label)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise PerfLensError(ErrorCode.INVALID_INPUT, "benchmark", f"{label} must contain integers")
    return tuple(cast(int, value) for value in values)


def _select_named(
    items: list[object],
    selected_name: str | None,
    name_of: Callable[[object], str],
) -> object:
    names = [name_of(item) for item in items]
    name = _choose_name(tuple(str(item) for item in names), selected_name)
    return items[names.index(name)]


def _select_name(
    items: list[object], selected_name: str | None, name_of: Callable[[object], str]
) -> str:
    names = tuple(name_of(item) for item in items)
    return _choose_name(tuple(dict.fromkeys(names)), selected_name)


def _choose_name(names: tuple[str, ...], selected_name: str | None) -> str:
    unique = tuple(dict.fromkeys(names))
    if selected_name is not None:
        if selected_name not in unique:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "benchmark",
                "Requested benchmark name was not found",
                details={"benchmark_name": selected_name, "available": unique[:50]},
            )
        return selected_name
    if len(unique) != 1:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            "Benchmark file contains multiple names; select one explicitly",
            details={"available": unique[:50]},
        )
    return unique[0]


def _pyperf_name(raw: object) -> str:
    benchmark = _mapping(raw, "pyperf benchmark")
    metadata = _mapping_or_empty(benchmark.get("metadata"))
    return str(metadata.get("name") or benchmark.get("name") or "unknown")


def _google_name(raw: object) -> str:
    benchmark = _mapping(raw, "Google Benchmark result")
    return str(benchmark.get("run_name") or benchmark.get("name") or "unknown")


def _optional_string(raw: object) -> str | None:
    return str(raw) if raw is not None else None


def _optional_positive_int(raw: object) -> int | None:
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else None


def _float_field(item: dict[str, object], field: str) -> float:
    value = item.get(field)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            f"Google Benchmark field {field} must be numeric",
        )
    parsed = float(value)
    if not math.isfinite(parsed):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "benchmark",
            f"Google Benchmark field {field} must be finite",
        )
    return parsed


def _invalid_format(label: str, exc: Exception) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "benchmark",
        f"Invalid {label} benchmark data",
        details={"exception_type": type(exc).__name__},
    )
