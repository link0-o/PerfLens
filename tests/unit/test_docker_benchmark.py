from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from perflens.contracts.artifacts import (
    BenchmarkArtifact,
    BenchmarkEnvironment,
    BenchmarkMetric,
)
from perflens.docker.benchmark import (
    benchmark_output_contract_sha256,
    load_managed_benchmark,
    workload_command_contract_sha256,
)
from perflens.domain.errors import PerfLensError


def _scratch(tmp_path: Path) -> Path:
    root = tmp_path / "scratch"
    root.mkdir(mode=0o700)
    return root


def _payload() -> bytes:
    artifact = BenchmarkArtifact(
        benchmark_id="benchmark-untrusted-input-id",
        name="managed throughput",
        repetitions=3,
        metrics={
            "throughput": BenchmarkMetric(
                unit="operations/second",
                higher_is_better=True,
                values=(100.0, 101.0, 99.0),
                median=100.0,
                mean=100.0,
                standard_deviation=1.0,
            )
        },
        environment=BenchmarkEnvironment(containerized=False),
        error_count=0,
        source_format="perflens",
    )
    return artifact.model_dump_json().encode()


def test_managed_benchmark_binds_one_safe_scratch_file(tmp_path: Path) -> None:
    root = _scratch(tmp_path)
    output = root / "results.json"
    payload = _payload()
    output.write_bytes(payload)
    output.chmod(0o600)

    benchmark = load_managed_benchmark(
        root,
        "results.json",
        source_format="perflens",
        benchmark_name=None,
    )

    assert benchmark.benchmark_id == f"benchmark-{hashlib.sha256(payload).hexdigest()[:16]}"
    assert benchmark.environment.containerized is True
    assert benchmark.error_count == 0
    assert any("private scratch output" in warning for warning in benchmark.warnings)


def test_managed_benchmark_rejects_escape_symlink_and_writable_output(tmp_path: Path) -> None:
    root = _scratch(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(_payload())
    alias = root / "alias.json"
    alias.symlink_to(outside)

    with pytest.raises(PerfLensError, match="must not be a symlink"):
        load_managed_benchmark(root, "alias.json", source_format="perflens", benchmark_name=None)
    with pytest.raises(PerfLensError, match="scratch-relative"):
        load_managed_benchmark(
            root,
            "../outside.json",
            source_format="perflens",
            benchmark_name=None,
        )

    output = root / "writable.json"
    output.write_bytes(_payload())
    output.chmod(0o620)
    with pytest.raises(PerfLensError, match="owner, mode"):
        load_managed_benchmark(
            root,
            "writable.json",
            source_format="perflens",
            benchmark_name=None,
        )


def test_managed_benchmark_contracts_bind_recipe_without_exporting_values() -> None:
    first = benchmark_output_contract_sha256("results.json", "perflens", "throughput")
    second = benchmark_output_contract_sha256("other.json", "perflens", "throughput")
    command = workload_command_contract_sha256("/usr/bin/python3", ("/workspace/bench.py",))

    assert first != second
    assert len(first) == 64
    assert len(command) == 64
    assert "results.json" not in first
