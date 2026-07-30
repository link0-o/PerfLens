from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from perflens.application.analyze import analyze_folded
from perflens.artifacts.filesystem import write_json_atomic
from perflens.cli.app import app

runner = CliRunner()


def test_cli_analyzes_folded_profile(fixture_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "nested" / "analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-folded",
            "--input",
            str(fixture_root / "folded" / "normal.folded"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text())
    assert payload["schema_version"] == "1.0"
    assert payload["metadata"]["total_weight"] == 471
    assert payload["hotspots"][0]["symbol"] == "compute"


def test_cli_refuses_to_overwrite_source(tmp_path: Path) -> None:
    source = tmp_path / "input.folded"
    source.write_text("main 1\n")
    result = runner.invoke(
        app,
        ["analyze-folded", "--input", str(source), "--output", str(source)],
    )
    assert result.exit_code == 5
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "PATH_SAFETY_VIOLATION"
    assert source.read_text() == "main 1\n"


def test_cli_resource_limit_has_stable_exit_code(fixture_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-folded",
            "--input",
            str(fixture_root / "folded" / "normal.folded"),
            "--output",
            str(output),
            "--max-input-bytes",
            "1",
        ],
    )
    assert result.exit_code == 4
    assert not output.exists()


def test_cli_analyzes_perf_script(fixture_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "perf-script-analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-perf-script",
            "--input",
            str(fixture_root / "perf_script" / "normal.perf-script"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["source_type"] == "perf_script"
    assert payload["metadata"]["total_weight"] == 100


def test_cli_classifies_and_renders_report(tmp_path: Path) -> None:
    profile = tmp_path / "input.folded"
    profile.write_text("main;malloc 10\n")
    analysis_path = tmp_path / "analysis.json"
    write_json_atomic(analyze_folded(profile), analysis_path, max_output_bytes=1 << 20)
    diagnosis_path = tmp_path / "diagnosis.json"
    report_path = tmp_path / "report.md"

    classified = runner.invoke(
        app,
        ["classify", "--analysis", str(analysis_path), "--output", str(diagnosis_path)],
    )
    reported = runner.invoke(
        app,
        [
            "report",
            "--analysis",
            str(analysis_path),
            "--output",
            str(report_path),
            "--problem",
            "Throughput regression",
        ],
    )

    assert classified.exit_code == 0, classified.output
    assert reported.exit_code == 0, reported.output
    diagnosis = json.loads(diagnosis_path.read_text(encoding="utf-8"))
    assert diagnosis["classifications"][0]["conclusion_status"] == "candidate"
    assert "Throughput regression" in report_path.read_text(encoding="utf-8")
