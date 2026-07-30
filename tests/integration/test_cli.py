from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

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
