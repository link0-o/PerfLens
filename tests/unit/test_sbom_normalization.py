from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/normalize_sbom.py"


def _run(source: Path, output: Path, epoch: str = "1788516660") -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        (
            sys.executable,
            str(SCRIPT),
            "--input",
            str(source),
            "--output",
            str(output),
            "--source-date-epoch",
            epoch,
        ),
        check=False,
        capture_output=True,
        text=True,
    )


def test_normalization_removes_volatile_metadata_and_is_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"name": "x"}},
                "components": [{"name": "dependency", "version": "1"}],
            }
        ),
        encoding="utf-8",
    )
    second.write_text(
        json.dumps(
            {
                "components": [{"version": "1", "name": "dependency"}],
                "metadata": {"component": {"name": "x"}, "timestamp": "2027-01-01T00:00:00Z"},
                "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
                "specVersion": "1.5",
                "bomFormat": "CycloneDX",
            }
        ),
        encoding="utf-8",
    )

    assert _run(first, first).returncode == 0
    assert _run(second, second).returncode == 0
    assert first.read_bytes() == second.read_bytes()
    normalized = json.loads(first.read_bytes())
    assert normalized["metadata"]["timestamp"] == "2026-09-04T10:11:00Z"
    assert normalized["serialNumber"].startswith("urn:uuid:")
    assert first.stat().st_mode & 0o777 == 0o644


def test_normalization_rejects_invalid_input_and_output_symlinks(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"bomFormat":"not-cyclonedx","metadata":{}}', encoding="utf-8")
    result = _run(invalid, tmp_path / "output.json")
    assert result.returncode == 2
    assert "CycloneDX" in result.stderr

    source = tmp_path / "source.json"
    source.write_text('{"bomFormat":"CycloneDX","metadata":{}}', encoding="utf-8")
    alias = tmp_path / "alias.json"
    alias.symlink_to(source)
    result = _run(alias, tmp_path / "other.json")
    assert result.returncode == 2
    assert "symbolic link" in result.stderr

    output_alias = tmp_path / "output-alias.json"
    output_alias.symlink_to(source)
    result = _run(source, output_alias)
    assert result.returncode == 2
    assert "symbolic link" in result.stderr


def test_normalization_rejects_invalid_epoch_and_missing_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    output = tmp_path / "output.json"
    source.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
    result = _run(source, output)
    assert result.returncode == 2
    assert "metadata" in result.stderr

    source.write_text('{"bomFormat":"CycloneDX","metadata":{}}', encoding="utf-8")
    result = _run(source, output, "-1")
    assert result.returncode == 2
    assert "UTC range" in result.stderr
