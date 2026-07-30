from __future__ import annotations

from pathlib import Path

import pytest

from perflens.application.analyze import analyze_folded
from perflens.artifacts.filesystem import write_json_atomic
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.security.paths import validate_input_file, validate_output_file


def test_missing_input_is_structured_error(tmp_path: Path) -> None:
    with pytest.raises(PerfLensError) as captured:
        validate_input_file(tmp_path / "missing.folded")
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_output_cannot_overwrite_input_or_symlink_to_it(tmp_path: Path) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    alias = tmp_path / "alias.json"
    alias.symlink_to(source)
    with pytest.raises(PerfLensError) as captured:
        validate_output_file(alias, input_path=source)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_atomic_writer_preserves_existing_file_when_limit_fails(tmp_path: Path) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    output = tmp_path / "analysis.json"
    output.write_text("preserve me")
    with pytest.raises(PerfLensError) as captured:
        write_json_atomic(artifact, output, max_output_bytes=1)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert output.read_text() == "preserve me"
