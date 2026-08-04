from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from perflens.application.analyze import analyze_folded
from perflens.artifacts.filesystem import write_json_atomic, write_json_new_atomic
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.security.paths import (
    validate_input_file,
    validate_new_output_file,
    validate_output_file,
)


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


def test_new_output_validation_and_writer_refuse_existing_paths(tmp_path: Path) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    output = tmp_path / "collection.json"
    safe_output = validate_new_output_file(output)
    write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)

    with pytest.raises(PerfLensError) as validation_error:
        validate_new_output_file(output)
    assert validation_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as write_error:
        write_json_new_atomic(artifact, output, max_output_bytes=1 << 20)
    assert write_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_atomic_writer_syncs_file_and_directory_and_uses_private_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    output = tmp_path / "durable.json"
    real_fsync = os.fsync
    synced_types: list[str] = []

    def track_fsync(descriptor: int) -> None:
        mode = os.fstat(descriptor).st_mode
        synced_types.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", track_fsync)
    write_json_new_atomic(artifact, output, max_output_bytes=1 << 20)

    assert synced_types == ["file", "directory"]
    assert output.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob(".perflens-*.tmp")) == []


def test_atomic_writer_syncs_each_created_parent_directory_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    output = tmp_path / "one" / "two" / "analysis.json"
    real_fsync = os.fsync
    synced_types: list[str] = []

    def track_fsync(descriptor: int) -> None:
        mode = os.fstat(descriptor).st_mode
        synced_types.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", track_fsync)
    write_json_atomic(artifact, output, max_output_bytes=1 << 20)

    assert synced_types == ["directory", "directory", "file", "directory"]
    assert output.is_file()


def test_file_sync_failure_preserves_old_output_and_cleans_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    output = tmp_path / "analysis.json"
    output.write_text("preserve", encoding="utf-8")
    real_fsync = os.fsync

    def fail_regular_file_sync(descriptor: int) -> None:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("injected file fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_regular_file_sync)
    with pytest.raises(PerfLensError) as failed:
        write_json_atomic(artifact, output, max_output_bytes=1 << 20)

    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert failed.value.details["published"] is False
    assert output.read_text(encoding="utf-8") == "preserve"
    assert list(tmp_path.glob(".perflens-*.tmp")) == []


def test_directory_sync_failure_reports_already_published_complete_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    output = tmp_path / "published.json"
    real_fsync = os.fsync

    def fail_directory_sync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_sync)
    with pytest.raises(PerfLensError) as failed:
        write_json_new_atomic(artifact, output, max_output_bytes=1 << 20)

    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert failed.value.details["published"] is True
    assert output.read_text(encoding="utf-8").endswith("\n")
    assert list(tmp_path.glob(".perflens-*.tmp")) == []


def test_atomic_writer_detects_parent_replacement_after_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    parent = tmp_path / "artifacts"
    parent.mkdir()
    moved = tmp_path / "moved-artifacts"
    output = parent / "analysis.json"
    real_fsync = os.fsync
    replaced = False

    def replace_after_directory_sync(descriptor: int) -> None:
        nonlocal replaced
        real_fsync(descriptor)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not replaced:
            parent.rename(moved)
            parent.mkdir()
            replaced = True

    monkeypatch.setattr(os, "fsync", replace_after_directory_sync)
    with pytest.raises(PerfLensError) as failed:
        write_json_new_atomic(artifact, output, max_output_bytes=1 << 20)

    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert failed.value.details["published"] is True
    assert not output.exists()
    assert (moved / output.name).is_file()


def test_atomic_writer_wraps_parent_creation_failures(tmp_path: Path) -> None:
    source = tmp_path / "source.folded"
    source.write_text("main 1\n")
    artifact = analyze_folded(source)
    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    with pytest.raises(PerfLensError) as failed:
        write_json_atomic(
            artifact,
            blocked_parent / "analysis.json",
            max_output_bytes=1 << 20,
        )
    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert failed.value.details["published"] is False
