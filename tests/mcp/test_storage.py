from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import BaseModel

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy


class _TestArtifact(BaseModel):
    value: str


def test_artifact_identifiers_cannot_traverse_root(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=False)
    with pytest.raises(PerfLensError) as captured:
        store.read_page("../secret", "analysis", offset=0, limit=100)
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_artifact_root_must_be_inside_allowed_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    with pytest.raises(ValueError, match="inside an allowed root"):
        ArtifactStore(outside, PathPolicy((allowed,)), allow_writes=True)


def test_artifact_store_requires_a_positive_size_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        ArtifactStore(
            tmp_path / "artifacts",
            PathPolicy((tmp_path,)),
            allow_writes=True,
            max_artifact_bytes=0,
        )


def test_new_output_file_is_confined_and_must_not_exist(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = PathPolicy((allowed,))
    assert policy.new_output_file(allowed / "profile.data") == allowed / "profile.data"

    outside = tmp_path / "outside.data"
    with pytest.raises(PerfLensError) as captured:
        policy.new_output_file(outside)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_artifact_save_is_no_overwrite_and_content_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)

    output = store.save(_TestArtifact(value="first"), "same-id", "test")
    original = output.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600
    assert store.save(_TestArtifact(value="first"), "same-id", "test") == output

    with pytest.raises(PerfLensError, match="different content") as collision:
        store.save(_TestArtifact(value="second"), "same-id", "test")
    assert collision.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert output.read_bytes() == original


@pytest.mark.parametrize("unsafe_kind", ["fifo", "symlink", "hardlink", "mode"])
def test_artifact_reads_reject_unsafe_file_types_without_blocking(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=False)
    artifact = root / "unsafe.analysis.json"
    if unsafe_kind == "fifo":
        os.mkfifo(artifact)
    elif unsafe_kind == "symlink":
        target = tmp_path / "target"
        target.write_text("secret", encoding="utf-8")
        artifact.symlink_to(target)
    else:
        artifact.write_text('{"value":"data"}\n', encoding="utf-8")
        artifact.chmod(0o600)
        if unsafe_kind == "hardlink":
            os.link(artifact, root / "second-link")
        else:
            artifact.chmod(0o644)

    with pytest.raises(PerfLensError) as unsafe:
        store.read_page("unsafe", "analysis", offset=0, limit=100)
    assert unsafe.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_artifact_read_pins_root_and_pages_safe_regular_file(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    output = store.save(_TestArtifact(value="paged"), "page", "test")

    text, next_offset, total = store.read_page("page", "test", offset=0, limit=8)
    assert text == output.read_text(encoding="utf-8")[:8]
    assert next_offset == 8
    assert total == output.stat().st_size

    moved = tmp_path / "moved-artifacts"
    root.rename(moved)
    root.mkdir()
    root.chmod(0o700)
    with pytest.raises(PerfLensError, match="root identity changed") as replaced:
        store.read_page("page", "test", offset=0, limit=8)
    assert replaced.value.code is ErrorCode.PATH_SAFETY_VIOLATION
