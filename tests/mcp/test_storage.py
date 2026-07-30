from __future__ import annotations

from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy


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


def test_new_output_file_is_confined_and_must_not_exist(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = PathPolicy((allowed,))
    assert policy.new_output_file(allowed / "profile.data") == allowed / "profile.data"

    outside = tmp_path / "outside.data"
    with pytest.raises(PerfLensError) as captured:
        policy.new_output_file(outside)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
