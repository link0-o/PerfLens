from __future__ import annotations

import os
from pathlib import Path

import pytest

from perflens.docker.treatment import (
    assert_treatment_snapshot_current,
    capture_treatment_snapshot,
)
from perflens.domain.errors import PerfLensError


def test_treatment_snapshot_binds_relative_path_and_content_without_exporting_path(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "workload.py"
    source.write_text("print('before')\n", encoding="utf-8")

    snapshot = capture_treatment_snapshot(project, (source,))

    assert len(snapshot.treatment_sha256) == 1
    assert str(source) not in snapshot.treatment_sha256[0]
    assert_treatment_snapshot_current(snapshot)


def test_treatment_snapshot_detects_change_and_rejects_escape(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "workload.py"
    source.write_text("before\n", encoding="utf-8")
    snapshot = capture_treatment_snapshot(project, (source,))
    source.write_text("after\n", encoding="utf-8")
    with pytest.raises(PerfLensError, match="changed during"):
        assert_treatment_snapshot_current(snapshot)

    outside = tmp_path / "outside"
    outside.write_text("secret\n", encoding="utf-8")
    with pytest.raises(PerfLensError, match="outside"):
        capture_treatment_snapshot(project, (outside,))


def test_treatment_snapshot_rejects_symlink_hardlink_wrong_owner_and_duplicates(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "workload"
    source.write_bytes(b"payload")
    alias = project / "alias"
    alias.symlink_to(source)
    hardlink = project / "hardlink"
    os.link(source, hardlink)

    with pytest.raises(PerfLensError, match="non-symlinked"):
        capture_treatment_snapshot(project, (alias,))
    with pytest.raises(PerfLensError, match="link count"):
        capture_treatment_snapshot(project, (source,))
    hardlink.unlink()
    with pytest.raises(PerfLensError, match="unique"):
        capture_treatment_snapshot(project, (source, source))
    with pytest.raises(PerfLensError, match="owner"):
        capture_treatment_snapshot(project, (source,), invoking_uid=os.geteuid() + 1)


def test_empty_treatment_snapshot_is_explicitly_unverified_but_valid(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    snapshot = capture_treatment_snapshot(project, ())

    assert snapshot.treatment_sha256 == ()
    assert_treatment_snapshot_current(snapshot)
