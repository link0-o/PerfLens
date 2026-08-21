from __future__ import annotations

import os
from pathlib import Path

import pytest

from perflens.docker.runtime_root import prepare_default_managed_runtime_root
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError


def test_managed_runtime_root_is_private_stable_and_project_bound(tmp_path: Path) -> None:
    parent = tmp_path / "runtime-parent"
    project = tmp_path / "project"
    parent.mkdir(mode=0o700)
    project.mkdir(mode=0o700)
    identity = inspect_managed_project_root(project)

    first = prepare_default_managed_runtime_root(identity, runtime_parent=parent)
    second = prepare_default_managed_runtime_root(identity, runtime_parent=parent)

    assert first == second
    assert first.parent == parent
    assert first.name == f"perflens-docker-{identity.identity_sha256[:20]}"
    metadata = first.stat(follow_symlinks=False)
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_mode & 0o777 == 0o700


def test_managed_runtime_root_rejects_writable_parent_and_symlink_child(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "runtime-parent"
    project = tmp_path / "project"
    parent.mkdir(mode=0o700)
    project.mkdir(mode=0o700)
    identity = inspect_managed_project_root(project)

    parent.chmod(0o770)
    with pytest.raises(PerfLensError) as writable:
        prepare_default_managed_runtime_root(identity, runtime_parent=parent)
    assert writable.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    parent.chmod(0o700)
    child = parent / f"perflens-docker-{identity.identity_sha256[:20]}"
    child.symlink_to(project, target_is_directory=True)
    with pytest.raises(PerfLensError) as linked:
        prepare_default_managed_runtime_root(identity, runtime_parent=parent)
    assert linked.value.code is ErrorCode.PATH_SAFETY_VIOLATION
