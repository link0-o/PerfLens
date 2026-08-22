from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import ContainerWorkloadSpecArtifact
from perflens.docker.workload import (
    assert_container_gate_current,
    build_container_workload_spec,
    inspect_container_gate,
    inspect_managed_project_root,
)
from perflens.domain.errors import PerfLensError


def _gate(tmp_path: Path) -> Path:
    path = tmp_path / "perflens-container-gate"
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(0o500)
    return path


def test_builder_binds_project_gate_and_fixed_sandbox(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    project = inspect_managed_project_root(project_path)
    gate = inspect_container_gate(
        _gate(tmp_path),
        trusted_owner_uids=(os.geteuid(),),
    )
    artifact = build_container_workload_spec(
        project=project,
        gate=gate,
        image_digest="sha256:" + "a" * 64,
        entrypoint="/usr/bin/python3",
        arguments=("/workspace/bench.py", "--rounds", "3"),
        container_user=f"{os.geteuid()}:{os.getegid()}",
        cpus=2,
        memory_bytes=536_870_912,
        pids=64,
        allowed_modes=("stat", "record", "sched"),
        treatment_paths=("src/workload.py",),
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    assert artifact.project_identity_sha256 == project.identity_sha256
    assert artifact.container_gate_sha256 == gate.sha256
    assert artifact.network_mode == "none"
    assert artifact.workspace_read_only is True
    assert len(artifact.treatment_path_sha256) == 1
    assert artifact.content_sha256 == contract_content_sha256(
        artifact,
        exclude={"content_sha256"},
    )
    serialized = artifact.model_dump_json()
    assert str(project_path) not in serialized
    assert str(gate.path) not in serialized
    assert "src/workload.py" not in serialized


def test_builder_rejects_gate_replacement_after_authorization(tmp_path: Path) -> None:
    gate_path = _gate(tmp_path)
    gate = inspect_container_gate(
        gate_path,
        trusted_owner_uids=(os.geteuid(),),
    )
    gate_path.chmod(0o700)
    gate_path.write_bytes(b"#!/bin/sh\nexit 1\n")
    gate_path.chmod(0o500)
    with pytest.raises(PerfLensError):
        assert_container_gate_current(gate)


@pytest.mark.parametrize("mode", [0o520, 0o502])
def test_gate_rejects_group_or_other_writable_binary(tmp_path: Path, mode: int) -> None:
    gate = _gate(tmp_path)
    gate.chmod(mode)
    with pytest.raises(PerfLensError):
        inspect_container_gate(gate, trusted_owner_uids=(os.geteuid(),))


def test_project_root_must_be_canonical_owned_directory(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(project, target_is_directory=True)
    with pytest.raises(PerfLensError):
        inspect_managed_project_root(alias)
    with pytest.raises(PerfLensError):
        inspect_managed_project_root(project / "missing")


@pytest.mark.parametrize("path", ["/etc/passwd", "../outside", "."])
def test_workload_rejects_non_project_treatment_path(
    tmp_path: Path,
    path: str,
) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    project = inspect_managed_project_root(project_path)
    gate = inspect_container_gate(_gate(tmp_path), trusted_owner_uids=(os.geteuid(),))
    with pytest.raises(PerfLensError):
        build_container_workload_spec(
            project=project,
            gate=gate,
            image_digest="sha256:" + "a" * 64,
            entrypoint="/usr/bin/python3",
            container_user=f"{os.geteuid()}:{os.getegid()}",
            cpus=1,
            memory_bytes=64 << 20,
            pids=32,
            treatment_paths=(path,),
        )


@pytest.mark.parametrize("container_user", ["root", "-1", "1:2:3", "4294967296"])
def test_workload_contract_requires_numeric_linux_uid_gid(container_user: str) -> None:
    with pytest.raises(ValidationError):
        ContainerWorkloadSpecArtifact.model_validate(
            {
                "schema_version": "1.0",
                "perflens_version": "0.3.1",
                "workload_spec_id": "container-workload-" + "a" * 20,
                "created_at": "2026-08-21T00:00:00+00:00",
                "project_identity_sha256": "b" * 64,
                "image_digest": "sha256:" + "c" * 64,
                "container_gate_sha256": "d" * 64,
                "entrypoint": "/bin/true",
                "working_directory": "/workspace",
                "container_user": container_user,
                "resources": {"cpus": 1, "memory_bytes": 6 << 20, "pids": 2},
                "allowed_modes": ["stat"],
                "authorization_mode": "per_run",
                "max_workload_runs": 1,
                "max_active_seconds": 1,
                "hard_expiry_seconds": 1,
                "workload_fingerprint": "e" * 64,
                "content_sha256": "f" * 64,
            }
        )
