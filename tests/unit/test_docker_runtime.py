from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from tests.support.docker import write_self_contained_test_elf

from perflens.application.evidence import contract_content_sha256
from perflens.collection.planning import AutomaticCollectionPolicy
from perflens.contracts.docker import (
    ContainerCgroupIdentity,
    ContainerNamespaceIdentity,
    ContainerTargetArtifact,
)
from perflens.docker.adapter import DockerCommandAdapter
from perflens.docker.project_config import (
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.docker.runtime import ExistingDockerRuntime
from perflens.docker.session import EXPLICIT_DOCKER_SESSION_AUTHORIZATION
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError


def _target() -> ContainerTargetArtifact:
    provisional = ContainerTargetArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        target_id="container-target-" + "4" * 20,
        created_at="2026-08-21T00:00:00+00:00",
        target_kind="existing_container",
        container_identity_sha256="5" * 64,
        image_identity_sha256="6" * 64,
        container_pid=12,
        host_pid=1234,
        host_uid=1000,
        host_start_time_ticks=5678,
        executable_name="worker",
        namespace=ContainerNamespaceIdentity(
            pid_namespace_inode=101,
            user_namespace_inode=102,
            mount_namespace_inode=103,
            cgroup_namespace_inode=104,
        ),
        cgroup=ContainerCgroupIdentity(inode=105, identity_sha256="7" * 64),
        uid_mapping="rootless_same_uid",
        adapter_recipe_id="local-docker-read-v1",
        adapter_sha256="8" * 64,
        identity_fingerprint="9" * 64,
        content_sha256="0" * 64,
    )
    return ContainerTargetArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ExistingDockerRuntime, Path]:
    policy_path = tmp_path / "perflens-setup" / "container-workload.toml"
    policy_path.parent.mkdir()
    policy_path.write_text(
        render_default_docker_project_policy().replace(
            "max_workload_runs = 6",
            "max_workload_runs = 2",
        ),
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    policy = load_docker_project_policy(policy_path, allowed_roots=(tmp_path,))
    target = _target()

    def fake_resolve(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(artifact=target, instance="instance-a", kernel="kernel-a")

    monkeypatch.setattr(
        "perflens.docker.runtime.resolve_existing_container_target",
        fake_resolve,
    )
    runtime = ExistingDockerRuntime(
        project=inspect_managed_project_root(tmp_path),
        project_policy=policy,
        allowed_roots=(tmp_path,),
        collection_policy=AutomaticCollectionPolicy(
            enabled=True,
            allowed_modes=("record", "stat", "sched"),
        ),
        client_connection_identity_sha256="a" * 64,
        adapter_factory=lambda: cast(DockerCommandAdapter, object()),
    )
    return runtime, policy_path


def test_existing_runtime_authorizes_bounded_modes_and_revokes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = _runtime(tmp_path, monkeypatch)
    target = runtime.resolve("service", host_pid=1234)
    assert target.host_pid == 1234

    session = runtime.authorize(
        "service",
        host_pid=1234,
        allowed_modes=("sched", "stat"),
        authorization_mode="bounded_session",
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
    )
    assert session.allowed_modes == ("stat", "sched")
    assert session.max_workload_runs == 2
    assert session.max_active_seconds == 1200
    lease = runtime.begin_existing_run(
        session.session_id,
        target,
        requested_modes=("stat",),
        reserve_active_seconds=10,
        reserve_evidence_bytes=1000,
    )
    assert lease.run_number == 1
    after_run = runtime.finish_existing_run(
        session.session_id,
        lease,
        actual_active_seconds=2,
        actual_evidence_bytes=120,
    )
    assert after_run.workload_runs_used == 1
    assert after_run.active_seconds_used == 2
    assert after_run.evidence_bytes_used == 120
    revoked = runtime.revoke(session.session_id)
    assert revoked.state == "revoked"
    assert runtime.revoke(session.session_id) == revoked


def test_existing_runtime_rejects_ungranted_modes_and_policy_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, policy_path = _runtime(tmp_path, monkeypatch)
    with pytest.raises(PerfLensError) as captured:
        runtime.authorize(
            "service",
            host_pid=1234,
            allowed_modes=("lock",),
            authorization_mode="per_run",
            explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    policy_path.write_text(
        policy_path.read_text(encoding="utf-8") + "\n# replaced\n",
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    with pytest.raises(PerfLensError) as replaced:
        runtime.resolve("service", host_pid=1234)
    assert "changed after MCP startup" in replaced.value.message


def test_existing_runtime_rejects_container_replacement_after_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = _runtime(tmp_path, monkeypatch)
    resolved = runtime.resolve_for_collection("service", host_pid=1234)

    def replaced_target(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            artifact=resolved.artifact,
            instance="instance-b",
            kernel=resolved.kernel,
        )

    monkeypatch.setattr(
        "perflens.docker.runtime.resolve_existing_container_target",
        replaced_target,
    )
    with pytest.raises(PerfLensError) as captured:
        runtime.assert_collection_target_current(
            "service",
            resolved,
            host_pid=1234,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "changed during collection" in captured.value.message


def test_existing_runtime_rejects_unknown_session_without_disclosing_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = _runtime(tmp_path, monkeypatch)
    with pytest.raises(PerfLensError) as captured:
        runtime.revoke("container-session-" + "f" * 20)
    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert "unknown" in captured.value.message


def test_managed_runtime_authorizes_only_the_fixed_project_recipe(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "perflens-setup" / "container-workload.toml"
    policy_path.parent.mkdir()
    policy_path.write_text(
        render_default_docker_project_policy()
        .replace(
            "allow_managed_temporary_containers = false",
            "allow_managed_temporary_containers = true",
        )
        .replace('image_digest = ""', 'image_digest = "sha256:' + "d" * 64 + '"')
        .replace('entrypoint = ""', 'entrypoint = "/usr/bin/python3"')
        .replace('container_user = ""', f'container_user = "{os.geteuid()}:{os.getegid()}"'),
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    gate = tmp_path / "perflens-container-gate"
    write_self_contained_test_elf(gate)
    runtime_root = tmp_path.parent / (tmp_path.name + "-runtime")
    runtime_root.mkdir(mode=0o700)
    policy = load_docker_project_policy(policy_path, allowed_roots=(tmp_path,))
    runtime = ExistingDockerRuntime(
        project=inspect_managed_project_root(tmp_path),
        project_policy=policy,
        allowed_roots=(tmp_path,),
        collection_policy=AutomaticCollectionPolicy(
            enabled=True,
            allowed_modes=("record", "stat", "sched"),
        ),
        client_connection_identity_sha256="a" * 64,
        adapter_factory=lambda: cast(DockerCommandAdapter, object()),
        managed_runtime_root=runtime_root,
        container_gate_path=gate,
        trusted_gate_owner_uids=(os.geteuid(),),
    )

    session = runtime.authorize_managed(
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
    )
    assert session.target_kind == "managed_temporary_container"
    assert session.authorization_mode == "per_run"
    assert session.allowed_modes == ("stat", "record", "sched")
    assert session.workload_spec_sha256 is not None
    assert session.existing_target_identity_sha256 is None


def test_managed_runtime_rejects_disabled_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = _runtime(tmp_path, monkeypatch)
    with pytest.raises(PerfLensError) as captured:
        runtime.authorize_managed(
            explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "disabled" in captured.value.message


def test_existing_runtime_prunes_inactive_private_access_before_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("perflens.docker.runtime._MAX_SESSION_ACCESS", 1)
    runtime, _ = _runtime(tmp_path, monkeypatch)
    first = runtime.authorize(
        "service",
        host_pid=1234,
        allowed_modes=("stat",),
        authorization_mode="per_run",
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
    )
    runtime.revoke(first.session_id)
    second = runtime.authorize(
        "service",
        host_pid=1234,
        allowed_modes=("stat",),
        authorization_mode="per_run",
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
    )
    assert second.session_id != first.session_id
