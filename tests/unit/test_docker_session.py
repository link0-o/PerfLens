from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    CollectionMode,
    ContainerCgroupIdentity,
    ContainerNamespaceIdentity,
    ContainerResourceLimits,
    ContainerTargetArtifact,
    ContainerWorkloadSpecArtifact,
)
from perflens.docker.session import (
    EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
    DockerRunLease,
    DockerSessionAuthority,
    SessionAccess,
)
from perflens.domain.errors import ErrorCode, PerfLensError

PROJECT = "a" * 64
CLIENT = "b" * 64
POLICY = "c" * 64


@dataclass(slots=True)
class _Clock:
    wall: datetime
    monotonic: float = 100.0

    def wall_now(self) -> datetime:
        return self.wall

    def monotonic_now(self) -> float:
        return self.monotonic

    def advance(self, seconds: int) -> None:
        self.wall += timedelta(seconds=seconds)
        self.monotonic += seconds


def _authority(*, max_sessions: int = 64) -> tuple[DockerSessionAuthority, _Clock]:
    clock = _Clock(datetime(2026, 8, 21, tzinfo=UTC))
    return (
        DockerSessionAuthority(
            wall_clock=clock.wall_now,
            monotonic_clock=clock.monotonic_now,
            max_sessions=max_sessions,
        ),
        clock,
    )


def _workload(
    *,
    authorization_mode: str = "bounded_session",
    modes: tuple[str, ...] = ("stat", "record", "sched"),
) -> ContainerWorkloadSpecArtifact:
    provisional = ContainerWorkloadSpecArtifact.model_validate(
        {
            "schema_version": "1.0",
            "perflens_version": "0.3.1",
            "workload_spec_id": "container-workload-" + "1" * 20,
            "created_at": "2026-08-21T00:00:00+00:00",
            "project_identity_sha256": PROJECT,
            "image_digest": "sha256:" + "2" * 64,
            "container_gate_sha256": "4" * 64,
            "entrypoint": "/usr/bin/python3",
            "arguments": ["/workspace/bench.py"],
            "working_directory": "/workspace",
            "container_user": "1000:1000",
            "resources": ContainerResourceLimits(
                cpus=2,
                memory_bytes=536_870_912,
                pids=64,
            ),
            "allowed_modes": modes,
            "authorization_mode": authorization_mode,
            "max_workload_runs": 6,
            "max_active_seconds": 1200,
            "hard_expiry_seconds": 7200,
            "workload_fingerprint": "3" * 64,
            "content_sha256": "0" * 64,
        }
    )
    return ContainerWorkloadSpecArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


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
        cgroup=ContainerCgroupIdentity(
            inode=105,
            identity_sha256="7" * 64,
        ),
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


def _authorize_managed(
    authority: DockerSessionAuthority,
    workload: ContainerWorkloadSpecArtifact | None = None,
):
    selected = workload or _workload()
    return authority.authorize_managed_workload(
        selected,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
        max_evidence_bytes=10_000,
    )


def _begin(authority: DockerSessionAuthority, access: SessionAccess, binding: str):
    return authority.begin_run(
        access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        binding_sha256=binding,
        requested_modes=("stat", "record"),
        reserve_active_seconds=100,
        reserve_evidence_bytes=1000,
    )


def test_managed_session_requires_explicit_authorization_and_keeps_secret_private() -> None:
    authority, _ = _authority()
    with pytest.raises(PerfLensError) as captured:
        authority.authorize_managed_workload(
            _workload(),
            client_connection_identity_sha256=CLIENT,
            policy_identity_sha256=POLICY,
            explicit_authorization="yes",
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    authorized = _authorize_managed(authority)
    assert authorized.artifact.state == "active"
    assert authorized.artifact.authorization_mode == "bounded_session"
    assert authorized.artifact.content_sha256 == contract_content_sha256(
        authorized.artifact,
        exclude={"content_sha256"},
    )
    public = authorized.artifact.model_dump_json()
    assert authorized.access.token not in public
    assert "token" not in public
    assert authorized.access.token not in repr(authorized)


def test_bounded_session_reserves_run_then_reconciles_actual_budget() -> None:
    authority, _ = _authority()
    workload = _workload()
    authorized = _authorize_managed(authority, workload)
    lease = _begin(authority, authorized.access, workload.content_sha256)
    during = authority.assert_run_current(
        authorized.access,
        lease,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        binding_sha256=workload.content_sha256,
        mode="record",
    )
    assert during.workload_runs_used == 1
    assert during.active_seconds_used == 100
    assert during.evidence_bytes_used == 1000
    assert during.instance_count == 1

    completed = authority.finish_run(
        authorized.access,
        lease,
        actual_active_seconds=25,
        actual_evidence_bytes=400,
    )
    assert completed.state == "active"
    assert completed.active_seconds_used == 25
    assert completed.evidence_bytes_used == 400
    assert completed.content_sha256 == contract_content_sha256(
        completed,
        exclude={"content_sha256"},
    )


def test_per_run_existing_session_exhausts_after_one_workload() -> None:
    authority, _ = _authority()
    target = _target()
    authorized = authority.authorize_existing_target(
        target,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        allowed_modes=("stat",),
        authorization_mode="per_run",
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
        max_active_seconds=60,
        max_evidence_bytes=1000,
    )
    lease = authority.begin_run(
        authorized.access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        binding_sha256=target.identity_fingerprint,
        requested_modes=("stat",),
        reserve_active_seconds=10,
        reserve_evidence_bytes=100,
    )
    finished = authority.finish_run(
        authorized.access,
        lease,
        actual_active_seconds=5,
        actual_evidence_bytes=50,
    )
    assert finished.state == "exhausted"
    assert finished.instance_count == 1
    assert finished.invalidation_reason is not None
    with pytest.raises(PerfLensError):
        authority.begin_run(
            authorized.access,
            project_identity_sha256=PROJECT,
            client_connection_identity_sha256=CLIENT,
            policy_identity_sha256=POLICY,
            binding_sha256=target.identity_fingerprint,
            requested_modes=("stat",),
            reserve_active_seconds=1,
            reserve_evidence_bytes=1,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("project_identity_sha256", "d" * 64),
        ("client_connection_identity_sha256", "d" * 64),
        ("policy_identity_sha256", "d" * 64),
        ("binding_sha256", "d" * 64),
    ),
)
def test_any_session_binding_change_revokes_authorization(
    field: str,
    replacement: str,
) -> None:
    authority, _ = _authority()
    workload = _workload()
    authorized = _authorize_managed(authority, workload)
    with pytest.raises(PerfLensError) as captured:
        authority.begin_run(
            authorized.access,
            project_identity_sha256=(
                replacement if field == "project_identity_sha256" else PROJECT
            ),
            client_connection_identity_sha256=(
                replacement if field == "client_connection_identity_sha256" else CLIENT
            ),
            policy_identity_sha256=(
                replacement if field == "policy_identity_sha256" else POLICY
            ),
            binding_sha256=(
                replacement if field == "binding_sha256" else workload.content_sha256
            ),
            requested_modes=("stat",),
            reserve_active_seconds=1,
            reserve_evidence_bytes=1,
        )
    assert "changed" in captured.value.message
    assert authority.snapshot(authorized.access).state == "revoked"


def test_mode_scope_concurrency_and_budget_limits_fail_closed() -> None:
    authority, _ = _authority()
    workload = _workload()
    authorized = _authorize_managed(authority, workload)
    with pytest.raises(PerfLensError):
        authority.begin_run(
            authorized.access,
            project_identity_sha256=PROJECT,
            client_connection_identity_sha256=CLIENT,
            policy_identity_sha256=POLICY,
            binding_sha256=workload.content_sha256,
            requested_modes=("lock",),
            reserve_active_seconds=1,
            reserve_evidence_bytes=1,
        )
    assert authority.snapshot(authorized.access).state == "active"

    lease = _begin(authority, authorized.access, workload.content_sha256)
    with pytest.raises(PerfLensError) as captured:
        _begin(authority, authorized.access, workload.content_sha256)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    authority.finish_run(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )

    with pytest.raises(PerfLensError) as captured:
        authority.begin_run(
            authorized.access,
            project_identity_sha256=PROJECT,
            client_connection_identity_sha256=CLIENT,
            policy_identity_sha256=POLICY,
            binding_sha256=workload.content_sha256,
            requested_modes=("stat",),
            reserve_active_seconds=1200,
            reserve_evidence_bytes=1,
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert authority.snapshot(authorized.access).state == "exhausted"


def test_concurrent_begin_run_grants_exactly_one_lease() -> None:
    authority, _ = _authority()
    workload = _workload()
    authorized = _authorize_managed(authority, workload)

    def attempt() -> DockerRunLease | ErrorCode:
        try:
            return _begin(authority, authorized.access, workload.content_sha256)
        except PerfLensError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(attempt), pool.submit(attempt))
        outcomes = tuple(future.result() for future in futures)
    leases = tuple(item for item in outcomes if isinstance(item, DockerRunLease))
    errors = tuple(item for item in outcomes if isinstance(item, ErrorCode))
    assert len(leases) == 1
    assert errors == (ErrorCode.RESOURCE_LIMIT_EXCEEDED,)
    authority.finish_run(
        authorized.access,
        leases[0],
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )


@pytest.mark.parametrize("modes", ((), ("record", "stat"), ("stat", "stat")))
def test_authorization_rejects_empty_noncanonical_or_duplicate_modes(
    modes: tuple[str, ...],
) -> None:
    authority, _ = _authority()
    with pytest.raises(PerfLensError):
        authority.authorize_existing_target(
            _target(),
            project_identity_sha256=PROJECT,
            client_connection_identity_sha256=CLIENT,
            policy_identity_sha256=POLICY,
            allowed_modes=cast(tuple[CollectionMode, ...], modes),
            authorization_mode="bounded_session",
            explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
        )


def test_forged_session_and_lease_tokens_and_replay_are_rejected() -> None:
    authority, _ = _authority()
    workload = _workload()
    authorized = _authorize_managed(authority, workload)
    forged_access = SessionAccess(authorized.access.session_id, "forged")
    with pytest.raises(PerfLensError):
        authority.snapshot(forged_access)

    lease = _begin(authority, authorized.access, workload.content_sha256)
    with pytest.raises(PerfLensError):
        authority.finish_run(
            authorized.access,
            replace(lease, token="forged"),  # noqa: S106 - deliberate token rejection
            actual_active_seconds=1,
            actual_evidence_bytes=1,
        )
    authority.finish_run(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    with pytest.raises(PerfLensError):
        authority.finish_run(
            authorized.access,
            lease,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
        )


def test_session_and_active_lease_expire_on_monotonic_deadlines() -> None:
    authority, clock = _authority()
    workload = _workload()
    authorized = _authorize_managed(authority, workload)
    lease = _begin(authority, authorized.access, workload.content_sha256)
    clock.monotonic += 221
    with pytest.raises(PerfLensError) as captured:
        authority.assert_run_current(
            authorized.access,
            lease,
            project_identity_sha256=PROJECT,
            client_connection_identity_sha256=CLIENT,
            policy_identity_sha256=POLICY,
            binding_sha256=workload.content_sha256,
            mode="stat",
        )
    assert "expired" in captured.value.message
    assert authority.snapshot(authorized.access).state == "expired"

    second, second_clock = _authority()
    another = _authorize_managed(second)
    second_clock.monotonic += 7201
    assert second.snapshot(another.access).state == "expired"


def test_connection_end_revokes_all_matching_sessions() -> None:
    authority, _ = _authority()
    first = _authorize_managed(authority)
    second = _authorize_managed(authority)
    revoked = authority.revoke_client_connection(CLIENT)
    assert revoked == tuple(sorted((first.artifact.session_id, second.artifact.session_id)))
    assert authority.snapshot(first.access).state == "revoked"
    assert authority.snapshot(second.access).state == "revoked"


def test_inactive_sessions_are_pruned_before_capacity_is_reused() -> None:
    authority, _ = _authority(max_sessions=2)
    first = _authorize_managed(authority)
    _authorize_managed(authority)
    with pytest.raises(PerfLensError) as captured:
        _authorize_managed(authority)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    authority.revoke(first.access)
    replacement_session = _authorize_managed(authority)
    assert replacement_session.artifact.state == "active"


def test_tampered_contract_and_overrun_revoke_or_exhaust_session() -> None:
    authority, _ = _authority()
    tampered = _workload().model_copy(update={"entrypoint": "/bin/other"})
    with pytest.raises(PerfLensError) as captured:
        _authorize_managed(authority, tampered)
    assert "digest" in captured.value.message

    workload = _workload()
    authorized = _authorize_managed(authority, workload)
    lease = _begin(authority, authorized.access, workload.content_sha256)
    with pytest.raises(PerfLensError) as captured:
        authority.finish_run(
            authorized.access,
            lease,
            actual_active_seconds=101,
            actual_evidence_bytes=1,
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert authority.snapshot(authorized.access).state == "exhausted"
