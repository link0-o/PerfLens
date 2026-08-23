from __future__ import annotations

# pyright: reportPrivateUsage=false
import os
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from perflens.collection import planning
from perflens.collection.collector import SOFTWARE_STAT_EVENTS
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    assert_plan_current,
    create_collection_plan,
)
from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectionModeCapability,
    ContainerCollectionCgroupBinding,
    ContainerCollectionNamespaceBinding,
    ContainerCollectionTargetBinding,
)
from perflens.contracts.docker import ContainerTargetArtifact
from perflens.docker.identity import NamespaceIdentity
from perflens.domain.errors import ErrorCode, PerfLensError


def _capabilities() -> CollectionCapabilityArtifact:
    return CollectionCapabilityArtifact(
        capability_id="capability-test",
        platform="Linux",
        kernel_release="test",
        effective_uid=os.geteuid(),
        perf_event_paranoid=3,
        tracefs_accessible=False,
        modes=tuple(
            CollectionModeCapability(
                mode=mode,
                status="blocked",
                required_privilege="cap_sys_admin_or_policy_change",
                reason="test policy",
            )
            for mode in ("record", "stat", "sched", "lock", "off_cpu")
        ),
    )


def _docker_target(
    *,
    host_uid: int | None = None,
    rootful_cross_uid: bool = False,
) -> ContainerTargetArtifact:
    uid = os.geteuid() if host_uid is None else host_uid
    return ContainerTargetArtifact.model_validate(
        {
            "perflens_version": "0.3.1",
            "target_id": "container-target-" + "a" * 20,
            "created_at": "2026-08-21T00:00:00+00:00",
            "target_kind": "existing_container",
            "container_identity_sha256": "a" * 64,
            "image_identity_sha256": "b" * 64,
            "container_pid": 12,
            "host_pid": 4321,
            "host_uid": uid,
            "host_start_time_ticks": 9876,
            "executable_name": "worker",
            "namespace": {
                "pid_namespace_inode": 101,
                "user_namespace_inode": 102,
                "mount_namespace_inode": 103,
                "cgroup_namespace_inode": 104,
            },
            "cgroup": {"inode": 105, "identity_sha256": "c" * 64},
            "uid_mapping": (
                "rootful_cross_uid" if rootful_cross_uid else "rootless_same_uid"
            ),
            "rootful_risk_authorized": rootful_cross_uid,
            "adapter_recipe_id": "local-docker-read-v1",
            "adapter_sha256": "d" * 64,
            "identity_fingerprint": "e" * 64,
            "content_sha256": "f" * 64,
        }
    )


def _collection_binding(target: ContainerTargetArtifact) -> ContainerCollectionTargetBinding:
    return ContainerCollectionTargetBinding(
        target_id=target.target_id,
        target_kind=target.target_kind,
        target_content_sha256=target.content_sha256,
        container_identity_sha256=target.container_identity_sha256,
        image_identity_sha256=target.image_identity_sha256,
        identity_fingerprint=target.identity_fingerprint,
        container_pid=target.container_pid,
        host_pid=target.host_pid,
        host_uid=target.host_uid,
        host_start_time_ticks=target.host_start_time_ticks,
        executable_name=target.executable_name,
        namespace=ContainerCollectionNamespaceBinding(
            pid_namespace_inode=101,
            user_namespace_inode=102,
            mount_namespace_inode=103,
            cgroup_namespace_inode=104,
        ),
        cgroup=ContainerCollectionCgroupBinding(
            inode=105,
            identity_sha256="c" * 64,
        ),
        uid_mapping=target.uid_mapping,
        rootful_risk_authorized=target.rootful_risk_authorized,
        adapter_recipe_id=target.adapter_recipe_id,
        adapter_sha256=target.adapter_sha256,
    )


def test_plan_binds_pid_identity_and_policy_limits() -> None:
    plan = create_collection_plan(
        CollectionPlanRequest(mode="record", pid=os.getppid(), duration_seconds=5),
        policy=AutomaticCollectionPolicy(enabled=True),
        capabilities=_capabilities(),
        now=datetime(2026, 8, 2, tzinfo=UTC),
    )

    assert plan.schema_version == "1.0"
    assert plan.policy_status == "allowed"
    assert plan.target_uid == os.geteuid()
    assert plan.target_start_time_ticks > 0
    assert plan.backend == "privileged_broker"
    assert plan.required_privilege == "cap_sys_admin_or_policy_change"
    assert plan.requested_event_source == "auto"
    assert plan.fallback_allowed is True
    assert plan.record_event == "cycles"
    assert plan.fallback_record_event == "cpu-clock"
    assert any("broker" in warning for warning in plan.warnings)
    assert_plan_current(plan, now=datetime(2026, 8, 2, 0, 1, tzinfo=UTC))


def test_docker_plan_binds_full_kernel_identity_and_revalidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _docker_target()
    binding = _collection_binding(target)

    def bind_target(_target: ContainerTargetArtifact) -> ContainerCollectionTargetBinding:
        return binding

    def current_target(
        _target: object,
        **_kwargs: object,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            host_uid=binding.host_uid,
            host_start_time_ticks=binding.host_start_time_ticks,
        )

    monkeypatch.setattr(planning, "bind_container_collection_target", bind_target)
    monkeypatch.setattr(
        planning,
        "assert_container_target_current",
        current_target,
    )

    plan = create_collection_plan(
        CollectionPlanRequest(mode="record", pid=target.host_pid, container_target=target),
        policy=AutomaticCollectionPolicy(enabled=True),
        capabilities=_capabilities(),
        now=datetime(2026, 8, 21, tzinfo=UTC),
    )

    assert plan.policy_status == "allowed"
    assert plan.target_runtime == "docker"
    assert plan.container_target == binding
    assert plan.plan_id.startswith("plan-")
    assert_plan_current(plan, now=datetime(2026, 8, 21, 0, 1, tzinfo=UTC))


def test_docker_plan_threads_authenticated_namespace_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _docker_target()
    binding = _collection_binding(target)
    attestation = NamespaceIdentity(pid=101, user=102, mount=103, cgroup=104)
    observed: list[NamespaceIdentity | None] = []

    def bind_target(
        _target: ContainerTargetArtifact,
        *,
        namespace_attestation: NamespaceIdentity | None = None,
    ) -> ContainerCollectionTargetBinding:
        observed.append(namespace_attestation)
        return binding

    def current_target(
        _target: object,
        *,
        namespace_attestation: NamespaceIdentity | None = None,
        allow_managed_exec_transition: bool = False,
    ) -> SimpleNamespace:
        assert allow_managed_exec_transition is False
        observed.append(namespace_attestation)
        return SimpleNamespace(
            host_uid=binding.host_uid,
            host_start_time_ticks=binding.host_start_time_ticks,
        )

    monkeypatch.setattr(planning, "bind_container_collection_target", bind_target)
    monkeypatch.setattr(
        planning,
        "assert_container_target_current",
        current_target,
    )
    plan = create_collection_plan(
        CollectionPlanRequest(
            mode="record",
            pid=target.host_pid,
            container_target=target,
        ),
        policy=AutomaticCollectionPolicy(enabled=True),
        capabilities=_capabilities(),
        now=datetime(2026, 8, 21, tzinfo=UTC),
        namespace_attestation=attestation,
    )
    assert_plan_current(
        plan,
        now=datetime(2026, 8, 21, 0, 1, tzinfo=UTC),
        namespace_attestation=attestation,
    )
    assert observed == [attestation, attestation]


def test_docker_plan_rejects_pid_mismatch_and_gates_rootful_cross_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _docker_target(host_uid=0, rootful_cross_uid=True)
    binding = _collection_binding(target)

    def bind_target(_target: ContainerTargetArtifact) -> ContainerCollectionTargetBinding:
        return binding

    monkeypatch.setattr(planning, "bind_container_collection_target", bind_target)

    with pytest.raises(PerfLensError, match="host PID differs"):
        create_collection_plan(
            CollectionPlanRequest(mode="record", pid=target.host_pid + 1, container_target=target),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )

    denied = create_collection_plan(
        CollectionPlanRequest(mode="record", pid=target.host_pid, container_target=target),
        policy=AutomaticCollectionPolicy(enabled=True, allow_other_uids=True),
        capabilities=_capabilities(),
    )
    assert denied.policy_status == "denied"
    assert any("cross-UID" in warning for warning in denied.warnings)

    allowed = create_collection_plan(
        CollectionPlanRequest(mode="record", pid=target.host_pid, container_target=target),
        policy=AutomaticCollectionPolicy(
            enabled=True,
            allow_rootful_container_targets=True,
        ),
        capabilities=_capabilities(),
    )
    assert allowed.policy_status == "allowed"

    arbitrary_cross_uid = _docker_target(
        host_uid=os.geteuid() + 1,
        rootful_cross_uid=True,
    )
    arbitrary_binding = _collection_binding(arbitrary_cross_uid)

    def bind_arbitrary_target(
        _target: ContainerTargetArtifact,
    ) -> ContainerCollectionTargetBinding:
        return arbitrary_binding

    monkeypatch.setattr(
        planning,
        "bind_container_collection_target",
        bind_arbitrary_target,
    )
    rejected = create_collection_plan(
        CollectionPlanRequest(
            mode="record",
            pid=arbitrary_cross_uid.host_pid,
            container_target=arbitrary_cross_uid,
        ),
        policy=AutomaticCollectionPolicy(
            enabled=True,
            allow_rootful_container_targets=True,
        ),
        capabilities=_capabilities(),
    )
    assert rejected.policy_status == "denied"
    assert any("verified UID-0" in warning for warning in rejected.warnings)



def test_plan_is_denied_outside_categorical_policy() -> None:
    plan = create_collection_plan(
        CollectionPlanRequest(mode="off_cpu", pid=os.getppid(), duration_seconds=31),
        policy=AutomaticCollectionPolicy(enabled=True, allowed_modes=("record", "stat")),
        capabilities=_capabilities(),
    )
    assert plan.policy_status == "denied"
    assert len(plan.warnings) >= 2
    assert plan.requested_event_source == "hardware_required"
    assert plan.fallback_allowed is False
    assert plan.record_event is None
    with pytest.raises(PerfLensError) as captured:
        assert_plan_current(plan)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_trace_plan_uses_fixed_recipe_fields_and_safety_ceilings() -> None:
    plan = create_collection_plan(
        CollectionPlanRequest(mode="off_cpu", pid=os.getppid(), duration_seconds=10),
        policy=AutomaticCollectionPolicy(
            enabled=True,
            allowed_modes=("off_cpu",),
        ),
        capabilities=_capabilities(),
    )

    assert plan.policy_status == "allowed"
    assert plan.frequency_hz is None
    assert plan.call_graph is None
    assert plan.events == ()
    assert plan.max_output_bytes == 64 << 20
    assert any("64 MiB" in warning for warning in plan.warnings)

    too_long = create_collection_plan(
        CollectionPlanRequest(mode="sched", pid=os.getppid(), duration_seconds=11),
        policy=AutomaticCollectionPolicy(
            enabled=True,
            allowed_modes=("sched",),
        ),
        capabilities=_capabilities(),
    )
    assert too_long.policy_status == "denied"
    assert any("10-second" in warning for warning in too_long.warnings)


def test_software_only_stat_plan_uses_fixed_software_events() -> None:
    plan = create_collection_plan(
        CollectionPlanRequest(
            mode="stat",
            pid=os.getppid(),
            event_source="software_only",
        ),
        policy=AutomaticCollectionPolicy(enabled=True),
        capabilities=_capabilities(),
    )

    assert plan.events == SOFTWARE_STAT_EVENTS
    assert plan.fallback_allowed is False
    assert plan.record_event is None


def test_auto_plan_can_be_hardware_only_when_policy_disables_fallback() -> None:
    plan = create_collection_plan(
        CollectionPlanRequest(mode="stat", pid=os.getppid()),
        policy=AutomaticCollectionPolicy(enabled=True, allow_software_fallback=False),
        capabilities=_capabilities(),
    )

    assert plan.policy_status == "allowed"
    assert plan.requested_event_source == "auto"
    assert plan.fallback_allowed is False
    assert plan.fallback_events == ()
    assert any("fallback is disabled" in warning for warning in plan.warnings)


def test_expired_plan_is_rejected() -> None:
    created = datetime(2026, 8, 2, tzinfo=UTC)
    plan = create_collection_plan(
        CollectionPlanRequest(mode="stat", pid=os.getppid()),
        policy=AutomaticCollectionPolicy(enabled=True, plan_ttl_seconds=1),
        capabilities=_capabilities(),
        now=created,
    )
    with pytest.raises(PerfLensError, match="expired"):
        assert_plan_current(plan, now=datetime(2026, 8, 2, 0, 0, 2, tzinfo=UTC))


def test_plan_reports_every_policy_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    def other_identity(_pid: int) -> tuple[int, int]:
        return os.geteuid() + 1, 42

    monkeypatch.setattr(planning, "inspect_pid_identity", other_identity)
    plan = create_collection_plan(
        CollectionPlanRequest(
            mode="record",
            pid=123,
            duration_seconds=2,
            frequency_hz=100,
            max_output_bytes=200,
        ),
        policy=AutomaticCollectionPolicy(
            enabled=True,
            allowed_modes=("stat",),
            max_duration_seconds=1,
            max_frequency_hz=99,
            max_output_bytes=100,
        ),
        capabilities=_capabilities(),
    )
    assert plan.policy_status == "denied"
    assert len(plan.warnings) == 6


@pytest.mark.parametrize(
    "policy",
    [
        AutomaticCollectionPolicy(max_duration_seconds=0),
        AutomaticCollectionPolicy(max_duration_seconds=86_401),
        AutomaticCollectionPolicy(max_frequency_hz=0),
        AutomaticCollectionPolicy(max_frequency_hz=10_001),
        AutomaticCollectionPolicy(max_output_bytes=0),
        AutomaticCollectionPolicy(plan_ttl_seconds=0),
        AutomaticCollectionPolicy(plan_ttl_seconds=3601),
    ],
)
def test_invalid_automatic_policy_limits_are_rejected(policy: AutomaticCollectionPolicy) -> None:
    with pytest.raises(ValueError, match="policy limits"):
        planning._validate_policy(policy)


@pytest.mark.parametrize(
    "plan_request",
    [
        CollectionPlanRequest(mode="record", pid=1, duration_seconds=float("nan")),
        CollectionPlanRequest(mode="record", pid=1, frequency_hz=0),
        CollectionPlanRequest(mode="record", pid=1, max_output_bytes=0),
        CollectionPlanRequest(mode="stat", pid=1, events=()),
        CollectionPlanRequest(mode="stat", pid=1, events=("cycles,bad",)),
        CollectionPlanRequest(mode="stat", pid=1, events=("task-clock",)),
    ],
)
def test_invalid_plan_requests_are_rejected(plan_request: CollectionPlanRequest) -> None:
    with pytest.raises(PerfLensError) as captured:
        planning._validate_request(plan_request)
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_pid_identity_rejects_invalid_and_missing_processes() -> None:
    for pid in (0, os.getpid(), 2_000_000_000):
        with pytest.raises(PerfLensError):
            planning.inspect_pid_identity(pid)


def test_plan_rejects_invalid_timestamp_and_changed_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = create_collection_plan(
        CollectionPlanRequest(mode="record", pid=os.getppid()),
        policy=AutomaticCollectionPolicy(enabled=True),
        capabilities=_capabilities(),
    )
    with pytest.raises(PerfLensError, match="invalid expiration"):
        assert_plan_current(plan.model_copy(update={"expires_at": "bad"}))
    with pytest.raises(PerfLensError, match="timezone"):
        assert_plan_current(plan.model_copy(update={"expires_at": "2099-01-01T00:00:00"}))

    def changed_identity(_pid: int) -> tuple[int, int]:
        return plan.target_uid, plan.target_start_time_ticks + 1

    monkeypatch.setattr(planning, "inspect_pid_identity", changed_identity)
    with pytest.raises(PerfLensError, match="identity changed"):
        assert_plan_current(plan)
