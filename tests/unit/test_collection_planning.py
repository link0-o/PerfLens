from __future__ import annotations

# pyright: reportPrivateUsage=false
import os
from datetime import UTC, datetime

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
)
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
