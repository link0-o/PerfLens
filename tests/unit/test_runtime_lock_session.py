from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.artifacts import ContractModel
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterCapabilityReference,
    RuntimeLockCapabilityArtifact,
    RuntimeLockRunArtifact,
    RuntimeLockSessionBudget,
    RuntimeLockSessionEndReason,
    RuntimeLockSessionPreviewArtifact,
    RuntimeLockWorkloadBinding,
    derive_runtime_lock_capability_id,
    derive_runtime_lock_run_id,
    derive_runtime_lock_workload_identity,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.session import (
    EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
    AuthorizedRuntimeLockSession,
    RuntimeLockRunLease,
    RuntimeLockSessionAccess,
    RuntimeLockSessionAuthority,
    RuntimeLockSessionRuntime,
    build_runtime_lock_session_preview,
)

NOW = datetime(2026, 8, 30, tzinfo=UTC)
PROJECT = "1" * 64
CLIENT = "2" * 64
POLICY = "3" * 64
CONFIG = "4" * 64
OPERATION = "5" * 64
TARGET = "6" * 64
WORKLOAD = "7" * 64
PROGRAM = "8" * 64


@dataclass(slots=True)
class _Clock:
    wall: datetime = NOW
    monotonic: float = 100.0

    def wall_now(self) -> datetime:
        return self.wall

    def monotonic_now(self) -> float:
        return self.monotonic

    def advance(self, seconds: int) -> None:
        self.wall += timedelta(seconds=seconds)
        self.monotonic += seconds


def _with_content[ArtifactT: ContractModel](artifact: ArtifactT) -> ArtifactT:
    model_type = type(artifact)
    return model_type.model_validate(
        {
            **artifact.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                artifact,
                exclude={"content_sha256"},
            ),
        }
    )


def _capability(
    *,
    native_status: str = "available",
) -> RuntimeLockCapabilityArtifact:
    created = NOW.isoformat()
    native = RuntimeLockAdapterCapabilityReference.model_validate(
        {
            "adapter_id": "native_pthread",
            "capability_id": "runtime-adapter-capability-" + "a" * 20,
            "capability_content_sha256": "a" * 64,
            "availability": native_status,
            "supported_semantics": (
                ("exact", "thresholded") if native_status in {"available", "partial"} else ()
            ),
            "limitations": () if native_status == "available" else ("not fully available",),
        }
    )
    generic = RuntimeLockAdapterCapabilityReference(
        adapter_id="generic_ndjson_import",
        capability_id="runtime-adapter-capability-" + "b" * 20,
        capability_content_sha256="b" * 64,
        availability="available",
        supported_semantics=("cumulative", "exact", "sampled", "thresholded"),
    )
    provisional = RuntimeLockCapabilityArtifact(
        schema_version="1.0",
        perflens_version="0.4.0",
        capability_id=derive_runtime_lock_capability_id(PROJECT, POLICY, created),
        created_at=created,
        project_identity_sha256=PROJECT,
        project_policy_sha256=POLICY,
        status="available",
        adapters=(generic, native),
        content_sha256="0" * 64,
    )
    return _with_content(provisional)


def _budget(**updates: int) -> RuntimeLockSessionBudget:
    values = RuntimeLockSessionBudget().model_dump(mode="python")
    return RuntimeLockSessionBudget.model_validate({**values, **updates})


def _preview(
    capability: RuntimeLockCapabilityArtifact | None = None,
    *,
    budget: RuntimeLockSessionBudget | None = None,
    adapters: tuple[str, ...] = ("native_pthread",),
    semantics: tuple[str, ...] = ("exact", "thresholded"),
    created_at: datetime = NOW,
):
    workload = RuntimeLockWorkloadBinding(
        adapter_id="native_pthread",
        workload_kind="native_elf",
        program="build/lock-workload",
        program_sha256=PROGRAM,
        program_size=4096,
        arguments=("--rounds", "10"),
        workload_identity_sha256=derive_runtime_lock_workload_identity(
            "native_pthread",
            "native_elf",
            "build/lock-workload",
            PROGRAM,
            4096,
            ".",
            ("--rounds", "10"),
        ),
    )
    return build_runtime_lock_session_preview(
        capability or _capability(),
        client_connection_identity_sha256=CLIENT,
        runtime_lock_config_sha256=CONFIG,
        target_scope="host_launched_workload",
        allowed_adapters=adapters,  # type: ignore[arg-type]
        allowed_semantics=semantics,  # type: ignore[arg-type]
        workload=workload,
        budget=budget,
        planned_actions=("Launch one authorized workload and collect Runtime Lock evidence.",),
        created_at=created_at,
    )


def _authority(
    *,
    max_sessions: int = 32,
) -> tuple[RuntimeLockSessionAuthority, _Clock]:
    clock = _Clock()
    return (
        RuntimeLockSessionAuthority(
            wall_clock=clock.wall_now,
            monotonic_clock=clock.monotonic_now,
            max_sessions=max_sessions,
        ),
        clock,
    )


def _authorize(
    authority: RuntimeLockSessionAuthority,
    *,
    preview: RuntimeLockSessionPreviewArtifact | None = None,
    capability: RuntimeLockCapabilityArtifact | None = None,
) -> AuthorizedRuntimeLockSession:
    selected_capability = capability or _capability()
    selected_preview = preview or _preview(selected_capability)
    return authority.authorize(
        selected_preview,
        selected_capability,
        preview_content_sha256=selected_preview.content_sha256,
        authorization_summary_sha256=selected_preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
    )


def _begin(
    authority: RuntimeLockSessionAuthority,
    authorized: AuthorizedRuntimeLockSession,
    *,
    operation: str = OPERATION,
    adapter: str = "native_pthread",
    semantics: str = "exact",
    seconds: int = 3,
    evidence_bytes: int = 1000,
    exact_events: int = 20,
) -> RuntimeLockRunLease:
    return authority.begin_run(
        authorized.access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        project_policy_sha256=POLICY,
        runtime_lock_config_sha256=CONFIG,
        capability_content_sha256=authorized.artifact.capability_content_sha256,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
        adapter_id=adapter,  # type: ignore[arg-type]
        measurement_semantics=semantics,  # type: ignore[arg-type]
        operation_identity_sha256=operation,
        target_identity_sha256=TARGET,
        workload_identity_sha256=WORKLOAD,
        reserve_active_seconds=seconds,
        reserve_evidence_bytes=evidence_bytes,
        reserve_exact_events=exact_events,
    )


def _run(
    lease: RuntimeLockRunLease,
    *,
    duration: int = 2,
    evidence_bytes: int = 800,
    events: int = 10,
) -> RuntimeLockRunArtifact:
    started = NOW.isoformat()
    finished = (NOW + timedelta(seconds=duration)).isoformat()
    evidence_sha = "8" * 64
    provisional = RuntimeLockRunArtifact(
        schema_version="1.0",
        perflens_version="0.4.0",
        run_id=derive_runtime_lock_run_id(
            lease.session_id,
            lease.adapter_id,
            evidence_sha,
            started,
        ),
        created_at=finished,
        started_at=started,
        finished_at=finished,
        session_id=lease.session_id,
        session_artifact_id=lease.session_artifact_id,
        session_artifact_content_sha256=lease.session_artifact_content_sha256,
        session_revision=lease.session_revision,
        target_scope="host_launched_workload",
        adapter_id=lease.adapter_id,
        measurement_semantics=lease.measurement_semantics,
        operation_identity_sha256=lease.operation_identity_sha256,
        target_identity_sha256=lease.target_identity_sha256,
        workload_identity_sha256=lease.workload_identity_sha256,
        runtime_lock_evidence_id="runtime-lock-evidence-" + "9" * 20,
        runtime_lock_evidence_content_sha256=evidence_sha,
        runtime_lock_analysis_id="runtime-lock-analysis-" + "a" * 20,
        runtime_lock_analysis_content_sha256="a" * 64,
        runtime_lock_verification_id="runtime-lock-verification-" + "b" * 20,
        runtime_lock_verification_content_sha256="b" * 64,
        duration_seconds=duration,
        evidence_bytes=evidence_bytes,
        event_count=events,
        correctness_status="passed",
        quality_status="complete",
        allowed_conclusions=("runtime_lock_wait_distribution",),
        forbidden_conclusions=("performance_root_cause",),
        content_sha256="0" * 64,
    )
    return _with_content(provisional)


def test_preview_and_authorization_are_content_bound_and_single_use() -> None:
    authority, _ = _authority()
    capability = _capability()
    preview = _preview(capability)
    assert preview.authorization_summary_sha256 != "0" * 64
    assert preview.content_sha256 == contract_content_sha256(
        preview,
        exclude={"content_sha256"},
    )

    with pytest.raises(PerfLensError, match="explicit bounded consent"):
        authority.authorize(
            preview,
            capability,
            preview_content_sha256=preview.content_sha256,
            authorization_summary_sha256=preview.authorization_summary_sha256,
            explicit_authorization="yes",
        )
    with pytest.raises(PerfLensError, match="summary changed"):
        authority.authorize(
            preview,
            capability,
            preview_content_sha256="0" * 64,
            authorization_summary_sha256=preview.authorization_summary_sha256,
            explicit_authorization=EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
        )

    authorized = _authorize(authority, preview=preview, capability=capability)
    assert authorized.artifact.state == "active"
    assert authorized.access.token not in authorized.artifact.model_dump_json()
    assert authorized.access.token not in repr(authorized)
    with pytest.raises(PerfLensError, match="already consumed"):
        _authorize(authority, preview=preview, capability=capability)


def test_preview_rejects_unavailable_adapter_and_unsupported_semantics() -> None:
    with pytest.raises(PerfLensError, match="unavailable Adapter"):
        _preview(_capability(native_status="unavailable"))
    with pytest.raises(PerfLensError, match="unsupported"):
        _preview(semantics=("cumulative",))
    with pytest.raises(PerfLensError, match="import roots require"):
        build_runtime_lock_session_preview(
            _capability(),
            client_connection_identity_sha256=CLIENT,
            runtime_lock_config_sha256=CONFIG,
            target_scope="host_launched_workload",
            allowed_adapters=("native_pthread",),
            allowed_semantics=("exact",),
            import_roots=("imports",),
            workload=RuntimeLockWorkloadBinding(
                adapter_id="native_pthread",
                workload_kind="native_elf",
                program="build/lock-workload",
                program_sha256=PROGRAM,
                program_size=4096,
                workload_identity_sha256=derive_runtime_lock_workload_identity(
                    "native_pthread",
                    "native_elf",
                    "build/lock-workload",
                    PROGRAM,
                    4096,
                    ".",
                    (),
                ),
            ),
            planned_actions=("Collect one bounded workload.",),
            created_at=NOW,
        )


def test_exact_run_reserves_reconciles_and_rejects_replay() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)
    reserved = authority.snapshot(authorized.access)
    assert reserved.workload_runs_used == 1
    assert reserved.active_seconds_used == 3
    assert reserved.evidence_bytes_used == 1000
    assert reserved.exact_events_used == 20

    completed = authority.finish_run(authorized.access, lease, _run(lease))
    assert completed.active_seconds_used == 2
    assert completed.evidence_bytes_used == 800
    assert completed.exact_events_used == 10
    with pytest.raises(PerfLensError, match="invalid or consumed"):
        authority.finish_run(authorized.access, lease, _run(lease))
    with pytest.raises(PerfLensError, match="already consumed"):
        _begin(authority, authorized)


def test_mutated_lease_and_tampered_run_are_rejected_without_consuming_real_lease() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)
    with pytest.raises(PerfLensError, match="invalid or consumed"):
        authority.finish_run(
            authorized.access,
            replace(lease, target_identity_sha256="0" * 64),
            _run(lease),
        )
    tampered = _run(lease).model_copy(update={"warnings": ("changed",)})
    with pytest.raises(PerfLensError, match="content digest"):
        authority.finish_run(authorized.access, lease, tampered)
    assert authority.finish_run(authorized.access, lease, _run(lease)).state == "active"


@pytest.mark.parametrize(
    "changed",
    ("project", "client", "policy", "config", "capability", "preview"),
)
def test_identity_or_policy_change_revokes_session(changed: str) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    values = {
        "project_identity_sha256": PROJECT,
        "client_connection_identity_sha256": CLIENT,
        "project_policy_sha256": POLICY,
        "runtime_lock_config_sha256": CONFIG,
        "capability_content_sha256": authorized.artifact.capability_content_sha256,
        "preview_content_sha256": authorized.artifact.preview_content_sha256,
    }
    key = {
        "project": "project_identity_sha256",
        "client": "client_connection_identity_sha256",
        "policy": "project_policy_sha256",
        "config": "runtime_lock_config_sha256",
        "capability": "capability_content_sha256",
        "preview": "preview_content_sha256",
    }[changed]
    values[key] = "0" * 64
    with pytest.raises(PerfLensError, match="identity or policy changed"):
        authority.begin_run(
            authorized.access,
            **values,
            adapter_id="native_pthread",
            measurement_semantics="exact",
            operation_identity_sha256=OPERATION,
            target_identity_sha256=TARGET,
            workload_identity_sha256=WORKLOAD,
            reserve_active_seconds=1,
            reserve_evidence_bytes=1,
            reserve_exact_events=1,
        )
    assert authority.snapshot(authorized.access).state == "revoked"


@pytest.mark.parametrize(
    ("adapter", "semantics", "exact_events", "match"),
    (
        ("java_jfr", "thresholded", 0, "outside authorization"),
        ("native_pthread", "cumulative", 0, "outside authorization"),
        ("native_pthread", "thresholded", 1, "cannot reserve exact"),
        ("native_pthread", "exact", 0, "exact-event reservation"),
    ),
)
def test_run_rejects_adapter_semantics_or_event_budget_mismatch(
    adapter: str,
    semantics: str,
    exact_events: int,
    match: str,
) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    with pytest.raises(PerfLensError, match=match):
        _begin(
            authority,
            authorized,
            adapter=adapter,
            semantics=semantics,
            exact_events=exact_events,
        )


def test_parallel_run_and_budget_exhaustion_are_fail_closed() -> None:
    authority, _ = _authority()
    authorized = _authorize(
        authority,
        preview=_preview(budget=_budget(max_workload_runs=1, max_active_seconds=3)),
    )
    lease = _begin(authority, authorized)
    with pytest.raises(PerfLensError, match="active operation"):
        _begin(authority, authorized, operation="a" * 64)
    authority.finish_run(authorized.access, lease, _run(lease))
    with pytest.raises(PerfLensError, match="workload budget is exhausted"):
        _begin(authority, authorized, operation="a" * 64)
    assert authority.snapshot(authorized.access).state == "exhausted"


def test_threaded_begin_run_allows_only_one_active_adapter_operation() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)

    def begin(operation: str) -> RuntimeLockRunLease | PerfLensError:
        try:
            return _begin(authority, authorized, operation=operation)
        except PerfLensError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(begin, ("c" * 64, "d" * 64)))
    leases = tuple(result for result in results if isinstance(result, RuntimeLockRunLease))
    errors = tuple(result for result in results if isinstance(result, PerfLensError))
    assert len(leases) == 1
    assert len(errors) == 1
    assert "active operation" in str(errors[0])

    authority.fail_run(
        authorized.access,
        leases[0],
        actual_active_seconds=0,
        actual_evidence_bytes=0,
        actual_exact_events=0,
        reason="internal_collection_error",
    )


def test_same_adapter_is_single_concurrency_across_sessions() -> None:
    authority, _ = _authority()
    first = _authorize(authority)
    second = _authorize(
        authority,
        preview=_preview(created_at=NOW - timedelta(seconds=1)),
    )
    first_lease = _begin(authority, first)

    with pytest.raises(PerfLensError, match="Adapter already has an active operation"):
        _begin(authority, second, operation="a" * 64)

    authority.finish_run(first.access, first_lease, _run(first_lease))
    second_lease = _begin(authority, second, operation="a" * 64)
    assert second_lease.adapter_id == "native_pthread"


@pytest.mark.parametrize(
    ("duration", "evidence_bytes", "events"),
    ((3, 800, 10), (2, 1001, 10), (2, 800, 21)),
)
def test_run_usage_outside_reservation_ends_session(
    duration: int,
    evidence_bytes: int,
    events: int,
) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized, seconds=2)
    with pytest.raises(PerfLensError, match="exceeded its reservation"):
        authority.finish_run(
            authorized.access,
            lease,
            _run(lease, duration=duration, evidence_bytes=evidence_bytes, events=events),
        )
    assert authority.snapshot(authorized.access).state == "exhausted"


def test_failed_run_consumes_operation_and_ends_session_without_retry() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)
    failed = authority.fail_run(
        authorized.access,
        lease,
        actual_active_seconds=0.2,
        actual_evidence_bytes=10,
        actual_exact_events=1,
        reason="adapter_output_invalid",
    )
    assert failed.state == "failed"
    assert failed.active_seconds_used == 1
    assert failed.evidence_bytes_used == 10
    assert failed.exact_events_used == 1
    with pytest.raises(PerfLensError, match="no longer active"):
        _begin(authority, authorized, operation="a" * 64)


def test_failed_run_rejects_arbitrary_public_reason_without_consuming_lease() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)

    with pytest.raises(PerfLensError, match="public reason code"):
        authority.fail_run(
            authorized.access,
            lease,
            actual_active_seconds=0,
            actual_evidence_bytes=0,
            reason=cast(RuntimeLockSessionEndReason, "/home/user/private/token=secret"),
        )

    failed = authority.fail_run(
        authorized.access,
        lease,
        actual_active_seconds=0,
        actual_evidence_bytes=0,
        reason="adapter_output_invalid",
    )
    assert failed.invalidation_reason == "adapter_output_invalid"


def test_non_exact_failed_run_rejects_invented_exact_event_usage() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(
        authority,
        authorized,
        semantics="thresholded",
        seconds=5,
        exact_events=0,
    )
    with pytest.raises(PerfLensError, match="cannot report exact events"):
        authority.fail_run(
            authorized.access,
            lease,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
            actual_exact_events=1,
            reason="adapter_output_invalid",
        )
    assert authority.snapshot(authorized.access).state == "active"


def test_run_target_scope_mismatch_fails_session() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)
    changed = _run(lease).model_copy(
        update={"target_scope": "managed_temporary_container", "content_sha256": "0" * 64}
    )
    changed = _with_content(changed)
    with pytest.raises(PerfLensError, match="differs from its lease"):
        authority.finish_run(authorized.access, lease, changed)
    assert authority.snapshot(authorized.access).state == "failed"


def test_expiry_forged_access_capacity_and_naive_clock_are_rejected() -> None:
    authority, clock = _authority(max_sessions=1)
    authorized = _authorize(authority)
    forged = RuntimeLockSessionAccess(
        session_id=authorized.access.session_id,
        token=authorized.access.token[::-1],
    )
    with pytest.raises(PerfLensError, match="access is invalid"):
        authority.snapshot(forged)
    with pytest.raises(PerfLensError) as captured:
        _authorize(authority, preview=_preview(created_at=NOW - timedelta(seconds=1)))
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert authority.revoke(authorized.access).state == "revoked"
    replacement = _authorize(
        authority,
        preview=_preview(created_at=NOW - timedelta(seconds=2)),
    )
    clock.advance(3600)
    assert authority.snapshot(replacement.access).state == "expired"

    naive = RuntimeLockSessionAuthority(wall_clock=lambda: datetime(2026, 8, 30))
    with pytest.raises(ValueError, match="timezone"):
        _authorize(naive)


def test_preview_and_operation_lease_expiry() -> None:
    authority, clock = _authority()
    clock.advance(601)
    with pytest.raises(PerfLensError, match="Preview expired"):
        _authorize(authority)

    authority, clock = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)
    clock.advance(124)
    with pytest.raises(PerfLensError, match="operation lease expired"):
        authority.finish_run(authorized.access, lease, _run(lease))


def test_consumed_preview_tombstone_survives_expiry_and_wall_clock_rollback() -> None:
    authority, clock = _authority()
    capability = _capability()
    preview = _preview(capability)
    authorized = _authorize(authority, preview=preview, capability=capability)
    authority.revoke(authorized.access)
    authority.discard(authorized.access)
    clock.monotonic += 601
    clock.wall = NOW - timedelta(hours=1)

    with pytest.raises(PerfLensError, match="already consumed"):
        _authorize(authority, preview=preview, capability=capability)


def test_run_must_use_current_session_revision_and_lease_wall_window() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin(authority, authorized)
    reserved = authority.snapshot(authorized.access)
    assert lease.session_revision == 1
    assert reserved.revision == 1
    assert reserved.previous_session_artifact_id == authorized.artifact.session_artifact_id
    assert reserved.previous_session_artifact_content_sha256 == authorized.artifact.content_sha256

    shifted_start = NOW - timedelta(microseconds=1)
    shifted_finish = shifted_start + timedelta(seconds=2)
    before_lease = _run(lease).model_copy(
        update={
            "run_id": derive_runtime_lock_run_id(
                lease.session_id,
                lease.adapter_id,
                "8" * 64,
                shifted_start.isoformat(),
            ),
            "started_at": shifted_start.isoformat(),
            "finished_at": shifted_finish.isoformat(),
            "created_at": shifted_finish.isoformat(),
            "content_sha256": "0" * 64,
        }
    )
    before_lease = _with_content(before_lease)
    with pytest.raises(PerfLensError, match="differs from its lease"):
        authority.finish_run(authorized.access, lease, before_lease)
    assert authority.snapshot(authorized.access).state == "failed"


@pytest.mark.parametrize("capacity", (0, 33))
def test_authority_rejects_capacity_outside_fixed_bound(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity is outside"):
        RuntimeLockSessionAuthority(max_sessions=capacity)


def test_runtime_binds_preview_to_connection_and_revokes_on_close() -> None:
    clock = _Clock()
    runtime = RuntimeLockSessionRuntime(
        project_identity_sha256=PROJECT,
        project_policy_sha256=POLICY,
        runtime_lock_config_sha256=CONFIG,
        client_connection_identity_sha256=CLIENT,
        wall_clock=clock.wall_now,
        monotonic_clock=clock.monotonic_now,
    )
    preview = runtime.preview(
        _capability(),
        target_scope="controlled_import",
        allowed_adapters=("generic_ndjson_import",),
        allowed_semantics=("exact",),
        import_roots=("runtime-lock-evidence",),
        planned_actions=("Import one bounded project-relative evidence file.",),
    )
    session = runtime.authorize(
        preview_id=preview.preview_id,
        preview_content_sha256=preview.content_sha256,
        authorization_summary_sha256=preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
    )
    with pytest.raises(PerfLensError, match="missing or consumed"):
        runtime.authorize(
            preview_id=preview.preview_id,
            preview_content_sha256=preview.content_sha256,
            authorization_summary_sha256=preview.authorization_summary_sha256,
            explicit_authorization=EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
        )
    revoked = runtime.close()
    assert len(revoked) == 1
    assert revoked[0].session_id == session.session_id
    assert revoked[0].state == "revoked"
    with pytest.raises(PerfLensError, match="runtime is closed"):
        runtime.snapshot(session.session_id)


def test_runtime_rejects_a_run_for_a_different_preview_workload() -> None:
    clock = _Clock()
    runtime = RuntimeLockSessionRuntime(
        project_identity_sha256=PROJECT,
        project_policy_sha256=POLICY,
        runtime_lock_config_sha256=CONFIG,
        client_connection_identity_sha256=CLIENT,
        wall_clock=clock.wall_now,
        monotonic_clock=clock.monotonic_now,
    )
    workload = _preview().workload
    assert workload is not None
    preview = runtime.preview(
        _capability(),
        target_scope="host_launched_workload",
        allowed_adapters=("native_pthread",),
        allowed_semantics=("exact",),
        workload=workload,
        planned_actions=("Launch one exact Native pthread workload.",),
    )
    session = runtime.authorize(
        preview_id=preview.preview_id,
        preview_content_sha256=preview.content_sha256,
        authorization_summary_sha256=preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
    )

    with pytest.raises(PerfLensError, match="differs from its authorized Preview"):
        runtime.begin_run(
            session.session_id,
            adapter_id="native_pthread",
            measurement_semantics="exact",
            operation_identity_sha256=OPERATION,
            target_identity_sha256=TARGET,
            workload_identity_sha256="f" * 64,
            reserve_active_seconds=3,
            reserve_evidence_bytes=1024,
            reserve_exact_events=10,
        )
    assert runtime.snapshot(session.session_id).workload_runs_used == 0
