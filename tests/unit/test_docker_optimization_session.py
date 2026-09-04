from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest
from pydantic import ValidationError

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerOptimizationBudget,
    DockerOptimizationPreviewArtifact,
    DockerOptimizationSessionArtifact,
    DockerRuntimeLockAuthorizationScope,
    OptimizationCollectionMode,
    derive_docker_build_artifact_id,
    derive_docker_optimization_preview_id,
    derive_docker_optimization_session_artifact_id,
    docker_runtime_lock_scope_sha256,
    docker_runtime_lock_version_constraints,
)
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockSessionBudget,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    AuthorizedDockerOptimizationSession,
    DockerOptimizationBuildLease,
    DockerOptimizationSessionAccess,
    DockerOptimizationSessionAuthority,
    DockerOptimizationWorkloadLease,
)
from perflens.domain.errors import ErrorCode, PerfLensError

PROJECT = "a" * 64
CLIENT = "b" * 64
POLICY = "c" * 64
CAPABILITY = "d" * 64
RECIPE = "e" * 64
CONTEXT = "f" * 64
NOW = datetime(2026, 8, 24, tzinfo=UTC)


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


def _budget(**updates: int) -> DockerOptimizationBudget:
    values = {
        "max_candidate_rounds": 3,
        "max_builds": 4,
        "max_workload_runs": 10,
        "max_recoverable_retries": 1,
        "max_build_seconds": 900,
        "max_total_build_seconds": 3600,
        "max_workload_active_seconds": 1800,
        "hard_expiry_seconds": 7200,
        "max_evidence_bytes": 1 << 30,
        "max_temporary_image_bytes": 10 << 30,
        "record_max_duration_seconds": 30,
        "record_frequency_hz": 99,
        "trace_max_duration_seconds": 10,
    }
    return DockerOptimizationBudget.model_validate({**values, **updates})


def _preview(
    *,
    budget: DockerOptimizationBudget | None = None,
    allowed_modes: tuple[OptimizationCollectionMode, ...] = (
        "stat",
        "record",
        "sched",
        "off_cpu",
        "lock",
    ),
    runtime_lock_scope: DockerRuntimeLockAuthorizationScope | None = None,
) -> DockerOptimizationPreviewArtifact:
    created_at = NOW.isoformat()
    data = {
        "schema_version": "1.1" if runtime_lock_scope is not None else "1.0",
        "perflens_version": "0.3.2",
        "preview_id": derive_docker_optimization_preview_id(
            PROJECT,
            RECIPE,
            CONTEXT,
            created_at,
        ),
        "created_at": created_at,
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "project_identity_sha256": PROJECT,
        "client_connection_identity_sha256": CLIENT,
        "project_policy_sha256": POLICY,
        "runtime_capability_sha256": "1" * 64,
        "build_capability_id": "docker-build-capability-" + "2" * 20,
        "build_capability_content_sha256": CAPABILITY,
        "recipe_id": "docker-build-recipe-" + "3" * 20,
        "recipe_content_sha256": RECIPE,
        "baseline_context_id": "docker-build-context-" + "4" * 20,
        "baseline_context_content_sha256": CONTEXT,
        "allowed_modes": allowed_modes,
        "network_tier": "local_only",
        "base_image_present": True,
        "baseline_build_required": True,
        "context_paths": ("Dockerfile", "src"),
        "mutable_paths": ("src",),
        "mutable_dockerfile": False,
        "mutable_dependency_lock": False,
        "budget": budget or _budget(),
        "runtime_lock_scope": runtime_lock_scope,
        "planned_actions": (
            "Build one baseline after authorization.",
            "Collect evidence and run matched A/B candidates.",
        ),
        "warnings": (),
        "authorization_summary_sha256": "5" * 64,
        "content_sha256": "0" * 64,
    }
    provisional = DockerOptimizationPreviewArtifact.model_validate(data)
    return DockerOptimizationPreviewArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _runtime_lock_scope(
    *,
    max_workload_runs: int = 6,
) -> DockerRuntimeLockAuthorizationScope:
    tools = ()
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    binding = RuntimeLockAdapterExecutionBinding(
        adapter_id="native_pthread",
        adapter_version="native-pthread-adapter-v1",
        backend_id="pthread-preload",
        runtime_version="glibc-2.41",
        profile="thresholded",
        measurement_semantics="thresholded",
        duration_threshold_ns=1_000,
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256="6" * 64,
        metadata_sha256="7" * 64,
        execution_identity_sha256=derive_runtime_lock_adapter_execution_identity(
            "native_pthread",
            "native-pthread-adapter-v1",
            "pthread-preload",
            "glibc-2.41",
            "thresholded",
            "thresholded",
            1_000,
            toolchain,
            "6" * 64,
            "7" * 64,
        ),
    )
    provisional = DockerRuntimeLockAuthorizationScope.model_construct(
        schema_version="1.1",
        runtime_lock_config_sha256="8" * 64,
        capability_id="runtime-lock-capability-" + "9" * 20,
        capability_content_sha256="a" * 64,
        allowed_adapters=("native_pthread",),
        allowed_semantics=("thresholded",),
        adapter_execution_bindings=(binding,),
        runtime_version_constraints=docker_runtime_lock_version_constraints((binding,)),
        budget=RuntimeLockSessionBudget(max_workload_runs=max_workload_runs),
        content_sha256="0" * 64,
    )
    return DockerRuntimeLockAuthorizationScope.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": docker_runtime_lock_scope_sha256(provisional),
        }
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("context_paths", ()),
        ("mutable_paths", ()),
        ("context_paths", ("src", "Dockerfile")),
        ("mutable_paths", ("src", "src")),
        ("mutable_paths", ("/etc",)),
        ("mutable_paths", ("../outside",)),
        ("mutable_paths", ("outside",)),
    ),
)
def test_preview_rejects_invalid_or_unbound_path_scope(
    field: str,
    value: tuple[str, ...],
) -> None:
    payload = _preview().model_dump(mode="json")
    payload[field] = value

    with pytest.raises(ValidationError):
        DockerOptimizationPreviewArtifact.model_validate(payload)


def test_preview_1_1_embeds_runtime_lock_scope_without_a_second_token() -> None:
    payload = _preview().model_dump(mode="json")
    payload["schema_version"] = "1.1"
    payload["runtime_lock_scope"] = _runtime_lock_scope().model_dump(mode="json")
    preview = DockerOptimizationPreviewArtifact.model_validate(payload)

    assert preview.runtime_lock_scope is not None
    assert "authorization" not in preview.runtime_lock_scope.model_dump_json()
    assert preview.runtime_lock_scope.runtime_version_constraints[0].allowed_versions == (
        "glibc-2.36",
        "glibc-2.41",
    )

    payload["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match=r"Preview 1\.0"):
        DockerOptimizationPreviewArtifact.model_validate(payload)


def test_schema_1_0_docker_artifacts_do_not_project_runtime_lock_defaults() -> None:
    preview_payload = _preview().model_dump(mode="json", exclude_none=True)
    assert "runtime_lock_scope" not in preview_payload

    authority, _ = _authority()
    session_payload = _authorize(authority).artifact.model_dump(mode="json", exclude_none=True)
    assert not any(key.startswith("runtime_lock_") for key in session_payload)


def test_runtime_lock_scope_rejects_unbound_adapter_or_semantics() -> None:
    payload = _runtime_lock_scope().model_dump(mode="json")
    payload["allowed_adapters"] = ["java_jfr"]
    with pytest.raises(ValidationError, match="bind every authorized Adapter"):
        DockerRuntimeLockAuthorizationScope.model_validate(payload)

    payload = _runtime_lock_scope().model_dump(mode="json")
    payload["allowed_semantics"] = ["exact"]
    with pytest.raises(ValidationError, match="semantics differ"):
        DockerRuntimeLockAuthorizationScope.model_validate(payload)

    payload = _runtime_lock_scope().model_dump(mode="json")
    payload["runtime_version_constraints"][0]["allowed_versions"] = ["glibc-9.99"]
    with pytest.raises(ValidationError, match="version constraints differ"):
        DockerRuntimeLockAuthorizationScope.model_validate(payload)


def _authority(
    *,
    max_sessions: int = 32,
) -> tuple[DockerOptimizationSessionAuthority, _Clock]:
    clock = _Clock()
    authority = DockerOptimizationSessionAuthority(
        wall_clock=clock.wall_now,
        monotonic_clock=clock.monotonic_now,
        max_sessions=max_sessions,
    )
    return authority, clock


def _authorize(
    authority: DockerOptimizationSessionAuthority,
    preview: DockerOptimizationPreviewArtifact | None = None,
) -> AuthorizedDockerOptimizationSession:
    selected = preview or _preview()
    return authority.authorize(
        selected,
        preview_content_sha256=selected.content_sha256,
        authorization_summary_sha256=selected.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    )


def _begin_build(
    authority: DockerOptimizationSessionAuthority,
    access: DockerOptimizationSessionAccess,
    *,
    kind: Literal["baseline", "candidate"] = "baseline",
    round_number: int = 0,
    context_sha256: str = CONTEXT,
    preview_content_sha256: str | None = None,
) -> DockerOptimizationBuildLease:
    return authority.begin_build(
        access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        project_policy_sha256=POLICY,
        preview_content_sha256=preview_content_sha256 or _preview().content_sha256,
        recipe_content_sha256=RECIPE,
        context_content_sha256=context_sha256,
        build_kind=kind,
        candidate_round=round_number,
    )


def _build_artifact(
    *,
    kind: Literal["baseline", "candidate"] = "baseline",
    round_number: int = 0,
    context_sha256: str = CONTEXT,
    image_bytes: int = 4096,
) -> DockerBuildArtifact:
    image_digest = "sha256:" + str(round_number + 6) * 64
    data = {
        "schema_version": "1.0",
        "perflens_version": "0.3.2",
        "build_id": derive_docker_build_artifact_id(
            context_sha256,
            kind,
            round_number,
            image_digest,
            NOW.isoformat(),
        ),
        "build_kind": kind,
        "candidate_round": round_number,
        "started_at": NOW.isoformat(),
        "finished_at": NOW.isoformat(),
        "recipe_id": "docker-build-recipe-" + "3" * 20,
        "recipe_content_sha256": RECIPE,
        "context_id": "docker-build-context-" + "4" * 20,
        "context_content_sha256": context_sha256,
        "builder_identity_sha256": "7" * 64,
        "network_policy_sha256": "8" * 64,
        "final_image_digest": image_digest,
        "platform": "linux/amd64",
        "image_size_bytes": image_bytes,
        "iid_file_sha256": "9" * 64,
        "metadata_file_sha256": "a" * 64,
        "provenance_sha256": "b" * 64,
        "immutable_manifest_sha256": "c" * 64,
        "treatment_manifest_sha256": "d" * 64,
        "cleanup_eligible": True,
        "content_sha256": "0" * 64,
    }
    provisional = DockerBuildArtifact.model_validate(data)
    return DockerBuildArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _finish_baseline(
    authority: DockerOptimizationSessionAuthority,
    authorized: AuthorizedDockerOptimizationSession,
) -> tuple[DockerOptimizationBuildLease, DockerOptimizationSessionArtifact]:
    lease = _begin_build(
        authority,
        authorized.access,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
    )
    session = authority.finish_build(
        authorized.access,
        lease,
        _build_artifact(),
        actual_build_seconds=12.2,
    )
    return lease, session


def test_authorization_binds_exact_preview_and_keeps_token_private() -> None:
    authority, _ = _authority()
    preview = _preview()
    with pytest.raises(PerfLensError):
        authority.authorize(
            preview,
            preview_content_sha256=preview.content_sha256,
            authorization_summary_sha256=preview.authorization_summary_sha256,
            explicit_authorization="yes",
        )
    with pytest.raises(PerfLensError):
        authority.authorize(
            preview,
            preview_content_sha256="0" * 64,
            authorization_summary_sha256=preview.authorization_summary_sha256,
            explicit_authorization=EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
        )

    authorized = _authorize(authority, preview)
    assert authorized.artifact.state == "active"
    assert authorized.artifact.content_sha256 == contract_content_sha256(
        authorized.artifact,
        exclude={"content_sha256"},
    )
    public = authorized.artifact.model_dump_json()
    assert authorized.access.token not in public
    assert authorized.access.token not in repr(authorized)


def test_session_1_1_accounts_runtime_lock_inside_outer_workload_budget() -> None:
    authority, _ = _authority()
    base = _authorize(authority).artifact.model_dump(mode="json")
    scope = _runtime_lock_scope()
    base.update(
        {
            "schema_version": "1.1",
            "workload_runs_used": 1,
            "workload_active_seconds_used": 2,
            "evidence_bytes_used": 4096,
            "runtime_lock_scope": scope.model_dump(mode="json"),
            "runtime_lock_status": "active",
            "runtime_lock_runs_used": 1,
            "runtime_lock_active_seconds_used": 2,
            "runtime_lock_evidence_bytes_used": 2048,
            "runtime_lock_exact_events_used": 0,
        }
    )
    base["session_artifact_id"] = derive_docker_optimization_session_artifact_id(
        base["session_id"],
        base["state"],
        base["updated_at"],
        base["builds_used"],
        base["workload_runs_used"],
        base["evidence_bytes_used"],
        scope.content_sha256,
        base["runtime_lock_runs_used"],
        base["runtime_lock_evidence_bytes_used"],
        base["runtime_lock_exact_events_used"],
        runtime_lock_status="active",
        runtime_lock_active_seconds_used=2,
    )
    session = DockerOptimizationSessionArtifact.model_validate(base)
    assert session.runtime_lock_runs_used == session.workload_runs_used

    base["runtime_lock_runs_used"] = 2
    with pytest.raises(ValidationError, match="bound Session evidence"):
        DockerOptimizationSessionArtifact.model_validate(base)

    base["runtime_lock_runs_used"] = 1
    base["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match=r"Session 1\.0"):
        DockerOptimizationSessionArtifact.model_validate(base)


def test_authority_charges_runtime_lock_once_inside_completed_workload() -> None:
    authority, _ = _authority()
    preview = _preview(runtime_lock_scope=_runtime_lock_scope())
    authorized = _authorize(authority, preview)
    session = authorized.artifact
    assert session.schema_version == "1.1"
    assert session.runtime_lock_status == "active"
    assert session.runtime_lock_runs_used == 0

    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(
        authority,
        authorized,
        session.baseline_build_id,
        seconds=5,
        evidence=500,
    )
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=4.1,
        actual_evidence_bytes=400,
    )
    with pytest.raises(PerfLensError, match="exceeds its enclosing workload"):
        authority.charge_runtime_lock_use(
            authorized.access,
            lease,
            actual_active_seconds=5.1,
            actual_evidence_bytes=401,
            exact_event_count=0,
        )

    charged = authority.charge_runtime_lock_use(
        authorized.access,
        lease,
        actual_active_seconds=2.1,
        actual_evidence_bytes=200,
        exact_event_count=0,
        result_status="partial",
    )
    assert charged.runtime_lock_status == "partial"
    assert charged.runtime_lock_runs_used == 1
    assert charged.runtime_lock_active_seconds_used == 3
    assert charged.runtime_lock_evidence_bytes_used == 200
    assert charged.runtime_lock_exact_events_used == 0
    assert charged.runtime_lock_runs_used <= charged.workload_runs_used
    assert charged.runtime_lock_active_seconds_used <= charged.workload_active_seconds_used
    assert charged.runtime_lock_evidence_bytes_used <= charged.evidence_bytes_used

    with pytest.raises(PerfLensError, match="replayed"):
        authority.charge_runtime_lock_use(
            authorized.access,
            lease,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
            exact_event_count=0,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("build_id", "docker-build-" + "f" * 20),
        ("mode", "record"),
        ("reserved_active_seconds", 4),
        ("reserved_evidence_bytes", 499),
        ("expires_at", (NOW + timedelta(seconds=2)).isoformat()),
    ),
)
def test_runtime_lock_charge_binds_the_entire_completed_workload_lease(
    field: str,
    replacement: object,
) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority, _preview(runtime_lock_scope=_runtime_lock_scope()))
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(
        authority,
        authorized,
        session.baseline_build_id,
        seconds=5,
        evidence=500,
    )
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=4,
        actual_evidence_bytes=400,
    )

    with pytest.raises(PerfLensError, match="completed workload"):
        authority.charge_runtime_lock_use(
            authorized.access,
            replace(lease, **{field: replacement}),
            actual_active_seconds=1,
            actual_evidence_bytes=1,
            exact_event_count=0,
        )


def test_charged_but_unpublished_runtime_lock_can_only_be_poisoned_once() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority, _preview(runtime_lock_scope=_runtime_lock_scope()))
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(authority, authorized, session.baseline_build_id)
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    authority.charge_runtime_lock_use(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
        exact_event_count=0,
    )

    poisoned = authority.fail_completed_runtime_lock_use(authorized.access, lease)
    assert poisoned.runtime_lock_status == "unavailable"
    with pytest.raises(PerfLensError, match="replayed"):
        authority.fail_completed_runtime_lock_use(authorized.access, lease)
    with pytest.raises(PerfLensError, match="no longer available"):
        authority.charge_runtime_lock_use(
            authorized.access,
            lease,
            actual_active_seconds=0,
            actual_evidence_bytes=0,
            exact_event_count=0,
        )


def test_published_runtime_lock_cannot_be_poisoned() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority, _preview(runtime_lock_scope=_runtime_lock_scope()))
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(authority, authorized, session.baseline_build_id)
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    authority.charge_runtime_lock_use(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
        exact_event_count=0,
    )
    authority.mark_runtime_lock_published(authorized.access, lease)

    with pytest.raises(PerfLensError, match="Published"):
        authority.fail_completed_runtime_lock_use(authorized.access, lease)


def test_runtime_lock_terminal_status_changes_session_id_with_frozen_clock() -> None:
    authority, _ = _authority()
    authorized = _authorize(
        authority,
        _preview(runtime_lock_scope=_runtime_lock_scope()),
    )
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(
        authority,
        authorized,
        session.baseline_build_id,
        seconds=5,
        evidence=500,
    )
    completed = authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=100,
    )
    failed = authority.fail_completed_runtime_lock_use(authorized.access, lease)
    assert failed.updated_at == completed.updated_at == NOW.isoformat()
    assert failed.runtime_lock_status == "unavailable"
    assert failed.session_artifact_id != completed.session_artifact_id

    with pytest.raises(PerfLensError, match="replayed"):
        authority.fail_completed_runtime_lock_use(authorized.access, lease)


def test_authority_rejects_unselected_or_unauthorized_exact_runtime_lock() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    with pytest.raises(PerfLensError, match="did not authorize Runtime Lock"):
        authority.charge_runtime_lock_use(
            authorized.access,
            DockerOptimizationWorkloadLease(
                lease_id="docker-optimization-lease-" + "0" * 20,
                session_id=authorized.artifact.session_id,
                build_id="docker-build-" + "0" * 20,
                mode="stat",
                reserved_active_seconds=1,
                reserved_evidence_bytes=1,
                expires_at=(NOW + timedelta(seconds=1)).isoformat(),
                token=authorized.access.token[::-1],
            ),
            actual_active_seconds=0,
            actual_evidence_bytes=0,
            exact_event_count=0,
        )

    preview = _preview(runtime_lock_scope=_runtime_lock_scope())
    authorized = _authorize(authority, preview)
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(authority, authorized, session.baseline_build_id)
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    with pytest.raises(PerfLensError, match="outside the authorized semantics"):
        authority.charge_runtime_lock_use(
            authorized.access,
            lease,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
            exact_event_count=1,
        )


def test_runtime_lock_budget_exhaustion_cannot_be_reactivated() -> None:
    authority, _ = _authority()
    preview = _preview(runtime_lock_scope=_runtime_lock_scope(max_workload_runs=1))
    authorized = _authorize(authority, preview)
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None

    first = _begin_test_workload(authority, authorized, session.baseline_build_id)
    authority.finish_workload(
        authorized.access,
        first,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    authority.charge_runtime_lock_use(
        authorized.access,
        first,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
        exact_event_count=0,
    )
    second = _begin_test_workload(authority, authorized, session.baseline_build_id)
    authority.finish_workload(
        authorized.access,
        second,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    with pytest.raises(PerfLensError, match="budget is exhausted"):
        authority.charge_runtime_lock_use(
            authorized.access,
            second,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
            exact_event_count=0,
        )
    assert authority.snapshot(authorized.access).runtime_lock_status == "exhausted"
    with pytest.raises(PerfLensError, match="budget is exhausted"):
        authority.charge_runtime_lock_use(
            authorized.access,
            second,
            actual_active_seconds=0,
            actual_evidence_bytes=0,
            exact_event_count=0,
        )


def test_build_sequence_reservations_success_and_replay_rejection() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    lease, baseline = _finish_baseline(authority, authorized)
    assert baseline.builds_used == 1
    assert baseline.build_seconds_used == 13
    assert baseline.baseline_build_id == _build_artifact().build_id

    with pytest.raises(PerfLensError):
        authority.finish_build(
            authorized.access,
            lease,
            _build_artifact(),
            actual_build_seconds=1,
        )
    with pytest.raises(PerfLensError):
        _begin_build(authority, authorized.access, kind="candidate", round_number=2)

    candidate_lease = _begin_build(
        authority,
        authorized.access,
        kind="candidate",
        round_number=1,
        context_sha256="1" * 64,
    )
    candidate = _build_artifact(
        kind="candidate",
        round_number=1,
        context_sha256="1" * 64,
    )
    completed = authority.finish_build(
        authorized.access,
        candidate_lease,
        candidate,
        actual_build_seconds=20,
    )
    assert completed.candidate_rounds_used == 1
    assert completed.latest_candidate_build_id == candidate.build_id


def test_recoverable_build_can_retry_once_and_consumes_build_budget() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    first = _begin_build(authority, authorized.access)
    failed = authority.fail_build(
        authorized.access,
        first,
        actual_build_seconds=2,
        recoverable=True,
        reason="compiler exited",
    )
    assert failed.state == "active"
    assert failed.builds_used == 1
    second = _begin_build(authority, authorized.access)
    completed = authority.finish_build(
        authorized.access,
        second,
        _build_artifact(),
        actual_build_seconds=2,
    )
    assert completed.builds_used == 2
    assert completed.recoverable_retries_used == 1
    with pytest.raises(PerfLensError):
        _begin_build(authority, authorized.access)


@pytest.mark.parametrize(
    "changed",
    ("project", "client", "policy", "preview", "recipe"),
)
def test_any_context_change_revokes_session(changed: str) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    values = {
        "project_identity_sha256": PROJECT,
        "client_connection_identity_sha256": CLIENT,
        "project_policy_sha256": POLICY,
        "preview_content_sha256": _preview().content_sha256,
        "recipe_content_sha256": RECIPE,
    }
    key = {
        "project": "project_identity_sha256",
        "client": "client_connection_identity_sha256",
        "policy": "project_policy_sha256",
        "preview": "preview_content_sha256",
        "recipe": "recipe_content_sha256",
    }[changed]
    values[key] = "0" * 64
    with pytest.raises(PerfLensError):
        authority.begin_build(
            authorized.access,
            **values,
            context_content_sha256=CONTEXT,
            build_kind="baseline",
            candidate_round=0,
        )
    assert authority.snapshot(authorized.access).state == "revoked"


def test_workload_mode_budget_reconciliation_and_mutated_lease_rejection() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    _, baseline = _finish_baseline(authority, authorized)
    assert baseline.baseline_build_id is not None
    lease = authority.begin_workload(
        authorized.access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        project_policy_sha256=POLICY,
        preview_content_sha256=_preview().content_sha256,
        recipe_content_sha256=RECIPE,
        build_id=baseline.baseline_build_id,
        mode="record",
        reserve_active_seconds=30,
        reserve_evidence_bytes=1000,
    )
    mutated = replace(lease, reserved_active_seconds=300)
    with pytest.raises(PerfLensError):
        authority.finish_workload(
            authorized.access,
            mutated,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
        )
    completed = authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=4.1,
        actual_evidence_bytes=400,
    )
    assert completed.workload_runs_used == 1
    assert completed.workload_active_seconds_used == 5
    assert completed.evidence_bytes_used == 400
    with pytest.raises(PerfLensError):
        authority.finish_workload(
            authorized.access,
            lease,
            actual_active_seconds=1,
            actual_evidence_bytes=1,
        )


def test_expiry_revoke_capacity_and_forged_access_fail_closed() -> None:
    authority, clock = _authority(max_sessions=1)
    authorized = _authorize(authority)
    forged = DockerOptimizationSessionAccess(
        session_id=authorized.access.session_id,
        token=authorized.access.token[::-1],
    )
    with pytest.raises(PerfLensError):
        authority.snapshot(forged)
    with pytest.raises(PerfLensError) as captured:
        _authorize(authority)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    revoked = authority.revoke(authorized.access)
    assert revoked.state == "revoked"
    replacement = _authorize(authority)
    clock.advance(7200)
    assert authority.snapshot(replacement.access).state == "expired"


@pytest.mark.parametrize("capacity", (0, 33))
def test_authority_rejects_capacity_outside_fixed_bound(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity is outside"):
        DockerOptimizationSessionAuthority(max_sessions=capacity)


def test_authorization_rejects_expired_preview_and_tampered_content() -> None:
    authority, clock = _authority()
    clock.advance(601)
    with pytest.raises(PerfLensError, match="Preview expired"):
        _authorize(authority)

    authority, _ = _authority()
    tampered = _preview().model_copy(update={"warnings": ("forged",)})
    with pytest.raises(PerfLensError, match="content digest"):
        _authorize(authority, tampered)


def test_build_rejects_parallel_operation_kind_mismatch_and_invalid_context() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    _begin_build(authority, authorized.access)
    with pytest.raises(PerfLensError, match="active operation"):
        _begin_build(authority, authorized.access)

    authority, _ = _authority()
    authorized = _authorize(authority)
    with pytest.raises(PerfLensError, match="kind and round differ"):
        _begin_build(authority, authorized.access, kind="candidate", round_number=0)
    with pytest.raises(PerfLensError, match="SHA-256"):
        _begin_build(authority, authorized.access, context_sha256="bad")


def test_build_budget_and_total_time_budget_fail_closed() -> None:
    authority, _ = _authority()
    authorized = _authorize(
        authority,
        _preview(budget=_budget(max_builds=2, max_candidate_rounds=1)),
    )
    first = _begin_build(
        authority,
        authorized.access,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
    )
    authority.fail_build(
        authorized.access,
        first,
        actual_build_seconds=1,
        recoverable=True,
        reason="retryable",
    )
    retry = _begin_build(
        authority,
        authorized.access,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
    )
    baseline = authority.finish_build(
        authorized.access,
        retry,
        _build_artifact(),
        actual_build_seconds=1,
    )
    with pytest.raises(PerfLensError, match="build budget is exhausted"):
        _begin_build(
            authority,
            authorized.access,
            kind="candidate",
            round_number=1,
            context_sha256="1" * 64,
            preview_content_sha256=authorized.artifact.preview_content_sha256,
        )
    assert authority.snapshot(authorized.access).state == "exhausted"
    assert baseline.baseline_build_id is not None

    authority, _ = _authority()
    authorized = _authorize(
        authority,
        _preview(budget=_budget(max_build_seconds=900, max_total_build_seconds=900)),
    )
    lease = _begin_build(
        authority,
        authorized.access,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
    )
    authority.fail_build(
        authorized.access,
        lease,
        actual_build_seconds=1,
        recoverable=True,
        reason="retryable",
    )
    with pytest.raises(PerfLensError, match="total build-time budget"):
        _begin_build(
            authority,
            authorized.access,
            preview_content_sha256=authorized.artifact.preview_content_sha256,
        )


@pytest.mark.parametrize("failure", ("binding", "duration", "image"))
def test_finish_build_rejects_mismatched_or_over_budget_result(failure: str) -> None:
    budget = _budget(max_temporary_image_bytes=4096)
    authority, _ = _authority()
    authorized = _authorize(authority, _preview(budget=budget))
    lease = _begin_build(
        authority,
        authorized.access,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
    )
    build = _build_artifact(image_bytes=4096)
    seconds = 1.0
    if failure == "binding":
        build = _build_artifact(context_sha256="1" * 64)
    elif failure == "duration":
        seconds = 901.0
    else:
        build = _build_artifact(image_bytes=4097)

    with pytest.raises(PerfLensError):
        authority.finish_build(
            authorized.access,
            lease,
            build,
            actual_build_seconds=seconds,
        )
    assert authority.snapshot(authorized.access).state in {"failed", "exhausted"}


def _begin_test_workload(
    authority: DockerOptimizationSessionAuthority,
    authorized: AuthorizedDockerOptimizationSession,
    build_id: str,
    *,
    mode: OptimizationCollectionMode = "stat",
    seconds: int = 1,
    evidence: int = 1,
) -> DockerOptimizationWorkloadLease:
    return authority.begin_workload(
        authorized.access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        project_policy_sha256=POLICY,
        preview_content_sha256=authorized.artifact.preview_content_sha256,
        recipe_content_sha256=RECIPE,
        build_id=build_id,
        mode=mode,
        reserve_active_seconds=seconds,
        reserve_evidence_bytes=evidence,
    )


@pytest.mark.parametrize(
    ("field", "match"),
    (
        ("build", "did not select"),
        ("mode", "outside session authorization"),
        ("seconds", "time reservation is invalid"),
        ("evidence", "evidence reservation is invalid"),
    ),
)
def test_workload_rejects_unbound_or_invalid_reservations(field: str, match: str) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority, _preview(allowed_modes=("stat",)))
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    build_id = session.baseline_build_id
    mode: OptimizationCollectionMode = "stat"
    seconds = 1
    evidence = 1
    if field == "build":
        build_id = "docker-build-" + "0" * 20
    elif field == "mode":
        mode = "record"
    elif field == "seconds":
        seconds = 0
    else:
        evidence = 0
    with pytest.raises(PerfLensError, match=match):
        _begin_test_workload(
            authority,
            authorized,
            build_id,
            mode=mode,
            seconds=seconds,
            evidence=evidence,
        )


def test_workload_parallel_and_budget_failures_are_terminal() -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    _begin_test_workload(authority, authorized, session.baseline_build_id)
    with pytest.raises(PerfLensError, match="active operation"):
        _begin_test_workload(authority, authorized, session.baseline_build_id)

    authority, _ = _authority()
    authorized = _authorize(
        authority,
        _preview(budget=_budget(max_workload_runs=1, max_workload_active_seconds=2)),
    )
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(authority, authorized, session.baseline_build_id)
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    with pytest.raises(PerfLensError, match="workload budget is exhausted"):
        _begin_test_workload(authority, authorized, session.baseline_build_id)

    authority, _ = _authority()
    authorized = _authorize(
        authority,
        _preview(budget=_budget(max_workload_runs=2, max_workload_active_seconds=2)),
    )
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(
        authority,
        authorized,
        session.baseline_build_id,
        seconds=1,
    )
    authority.finish_workload(
        authorized.access,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=1,
    )
    with pytest.raises(PerfLensError, match="reservation exceeds"):
        _begin_test_workload(
            authority,
            authorized,
            session.baseline_build_id,
            seconds=2,
        )


@pytest.mark.parametrize(
    ("actual_seconds", "actual_evidence"),
    ((2.0, 1), (1.0, 2), (1.0, -1)),
)
def test_finish_workload_rejects_usage_outside_reservation(
    actual_seconds: float,
    actual_evidence: int,
) -> None:
    authority, _ = _authority()
    authorized = _authorize(authority)
    _, session = _finish_baseline(authority, authorized)
    assert session.baseline_build_id is not None
    lease = _begin_test_workload(authority, authorized, session.baseline_build_id)
    with pytest.raises(PerfLensError):
        authority.finish_workload(
            authorized.access,
            lease,
            actual_active_seconds=actual_seconds,
            actual_evidence_bytes=actual_evidence,
        )


def test_session_and_operation_lease_expiry_are_rejected() -> None:
    authority, clock = _authority()
    authorized = _authorize(authority)
    clock.advance(7200)
    with pytest.raises(PerfLensError, match="no longer active"):
        _begin_build(authority, authorized.access)

    authority, clock = _authority()
    authorized = _authorize(authority)
    lease = _begin_build(authority, authorized.access)
    clock.advance(1021)
    with pytest.raises(PerfLensError, match="operation lease expired"):
        authority.finish_build(
            authorized.access,
            lease,
            _build_artifact(),
            actual_build_seconds=1,
        )


def test_authority_rejects_naive_clock_and_invalid_durations() -> None:
    authority = DockerOptimizationSessionAuthority(
        wall_clock=lambda: datetime(2026, 8, 24),
    )
    with pytest.raises(ValueError, match="timezone"):
        _authorize(authority)

    authority, _ = _authority()
    authorized = _authorize(authority)
    lease = _begin_build(authority, authorized.access)
    with pytest.raises(PerfLensError, match="actual duration is invalid"):
        authority.finish_build(
            authorized.access,
            lease,
            _build_artifact(),
            actual_build_seconds=float("nan"),
        )
