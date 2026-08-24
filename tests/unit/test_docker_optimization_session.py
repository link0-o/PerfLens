from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerOptimizationBudget,
    DockerOptimizationPreviewArtifact,
    DockerOptimizationSessionArtifact,
    derive_docker_build_artifact_id,
    derive_docker_optimization_preview_id,
)
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    AuthorizedDockerOptimizationSession,
    DockerOptimizationBuildLease,
    DockerOptimizationSessionAccess,
    DockerOptimizationSessionAuthority,
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
) -> DockerOptimizationPreviewArtifact:
    created_at = NOW.isoformat()
    data = {
        "schema_version": "1.0",
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
        "allowed_modes": ("stat", "record", "sched", "off_cpu", "lock"),
        "network_tier": "local_only",
        "base_image_present": True,
        "baseline_build_required": True,
        "mutable_dockerfile": False,
        "mutable_dependency_lock": False,
        "budget": budget or _budget(),
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
) -> DockerOptimizationBuildLease:
    return authority.begin_build(
        access,
        project_identity_sha256=PROJECT,
        client_connection_identity_sha256=CLIENT,
        project_policy_sha256=POLICY,
        preview_content_sha256=_preview().content_sha256,
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
    lease = _begin_build(authority, authorized.access)
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
