"""Process-local authorization, budgets, and leases for Docker optimization sessions."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerOptimizationPreviewArtifact,
    DockerOptimizationSessionArtifact,
    DockerRuntimeLockStatus,
    OptimizationCollectionMode,
    derive_docker_optimization_session_artifact_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError

EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION = (
    "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
)
EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE = (
    "I_EXPLICITLY_ACCEPT_THIS_UNVERIFIED_DOCKER_CANDIDATE"
)
_MAX_SESSIONS = 32
_LEASE_GRACE_SECONDS = 120


@dataclass(frozen=True, slots=True)
class DockerOptimizationSessionAccess:
    session_id: str
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizedDockerOptimizationSession:
    artifact: DockerOptimizationSessionArtifact
    access: DockerOptimizationSessionAccess = field(repr=False)


@dataclass(frozen=True, slots=True)
class DockerOptimizationBuildLease:
    lease_id: str
    session_id: str
    build_kind: Literal["baseline", "candidate"]
    candidate_round: int
    context_content_sha256: str
    expires_at: str
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class DockerOptimizationWorkloadLease:
    lease_id: str
    session_id: str
    build_id: str
    mode: OptimizationCollectionMode
    reserved_active_seconds: int
    reserved_evidence_bytes: int
    expires_at: str
    token: str = field(repr=False)


@dataclass(slots=True)
class _ActiveLease:
    lease_id: str
    token_sha256: str
    kind: Literal["build", "workload"]
    operation_key: str
    wall_expires_at: datetime
    monotonic_expires_at: float
    reserved_seconds: int
    reserved_evidence_bytes: int = 0


@dataclass(slots=True)
class _CompletedWorkload:
    token_sha256: str
    lease_identity_sha256: str
    actual_active_seconds: int
    actual_evidence_bytes: int
    runtime_lock_charged: bool = False
    runtime_lock_published: bool = False
    runtime_lock_poisoned: bool = False


@dataclass(slots=True)
class _OptimizationSessionState:
    artifact: DockerOptimizationSessionArtifact
    token_sha256: str
    monotonic_expires_at: float
    active_lease: _ActiveLease | None = None
    operation_attempts: dict[str, int] = field(default_factory=dict[str, int])
    completed_workloads: dict[str, _CompletedWorkload] = field(
        default_factory=dict[str, _CompletedWorkload]
    )


class DockerOptimizationSessionAuthority:
    """Keep authorization tokens and single-use leases in one MCP process only."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        max_sessions: int = _MAX_SESSIONS,
    ) -> None:
        if not 1 <= max_sessions <= _MAX_SESSIONS:
            raise ValueError("Docker optimization session capacity is outside its fixed bound")
        self._wall_clock = wall_clock or (lambda: datetime.now(tz=UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_sessions = max_sessions
        self._sessions: dict[str, _OptimizationSessionState] = {}
        self._lock = threading.RLock()

    def authorize(
        self,
        preview: DockerOptimizationPreviewArtifact,
        *,
        preview_content_sha256: str,
        authorization_summary_sha256: str,
        explicit_authorization: str,
    ) -> AuthorizedDockerOptimizationSession:
        _verify_content(preview)
        if explicit_authorization != EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION:
            raise _authorization_error("Docker optimization requires explicit bounded consent")
        if not hmac.compare_digest(
            preview.content_sha256,
            preview_content_sha256,
        ) or not hmac.compare_digest(
            preview.authorization_summary_sha256,
            authorization_summary_sha256,
        ):
            raise _authorization_error("Docker optimization authorization summary changed")
        with self._lock:
            self._prune()
            if len(self._sessions) >= self._max_sessions:
                raise _resource_error("Docker optimization in-memory session capacity is exhausted")
            now = self._wall_now()
            if now >= datetime.fromisoformat(preview.expires_at):
                raise _authorization_error("Docker optimization Preview expired")
            nonce = secrets.token_bytes(32)
            token = secrets.token_urlsafe(32)
            receipt = hashlib.sha256(
                b"\0".join(
                    (
                        b"perflens-docker-optimization-authorization-v1",
                        nonce,
                        preview.preview_id.encode("ascii"),
                        preview.content_sha256.encode("ascii"),
                        preview.authorization_summary_sha256.encode("ascii"),
                        preview.client_connection_identity_sha256.encode("ascii"),
                    )
                )
            ).hexdigest()
            session_id = (
                "docker-optimization-session-"
                + hashlib.sha256(nonce + receipt.encode("ascii")).hexdigest()[:20]
            )
            expires_at = now + timedelta(seconds=preview.budget.hard_expiry_seconds)
            artifact = _new_session_artifact(
                session_id=session_id,
                created_at=now,
                expires_at=expires_at,
                preview=preview,
                authorization_receipt_sha256=receipt,
            )
            access = DockerOptimizationSessionAccess(session_id=session_id, token=token)
            self._sessions[session_id] = _OptimizationSessionState(
                artifact=artifact,
                token_sha256=_secret_sha256(token),
                monotonic_expires_at=(self._monotonic_clock() + preview.budget.hard_expiry_seconds),
            )
            return AuthorizedDockerOptimizationSession(artifact=artifact, access=access)

    def begin_build(
        self,
        access: DockerOptimizationSessionAccess,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        project_policy_sha256: str,
        preview_content_sha256: str,
        recipe_content_sha256: str,
        context_content_sha256: str,
        build_kind: Literal["baseline", "candidate"],
        candidate_round: int,
    ) -> DockerOptimizationBuildLease:
        _validate_sha256(context_content_sha256, "Docker build Context")
        operation_key = f"build:{build_kind}:{candidate_round}"
        with self._lock:
            state = self._require(access)
            self._assert_context(
                state,
                project_identity_sha256=project_identity_sha256,
                client_connection_identity_sha256=client_connection_identity_sha256,
                project_policy_sha256=project_policy_sha256,
                preview_content_sha256=preview_content_sha256,
                recipe_content_sha256=recipe_content_sha256,
            )
            if state.active_lease is not None:
                raise _resource_error("Docker optimization already has an active operation")
            artifact = state.artifact
            if (build_kind == "baseline") != (candidate_round == 0):
                raise _authorization_error("Docker optimization build kind and round differ")
            if build_kind == "baseline":
                if artifact.baseline_build_id is not None:
                    raise _authorization_error("Docker optimization baseline is already built")
            elif (
                artifact.baseline_build_id is None
                or candidate_round != artifact.candidate_rounds_used + 1
                or candidate_round > artifact.budget.max_candidate_rounds
            ):
                raise _authorization_error("Docker candidate round is out of sequence")
            attempts = state.operation_attempts.get(operation_key, 0)
            if attempts > artifact.budget.max_recoverable_retries:
                raise _resource_error("Docker optimization retry budget is exhausted")
            if artifact.builds_used >= artifact.budget.max_builds:
                self._end(state, "exhausted", "Docker optimization build budget was exhausted.")
                raise _resource_error("Docker optimization build budget is exhausted")
            reservation = artifact.budget.max_build_seconds
            if artifact.build_seconds_used + reservation > artifact.budget.max_total_build_seconds:
                self._end(
                    state,
                    "exhausted",
                    "Docker optimization total build-time budget was exhausted.",
                )
                raise _resource_error("Docker optimization total build-time budget is exhausted")
            state.operation_attempts[operation_key] = attempts + 1
            retries = artifact.recoverable_retries_used + (1 if attempts else 0)
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                builds_used=artifact.builds_used + 1,
                recoverable_retries_used=retries,
                build_seconds_used=artifact.build_seconds_used + reservation,
            )
            active, lease_token = self._new_lease(
                state,
                kind="build",
                operation_key=operation_key,
                reserve_seconds=reservation,
            )
            return DockerOptimizationBuildLease(
                lease_id=active.lease_id,
                session_id=artifact.session_id,
                build_kind=build_kind,
                candidate_round=candidate_round,
                context_content_sha256=context_content_sha256,
                expires_at=active.wall_expires_at.isoformat(),
                token=lease_token,
            )

    def finish_build(
        self,
        access: DockerOptimizationSessionAccess,
        lease: DockerOptimizationBuildLease,
        build: DockerBuildArtifact,
        *,
        actual_build_seconds: float,
    ) -> DockerOptimizationSessionArtifact:
        _verify_content(build)
        actual_seconds = _bounded_actual_seconds(actual_build_seconds)
        with self._lock:
            state = self._require(access)
            active = self._require_lease(state, lease.lease_id, lease.token, kind="build")
            if (
                lease.session_id != state.artifact.session_id
                or active.operation_key != f"build:{lease.build_kind}:{lease.candidate_round}"
                or build.build_kind != lease.build_kind
                or build.candidate_round != lease.candidate_round
                or build.context_content_sha256 != lease.context_content_sha256
                or build.recipe_id != state.artifact.recipe_id
                or build.recipe_content_sha256 != state.artifact.recipe_content_sha256
            ):
                self._end(state, "failed", "Docker Build Artifact differed from its lease.")
                state.active_lease = None
                raise _authorization_error("Docker Build Artifact differs from its lease")
            if actual_seconds > active.reserved_seconds:
                self._end(state, "exhausted", "Docker build exceeded its time reservation.")
                state.active_lease = None
                raise _resource_error("Docker build exceeded its time reservation")
            artifact = state.artifact
            image_total = artifact.temporary_image_bytes_used + build.image_size_bytes
            if image_total > artifact.budget.max_temporary_image_bytes:
                self._end(state, "exhausted", "Docker temporary image budget was exhausted.")
                state.active_lease = None
                raise _resource_error("Docker temporary image budget is exhausted")
            updates: dict[str, object] = {
                "build_seconds_used": (
                    artifact.build_seconds_used - active.reserved_seconds + actual_seconds
                ),
                "temporary_image_bytes_used": image_total,
            }
            if lease.build_kind == "baseline":
                updates["baseline_build_id"] = build.build_id
            else:
                updates["candidate_rounds_used"] = lease.candidate_round
                updates["latest_candidate_build_id"] = build.build_id
            state.active_lease = None
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                **updates,
            )
            return state.artifact

    def fail_build(
        self,
        access: DockerOptimizationSessionAccess,
        lease: DockerOptimizationBuildLease,
        *,
        actual_build_seconds: float,
        recoverable: bool,
        reason: str,
    ) -> DockerOptimizationSessionArtifact:
        actual_seconds = _bounded_actual_seconds(actual_build_seconds)
        with self._lock:
            state = self._require(access)
            active = self._require_lease(state, lease.lease_id, lease.token, kind="build")
            if (
                lease.session_id != state.artifact.session_id
                or active.operation_key != f"build:{lease.build_kind}:{lease.candidate_round}"
            ):
                raise _authorization_error("Docker optimization Build lease fields changed")
            artifact = state.artifact
            state.active_lease = None
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                build_seconds_used=(
                    artifact.build_seconds_used
                    - active.reserved_seconds
                    + min(actual_seconds, active.reserved_seconds)
                ),
            )
            attempts = state.operation_attempts[active.operation_key]
            if not recoverable or attempts > artifact.budget.max_recoverable_retries:
                self._end(state, "failed", reason)
            return state.artifact

    def begin_workload(
        self,
        access: DockerOptimizationSessionAccess,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        project_policy_sha256: str,
        preview_content_sha256: str,
        recipe_content_sha256: str,
        build_id: str,
        mode: OptimizationCollectionMode,
        reserve_active_seconds: int,
        reserve_evidence_bytes: int,
    ) -> DockerOptimizationWorkloadLease:
        with self._lock:
            state = self._require(access)
            self._assert_context(
                state,
                project_identity_sha256=project_identity_sha256,
                client_connection_identity_sha256=client_connection_identity_sha256,
                project_policy_sha256=project_policy_sha256,
                preview_content_sha256=preview_content_sha256,
                recipe_content_sha256=recipe_content_sha256,
            )
            artifact = state.artifact
            if state.active_lease is not None:
                raise _resource_error("Docker optimization already has an active operation")
            if build_id not in {
                artifact.baseline_build_id,
                artifact.latest_candidate_build_id,
            }:
                raise _authorization_error("Docker workload did not select a session Build")
            if mode not in artifact.allowed_modes:
                raise _authorization_error("Docker workload mode is outside session authorization")
            if not 1 <= reserve_active_seconds <= artifact.budget.max_workload_active_seconds:
                raise _resource_error("Docker workload time reservation is invalid")
            if not 1 <= reserve_evidence_bytes <= artifact.budget.max_evidence_bytes:
                raise _resource_error("Docker workload evidence reservation is invalid")
            if artifact.workload_runs_used >= artifact.budget.max_workload_runs:
                self._end(state, "exhausted", "Docker optimization workload budget was exhausted.")
                raise _resource_error("Docker optimization workload budget is exhausted")
            if (
                artifact.workload_active_seconds_used + reserve_active_seconds
                > artifact.budget.max_workload_active_seconds
                or artifact.evidence_bytes_used + reserve_evidence_bytes
                > artifact.budget.max_evidence_bytes
            ):
                self._end(state, "exhausted", "Docker optimization evidence budget was exhausted.")
                raise _resource_error("Docker optimization workload reservation exceeds its budget")
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                workload_runs_used=artifact.workload_runs_used + 1,
                workload_active_seconds_used=(
                    artifact.workload_active_seconds_used + reserve_active_seconds
                ),
                evidence_bytes_used=artifact.evidence_bytes_used + reserve_evidence_bytes,
            )
            active, lease_token = self._new_lease(
                state,
                kind="workload",
                operation_key=f"workload:{artifact.workload_runs_used + 1}:{build_id}:{mode}",
                reserve_seconds=reserve_active_seconds,
                reserve_evidence_bytes=reserve_evidence_bytes,
            )
            return DockerOptimizationWorkloadLease(
                lease_id=active.lease_id,
                session_id=artifact.session_id,
                build_id=build_id,
                mode=mode,
                reserved_active_seconds=reserve_active_seconds,
                reserved_evidence_bytes=reserve_evidence_bytes,
                expires_at=active.wall_expires_at.isoformat(),
                token=lease_token,
            )

    def finish_workload(
        self,
        access: DockerOptimizationSessionAccess,
        lease: DockerOptimizationWorkloadLease,
        *,
        actual_active_seconds: float,
        actual_evidence_bytes: int,
    ) -> DockerOptimizationSessionArtifact:
        actual_seconds = _bounded_actual_seconds(actual_active_seconds)
        if actual_evidence_bytes < 0:
            raise _resource_error("Docker workload evidence use cannot be negative")
        with self._lock:
            state = self._require(access)
            active = self._require_lease(state, lease.lease_id, lease.token, kind="workload")
            if (
                lease.session_id != state.artifact.session_id
                or active.operation_key
                != (f"workload:{state.artifact.workload_runs_used}:{lease.build_id}:{lease.mode}")
                or active.reserved_seconds != lease.reserved_active_seconds
                or active.reserved_evidence_bytes != lease.reserved_evidence_bytes
            ):
                raise _authorization_error("Docker optimization Workload lease fields changed")
            if (
                actual_seconds > lease.reserved_active_seconds
                or actual_evidence_bytes > lease.reserved_evidence_bytes
            ):
                self._end(state, "exhausted", "Docker workload exceeded its reservation.")
                state.active_lease = None
                raise _resource_error("Docker workload exceeded its reservation")
            artifact = state.artifact
            state.active_lease = None
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                workload_active_seconds_used=(
                    artifact.workload_active_seconds_used - active.reserved_seconds + actual_seconds
                ),
                evidence_bytes_used=(
                    artifact.evidence_bytes_used
                    - active.reserved_evidence_bytes
                    + actual_evidence_bytes
                ),
            )
            state.completed_workloads[lease.lease_id] = _CompletedWorkload(
                token_sha256=_secret_sha256(lease.token),
                lease_identity_sha256=_workload_lease_identity_sha256(lease),
                actual_active_seconds=actual_seconds,
                actual_evidence_bytes=actual_evidence_bytes,
            )
            return state.artifact

    def charge_runtime_lock_use(
        self,
        access: DockerOptimizationSessionAccess,
        lease: DockerOptimizationWorkloadLease,
        *,
        actual_active_seconds: float,
        actual_evidence_bytes: int,
        exact_event_count: int,
        result_status: Literal["active", "partial", "unavailable"] = "active",
    ) -> DockerOptimizationSessionArtifact:
        """Account one Runtime Lock result inside an already charged workload.

        The consumed workload lease is retained only as a bounded in-memory replay guard.
        Runtime Lock time and bytes must be subsets of that exact workload and of the
        enclosing optimization Session counters.
        """
        actual_seconds = _bounded_actual_seconds(actual_active_seconds)
        if actual_evidence_bytes < 0 or exact_event_count < 0:
            raise _resource_error("Docker Runtime Lock use cannot be negative")
        with self._lock:
            state = self._require(access)
            artifact = state.artifact
            scope = artifact.runtime_lock_scope
            if scope is None:
                raise _authorization_error(
                    "Docker optimization Session did not authorize Runtime Lock"
                )
            if artifact.runtime_lock_status == "exhausted":
                raise _resource_error("Docker Runtime Lock budget is exhausted")
            if artifact.runtime_lock_status == "unavailable":
                raise _resource_error("Docker Runtime Lock collection is no longer available")
            completed = state.completed_workloads.get(lease.lease_id)
            if (
                completed is None
                or lease.session_id != artifact.session_id
                or not hmac.compare_digest(
                    completed.token_sha256,
                    _secret_sha256(lease.token),
                )
                or not hmac.compare_digest(
                    completed.lease_identity_sha256,
                    _workload_lease_identity_sha256(lease),
                )
            ):
                raise _authorization_error(
                    "Docker Runtime Lock evidence is not bound to a completed workload"
                )
            if completed.runtime_lock_charged:
                raise _authorization_error("Docker Runtime Lock workload charge was replayed")
            if (
                actual_seconds > completed.actual_active_seconds
                or actual_evidence_bytes > completed.actual_evidence_bytes
            ):
                raise _authorization_error("Docker Runtime Lock use exceeds its enclosing workload")
            if exact_event_count and "exact" not in scope.allowed_semantics:
                raise _authorization_error(
                    "Docker Runtime Lock exact events were outside the authorized semantics"
                )
            if exact_event_count > scope.budget.max_exact_events:
                raise _resource_error("Docker Runtime Lock exact-event limit was exceeded")
            runtime_runs = (artifact.runtime_lock_runs_used or 0) + 1
            runtime_active = (artifact.runtime_lock_active_seconds_used or 0) + actual_seconds
            runtime_bytes = (artifact.runtime_lock_evidence_bytes_used or 0) + actual_evidence_bytes
            runtime_exact = (artifact.runtime_lock_exact_events_used or 0) + exact_event_count
            if (
                runtime_runs > scope.budget.max_workload_runs
                or runtime_active > scope.budget.max_active_seconds
                or runtime_bytes > scope.budget.max_evidence_bytes
                or runtime_exact > scope.budget.max_workload_runs * scope.budget.max_exact_events
            ):
                state.artifact = _update_session(
                    artifact,
                    updated_at=self._wall_now(),
                    runtime_lock_status="exhausted",
                )
                raise _resource_error("Docker Runtime Lock budget is exhausted")
            updated = _update_session(
                artifact,
                updated_at=self._wall_now(),
                runtime_lock_status=_merge_runtime_lock_status(
                    artifact.runtime_lock_status,
                    prior_runs=artifact.runtime_lock_runs_used or 0,
                    result_status=result_status,
                ),
                runtime_lock_runs_used=runtime_runs,
                runtime_lock_active_seconds_used=runtime_active,
                runtime_lock_evidence_bytes_used=runtime_bytes,
                runtime_lock_exact_events_used=runtime_exact,
            )
            completed.runtime_lock_charged = True
            state.artifact = updated
            return state.artifact

    def fail_completed_runtime_lock_use(
        self,
        access: DockerOptimizationSessionAccess,
        lease: DockerOptimizationWorkloadLease,
    ) -> DockerOptimizationSessionArtifact:
        """Fail closed after perf completed but Runtime Lock finalization did not.

        The outer workload was already charged, so charging it again would be a replay.
        This transition authenticates the consumed lease, marks its Runtime Lock slot used,
        records an unavailable result, and leaves only explicit finalize/revoke actions usable.
        """

        with self._lock:
            state = self._require(access)
            completed = state.completed_workloads.get(lease.lease_id)
            if (
                completed is None
                or lease.session_id != state.artifact.session_id
                or not hmac.compare_digest(
                    completed.token_sha256,
                    _secret_sha256(lease.token),
                )
                or not hmac.compare_digest(
                    completed.lease_identity_sha256,
                    _workload_lease_identity_sha256(lease),
                )
            ):
                raise _authorization_error(
                    "Docker Runtime Lock failed-finalization transition is invalid"
                )
            if completed.runtime_lock_published:
                raise _authorization_error("Published Docker Runtime Lock work cannot be poisoned")
            if completed.runtime_lock_poisoned:
                raise _authorization_error("Docker Runtime Lock failed-finalization was replayed")
            completed.runtime_lock_charged = True
            completed.runtime_lock_poisoned = True
            state.artifact = _update_session(
                state.artifact,
                updated_at=self._wall_now(),
                runtime_lock_status="unavailable",
            )
            return state.artifact

    def mark_runtime_lock_published(
        self,
        access: DockerOptimizationSessionAccess,
        lease: DockerOptimizationWorkloadLease,
    ) -> DockerOptimizationSessionArtifact:
        """Seal one charged Runtime Lock result after Run and parent persistence."""

        with self._lock:
            state = self._require(access)
            completed = state.completed_workloads.get(lease.lease_id)
            if (
                completed is None
                or lease.session_id != state.artifact.session_id
                or not hmac.compare_digest(
                    completed.token_sha256,
                    _secret_sha256(lease.token),
                )
                or not hmac.compare_digest(
                    completed.lease_identity_sha256,
                    _workload_lease_identity_sha256(lease),
                )
                or not completed.runtime_lock_charged
                or completed.runtime_lock_published
                or completed.runtime_lock_poisoned
            ):
                raise _authorization_error("Docker Runtime Lock publication transition is invalid")
            completed.runtime_lock_published = True
            return state.artifact

    def revoke(
        self,
        access: DockerOptimizationSessionAccess,
    ) -> DockerOptimizationSessionArtifact:
        with self._lock:
            state = self._require(access, allow_inactive=True)
            if state.artifact.state == "active":
                self._end(state, "revoked", "Docker optimization was explicitly revoked.")
            state.active_lease = None
            return state.artifact

    def snapshot(
        self,
        access: DockerOptimizationSessionAccess,
    ) -> DockerOptimizationSessionArtifact:
        with self._lock:
            return self._require(access, allow_inactive=True).artifact

    def _new_lease(
        self,
        state: _OptimizationSessionState,
        *,
        kind: Literal["build", "workload"],
        operation_key: str,
        reserve_seconds: int,
        reserve_evidence_bytes: int = 0,
    ) -> tuple[_ActiveLease, str]:
        token = secrets.token_urlsafe(32)
        nonce = secrets.token_bytes(32)
        now = self._wall_now()
        remaining = max(
            0,
            int((datetime.fromisoformat(state.artifact.expires_at) - now).total_seconds()),
        )
        duration = min(reserve_seconds + _LEASE_GRACE_SECONDS, remaining)
        if duration <= 0:
            self._expire(state)
            raise _authorization_error("Docker optimization expired before its operation")
        lease_id = (
            "docker-optimization-lease-"
            + hashlib.sha256(nonce + operation_key.encode("utf-8")).hexdigest()[:20]
        )
        active = _ActiveLease(
            lease_id=lease_id,
            token_sha256=_secret_sha256(token),
            kind=kind,
            operation_key=operation_key,
            wall_expires_at=now + timedelta(seconds=duration),
            monotonic_expires_at=self._monotonic_clock() + duration,
            reserved_seconds=reserve_seconds,
            reserved_evidence_bytes=reserve_evidence_bytes,
        )
        state.active_lease = active
        return active, token

    def _require(
        self,
        access: DockerOptimizationSessionAccess,
        *,
        allow_inactive: bool = False,
    ) -> _OptimizationSessionState:
        state = self._sessions.get(access.session_id)
        if state is None or not hmac.compare_digest(
            state.token_sha256,
            _secret_sha256(access.token),
        ):
            raise _authorization_error("Docker optimization session access is invalid")
        if state.artifact.state == "active" and self._session_expired(state):
            self._expire(state)
        if not allow_inactive and state.artifact.state != "active":
            raise _authorization_error("Docker optimization session is no longer active")
        if state.active_lease is not None and self._lease_expired(state.active_lease):
            self._end(state, "expired", "Docker optimization operation lease expired.")
            state.active_lease = None
            raise _authorization_error("Docker optimization operation lease expired")
        return state

    def _require_lease(
        self,
        state: _OptimizationSessionState,
        lease_id: str,
        token: str,
        *,
        kind: Literal["build", "workload"],
    ) -> _ActiveLease:
        active = state.active_lease
        if (
            active is None
            or active.kind != kind
            or active.lease_id != lease_id
            or not hmac.compare_digest(active.token_sha256, _secret_sha256(token))
        ):
            raise _authorization_error("Docker optimization lease is invalid or consumed")
        if self._lease_expired(active):
            self._end(state, "expired", "Docker optimization operation lease expired.")
            state.active_lease = None
            raise _authorization_error("Docker optimization operation lease expired")
        return active

    def _assert_context(
        self,
        state: _OptimizationSessionState,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        project_policy_sha256: str,
        preview_content_sha256: str,
        recipe_content_sha256: str,
    ) -> None:
        artifact = state.artifact
        checks = (
            (project_identity_sha256, artifact.project_identity_sha256),
            (client_connection_identity_sha256, artifact.client_connection_identity_sha256),
            (project_policy_sha256, artifact.project_policy_sha256),
            (preview_content_sha256, artifact.preview_content_sha256),
            (recipe_content_sha256, artifact.recipe_content_sha256),
        )
        if any(not hmac.compare_digest(actual, expected) for actual, expected in checks):
            self._end(state, "revoked", "Docker optimization identity or policy changed.")
            state.active_lease = None
            raise _authorization_error("Docker optimization identity or policy changed")

    def _session_expired(self, state: _OptimizationSessionState) -> bool:
        return (
            self._wall_now() >= datetime.fromisoformat(state.artifact.expires_at)
            or self._monotonic_clock() >= state.monotonic_expires_at
        )

    def _lease_expired(self, lease: _ActiveLease) -> bool:
        return (
            self._wall_now() >= lease.wall_expires_at
            or self._monotonic_clock() >= lease.monotonic_expires_at
        )

    def _expire(self, state: _OptimizationSessionState) -> None:
        self._end(state, "expired", "Docker optimization reached its hard expiry.")
        state.active_lease = None

    def _end(
        self,
        state: _OptimizationSessionState,
        state_name: Literal["revoked", "expired", "exhausted", "failed"],
        reason: str,
    ) -> None:
        state.artifact = _update_session(
            state.artifact,
            updated_at=self._wall_now(),
            state=state_name,
            invalidation_reason=_bounded_reason(reason),
        )

    def _prune(self) -> None:
        for state in self._sessions.values():
            if state.artifact.state == "active" and self._session_expired(state):
                self._expire(state)
        inactive = [
            session_id
            for session_id, state in self._sessions.items()
            if state.artifact.state != "active"
        ]
        while len(self._sessions) >= self._max_sessions and inactive:
            self._sessions.pop(inactive.pop(0), None)

    def _wall_now(self) -> datetime:
        now = self._wall_clock()
        if now.tzinfo is None:
            raise ValueError("Docker optimization wall clock must include a timezone")
        return now


def _new_session_artifact(
    *,
    session_id: str,
    created_at: datetime,
    expires_at: datetime,
    preview: DockerOptimizationPreviewArtifact,
    authorization_receipt_sha256: str,
) -> DockerOptimizationSessionArtifact:
    runtime_lock_scope = preview.runtime_lock_scope
    schema_version = "1.1" if runtime_lock_scope is not None else preview.schema_version
    runtime_fields: dict[str, object] = {}
    if schema_version == "1.1":
        runtime_fields = {
            "runtime_lock_scope": runtime_lock_scope,
            "runtime_lock_status": ("active" if runtime_lock_scope is not None else "not_selected"),
            "runtime_lock_runs_used": 0,
            "runtime_lock_active_seconds_used": 0,
            "runtime_lock_evidence_bytes_used": 0,
            "runtime_lock_exact_events_used": 0,
        }
    if runtime_lock_scope is not None:
        session_artifact_id = derive_docker_optimization_session_artifact_id(
            session_id,
            "active",
            created_at.isoformat(),
            0,
            0,
            0,
            runtime_lock_scope.content_sha256,
            0,
            0,
            0,
            runtime_lock_status="active",
            runtime_lock_active_seconds_used=0,
        )
    else:
        session_artifact_id = derive_docker_optimization_session_artifact_id(
            session_id,
            "active",
            created_at.isoformat(),
            0,
            0,
            0,
        )
    data = {
        "schema_version": schema_version,
        "perflens_version": __version__,
        "session_artifact_id": session_artifact_id,
        "session_id": session_id,
        "created_at": created_at.isoformat(),
        "updated_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "state": "active",
        "project_identity_sha256": preview.project_identity_sha256,
        "client_connection_identity_sha256": preview.client_connection_identity_sha256,
        "project_policy_sha256": preview.project_policy_sha256,
        "preview_id": preview.preview_id,
        "preview_content_sha256": preview.content_sha256,
        "build_capability_content_sha256": preview.build_capability_content_sha256,
        "recipe_id": preview.recipe_id,
        "recipe_content_sha256": preview.recipe_content_sha256,
        "authorization_receipt_sha256": authorization_receipt_sha256,
        "allowed_modes": preview.allowed_modes,
        "budget": preview.budget,
        "builds_used": 0,
        "candidate_rounds_used": 0,
        "workload_runs_used": 0,
        "recoverable_retries_used": 0,
        "build_seconds_used": 0,
        "workload_active_seconds_used": 0,
        "evidence_bytes_used": 0,
        "temporary_image_bytes_used": 0,
        **runtime_fields,
        "baseline_build_id": None,
        "latest_candidate_build_id": None,
        "invalidation_reason": None,
        "content_sha256": "0" * 64,
    }
    return _with_content(DockerOptimizationSessionArtifact.model_validate(data))


def _update_session(
    artifact: DockerOptimizationSessionArtifact,
    *,
    updated_at: datetime,
    **updates: object,
) -> DockerOptimizationSessionArtifact:
    updated_timestamp = updated_at.isoformat()
    data = {
        **artifact.model_dump(mode="json"),
        **updates,
        "updated_at": updated_timestamp,
        "content_sha256": "0" * 64,
    }
    state_name = data["state"]
    builds_used = data["builds_used"]
    workload_runs_used = data["workload_runs_used"]
    evidence_bytes_used = data["evidence_bytes_used"]
    if (
        not isinstance(state_name, str)
        or isinstance(builds_used, bool)
        or not isinstance(builds_used, int)
        or isinstance(workload_runs_used, bool)
        or not isinstance(workload_runs_used, int)
        or isinstance(evidence_bytes_used, bool)
        or not isinstance(evidence_bytes_used, int)
    ):
        raise ValueError("Docker optimization Session update has invalid counters")
    if artifact.runtime_lock_scope is not None:
        runtime_lock_runs_used = data["runtime_lock_runs_used"]
        runtime_lock_status = data["runtime_lock_status"]
        runtime_lock_active_seconds_used = data["runtime_lock_active_seconds_used"]
        runtime_lock_evidence_bytes_used = data["runtime_lock_evidence_bytes_used"]
        runtime_lock_exact_events_used = data["runtime_lock_exact_events_used"]
        if (
            not isinstance(runtime_lock_status, str)
            or runtime_lock_status
            not in {"not_selected", "active", "partial", "unavailable", "exhausted"}
            or isinstance(runtime_lock_active_seconds_used, bool)
            or not isinstance(runtime_lock_active_seconds_used, int)
            or isinstance(runtime_lock_runs_used, bool)
            or not isinstance(runtime_lock_runs_used, int)
            or isinstance(runtime_lock_evidence_bytes_used, bool)
            or not isinstance(runtime_lock_evidence_bytes_used, int)
            or isinstance(runtime_lock_exact_events_used, bool)
            or not isinstance(runtime_lock_exact_events_used, int)
        ):
            raise ValueError("Docker Runtime Lock Session update has invalid counters")
        checked_runtime_lock_status = cast(DockerRuntimeLockStatus, runtime_lock_status)
        data["session_artifact_id"] = derive_docker_optimization_session_artifact_id(
            artifact.session_id,
            state_name,
            updated_timestamp,
            builds_used,
            workload_runs_used,
            evidence_bytes_used,
            artifact.runtime_lock_scope.content_sha256,
            runtime_lock_runs_used,
            runtime_lock_evidence_bytes_used,
            runtime_lock_exact_events_used,
            runtime_lock_status=checked_runtime_lock_status,
            runtime_lock_active_seconds_used=runtime_lock_active_seconds_used,
        )
    else:
        data["session_artifact_id"] = derive_docker_optimization_session_artifact_id(
            artifact.session_id,
            state_name,
            updated_timestamp,
            builds_used,
            workload_runs_used,
            evidence_bytes_used,
        )
    return _with_content(DockerOptimizationSessionArtifact.model_validate(data))


def _with_content(
    artifact: DockerOptimizationSessionArtifact,
) -> DockerOptimizationSessionArtifact:
    return DockerOptimizationSessionArtifact.model_validate(
        {
            **artifact.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                artifact,
                exclude={"content_sha256"},
            ),
        }
    )


def _verify_content(artifact: DockerOptimizationPreviewArtifact | DockerBuildArtifact) -> None:
    if artifact.content_sha256 != contract_content_sha256(
        artifact,
        exclude={"content_sha256"},
    ):
        raise _authorization_error("Docker optimization Artifact content digest does not match")


def _merge_runtime_lock_status(
    current: str | None,
    *,
    prior_runs: int,
    result_status: Literal["active", "partial", "unavailable"],
) -> Literal["active", "partial", "unavailable"]:
    """Conservatively combine per-run quality into the Session-level projection."""
    if current == "partial" or result_status == "partial":
        return "partial"
    if current == "unavailable":
        return "unavailable" if result_status == "unavailable" else "partial"
    if result_status == "unavailable":
        return "unavailable" if prior_runs == 0 else "partial"
    return "active"


def _bounded_actual_seconds(value: float) -> int:
    if not math.isfinite(value) or value < 0:
        raise _resource_error("Docker optimization actual duration is invalid")
    return math.ceil(value)


def _secret_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _workload_lease_identity_sha256(lease: DockerOptimizationWorkloadLease) -> str:
    return hashlib.sha256(
        (
            "perflens-docker-workload-lease-v1\0"
            f"{lease.lease_id}\0{lease.session_id}\0{lease.build_id}\0{lease.mode}\0"
            f"{lease.reserved_active_seconds}\0{lease.reserved_evidence_bytes}\0"
            f"{lease.expires_at}\0{_secret_sha256(lease.token)}"
        ).encode()
    ).hexdigest()


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise _authorization_error(f"{label} must be a SHA-256 digest")


def _bounded_reason(value: str) -> str:
    return value.strip()[:512] or "Docker optimization ended."


def _authorization_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_optimization_authorization",
        message,
        recoverable=True,
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "docker_optimization_authorization",
        message,
        recoverable=True,
    )
