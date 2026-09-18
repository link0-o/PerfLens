"""Content-bound authorization and single-use leases for Runtime Lock sessions."""

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
from typing import Literal

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.artifacts import ContractModel
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterId,
    RuntimeLockCapabilityArtifact,
    RuntimeLockProcessTargetBinding,
    RuntimeLockRunArtifact,
    RuntimeLockRunFinalizationArtifact,
    RuntimeLockSessionArtifact,
    RuntimeLockSessionBudget,
    RuntimeLockSessionEndReason,
    RuntimeLockSessionPreviewArtifact,
    RuntimeLockTargetScope,
    RuntimeLockWorkloadBinding,
    derive_runtime_lock_preview_id,
    derive_runtime_lock_run_finalization_id,
    derive_runtime_lock_session_artifact_id,
)
from perflens.contracts.runtime_locks import MeasurementSemantics
from perflens.domain.errors import ErrorCode, PerfLensError

EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION = (
    "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
)

_MAX_SESSIONS = 32
_MAX_PENDING_PREVIEWS = 16
_MAX_CONSUMED_PREVIEWS = 256
_PREVIEW_EXPIRY_SECONDS = 600
_LEASE_GRACE_SECONDS = 120


@dataclass(frozen=True, slots=True)
class RuntimeLockSessionAccess:
    """Process-local bearer capability; it is never serialized into an Artifact."""

    session_id: str
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizedRuntimeLockSession:
    artifact: RuntimeLockSessionArtifact
    access: RuntimeLockSessionAccess = field(repr=False)


@dataclass(frozen=True, slots=True)
class RuntimeLockRunLease:
    lease_id: str
    session_id: str
    run_number: int
    adapter_id: RuntimeLockAdapterId
    measurement_semantics: MeasurementSemantics
    operation_identity_sha256: str
    target_identity_sha256: str
    workload_identity_sha256: str
    reserved_active_seconds: int
    reserved_evidence_bytes: int
    reserved_exact_events: int
    session_artifact_id: str
    session_artifact_content_sha256: str
    session_revision: int
    expires_at: str
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RuntimeLockRunSettlement:
    """Artifacts that must be persisted Session-first and marker-last."""

    session: RuntimeLockSessionArtifact
    finalization: RuntimeLockRunFinalizationArtifact


@dataclass(slots=True)
class _ActiveLease:
    lease_id: str
    token_sha256: str
    run_number: int
    adapter_id: RuntimeLockAdapterId
    measurement_semantics: MeasurementSemantics
    operation_identity_sha256: str
    target_identity_sha256: str
    workload_identity_sha256: str
    reserved_active_seconds: int
    reserved_evidence_bytes: int
    reserved_exact_events: int
    wall_started_at: datetime
    wall_expires_at: datetime
    monotonic_expires_at: float


@dataclass(slots=True)
class _RuntimeLockSessionState:
    artifact: RuntimeLockSessionArtifact
    token_sha256: str
    monotonic_expires_at: float
    adapter_semantics: dict[RuntimeLockAdapterId, frozenset[MeasurementSemantics]]
    used_operation_identities: set[str] = field(default_factory=set[str])
    active_lease: _ActiveLease | None = None


class RuntimeLockSessionAuthority:
    """Keep Runtime Lock authorization secrets and leases in one MCP process."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        max_sessions: int = _MAX_SESSIONS,
    ) -> None:
        if not 1 <= max_sessions <= _MAX_SESSIONS:
            raise ValueError("Runtime Lock session capacity is outside its fixed bound")
        self._wall_clock = wall_clock or (lambda: datetime.now(tz=UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_sessions = max_sessions
        self._sessions: dict[str, _RuntimeLockSessionState] = {}
        self._consumed_previews: dict[tuple[str, str], tuple[datetime, float]] = {}
        self._active_adapters: dict[RuntimeLockAdapterId, str] = {}
        self._lock = threading.RLock()

    def authorize(
        self,
        preview: RuntimeLockSessionPreviewArtifact,
        capability: RuntimeLockCapabilityArtifact,
        *,
        preview_content_sha256: str,
        authorization_summary_sha256: str,
        explicit_authorization: str,
    ) -> AuthorizedRuntimeLockSession:
        _verify_content(preview)
        _verify_content(capability)
        if explicit_authorization != EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION:
            raise _authorization_error("Runtime Lock session requires explicit bounded consent")
        if not hmac.compare_digest(preview.content_sha256, preview_content_sha256) or not (
            hmac.compare_digest(
                preview.authorization_summary_sha256,
                authorization_summary_sha256,
            )
        ):
            raise _authorization_error("Runtime Lock authorization summary changed")
        expected_summary = contract_content_sha256(
            preview,
            exclude={"authorization_summary_sha256", "content_sha256"},
        )
        if not hmac.compare_digest(preview.authorization_summary_sha256, expected_summary):
            raise _authorization_error("Runtime Lock authorization summary digest is invalid")
        if (
            preview.capability_id != capability.capability_id
            or not hmac.compare_digest(
                preview.capability_content_sha256,
                capability.content_sha256,
            )
            or not hmac.compare_digest(
                preview.project_identity_sha256,
                capability.project_identity_sha256,
            )
            or not hmac.compare_digest(
                preview.project_policy_sha256,
                capability.project_policy_sha256,
            )
        ):
            raise _authorization_error("Runtime Lock capability differs from its Preview")
        adapter_semantics = _authorized_adapter_semantics(preview, capability)
        consumed_key = (preview.preview_id, preview.content_sha256)
        with self._lock:
            self._prune()
            if consumed_key in self._consumed_previews:
                raise _authorization_error("Runtime Lock Preview is already consumed")
            if len(self._consumed_previews) >= _MAX_CONSUMED_PREVIEWS:
                raise _resource_error("Runtime Lock consumed-Preview capacity is exhausted")
            if len(self._sessions) >= self._max_sessions:
                raise _resource_error("Runtime Lock in-memory session capacity is exhausted")
            now = self._wall_now()
            if now < datetime.fromisoformat(preview.created_at):
                raise _authorization_error("Runtime Lock Preview was created in the future")
            if now >= datetime.fromisoformat(preview.expires_at):
                raise _authorization_error("Runtime Lock Preview expired")
            if datetime.fromisoformat(preview.expires_at) - datetime.fromisoformat(
                preview.created_at
            ) > timedelta(seconds=_PREVIEW_EXPIRY_SECONDS):
                raise _authorization_error("Runtime Lock Preview lifetime exceeds its fixed bound")
            nonce = secrets.token_bytes(32)
            token = secrets.token_urlsafe(32)
            receipt = hashlib.sha256(
                b"\0".join(
                    (
                        b"perflens-runtime-lock-authorization-v1",
                        nonce,
                        preview.preview_id.encode("ascii"),
                        preview.content_sha256.encode("ascii"),
                        preview.authorization_summary_sha256.encode("ascii"),
                        preview.client_connection_identity_sha256.encode("ascii"),
                    )
                )
            ).hexdigest()
            session_id = (
                "runtime-lock-session-"
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
            access = RuntimeLockSessionAccess(session_id=session_id, token=token)
            self._sessions[session_id] = _RuntimeLockSessionState(
                artifact=artifact,
                token_sha256=_secret_sha256(token),
                monotonic_expires_at=(self._monotonic_clock() + preview.budget.hard_expiry_seconds),
                adapter_semantics=adapter_semantics,
            )
            preview_remaining = max(
                0.0,
                (datetime.fromisoformat(preview.expires_at) - now).total_seconds(),
            )
            self._consumed_previews[consumed_key] = (
                datetime.fromisoformat(preview.expires_at),
                self._monotonic_clock() + preview_remaining,
            )
            return AuthorizedRuntimeLockSession(artifact=artifact, access=access)

    def begin_run(
        self,
        access: RuntimeLockSessionAccess,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        project_policy_sha256: str,
        runtime_lock_config_sha256: str,
        capability_content_sha256: str,
        preview_content_sha256: str,
        adapter_id: RuntimeLockAdapterId,
        measurement_semantics: MeasurementSemantics,
        operation_identity_sha256: str,
        target_identity_sha256: str,
        workload_identity_sha256: str,
        reserve_active_seconds: int,
        reserve_evidence_bytes: int,
        reserve_exact_events: int = 0,
    ) -> RuntimeLockRunLease:
        for digest, label in (
            (operation_identity_sha256, "Runtime Lock operation identity"),
            (target_identity_sha256, "Runtime Lock target identity"),
            (workload_identity_sha256, "Runtime Lock workload identity"),
        ):
            _validate_sha256(digest, label)
        with self._lock:
            state = self._require(access)
            self._assert_context(
                state,
                project_identity_sha256=project_identity_sha256,
                client_connection_identity_sha256=client_connection_identity_sha256,
                project_policy_sha256=project_policy_sha256,
                runtime_lock_config_sha256=runtime_lock_config_sha256,
                capability_content_sha256=capability_content_sha256,
                preview_content_sha256=preview_content_sha256,
            )
            if state.active_lease is not None:
                raise _resource_error("Runtime Lock session already has an active operation")
            if adapter_id in self._active_adapters:
                raise _resource_error(
                    "Runtime Lock Adapter already has an active operation in this process"
                )
            if operation_identity_sha256 in state.used_operation_identities:
                raise _authorization_error("Runtime Lock operation identity was already consumed")
            allowed_semantics = state.adapter_semantics.get(adapter_id)
            if allowed_semantics is None or measurement_semantics not in allowed_semantics:
                raise _authorization_error(
                    "Runtime Lock Adapter and semantics pair is outside authorization"
                )
            artifact = state.artifact
            budget = artifact.budget
            max_duration = (
                budget.max_exact_duration_seconds
                if measurement_semantics == "exact"
                else budget.max_collection_duration_seconds
            )
            if not 1 <= reserve_active_seconds <= max_duration:
                raise _resource_error("Runtime Lock active-time reservation is invalid")
            if not 1 <= reserve_evidence_bytes <= budget.max_evidence_bytes:
                raise _resource_error("Runtime Lock evidence reservation is invalid")
            if measurement_semantics == "exact":
                if not 1 <= reserve_exact_events <= budget.max_exact_events:
                    raise _resource_error("Runtime Lock exact-event reservation is invalid")
            elif reserve_exact_events != 0:
                raise _resource_error("Non-exact Runtime Lock run cannot reserve exact events")
            if artifact.workload_runs_used >= budget.max_workload_runs:
                self._end(state, "exhausted", "workload_budget_exhausted")
                raise _resource_error("Runtime Lock workload budget is exhausted")
            if (
                artifact.active_seconds_used + reserve_active_seconds > budget.max_active_seconds
                or artifact.evidence_bytes_used + reserve_evidence_bytes > budget.max_evidence_bytes
            ):
                self._end(state, "exhausted", "session_budget_exhausted")
                raise _resource_error("Runtime Lock reservation exceeds its Session budget")
            run_number = artifact.workload_runs_used + 1
            state.used_operation_identities.add(operation_identity_sha256)
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                workload_runs_used=run_number,
                active_seconds_used=(artifact.active_seconds_used + reserve_active_seconds),
                evidence_bytes_used=(artifact.evidence_bytes_used + reserve_evidence_bytes),
                exact_events_used=artifact.exact_events_used + reserve_exact_events,
            )
            lease_token = secrets.token_urlsafe(32)
            lease_nonce = secrets.token_bytes(32)
            now = self._wall_now()
            remaining = max(
                0,
                int((datetime.fromisoformat(state.artifact.expires_at) - now).total_seconds()),
            )
            lease_seconds = min(reserve_active_seconds + _LEASE_GRACE_SECONDS, remaining)
            if lease_seconds <= 0:
                self._expire(state)
                raise _authorization_error("Runtime Lock Session expired before its operation")
            lease_id = (
                "runtime-lock-lease-"
                + hashlib.sha256(
                    lease_nonce + operation_identity_sha256.encode("ascii")
                ).hexdigest()[:20]
            )
            active = _ActiveLease(
                lease_id=lease_id,
                token_sha256=_secret_sha256(lease_token),
                run_number=run_number,
                adapter_id=adapter_id,
                measurement_semantics=measurement_semantics,
                operation_identity_sha256=operation_identity_sha256,
                target_identity_sha256=target_identity_sha256,
                workload_identity_sha256=workload_identity_sha256,
                reserved_active_seconds=reserve_active_seconds,
                reserved_evidence_bytes=reserve_evidence_bytes,
                reserved_exact_events=reserve_exact_events,
                wall_started_at=now,
                wall_expires_at=now + timedelta(seconds=lease_seconds),
                monotonic_expires_at=self._monotonic_clock() + lease_seconds,
            )
            state.active_lease = active
            self._active_adapters[adapter_id] = lease_id
            return RuntimeLockRunLease(
                lease_id=lease_id,
                session_id=state.artifact.session_id,
                run_number=run_number,
                adapter_id=adapter_id,
                measurement_semantics=measurement_semantics,
                operation_identity_sha256=operation_identity_sha256,
                target_identity_sha256=target_identity_sha256,
                workload_identity_sha256=workload_identity_sha256,
                reserved_active_seconds=reserve_active_seconds,
                reserved_evidence_bytes=reserve_evidence_bytes,
                reserved_exact_events=reserve_exact_events,
                session_artifact_id=state.artifact.session_artifact_id,
                session_artifact_content_sha256=state.artifact.content_sha256,
                session_revision=state.artifact.revision,
                expires_at=active.wall_expires_at.isoformat(),
                token=lease_token,
            )

    def finish_run(
        self,
        access: RuntimeLockSessionAccess,
        lease: RuntimeLockRunLease,
        run: RuntimeLockRunArtifact,
    ) -> RuntimeLockRunSettlement:
        _verify_content(run)
        with self._lock:
            state = self._require(access)
            active = self._require_lease(state, lease)
            if not _run_matches_lease(state.artifact, active, lease, run):
                self._end(state, "failed", "run_artifact_mismatch")
                raise _authorization_error("Runtime Lock Run Artifact differs from its lease")
            if (
                run.duration_seconds > active.reserved_active_seconds
                or run.evidence_bytes > active.reserved_evidence_bytes
                or (
                    active.measurement_semantics == "exact"
                    and run.event_count > active.reserved_exact_events
                )
            ):
                self._end(state, "exhausted", "operation_reservation_exceeded")
                raise _resource_error("Runtime Lock Run exceeded its reservation")
            artifact = state.artifact
            self._release_active_lease(state)
            finalization_id = derive_runtime_lock_run_finalization_id(
                artifact.session_id,
                active.operation_identity_sha256,
            )
            settled_at = max(
                self._wall_now(),
                datetime.fromisoformat(run.created_at),
            )
            state.artifact = _update_session(
                artifact,
                updated_at=settled_at,
                active_seconds_used=(
                    artifact.active_seconds_used
                    - active.reserved_active_seconds
                    + run.duration_seconds
                ),
                evidence_bytes_used=(
                    artifact.evidence_bytes_used
                    - active.reserved_evidence_bytes
                    + run.evidence_bytes
                ),
                exact_events_used=(
                    artifact.exact_events_used
                    - active.reserved_exact_events
                    + (run.event_count if active.measurement_semantics == "exact" else 0)
                ),
                settlement_finalization_id=finalization_id,
            )
            finalization = _build_run_finalization(
                reserved_session=artifact,
                final_session=state.artifact,
                active=active,
                outcome="completed",
                run=run,
                accounted_active_seconds=run.duration_seconds,
                accounted_evidence_bytes=run.evidence_bytes,
                accounted_exact_events=(
                    run.event_count if active.measurement_semantics == "exact" else 0
                ),
                failure_reason=None,
            )
            return RuntimeLockRunSettlement(
                session=state.artifact,
                finalization=finalization,
            )

    def fail_run(
        self,
        access: RuntimeLockSessionAccess,
        lease: RuntimeLockRunLease,
        *,
        actual_active_seconds: float,
        actual_evidence_bytes: int,
        actual_exact_events: int = 0,
        reason: RuntimeLockSessionEndReason,
    ) -> RuntimeLockRunSettlement:
        actual_seconds = _bounded_actual_seconds(actual_active_seconds)
        public_reason = _public_end_reason(reason)
        if actual_evidence_bytes < 0 or actual_exact_events < 0:
            raise _resource_error("Runtime Lock failed-run usage cannot be negative")
        if lease.measurement_semantics != "exact" and actual_exact_events:
            raise _resource_error("Non-exact Runtime Lock run cannot report exact events")
        with self._lock:
            state = self._require(access)
            active = self._require_lease(state, lease)
            over_budget = (
                actual_seconds > active.reserved_active_seconds
                or actual_evidence_bytes > active.reserved_evidence_bytes
                or actual_exact_events > active.reserved_exact_events
            )
            artifact = state.artifact
            accounted_active_seconds = min(actual_seconds, active.reserved_active_seconds)
            accounted_evidence_bytes = min(
                actual_evidence_bytes,
                active.reserved_evidence_bytes,
            )
            accounted_exact_events = min(
                actual_exact_events,
                active.reserved_exact_events,
            )
            finalization_id = derive_runtime_lock_run_finalization_id(
                artifact.session_id,
                active.operation_identity_sha256,
            )
            state.artifact = _update_session(
                artifact,
                updated_at=self._wall_now(),
                active_seconds_used=(
                    artifact.active_seconds_used
                    - active.reserved_active_seconds
                    + accounted_active_seconds
                ),
                evidence_bytes_used=(
                    artifact.evidence_bytes_used
                    - active.reserved_evidence_bytes
                    + accounted_evidence_bytes
                ),
                exact_events_used=(
                    artifact.exact_events_used
                    - active.reserved_exact_events
                    + accounted_exact_events
                ),
                state="exhausted" if over_budget else "failed",
                invalidation_reason=(
                    "operation_reservation_exceeded" if over_budget else public_reason
                ),
                settlement_finalization_id=finalization_id,
            )
            self._release_active_lease(state)
            finalization = _build_run_finalization(
                reserved_session=artifact,
                final_session=state.artifact,
                active=active,
                outcome="failed",
                run=None,
                accounted_active_seconds=accounted_active_seconds,
                accounted_evidence_bytes=accounted_evidence_bytes,
                accounted_exact_events=accounted_exact_events,
                failure_reason=("operation_reservation_exceeded" if over_budget else public_reason),
            )
            return RuntimeLockRunSettlement(
                session=state.artifact,
                finalization=finalization,
            )

    def revoke(
        self,
        access: RuntimeLockSessionAccess,
        *,
        reason: RuntimeLockSessionEndReason = "explicitly_revoked",
    ) -> RuntimeLockSessionArtifact:
        with self._lock:
            state = self._require(access, allow_inactive=True)
            if state.artifact.state == "active":
                self._end(state, "revoked", reason)
            else:
                self._release_active_lease(state)
            return state.artifact

    def snapshot(self, access: RuntimeLockSessionAccess) -> RuntimeLockSessionArtifact:
        with self._lock:
            return self._require(access, allow_inactive=True).artifact

    def discard(self, access: RuntimeLockSessionAccess) -> None:
        """Erase one process-local bearer token after its public state is persisted."""

        with self._lock:
            state = self._require(access, allow_inactive=True)
            if state.artifact.state == "active":
                raise _authorization_error("Active Runtime Lock Session cannot be discarded")
            self._release_active_lease(state)
            self._sessions.pop(access.session_id, None)

    def abandon_unpublished(self, access: RuntimeLockSessionAccess) -> None:
        """Fail closed when a reconciled Session cannot be published atomically.

        This path intentionally emits no replacement Artifact.  A Session whose
        marker-last settlement did not reach durable storage cannot safely form
        the parent of another run, so its process-local bearer capability is
        destroyed regardless of the in-memory Session state.
        """

        with self._lock:
            state = self._require(access, allow_inactive=True)
            self._release_active_lease(state)
            self._sessions.pop(access.session_id, None)

    def _require(
        self,
        access: RuntimeLockSessionAccess,
        *,
        allow_inactive: bool = False,
    ) -> _RuntimeLockSessionState:
        state = self._sessions.get(access.session_id)
        if state is None or not hmac.compare_digest(
            state.token_sha256,
            _secret_sha256(access.token),
        ):
            raise _authorization_error("Runtime Lock Session access is invalid")
        if state.artifact.state == "active" and self._session_expired(state):
            self._expire(state)
        if not allow_inactive and state.artifact.state != "active":
            raise _authorization_error("Runtime Lock Session is no longer active")
        if state.active_lease is not None and self._lease_expired(state.active_lease):
            self._end(state, "expired", "operation_lease_expired")
            raise _authorization_error("Runtime Lock operation lease expired")
        return state

    def _require_lease(
        self,
        state: _RuntimeLockSessionState,
        lease: RuntimeLockRunLease,
    ) -> _ActiveLease:
        active = state.active_lease
        if (
            active is None
            or active.lease_id != lease.lease_id
            or not hmac.compare_digest(active.token_sha256, _secret_sha256(lease.token))
            or lease.session_id != state.artifact.session_id
            or lease.session_artifact_id != state.artifact.session_artifact_id
            or not hmac.compare_digest(
                lease.session_artifact_content_sha256,
                state.artifact.content_sha256,
            )
            or lease.session_revision != state.artifact.revision
            or lease.expires_at != active.wall_expires_at.isoformat()
            or active.run_number != lease.run_number
            or active.adapter_id != lease.adapter_id
            or active.measurement_semantics != lease.measurement_semantics
            or active.operation_identity_sha256 != lease.operation_identity_sha256
            or active.target_identity_sha256 != lease.target_identity_sha256
            or active.workload_identity_sha256 != lease.workload_identity_sha256
            or active.reserved_active_seconds != lease.reserved_active_seconds
            or active.reserved_evidence_bytes != lease.reserved_evidence_bytes
            or active.reserved_exact_events != lease.reserved_exact_events
        ):
            raise _authorization_error("Runtime Lock operation lease is invalid or consumed")
        if self._lease_expired(active):
            self._end(state, "expired", "operation_lease_expired")
            raise _authorization_error("Runtime Lock operation lease expired")
        return active

    def _assert_context(
        self,
        state: _RuntimeLockSessionState,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        project_policy_sha256: str,
        runtime_lock_config_sha256: str,
        capability_content_sha256: str,
        preview_content_sha256: str,
    ) -> None:
        artifact = state.artifact
        checks = (
            (project_identity_sha256, artifact.project_identity_sha256),
            (client_connection_identity_sha256, artifact.client_connection_identity_sha256),
            (project_policy_sha256, artifact.project_policy_sha256),
            (runtime_lock_config_sha256, artifact.runtime_lock_config_sha256),
            (capability_content_sha256, artifact.capability_content_sha256),
            (preview_content_sha256, artifact.preview_content_sha256),
        )
        if any(not hmac.compare_digest(actual, expected) for actual, expected in checks):
            self._end(state, "revoked", "identity_or_policy_changed")
            raise _authorization_error("Runtime Lock identity or policy changed")

    def _session_expired(self, state: _RuntimeLockSessionState) -> bool:
        return (
            self._wall_now() >= datetime.fromisoformat(state.artifact.expires_at)
            or self._monotonic_clock() >= state.monotonic_expires_at
        )

    def _lease_expired(self, lease: _ActiveLease) -> bool:
        return (
            self._wall_now() >= lease.wall_expires_at
            or self._monotonic_clock() >= lease.monotonic_expires_at
        )

    def _expire(self, state: _RuntimeLockSessionState) -> None:
        self._end(state, "expired", "hard_expiry_reached")

    def _end(
        self,
        state: _RuntimeLockSessionState,
        state_name: str,
        reason: RuntimeLockSessionEndReason,
    ) -> None:
        public_reason = _public_end_reason(reason)
        state.artifact = _update_session(
            state.artifact,
            updated_at=self._wall_now(),
            state=state_name,
            invalidation_reason=public_reason,
        )
        self._release_active_lease(state)

    def _release_active_lease(self, state: _RuntimeLockSessionState) -> None:
        active = state.active_lease
        if active is not None and self._active_adapters.get(active.adapter_id) == active.lease_id:
            self._active_adapters.pop(active.adapter_id, None)
        state.active_lease = None

    def _prune(self) -> None:
        # Consumed Preview identities are process-lifetime tombstones.  They are
        # deliberately not expired with wall time: otherwise a later clock
        # rollback could make a previously consumed Preview replayable.  The
        # fixed capacity fails closed instead of evicting tombstones.
        for state in self._sessions.values():
            if state.artifact.state == "active" and self._session_expired(state):
                self._expire(state)
        inactive = [
            session_id
            for session_id, state in self._sessions.items()
            if state.artifact.state != "active"
        ]
        while len(self._sessions) >= self._max_sessions and inactive:
            removed = self._sessions.pop(inactive.pop(0), None)
            if removed is not None:
                self._release_active_lease(removed)

    def _wall_now(self) -> datetime:
        now = self._wall_clock()
        if now.tzinfo is None:
            raise ValueError("Runtime Lock wall clock must include a timezone")
        return now


@dataclass(slots=True)
class _PendingRuntimeLockPreview:
    preview: RuntimeLockSessionPreviewArtifact
    capability: RuntimeLockCapabilityArtifact
    monotonic_expires_at: float
    consumed: bool = False


@dataclass(slots=True)
class _RuntimeSession:
    access: RuntimeLockSessionAccess = field(repr=False)
    pending: _PendingRuntimeLockPreview = field(repr=False)


class RuntimeLockSessionRuntime:
    """Bind Preview and Session authority to one client connection."""

    def __init__(
        self,
        *,
        project_identity_sha256: str,
        project_policy_sha256: str,
        runtime_lock_config_sha256: str,
        client_connection_identity_sha256: str | None = None,
        authority: RuntimeLockSessionAuthority | None = None,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        for digest, label in (
            (project_identity_sha256, "Runtime Lock project identity"),
            (project_policy_sha256, "Runtime Lock project policy"),
            (runtime_lock_config_sha256, "Runtime Lock configuration"),
        ):
            _validate_sha256(digest, label)
        self._project_identity = project_identity_sha256
        self._project_policy = project_policy_sha256
        self._config_identity = runtime_lock_config_sha256
        self._client_identity = (
            client_connection_identity_sha256 or hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        )
        _validate_sha256(self._client_identity, "Runtime Lock client connection")
        self._wall_clock = wall_clock or (lambda: datetime.now(tz=UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._authority = authority or RuntimeLockSessionAuthority(
            wall_clock=self._wall_clock,
            monotonic_clock=self._monotonic_clock,
        )
        self._pending: dict[str, _PendingRuntimeLockPreview] = {}
        self._sessions: dict[str, _RuntimeSession] = {}
        self._lock = threading.RLock()
        self._closed = False

    def preview(
        self,
        capability: RuntimeLockCapabilityArtifact,
        *,
        target_scope: RuntimeLockTargetScope,
        allowed_adapters: tuple[RuntimeLockAdapterId, ...],
        allowed_semantics: tuple[MeasurementSemantics, ...],
        import_roots: tuple[str, ...] = (),
        workload: RuntimeLockWorkloadBinding | None = None,
        process_target: RuntimeLockProcessTargetBinding | None = None,
        profile_kind: Literal["mutex", "block"] | None = None,
        adapter_execution_bindings: tuple[RuntimeLockAdapterExecutionBinding, ...] = (),
        budget: RuntimeLockSessionBudget | None = None,
        planned_actions: tuple[str, ...],
        warnings: tuple[str, ...] = (),
        expires_in_seconds: int = _PREVIEW_EXPIRY_SECONDS,
    ) -> RuntimeLockSessionPreviewArtifact:
        if target_scope in {"managed_temporary_container", "docker_optimization"}:
            raise _authorization_error(
                "Docker Runtime Lock scope requires one content-bound parent Docker "
                "authorization"
            )
        with self._lock:
            self._ensure_open()
            self._prune_pending()
            self._prune_sessions()
            if not hmac.compare_digest(
                capability.project_identity_sha256,
                self._project_identity,
            ) or not hmac.compare_digest(
                capability.project_policy_sha256,
                self._project_policy,
            ):
                raise _authorization_error(
                    "Runtime Lock capability is not bound to this project policy"
                )
            if sum(not item.consumed for item in self._pending.values()) >= _MAX_PENDING_PREVIEWS:
                raise _resource_error("Runtime Lock Preview capacity is exhausted")
            preview = build_runtime_lock_session_preview(
                capability,
                client_connection_identity_sha256=self._client_identity,
                runtime_lock_config_sha256=self._config_identity,
                target_scope=target_scope,
                allowed_adapters=allowed_adapters,
                allowed_semantics=allowed_semantics,
                import_roots=import_roots,
                workload=workload,
                process_target=process_target,
                profile_kind=profile_kind,
                adapter_execution_bindings=adapter_execution_bindings,
                budget=budget,
                planned_actions=planned_actions,
                warnings=warnings,
                created_at=self._wall_now(),
                expires_in_seconds=expires_in_seconds,
            )
            self._pending[preview.preview_id] = _PendingRuntimeLockPreview(
                preview=preview,
                capability=capability,
                monotonic_expires_at=self._monotonic_clock() + expires_in_seconds,
            )
            return preview

    def authorize(
        self,
        *,
        preview_id: str,
        preview_content_sha256: str,
        authorization_summary_sha256: str,
        explicit_authorization: str,
    ) -> RuntimeLockSessionArtifact:
        with self._lock:
            self._ensure_open()
            self._prune_pending()
            self._prune_sessions()
            pending = self._pending.get(preview_id)
            if pending is None or pending.consumed:
                raise _authorization_error("Runtime Lock Preview is missing or consumed")
            if len(self._sessions) >= _MAX_SESSIONS:
                raise _resource_error("Runtime Lock active-session capacity is exhausted")
            authorized = self._authority.authorize(
                pending.preview,
                pending.capability,
                preview_content_sha256=preview_content_sha256,
                authorization_summary_sha256=authorization_summary_sha256,
                explicit_authorization=explicit_authorization,
            )
            pending.consumed = True
            self._sessions[authorized.artifact.session_id] = _RuntimeSession(
                access=authorized.access,
                pending=pending,
            )
            return authorized.artifact

    def begin_run(
        self,
        session_id: str,
        *,
        adapter_id: RuntimeLockAdapterId,
        measurement_semantics: MeasurementSemantics,
        operation_identity_sha256: str,
        target_identity_sha256: str,
        workload_identity_sha256: str,
        reserve_active_seconds: int,
        reserve_evidence_bytes: int,
        reserve_exact_events: int = 0,
    ) -> RuntimeLockRunLease:
        with self._lock:
            session = self._require_session(session_id)
            workload = session.pending.preview.workload
            if workload is not None and not hmac.compare_digest(
                workload_identity_sha256,
                workload.workload_identity_sha256,
            ):
                raise _authorization_error(
                    "Runtime Lock workload identity differs from its authorized Preview"
                )
            return self._authority.begin_run(
                session.access,
                project_identity_sha256=self._project_identity,
                client_connection_identity_sha256=self._client_identity,
                project_policy_sha256=self._project_policy,
                runtime_lock_config_sha256=self._config_identity,
                capability_content_sha256=session.pending.capability.content_sha256,
                preview_content_sha256=session.pending.preview.content_sha256,
                adapter_id=adapter_id,
                measurement_semantics=measurement_semantics,
                operation_identity_sha256=operation_identity_sha256,
                target_identity_sha256=target_identity_sha256,
                workload_identity_sha256=workload_identity_sha256,
                reserve_active_seconds=reserve_active_seconds,
                reserve_evidence_bytes=reserve_evidence_bytes,
                reserve_exact_events=reserve_exact_events,
            )

    def finish_run(
        self,
        session_id: str,
        lease: RuntimeLockRunLease,
        run: RuntimeLockRunArtifact,
    ) -> RuntimeLockRunSettlement:
        with self._lock:
            session = self._require_session(session_id)
            return self._authority.finish_run(session.access, lease, run)

    def fail_run(
        self,
        session_id: str,
        lease: RuntimeLockRunLease,
        *,
        actual_active_seconds: float,
        actual_evidence_bytes: int,
        actual_exact_events: int = 0,
        reason: RuntimeLockSessionEndReason,
    ) -> RuntimeLockRunSettlement:
        with self._lock:
            session = self._require_session(session_id)
            return self._authority.fail_run(
                session.access,
                lease,
                actual_active_seconds=actual_active_seconds,
                actual_evidence_bytes=actual_evidence_bytes,
                actual_exact_events=actual_exact_events,
                reason=reason,
            )

    def snapshot(self, session_id: str) -> RuntimeLockSessionArtifact:
        with self._lock:
            return self._authority.snapshot(self._require_session(session_id).access)

    def revoke(
        self,
        session_id: str,
        *,
        reason: RuntimeLockSessionEndReason = "explicitly_revoked",
    ) -> RuntimeLockSessionArtifact:
        with self._lock:
            session = self._require_session(session_id)
            artifact = self._authority.revoke(session.access, reason=reason)
            self._authority.discard(session.access)
            self._sessions.pop(session_id, None)
            return artifact

    def abandon_unpublished(self, session_id: str) -> None:
        """Destroy an authorization whose final state was not durably published."""

        with self._lock:
            session = self._require_session(session_id)
            self._authority.abandon_unpublished(session.access)
            self._sessions.pop(session_id, None)

    def close(self) -> tuple[RuntimeLockSessionArtifact, ...]:
        with self._lock:
            if self._closed:
                return ()
            self._closed = True
            revoked_items: list[RuntimeLockSessionArtifact] = []
            for session in self._sessions.values():
                artifact = self._authority.revoke(session.access)
                revoked_items.append(artifact)
                self._authority.discard(session.access)
            revoked = tuple(revoked_items)
            self._pending.clear()
            self._sessions.clear()
            return revoked

    def _require_session(self, session_id: str) -> _RuntimeSession:
        self._ensure_open()
        session = self._sessions.get(session_id)
        if session is None:
            raise _authorization_error("Runtime Lock Session is not bound to this connection")
        return session

    def _prune_pending(self) -> None:
        now = self._wall_now()
        monotonic_now = self._monotonic_clock()
        expired = [
            preview_id
            for preview_id, item in self._pending.items()
            if item.consumed
            or now >= datetime.fromisoformat(item.preview.expires_at)
            or monotonic_now >= item.monotonic_expires_at
        ]
        for preview_id in expired:
            self._pending.pop(preview_id, None)

    def _prune_sessions(self) -> None:
        inactive: list[str] = []
        for session_id, session in self._sessions.items():
            try:
                artifact = self._authority.snapshot(session.access)
            except PerfLensError:
                inactive.append(session_id)
                continue
            if artifact.state != "active":
                inactive.append(session_id)
        for session_id in inactive:
            self._sessions.pop(session_id, None)

    def _ensure_open(self) -> None:
        if self._closed:
            raise _authorization_error("Runtime Lock Session runtime is closed")

    def _wall_now(self) -> datetime:
        now = self._wall_clock()
        if now.tzinfo is None:
            raise ValueError("Runtime Lock wall clock must include a timezone")
        return now


def build_runtime_lock_session_preview(
    capability: RuntimeLockCapabilityArtifact,
    *,
    client_connection_identity_sha256: str,
    runtime_lock_config_sha256: str,
    target_scope: RuntimeLockTargetScope,
    allowed_adapters: tuple[RuntimeLockAdapterId, ...],
    allowed_semantics: tuple[MeasurementSemantics, ...],
    import_roots: tuple[str, ...] = (),
    workload: RuntimeLockWorkloadBinding | None = None,
    process_target: RuntimeLockProcessTargetBinding | None = None,
    profile_kind: Literal["mutex", "block"] | None = None,
    adapter_execution_bindings: tuple[RuntimeLockAdapterExecutionBinding, ...] = (),
    budget: RuntimeLockSessionBudget | None = None,
    planned_actions: tuple[str, ...],
    warnings: tuple[str, ...] = (),
    created_at: datetime | None = None,
    expires_in_seconds: int = _PREVIEW_EXPIRY_SECONDS,
) -> RuntimeLockSessionPreviewArtifact:
    if target_scope in {"managed_temporary_container", "docker_optimization"}:
        raise _authorization_error(
            "Docker Runtime Lock scope requires one content-bound parent Docker authorization"
        )
    _verify_content(capability)
    _validate_sha256(client_connection_identity_sha256, "Runtime Lock client connection")
    _validate_sha256(runtime_lock_config_sha256, "Runtime Lock configuration")
    if not 1 <= expires_in_seconds <= _PREVIEW_EXPIRY_SECONDS:
        raise _resource_error("Runtime Lock Preview expiry is outside its fixed bound")
    now = created_at or datetime.now(tz=UTC)
    if now.tzinfo is None:
        raise ValueError("Runtime Lock Preview time must include a timezone")
    adapters = tuple(sorted(allowed_adapters))
    semantics = tuple(sorted(allowed_semantics))
    if target_scope != "controlled_import" and import_roots:
        raise _authorization_error(
            "Runtime Lock import roots require the controlled-import target scope"
        )
    _validate_preview_scope(capability, adapters, semantics)
    created = now.isoformat()
    data = {
        "schema_version": "1.1",
        "perflens_version": __version__,
        "preview_id": derive_runtime_lock_preview_id(
            capability.project_identity_sha256,
            capability.project_policy_sha256,
            capability.content_sha256,
            created,
        ),
        "created_at": created,
        "expires_at": (now + timedelta(seconds=expires_in_seconds)).isoformat(),
        "project_identity_sha256": capability.project_identity_sha256,
        "client_connection_identity_sha256": client_connection_identity_sha256,
        "project_policy_sha256": capability.project_policy_sha256,
        "capability_id": capability.capability_id,
        "capability_content_sha256": capability.content_sha256,
        "runtime_lock_config_sha256": runtime_lock_config_sha256,
        "target_scope": target_scope,
        "allowed_adapters": adapters,
        "allowed_semantics": semantics,
        "import_roots": tuple(sorted(import_roots)),
        "workload": workload,
        "process_target": process_target,
        "profile_kind": profile_kind,
        "adapter_execution_bindings": adapter_execution_bindings,
        "budget": budget or RuntimeLockSessionBudget(),
        "planned_actions": planned_actions,
        "warnings": warnings,
        "authorization_summary_sha256": "0" * 64,
        "content_sha256": "0" * 64,
    }
    provisional = RuntimeLockSessionPreviewArtifact.model_validate(data)
    summary = contract_content_sha256(
        provisional,
        exclude={"authorization_summary_sha256", "content_sha256"},
    )
    with_summary = RuntimeLockSessionPreviewArtifact.model_validate(
        {**provisional.model_dump(mode="json"), "authorization_summary_sha256": summary}
    )
    return RuntimeLockSessionPreviewArtifact.model_validate(
        {
            **with_summary.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                with_summary,
                exclude={"content_sha256"},
            ),
        }
    )


def _authorized_adapter_semantics(
    preview: RuntimeLockSessionPreviewArtifact,
    capability: RuntimeLockCapabilityArtifact,
) -> dict[RuntimeLockAdapterId, frozenset[MeasurementSemantics]]:
    references = {reference.adapter_id: reference for reference in capability.adapters}
    result: dict[RuntimeLockAdapterId, frozenset[MeasurementSemantics]] = {}
    covered_semantics: set[MeasurementSemantics] = set()
    for adapter_id in preview.allowed_adapters:
        reference = references.get(adapter_id)
        if reference is None or reference.availability not in {"available", "partial"}:
            raise _authorization_error("Runtime Lock Preview selects an unavailable Adapter")
        selected = frozenset(reference.supported_semantics) & frozenset(preview.allowed_semantics)
        if not selected:
            raise _authorization_error(
                "Runtime Lock Preview selects an unsupported Adapter semantics pair"
            )
        result[adapter_id] = selected
        covered_semantics.update(selected)
    if covered_semantics != set(preview.allowed_semantics):
        raise _authorization_error("Runtime Lock Preview contains unsupported semantics")
    return result


def _validate_preview_scope(
    capability: RuntimeLockCapabilityArtifact,
    adapters: tuple[RuntimeLockAdapterId, ...],
    semantics: tuple[MeasurementSemantics, ...],
) -> None:
    if capability.status in {"disabled", "unavailable"}:
        raise _authorization_error("Runtime Lock capability is unavailable")
    if not adapters or len(adapters) != len(set(adapters)):
        raise _authorization_error("Runtime Lock Preview Adapter scope is invalid")
    if not semantics or len(semantics) != len(set(semantics)):
        raise _authorization_error("Runtime Lock Preview semantics scope is invalid")
    references = {reference.adapter_id: reference for reference in capability.adapters}
    covered_semantics: set[MeasurementSemantics] = set()
    for adapter_id in adapters:
        reference = references.get(adapter_id)
        if reference is None or reference.availability not in {"available", "partial"}:
            raise _authorization_error("Runtime Lock Preview selects an unavailable Adapter")
        selected = set(reference.supported_semantics) & set(semantics)
        if not selected:
            raise _authorization_error(
                "Runtime Lock Preview selects an unsupported Adapter semantics pair"
            )
        covered_semantics.update(selected)
    if covered_semantics != set(semantics):
        raise _authorization_error("Runtime Lock Preview contains unsupported semantics")


def _new_session_artifact(
    *,
    session_id: str,
    created_at: datetime,
    expires_at: datetime,
    preview: RuntimeLockSessionPreviewArtifact,
    authorization_receipt_sha256: str,
) -> RuntimeLockSessionArtifact:
    data = {
        "schema_version": preview.schema_version,
        "perflens_version": __version__,
        "session_artifact_id": derive_runtime_lock_session_artifact_id(
            session_id,
            0,
            "active",
            created_at.isoformat(),
            None,
            None,
            0,
            0,
            0,
            0,
        ),
        "session_id": session_id,
        "revision": 0,
        "previous_session_artifact_id": None,
        "previous_session_artifact_content_sha256": None,
        "created_at": created_at.isoformat(),
        "updated_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "state": "active",
        "project_identity_sha256": preview.project_identity_sha256,
        "client_connection_identity_sha256": preview.client_connection_identity_sha256,
        "project_policy_sha256": preview.project_policy_sha256,
        "capability_id": preview.capability_id,
        "capability_content_sha256": preview.capability_content_sha256,
        "runtime_lock_config_sha256": preview.runtime_lock_config_sha256,
        "preview_id": preview.preview_id,
        "preview_content_sha256": preview.content_sha256,
        "authorization_receipt_sha256": authorization_receipt_sha256,
        "target_scope": preview.target_scope,
        "allowed_adapters": preview.allowed_adapters,
        "allowed_semantics": preview.allowed_semantics,
        "budget": preview.budget,
        "workload_runs_used": 0,
        "active_seconds_used": 0,
        "evidence_bytes_used": 0,
        "exact_events_used": 0,
        "invalidation_reason": None,
        "content_sha256": "0" * 64,
    }
    return _with_content(RuntimeLockSessionArtifact.model_validate(data))


def _update_session(
    artifact: RuntimeLockSessionArtifact,
    *,
    updated_at: datetime,
    **updates: object,
) -> RuntimeLockSessionArtifact:
    prior = datetime.fromisoformat(artifact.updated_at)
    effective_updated_at = updated_at if updated_at > prior else prior + timedelta(microseconds=1)
    timestamp = effective_updated_at.isoformat()
    data = {
        **artifact.model_dump(mode="json"),
        # A settlement marker describes exactly one predecessor -> successor
        # transition and must never leak into a later unrelated revision.
        "settlement_finalization_id": None,
        **updates,
        "revision": artifact.revision + 1,
        "previous_session_artifact_id": artifact.session_artifact_id,
        "previous_session_artifact_content_sha256": artifact.content_sha256,
        "updated_at": timestamp,
        "content_sha256": "0" * 64,
    }
    state = data["state"]
    revision = data["revision"]
    previous_id = data["previous_session_artifact_id"]
    previous_content = data["previous_session_artifact_content_sha256"]
    runs = data["workload_runs_used"]
    active_seconds = data["active_seconds_used"]
    evidence = data["evidence_bytes_used"]
    exact_events = data["exact_events_used"]
    settlement_finalization_id = data.get("settlement_finalization_id")
    if (
        not isinstance(state, str)
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or not isinstance(previous_id, str)
        or not isinstance(previous_content, str)
        or isinstance(runs, bool)
        or not isinstance(runs, int)
        or isinstance(active_seconds, bool)
        or not isinstance(active_seconds, int)
        or isinstance(evidence, bool)
        or not isinstance(evidence, int)
        or isinstance(exact_events, bool)
        or not isinstance(exact_events, int)
        or (
            settlement_finalization_id is not None
            and not isinstance(settlement_finalization_id, str)
        )
    ):
        raise ValueError("Runtime Lock Session update contains invalid counters")
    data["session_artifact_id"] = derive_runtime_lock_session_artifact_id(
        artifact.session_id,
        revision,
        state,
        timestamp,
        previous_id,
        previous_content,
        runs,
        active_seconds,
        evidence,
        exact_events,
        settlement_finalization_id,
    )
    return _with_content(RuntimeLockSessionArtifact.model_validate(data))


def _with_content(artifact: RuntimeLockSessionArtifact) -> RuntimeLockSessionArtifact:
    return RuntimeLockSessionArtifact.model_validate(
        {
            **artifact.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                artifact,
                exclude={"content_sha256"},
            ),
        }
    )


def _build_run_finalization(
    *,
    reserved_session: RuntimeLockSessionArtifact,
    final_session: RuntimeLockSessionArtifact,
    active: _ActiveLease,
    outcome: str,
    run: RuntimeLockRunArtifact | None,
    accounted_active_seconds: int,
    accounted_evidence_bytes: int,
    accounted_exact_events: int,
    failure_reason: RuntimeLockSessionEndReason | None,
) -> RuntimeLockRunFinalizationArtifact:
    finalization_id = derive_runtime_lock_run_finalization_id(
        reserved_session.session_id,
        active.operation_identity_sha256,
    )
    provisional = RuntimeLockRunFinalizationArtifact.model_validate(
        {
            "schema_version": "1.1",
            "perflens_version": __version__,
            "finalization_id": finalization_id,
            "created_at": final_session.updated_at,
            "session_id": reserved_session.session_id,
            "operation_identity_sha256": active.operation_identity_sha256,
            "outcome": outcome,
            "adapter_id": active.adapter_id,
            "measurement_semantics": active.measurement_semantics,
            "reserved_session_artifact_id": reserved_session.session_artifact_id,
            "reserved_session_artifact_content_sha256": reserved_session.content_sha256,
            "reserved_session_revision": reserved_session.revision,
            "final_session_artifact_id": final_session.session_artifact_id,
            "final_session_artifact_content_sha256": final_session.content_sha256,
            "final_session_revision": final_session.revision,
            "reserved_active_seconds": active.reserved_active_seconds,
            "reserved_evidence_bytes": active.reserved_evidence_bytes,
            "reserved_exact_events": active.reserved_exact_events,
            "accounted_active_seconds": accounted_active_seconds,
            "accounted_evidence_bytes": accounted_evidence_bytes,
            "accounted_exact_events": accounted_exact_events,
            "run_id": run.run_id if run is not None else None,
            "run_content_sha256": run.content_sha256 if run is not None else None,
            "failure_reason": failure_reason,
            "content_sha256": "0" * 64,
        }
    )
    return RuntimeLockRunFinalizationArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _run_matches_lease(
    session: RuntimeLockSessionArtifact,
    active: _ActiveLease,
    lease: RuntimeLockRunLease,
    run: RuntimeLockRunArtifact,
) -> bool:
    run_started = datetime.fromisoformat(run.started_at)
    run_finished = datetime.fromisoformat(run.finished_at)
    run_created = datetime.fromisoformat(run.created_at)
    run_session_content_sha256 = run.session_artifact_content_sha256
    if run_session_content_sha256 is None:
        return False
    return (
        lease.session_id == session.session_id
        and lease.session_artifact_id == session.session_artifact_id
        and hmac.compare_digest(
            lease.session_artifact_content_sha256,
            session.content_sha256,
        )
        and lease.session_revision == session.revision
        and run.session_id == session.session_id
        and run.session_artifact_id == session.session_artifact_id
        and hmac.compare_digest(
            run_session_content_sha256,
            session.content_sha256,
        )
        and run.session_revision == session.revision
        and run.adapter_id == active.adapter_id
        and run.target_scope == session.target_scope
        and run.measurement_semantics == active.measurement_semantics
        and hmac.compare_digest(
            run.operation_identity_sha256,
            active.operation_identity_sha256,
        )
        and hmac.compare_digest(
            run.target_identity_sha256,
            active.target_identity_sha256,
        )
        and hmac.compare_digest(
            run.workload_identity_sha256,
            active.workload_identity_sha256,
        )
        and active.wall_started_at <= run_started
        and run_started <= run_finished
        and run_finished <= active.wall_expires_at
        and run_finished <= run_created
        and run_created <= active.wall_expires_at
    )


def _verify_content(artifact: ContractModel) -> None:
    content_sha256 = getattr(artifact, "content_sha256", None)
    if not isinstance(content_sha256, str) or not hmac.compare_digest(
        content_sha256,
        contract_content_sha256(artifact, exclude={"content_sha256"}),
    ):
        raise _authorization_error("Runtime Lock Artifact content digest does not match")


def _bounded_actual_seconds(value: float) -> int:
    if not math.isfinite(value) or value < 0:
        raise _resource_error("Runtime Lock actual duration is invalid")
    return math.ceil(value)


def _secret_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise _authorization_error(f"{label} must be a SHA-256 digest")


def _public_end_reason(value: str) -> RuntimeLockSessionEndReason:
    allowed = {
        "adapter_output_invalid",
        "adapter_unavailable",
        "correctness_failed",
        "explicitly_revoked",
        "hard_expiry_reached",
        "identity_or_policy_changed",
        "internal_collection_error",
        "operation_lease_expired",
        "operation_reservation_exceeded",
        "request_rejected",
        "resource_limit_exceeded",
        "run_artifact_mismatch",
        "session_budget_exhausted",
        "target_exited",
        "target_identity_changed",
        "workload_budget_exhausted",
    }
    if value not in allowed:
        raise _authorization_error("Runtime Lock failure reason is not a public reason code")
    return value  # type: ignore[return-value]


def _authorization_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_authorization",
        message,
        recoverable=True,
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "runtime_lock_authorization",
        message,
        recoverable=True,
    )
