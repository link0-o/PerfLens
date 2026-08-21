"""In-memory, bounded Docker authorization sessions and per-run leases."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    CollectionMode,
    ContainerOptimizationSessionArtifact,
    ContainerTargetArtifact,
    ContainerWorkloadSpecArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError

EXPLICIT_DOCKER_SESSION_AUTHORIZATION = (
    "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
)
_CANONICAL_MODES: tuple[CollectionMode, ...] = (
    "stat",
    "record",
    "sched",
    "off_cpu",
    "lock",
)
_MAX_SESSIONS = 64
_MAX_HARD_EXPIRY_SECONDS = 7200
_DEFAULT_MAX_EVIDENCE_BYTES = 1 << 30
_LEASE_GRACE_SECONDS = 120


@dataclass(frozen=True, slots=True)
class SessionAccess:
    session_id: str
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizedDockerSession:
    artifact: ContainerOptimizationSessionArtifact
    access: SessionAccess = field(repr=False)


@dataclass(frozen=True, slots=True)
class DockerRunLease:
    lease_id: str
    session_id: str
    run_number: int
    target_kind: str
    binding_sha256: str
    allowed_modes: tuple[CollectionMode, ...]
    reserved_active_seconds: int
    reserved_evidence_bytes: int
    expires_at: str
    token: str = field(repr=False)


@dataclass(slots=True)
class _ActiveLease:
    lease_id: str
    token_sha256: str
    binding_sha256: str
    allowed_modes: tuple[CollectionMode, ...]
    reserved_active_seconds: int
    reserved_evidence_bytes: int
    wall_expires_at: datetime
    monotonic_expires_at: float


@dataclass(slots=True)
class _SessionState:
    artifact: ContainerOptimizationSessionArtifact
    token_sha256: str
    policy_identity_sha256: str
    monotonic_expires_at: float
    active_lease: _ActiveLease | None = None


class DockerSessionAuthority:
    """Process-local authorization state; restart or disconnect revokes access."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        max_sessions: int = _MAX_SESSIONS,
    ) -> None:
        if not 1 <= max_sessions <= _MAX_SESSIONS:
            raise ValueError("Docker session capacity is outside the fixed bound")
        self._wall_clock = wall_clock or (lambda: datetime.now(tz=UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_sessions = max_sessions
        self._sessions: dict[str, _SessionState] = {}
        self._lock = threading.RLock()

    def authorize_existing_target(
        self,
        target: ContainerTargetArtifact,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
        allowed_modes: tuple[CollectionMode, ...],
        authorization_mode: str,
        explicit_authorization: str,
        max_workload_runs: int = 6,
        max_active_seconds: int = 1200,
        max_evidence_bytes: int = _DEFAULT_MAX_EVIDENCE_BYTES,
        hard_expiry_seconds: int = _MAX_HARD_EXPIRY_SECONDS,
    ) -> AuthorizedDockerSession:
        _verify_contract_content(target, target.content_sha256)
        if target.target_kind != "existing_container":
            raise _authorization_error("Existing-container authorization received another target")
        modes = _validate_modes(allowed_modes)
        return self._authorize(
            target_kind="existing_container",
            authorization_mode=authorization_mode,
            project_identity_sha256=project_identity_sha256,
            client_connection_identity_sha256=client_connection_identity_sha256,
            policy_identity_sha256=policy_identity_sha256,
            allowed_modes=modes,
            explicit_authorization=explicit_authorization,
            workload_spec_sha256=None,
            existing_target_identity_sha256=target.identity_fingerprint,
            max_workload_runs=(
                1 if authorization_mode == "per_run" else max_workload_runs
            ),
            max_active_seconds=max_active_seconds,
            max_evidence_bytes=max_evidence_bytes,
            hard_expiry_seconds=hard_expiry_seconds,
        )

    def authorize_managed_workload(
        self,
        workload: ContainerWorkloadSpecArtifact,
        *,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
        explicit_authorization: str,
        max_evidence_bytes: int = _DEFAULT_MAX_EVIDENCE_BYTES,
    ) -> AuthorizedDockerSession:
        _verify_contract_content(workload, workload.content_sha256)
        modes = _validate_modes(workload.allowed_modes)
        return self._authorize(
            target_kind="managed_temporary_container",
            authorization_mode=workload.authorization_mode,
            project_identity_sha256=workload.project_identity_sha256,
            client_connection_identity_sha256=client_connection_identity_sha256,
            policy_identity_sha256=policy_identity_sha256,
            allowed_modes=modes,
            explicit_authorization=explicit_authorization,
            workload_spec_sha256=workload.content_sha256,
            existing_target_identity_sha256=None,
            max_workload_runs=(
                1 if workload.authorization_mode == "per_run" else workload.max_workload_runs
            ),
            max_active_seconds=workload.max_active_seconds,
            max_evidence_bytes=max_evidence_bytes,
            hard_expiry_seconds=workload.hard_expiry_seconds,
        )

    def begin_run(
        self,
        access: SessionAccess,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
        binding_sha256: str,
        requested_modes: tuple[CollectionMode, ...],
        reserve_active_seconds: int,
        reserve_evidence_bytes: int,
    ) -> DockerRunLease:
        modes = _validate_modes(requested_modes)
        _validate_sha256(binding_sha256, "Docker run binding")
        if reserve_active_seconds <= 0 or reserve_evidence_bytes <= 0:
            raise _resource_error("Docker run reservation must be positive")
        with self._lock:
            state = self._require_session(access)
            self._assert_session_context(
                state,
                project_identity_sha256=project_identity_sha256,
                client_connection_identity_sha256=client_connection_identity_sha256,
                policy_identity_sha256=policy_identity_sha256,
                binding_sha256=binding_sha256,
            )
            if state.active_lease is not None:
                raise _resource_error("Docker session already has an active workload run")
            artifact = state.artifact
            if any(mode not in artifact.allowed_modes for mode in modes):
                raise _authorization_error(
                    "Docker run requests a mode outside session authorization"
                )
            if artifact.workload_runs_used >= artifact.max_workload_runs:
                self._end_session(state, "exhausted", "Docker workload run budget was exhausted.")
                raise _resource_error("Docker workload run budget is exhausted")
            if artifact.active_seconds_used + reserve_active_seconds > artifact.max_active_seconds:
                self._end_session(state, "exhausted", "Docker active-time budget was exhausted.")
                raise _resource_error("Docker active-time budget is exhausted")
            if artifact.evidence_bytes_used + reserve_evidence_bytes > artifact.max_evidence_bytes:
                self._end_session(state, "exhausted", "Docker evidence budget was exhausted.")
                raise _resource_error("Docker evidence budget is exhausted")
            run_number = artifact.workload_runs_used + 1
            lease_token = secrets.token_urlsafe(32)
            lease_nonce = secrets.token_bytes(32)
            wall_now = self._wall_now()
            lease_seconds = min(
                reserve_active_seconds + _LEASE_GRACE_SECONDS,
                max(
                    1,
                    int(
                        (datetime.fromisoformat(artifact.expires_at) - wall_now).total_seconds()
                    ),
                ),
            )
            if lease_seconds <= 0:
                self._expire_session(state)
                raise _authorization_error("Docker session expired before the workload run")
            lease_id = "docker-lease-" + hashlib.sha256(
                lease_nonce + artifact.session_id.encode("ascii")
            ).hexdigest()[:20]
            wall_expires = wall_now + timedelta(seconds=lease_seconds)
            state.active_lease = _ActiveLease(
                lease_id=lease_id,
                token_sha256=_secret_sha256(lease_token),
                binding_sha256=binding_sha256,
                allowed_modes=modes,
                reserved_active_seconds=reserve_active_seconds,
                reserved_evidence_bytes=reserve_evidence_bytes,
                wall_expires_at=wall_expires,
                monotonic_expires_at=self._monotonic_clock() + lease_seconds,
            )
            instance_count = (
                artifact.instance_count + 1
                if artifact.target_kind == "managed_temporary_container"
                else max(artifact.instance_count, 1)
            )
            state.artifact = _updated_artifact(
                artifact,
                workload_runs_used=run_number,
                active_seconds_used=artifact.active_seconds_used + reserve_active_seconds,
                evidence_bytes_used=artifact.evidence_bytes_used + reserve_evidence_bytes,
                instance_count=instance_count,
            )
            return DockerRunLease(
                lease_id=lease_id,
                session_id=artifact.session_id,
                run_number=run_number,
                target_kind=artifact.target_kind,
                binding_sha256=binding_sha256,
                allowed_modes=modes,
                reserved_active_seconds=reserve_active_seconds,
                reserved_evidence_bytes=reserve_evidence_bytes,
                expires_at=wall_expires.isoformat(),
                token=lease_token,
            )

    def assert_run_current(
        self,
        access: SessionAccess,
        lease: DockerRunLease,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
        binding_sha256: str,
        mode: CollectionMode,
    ) -> ContainerOptimizationSessionArtifact:
        with self._lock:
            state = self._require_session(access)
            self._assert_session_context(
                state,
                project_identity_sha256=project_identity_sha256,
                client_connection_identity_sha256=client_connection_identity_sha256,
                policy_identity_sha256=policy_identity_sha256,
                binding_sha256=binding_sha256,
            )
            active = self._require_lease(state, lease)
            if mode not in active.allowed_modes:
                raise _authorization_error("Collection mode is outside the active Docker run lease")
            return state.artifact

    def finish_run(
        self,
        access: SessionAccess,
        lease: DockerRunLease,
        *,
        actual_active_seconds: int,
        actual_evidence_bytes: int,
    ) -> ContainerOptimizationSessionArtifact:
        if actual_active_seconds < 0 or actual_evidence_bytes < 0:
            raise _resource_error("Docker run actual resource use cannot be negative")
        with self._lock:
            state = self._require_session(access)
            active = self._require_lease(state, lease)
            if (
                actual_active_seconds > active.reserved_active_seconds
                or actual_evidence_bytes > active.reserved_evidence_bytes
            ):
                self._end_session(
                    state,
                    "exhausted",
                    "Docker run exceeded its reserved resource budget.",
                )
                state.active_lease = None
                raise _resource_error("Docker run exceeded its reserved resource budget")
            artifact = state.artifact
            state.active_lease = None
            state.artifact = _updated_artifact(
                artifact,
                active_seconds_used=(
                    artifact.active_seconds_used
                    - active.reserved_active_seconds
                    + actual_active_seconds
                ),
                evidence_bytes_used=(
                    artifact.evidence_bytes_used
                    - active.reserved_evidence_bytes
                    + actual_evidence_bytes
                ),
            )
            updated = state.artifact
            if (
                updated.authorization_mode == "per_run"
                or updated.workload_runs_used >= updated.max_workload_runs
                or updated.active_seconds_used >= updated.max_active_seconds
                or updated.evidence_bytes_used >= updated.max_evidence_bytes
            ):
                self._end_session(
                    state,
                    "exhausted",
                    "Docker authorization budget was exhausted.",
                )
            return state.artifact

    def revoke(
        self,
        access: SessionAccess,
    ) -> ContainerOptimizationSessionArtifact:
        with self._lock:
            state = self._require_session(access, allow_inactive=True)
            if state.artifact.state == "active":
                self._end_session(
                    state,
                    "revoked",
                    "Docker session was explicitly revoked.",
                )
            state.active_lease = None
            return state.artifact

    def revoke_client_connection(
        self,
        client_connection_identity_sha256: str,
    ) -> tuple[str, ...]:
        _validate_sha256(client_connection_identity_sha256, "client connection identity")
        revoked: list[str] = []
        with self._lock:
            for session_id, state in self._sessions.items():
                if (
                    state.artifact.state == "active"
                    and state.artifact.client_connection_identity_sha256
                    == client_connection_identity_sha256
                ):
                    self._end_session(
                        state,
                        "revoked",
                        "Docker client connection ended.",
                    )
                    state.active_lease = None
                    revoked.append(session_id)
        return tuple(sorted(revoked))

    def snapshot(self, access: SessionAccess) -> ContainerOptimizationSessionArtifact:
        with self._lock:
            state = self._require_session(access, allow_inactive=True)
            return state.artifact

    def _authorize(
        self,
        *,
        target_kind: str,
        authorization_mode: str,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
        allowed_modes: tuple[CollectionMode, ...],
        explicit_authorization: str,
        workload_spec_sha256: str | None,
        existing_target_identity_sha256: str | None,
        max_workload_runs: int,
        max_active_seconds: int,
        max_evidence_bytes: int,
        hard_expiry_seconds: int,
    ) -> AuthorizedDockerSession:
        if explicit_authorization != EXPLICIT_DOCKER_SESSION_AUTHORIZATION:
            raise _authorization_error("Docker session requires explicit bounded authorization")
        if authorization_mode not in {"per_run", "bounded_session"}:
            raise _authorization_error("Docker authorization mode is invalid")
        for value, label in (
            (project_identity_sha256, "project identity"),
            (client_connection_identity_sha256, "client connection identity"),
            (policy_identity_sha256, "Collector policy identity"),
        ):
            _validate_sha256(value, label)
        if not 1 <= max_workload_runs <= 6:
            raise _resource_error("Docker workload run budget is outside the fixed bound")
        if not 1 <= max_active_seconds <= 1200:
            raise _resource_error("Docker active-time budget is outside the fixed bound")
        if not 1 <= max_evidence_bytes <= 1 << 40:
            raise _resource_error("Docker evidence budget is outside the fixed bound")
        if not 1 <= hard_expiry_seconds <= _MAX_HARD_EXPIRY_SECONDS:
            raise _resource_error("Docker hard expiry is outside the fixed bound")
        with self._lock:
            self._prune_inactive()
            if len(self._sessions) >= self._max_sessions:
                raise _resource_error("Docker in-memory session capacity is exhausted")
            wall_now = self._wall_now()
            monotonic_now = self._monotonic_clock()
            token = secrets.token_urlsafe(32)
            nonce = secrets.token_bytes(32)
            binding = workload_spec_sha256 or existing_target_identity_sha256
            assert binding is not None
            receipt = hashlib.sha256(
                b"\0".join(
                    (
                        nonce,
                        target_kind.encode("ascii"),
                        authorization_mode.encode("ascii"),
                        project_identity_sha256.encode("ascii"),
                        client_connection_identity_sha256.encode("ascii"),
                        policy_identity_sha256.encode("ascii"),
                        binding.encode("ascii"),
                        ",".join(allowed_modes).encode("ascii"),
                        str(max_workload_runs).encode("ascii"),
                        str(max_active_seconds).encode("ascii"),
                        str(max_evidence_bytes).encode("ascii"),
                        wall_now.isoformat().encode("ascii"),
                    )
                )
            ).hexdigest()
            session_id = "container-session-" + hashlib.sha256(
                nonce + receipt.encode("ascii")
            ).hexdigest()[:20]
            expires_at = wall_now + timedelta(seconds=hard_expiry_seconds)
            provisional = ContainerOptimizationSessionArtifact.model_validate(
                {
                    "schema_version": "1.0",
                    "perflens_version": __version__,
                    "session_id": session_id,
                    "created_at": wall_now.isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "target_kind": target_kind,
                    "authorization_mode": authorization_mode,
                    "project_identity_sha256": project_identity_sha256,
                    "client_connection_identity_sha256": client_connection_identity_sha256,
                    "authorization_receipt_sha256": receipt,
                    "workload_spec_sha256": workload_spec_sha256,
                    "existing_target_identity_sha256": existing_target_identity_sha256,
                    "allowed_modes": allowed_modes,
                    "state": "active",
                    "max_workload_runs": max_workload_runs,
                    "workload_runs_used": 0,
                    "max_active_seconds": max_active_seconds,
                    "active_seconds_used": 0,
                    "max_evidence_bytes": max_evidence_bytes,
                    "evidence_bytes_used": 0,
                    "instance_count": 0,
                    "content_sha256": "0" * 64,
                }
            )
            artifact = _with_content_sha256(provisional)
            access = SessionAccess(session_id, token)
            self._sessions[session_id] = _SessionState(
                artifact=artifact,
                token_sha256=_secret_sha256(token),
                policy_identity_sha256=policy_identity_sha256,
                monotonic_expires_at=monotonic_now + hard_expiry_seconds,
            )
            return AuthorizedDockerSession(artifact, access)

    def _require_session(
        self,
        access: SessionAccess,
        *,
        allow_inactive: bool = False,
    ) -> _SessionState:
        state = self._sessions.get(access.session_id)
        if state is None or not hmac.compare_digest(
            state.token_sha256,
            _secret_sha256(access.token),
        ):
            raise _authorization_error("Docker session access is invalid")
        if state.artifact.state == "active" and self._session_expired(state):
            self._expire_session(state)
        if not allow_inactive and state.artifact.state != "active":
            raise _authorization_error("Docker session is no longer active")
        if state.active_lease is not None and self._lease_expired(state.active_lease):
            self._end_session(state, "expired", "Docker run lease expired.")
            state.active_lease = None
            raise _authorization_error("Docker run lease expired")
        return state

    def _assert_session_context(
        self,
        state: _SessionState,
        *,
        project_identity_sha256: str,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
        binding_sha256: str,
    ) -> None:
        artifact = state.artifact
        expected_binding = (
            artifact.workload_spec_sha256
            if artifact.target_kind == "managed_temporary_container"
            else artifact.existing_target_identity_sha256
        )
        checks = (
            (project_identity_sha256, artifact.project_identity_sha256),
            (client_connection_identity_sha256, artifact.client_connection_identity_sha256),
            (policy_identity_sha256, state.policy_identity_sha256),
            (binding_sha256, expected_binding),
        )
        if any(
            expected is None or not hmac.compare_digest(actual, expected)
            for actual, expected in checks
        ):
            self._end_session(
                state,
                "revoked",
                "Docker session binding or policy changed.",
            )
            state.active_lease = None
            raise _authorization_error("Docker session binding or policy changed")

    def _require_lease(
        self,
        state: _SessionState,
        lease: DockerRunLease,
    ) -> _ActiveLease:
        active = state.active_lease
        if (
            active is None
            or lease.session_id != state.artifact.session_id
            or lease.lease_id != active.lease_id
            or lease.binding_sha256 != active.binding_sha256
            or not hmac.compare_digest(active.token_sha256, _secret_sha256(lease.token))
        ):
            raise _authorization_error("Docker run lease is invalid or already consumed")
        if self._lease_expired(active):
            self._end_session(state, "expired", "Docker run lease expired.")
            state.active_lease = None
            raise _authorization_error("Docker run lease expired")
        return active

    def _session_expired(self, state: _SessionState) -> bool:
        expires_at = datetime.fromisoformat(state.artifact.expires_at)
        return (
            self._wall_now() >= expires_at
            or self._monotonic_clock() >= state.monotonic_expires_at
        )

    def _lease_expired(self, lease: _ActiveLease) -> bool:
        return (
            self._wall_now() >= lease.wall_expires_at
            or self._monotonic_clock() >= lease.monotonic_expires_at
        )

    def _expire_session(self, state: _SessionState) -> None:
        self._end_session(state, "expired", "Docker session reached its hard expiry.")
        state.active_lease = None

    def _end_session(self, state: _SessionState, state_name: str, reason: str) -> None:
        state.artifact = _updated_artifact(
            state.artifact,
            state=state_name,
            invalidation_reason=_bounded_reason(reason),
        )

    def _prune_inactive(self) -> None:
        for state in self._sessions.values():
            if state.artifact.state == "active" and self._session_expired(state):
                self._expire_session(state)
        inactive = tuple(
            session_id
            for session_id, state in self._sessions.items()
            if state.artifact.state != "active"
        )
        while len(self._sessions) >= self._max_sessions and inactive:
            self._sessions.pop(inactive[0], None)
            inactive = inactive[1:]

    def _wall_now(self) -> datetime:
        value = self._wall_clock()
        if value.tzinfo is None:
            raise ValueError("Docker session wall clock must be timezone-aware")
        return value


def _updated_artifact(
    artifact: ContainerOptimizationSessionArtifact,
    **updates: object,
) -> ContainerOptimizationSessionArtifact:
    data = {**artifact.model_dump(mode="json"), **updates, "content_sha256": "0" * 64}
    return _with_content_sha256(ContainerOptimizationSessionArtifact.model_validate(data))


def _with_content_sha256(
    artifact: ContainerOptimizationSessionArtifact,
) -> ContainerOptimizationSessionArtifact:
    return ContainerOptimizationSessionArtifact.model_validate(
        {
            **artifact.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                artifact,
                exclude={"content_sha256"},
            ),
        }
    )


def _verify_contract_content(artifact: BaseModel, content_sha256: str) -> None:
    if not hmac.compare_digest(
        contract_content_sha256(artifact, exclude={"content_sha256"}),
        content_sha256,
    ):
        raise _authorization_error("Docker authorization input content digest does not match")


def _validate_modes(modes: tuple[CollectionMode, ...]) -> tuple[CollectionMode, ...]:
    if not modes or len(set(modes)) != len(modes):
        raise _authorization_error("Docker authorization modes must be non-empty and unique")
    try:
        canonical = tuple(sorted(modes, key=_CANONICAL_MODES.index))
    except ValueError as exc:
        raise _authorization_error("Docker authorization contains an unsupported mode") from exc
    if modes != canonical:
        raise _authorization_error("Docker authorization modes must use canonical order")
    return modes


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise _authorization_error(f"{label} must be a SHA-256 digest")


def _secret_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bounded_reason(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        return "Docker session ended."
    return normalized[:512]


def _authorization_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_authorization",
        message,
        recoverable=True,
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "docker_authorization",
        message,
        recoverable=True,
    )
