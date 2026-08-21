"""Project-bound existing-container discovery and authorization coordination."""

from __future__ import annotations

import hashlib
import secrets
import threading
from collections.abc import Callable
from pathlib import Path

from perflens.collection.planning import AutomaticCollectionPolicy
from perflens.contracts.docker import (
    AuthorizationMode,
    CollectionMode,
    ContainerOptimizationSessionArtifact,
    ContainerProcessInventoryArtifact,
    ContainerTargetArtifact,
)
from perflens.docker.adapter import DockerCommandAdapter
from perflens.docker.capability import open_local_docker_adapter
from perflens.docker.existing import discover_existing_container_processes
from perflens.docker.identity import (
    LinuxContainerIdentityReader,
    resolve_existing_container_target,
)
from perflens.docker.project_config import (
    DockerProjectPolicy,
    assert_docker_project_policy_current,
)
from perflens.docker.session import (
    DockerRunLease,
    DockerSessionAuthority,
    SessionAccess,
)
from perflens.docker.workload import (
    ManagedProjectIdentity,
    assert_managed_project_current,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_CANONICAL_MODES: tuple[CollectionMode, ...] = (
    "stat",
    "record",
    "sched",
    "off_cpu",
    "lock",
)
_MAX_SESSION_ACCESS = 64


class ExistingDockerRuntime:
    """Keep Docker authorization private to one project-scoped MCP lifetime."""

    def __init__(
        self,
        *,
        project: ManagedProjectIdentity,
        project_policy: DockerProjectPolicy,
        allowed_roots: tuple[Path, ...],
        collection_policy: AutomaticCollectionPolicy,
        client_connection_identity_sha256: str | None = None,
        adapter_factory: Callable[[], DockerCommandAdapter] | None = None,
        reader_factory: Callable[[], LinuxContainerIdentityReader] | None = None,
        authority: DockerSessionAuthority | None = None,
    ) -> None:
        if not collection_policy.enabled:
            raise ValueError("Docker runtime requires enabled automatic collection")
        self._project = project
        self._project_policy = project_policy
        self._allowed_roots = allowed_roots
        self._collection_policy = collection_policy
        self._client_identity = client_connection_identity_sha256 or hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()
        if (
            len(self._client_identity) != 64
            or any(character not in "0123456789abcdef" for character in self._client_identity)
        ):
            raise ValueError("Docker client connection identity must be a SHA-256 digest")
        self._adapter_factory = adapter_factory or open_local_docker_adapter
        self._reader_factory = reader_factory or LinuxContainerIdentityReader
        self._authority = authority or DockerSessionAuthority()
        self._access: dict[str, SessionAccess] = {}
        self._session_lock = threading.RLock()

    def discover(
        self,
        container_reference: str,
        *,
        observation_duration_ms: int = 100,
    ) -> ContainerProcessInventoryArtifact:
        self._assert_context_current()
        result = discover_existing_container_processes(
            self._adapter_factory(),
            container_reference,
            reader=self._reader_factory(),
            observation_duration_ms=observation_duration_ms,
        )
        return result.inventory

    def resolve(
        self,
        container_reference: str,
        *,
        host_pid: int | None = None,
        container_pid: int | None = None,
    ) -> ContainerTargetArtifact:
        self._assert_context_current()
        return resolve_existing_container_target(
            self._adapter_factory(),
            container_reference,
            host_pid=host_pid,
            container_pid=container_pid,
            reader=self._reader_factory(),
            allow_rootful_cross_uid=(
                self._collection_policy.allow_rootful_container_targets
            ),
        ).artifact

    def authorize(
        self,
        container_reference: str,
        *,
        host_pid: int | None,
        container_pid: int | None = None,
        allowed_modes: tuple[CollectionMode, ...],
        authorization_mode: AuthorizationMode | None,
        explicit_authorization: str,
    ) -> ContainerOptimizationSessionArtifact:
        self._assert_context_current()
        modes = self._authorized_modes(allowed_modes)
        mode = authorization_mode or self._project_policy.default_authorization_mode
        target = self.resolve(
            container_reference,
            host_pid=host_pid,
            container_pid=container_pid,
        )
        with self._session_lock:
            self._prune_access_locked()
            if len(self._access) >= _MAX_SESSION_ACCESS:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "docker_authorization",
                    "Docker MCP session access capacity is exhausted",
                    recoverable=True,
                )
            authorized = self._authority.authorize_existing_target(
                target,
                project_identity_sha256=self._project.identity_sha256,
                client_connection_identity_sha256=self._client_identity,
                policy_identity_sha256=self._project_policy.sha256,
                allowed_modes=modes,
                authorization_mode=mode,
                explicit_authorization=explicit_authorization,
                max_workload_runs=self._project_policy.max_workload_runs,
                max_active_seconds=self._project_policy.max_active_seconds,
                max_evidence_bytes=self._project_policy.max_evidence_bytes,
                hard_expiry_seconds=self._project_policy.hard_expiry_seconds,
            )
            self._access[authorized.artifact.session_id] = authorized.access
            return authorized.artifact

    def revoke(self, session_id: str) -> ContainerOptimizationSessionArtifact:
        with self._session_lock:
            access = self._require_access_locked(session_id)
            return self._authority.revoke(access)

    def begin_existing_run(
        self,
        session_id: str,
        target: ContainerTargetArtifact,
        *,
        requested_modes: tuple[CollectionMode, ...],
        reserve_active_seconds: int,
        reserve_evidence_bytes: int,
    ) -> DockerRunLease:
        self._assert_context_current()
        modes = self._authorized_modes(requested_modes)
        with self._session_lock:
            access = self._require_access_locked(session_id)
            return self._authority.begin_run(
                access,
                project_identity_sha256=self._project.identity_sha256,
                client_connection_identity_sha256=self._client_identity,
                policy_identity_sha256=self._project_policy.sha256,
                binding_sha256=target.identity_fingerprint,
                requested_modes=modes,
                reserve_active_seconds=reserve_active_seconds,
                reserve_evidence_bytes=reserve_evidence_bytes,
            )

    def finish_existing_run(
        self,
        session_id: str,
        lease: DockerRunLease,
        *,
        actual_active_seconds: int,
        actual_evidence_bytes: int,
    ) -> ContainerOptimizationSessionArtifact:
        with self._session_lock:
            access = self._require_access_locked(session_id)
            return self._authority.finish_run(
                access,
                lease,
                actual_active_seconds=actual_active_seconds,
                actual_evidence_bytes=actual_evidence_bytes,
            )

    def _prune_access_locked(self) -> None:
        inactive = tuple(
            session_id
            for session_id, access in self._access.items()
            if self._authority.snapshot(access).state != "active"
        )
        for session_id in inactive:
            self._access.pop(session_id, None)

    def _require_access_locked(self, session_id: str) -> SessionAccess:
        access = self._access.get(session_id)
        if access is None:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "docker_authorization",
                "Docker session is unknown to this MCP process",
                recoverable=True,
            )
        return access

    def _assert_context_current(self) -> None:
        assert_docker_project_policy_current(
            self._project_policy,
            allowed_roots=self._allowed_roots,
        )
        assert_managed_project_current(self._project)

    def _authorized_modes(
        self,
        requested: tuple[CollectionMode, ...],
    ) -> tuple[CollectionMode, ...]:
        modes = requested or self._collection_policy.allowed_modes
        if not modes or len(set(modes)) != len(modes):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "docker_authorization",
                "Docker session modes must be non-empty and unique",
            )
        if any(mode not in self._collection_policy.allowed_modes for mode in modes):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_authorization",
                "Docker session requests a mode outside MCP automatic-collection policy",
                recoverable=True,
            )
        return tuple(mode for mode in _CANONICAL_MODES if mode in modes)
