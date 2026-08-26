"""Project-bound orchestration for one-confirmation Docker optimization sessions."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import stat
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerBuildContextArtifact,
    DockerBuildRecipeArtifact,
    DockerOptimizationDispositionArtifact,
    DockerOptimizationIterationArtifact,
    DockerOptimizationPreviewArtifact,
    DockerOptimizationSessionArtifact,
    OptimizationCollectionMode,
    derive_docker_optimization_disposition_id,
    derive_docker_optimization_preview_id,
)
from perflens.docker.build_adapter import (
    DockerBuildExecutionResult,
    TypedDockerBuildAdapter,
)
from perflens.docker.build_capability import project_docker_build_capability
from perflens.docker.build_context import (
    DockerBuildContextSnapshot,
    build_docker_build_recipe,
    capture_docker_build_context,
)
from perflens.docker.optimization_session import (
    EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE,
    DockerOptimizationSessionAccess,
    DockerOptimizationSessionAuthority,
    DockerOptimizationWorkloadLease,
)
from perflens.docker.project_config import (
    DockerProjectPolicy,
    assert_docker_project_policy_current,
)
from perflens.docker.workload import ManagedProjectIdentity, assert_managed_project_current
from perflens.domain.errors import ErrorCode, PerfLensError

_CANONICAL_MODES: tuple[OptimizationCollectionMode, ...] = (
    "stat",
    "record",
    "sched",
    "off_cpu",
    "lock",
)
_MAX_PENDING_PREVIEWS = 16
_MAX_ACTIVE_SESSIONS = 16
_PREVIEW_EXPIRY_SECONDS = 600


@dataclass(frozen=True, slots=True)
class DockerOptimizationPreviewResult:
    preview: DockerOptimizationPreviewArtifact
    capability: DockerBuildCapabilityArtifact
    recipe: DockerBuildRecipeArtifact
    context: DockerBuildContextArtifact


@dataclass(frozen=True, slots=True)
class DockerOptimizationBuildResult:
    build: DockerBuildArtifact
    session: DockerOptimizationSessionArtifact


@dataclass(frozen=True, slots=True)
class DockerOptimizationDispositionResult:
    disposition: DockerOptimizationDispositionArtifact
    session: DockerOptimizationSessionArtifact


@dataclass(slots=True)
class _PendingPreview:
    result: DockerOptimizationPreviewResult
    snapshot: DockerBuildContextSnapshot
    adapter: TypedDockerBuildAdapter
    private_directory: Path
    monotonic_expires_at: float
    consumed: bool = False


@dataclass(slots=True)
class _OptimizationRuntimeSession:
    access: DockerOptimizationSessionAccess = field(repr=False)
    preview: _PendingPreview = field(repr=False)
    builds: dict[str, DockerBuildExecutionResult] = field(default_factory=lambda: {})
    latest_treatment_manifest_sha256: str | None = None
    resources_released: bool = False


class DockerOptimizationRuntime:
    """Bind Preview, authorization, builds, and workload leases to one MCP connection."""

    def __init__(
        self,
        *,
        project: ManagedProjectIdentity,
        project_policy: DockerProjectPolicy,
        allowed_roots: tuple[Path, ...],
        private_root: Path,
        runtime_capability_factory: Callable[[], DockerRuntimeCapabilityArtifact],
        build_adapter_factory: Callable[[Path], TypedDockerBuildAdapter],
        collector_available: Callable[[], bool],
        collector_modes: tuple[OptimizationCollectionMode, ...],
        client_connection_identity_sha256: str | None = None,
        authority: DockerOptimizationSessionAuthority | None = None,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self._project = project
        self._policy = project_policy
        self._allowed_roots = allowed_roots
        self._private_root = _safe_private_root(private_root, uid=project.owner_uid)
        self._runtime_capability_factory = runtime_capability_factory
        self._build_adapter_factory = build_adapter_factory
        self._collector_available = collector_available
        self._collector_modes = _canonical_modes(collector_modes)
        self._client_identity = client_connection_identity_sha256 or hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()
        _validate_sha256(self._client_identity, "Docker optimization client connection")
        self._wall_clock = wall_clock or (lambda: datetime.now(tz=UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._authority = authority or DockerOptimizationSessionAuthority(
            wall_clock=self._wall_clock,
            monotonic_clock=self._monotonic_clock,
        )
        self._pending: dict[str, _PendingPreview] = {}
        self._sessions: dict[str, _OptimizationRuntimeSession] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._cleanup_timer_enabled = wall_clock is None and monotonic_clock is None
        self._cleanup_timer: threading.Timer | None = None

    def inspect_capability(self) -> DockerBuildCapabilityArtifact:
        with self._lock:
            self._ensure_open_locked()
            self._prune_pending_locked()
            self._prune_sessions_locked()
            self._schedule_cleanup_locked()
        self._assert_project_current()
        runtime = self._runtime_capability_factory()
        _verify_content(runtime)
        private_directory: Path | None = None
        adapter: TypedDockerBuildAdapter | None = None
        try:
            private_directory = _new_private_directory(self._private_root)
            adapter = self._build_adapter_factory(private_directory)
            docker_tool = adapter.docker_tool_projection
            buildx_tool = adapter.buildx_tool_projection
            builder = adapter.builder_projection
            tiers = adapter.available_network_tiers
            base_present = adapter.base_image_present(
                self._policy.optimization.base_image_digest
            ) if self._policy.optimization.base_image_digest else False
        except PerfLensError:
            docker_tool = None
            buildx_tool = None
            builder = None
            tiers = ()
            base_present = False
        finally:
            if adapter is not None:
                adapter.close()
            if private_directory is not None:
                _remove_private_directory(private_directory)
        return project_docker_build_capability(
            runtime=runtime,
            policy=self._policy,
            docker_tool=docker_tool,
            buildx_tool=buildx_tool,
            builder=builder,
            available_network_tiers=tiers,
            base_image_present=base_present,
            collector_available=self._collector_available(),
            checked_at=self._wall_now(),
        )

    def preview(
        self,
        *,
        allowed_modes: tuple[OptimizationCollectionMode, ...],
    ) -> DockerOptimizationPreviewResult:
        modes = _canonical_modes(allowed_modes)
        if any(mode not in self._collector_modes for mode in modes):
            raise _authorization_error(
                "Docker optimization Preview requests a mode unavailable from the Collector"
            )
        self._assert_project_current()
        runtime = self._runtime_capability_factory()
        _verify_content(runtime)
        with self._lock:
            self._ensure_open_locked()
            self._prune_pending_locked()
            self._prune_sessions_locked()
            if (
                sum(not pending.consumed for pending in self._pending.values())
                >= _MAX_PENDING_PREVIEWS
            ):
                raise _resource_error("Docker optimization Preview capacity is exhausted")
            private_directory = _new_private_directory(self._private_root)
            adapter: TypedDockerBuildAdapter | None = None
            try:
                adapter = self._build_adapter_factory(private_directory)
                capability = project_docker_build_capability(
                    runtime=runtime,
                    policy=self._policy,
                    docker_tool=adapter.docker_tool_projection,
                    buildx_tool=adapter.buildx_tool_projection,
                    builder=adapter.builder_projection,
                    available_network_tiers=adapter.available_network_tiers,
                    base_image_present=adapter.base_image_present(
                        self._policy.optimization.base_image_digest
                    ),
                    collector_available=self._collector_available(),
                    checked_at=self._wall_now(),
                )
                if capability.status != "available" or not capability.build_supported:
                    raise _authorization_error(
                        "Docker optimization capability is incomplete; inspect its limitations"
                    )
                recipe = build_docker_build_recipe(
                    self._policy,
                    project_identity_sha256=self._project.identity_sha256,
                    created_at=self._wall_now(),
                )
                snapshot = capture_docker_build_context(
                    self._policy,
                    recipe,
                    project_root=self._project.path,
                    private_directory=private_directory,
                    invoking_uid=self._project.owner_uid,
                    created_at=self._wall_now(),
                )
                result = self._build_preview_artifact(
                    runtime=runtime,
                    capability=capability,
                    recipe=recipe,
                    context=snapshot.artifact,
                    modes=modes,
                )
                pending = _PendingPreview(
                    result=result,
                    snapshot=snapshot,
                    adapter=adapter,
                    private_directory=private_directory,
                    monotonic_expires_at=(
                        self._monotonic_clock() + _PREVIEW_EXPIRY_SECONDS
                    ),
                )
                self._pending[result.preview.preview_id] = pending
                self._schedule_cleanup_locked()
                return result
            except BaseException:
                if adapter is not None:
                    adapter.close()
                _remove_private_directory(private_directory)
                raise

    def authorize(
        self,
        *,
        preview_id: str,
        preview_content_sha256: str,
        authorization_summary_sha256: str,
        explicit_authorization: str,
    ) -> DockerOptimizationSessionArtifact:
        with self._lock:
            self._ensure_open_locked()
            self._prune_pending_locked()
            self._prune_sessions_locked()
            pending = self._pending.get(preview_id)
            if pending is None or pending.consumed:
                raise _authorization_error("Docker optimization Preview is missing or consumed")
            self._assert_project_current()
            _assert_snapshot_current(pending.snapshot)
            if (
                sum(
                    self._authority.snapshot(session.access).state == "active"
                    for session in self._sessions.values()
                )
                >= _MAX_ACTIVE_SESSIONS
            ):
                raise _resource_error("Docker optimization active-session capacity is exhausted")
            authorized = self._authority.authorize(
                pending.result.preview,
                preview_content_sha256=preview_content_sha256,
                authorization_summary_sha256=authorization_summary_sha256,
                explicit_authorization=explicit_authorization,
            )
            pending.consumed = True
            self._sessions[authorized.artifact.session_id] = _OptimizationRuntimeSession(
                access=authorized.access,
                preview=pending,
                latest_treatment_manifest_sha256=(
                    pending.snapshot.artifact.mutable_manifest_sha256
                ),
            )
            self._schedule_cleanup_locked()
            return authorized.artifact

    def build(
        self,
        session_id: str,
        *,
        build_kind: Literal["baseline", "candidate"],
        candidate_round: int,
    ) -> DockerOptimizationBuildResult:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(session_id)
            pending = runtime_session.preview
            self._assert_project_current()
            if build_kind == "baseline":
                snapshot = pending.snapshot
            else:
                snapshot = capture_docker_build_context(
                    self._policy,
                    pending.result.recipe,
                    project_root=self._project.path,
                    private_directory=pending.private_directory,
                    invoking_uid=self._project.owner_uid,
                    created_at=self._wall_now(),
                )
                if snapshot.artifact.immutable_manifest_sha256 != (
                    pending.snapshot.artifact.immutable_manifest_sha256
                ):
                    self._authority.revoke(runtime_session.access)
                    _discard_snapshot(snapshot)
                    self._release_runtime_session_locked(session_id, runtime_session)
                    self._schedule_cleanup_locked()
                    raise _authorization_error(
                        "Docker optimization immutable build context changed"
                    )
                if snapshot.artifact.mutable_manifest_sha256 == (
                    runtime_session.latest_treatment_manifest_sha256
                ):
                    _discard_snapshot(snapshot)
                    raise _authorization_error(
                        "Docker candidate has no new authorized Treatment"
                    )
            lease = self._authority.begin_build(
                runtime_session.access,
                project_identity_sha256=self._project.identity_sha256,
                client_connection_identity_sha256=self._client_identity,
                project_policy_sha256=self._policy.sha256,
                preview_content_sha256=pending.result.preview.content_sha256,
                recipe_content_sha256=pending.result.recipe.content_sha256,
                context_content_sha256=snapshot.artifact.content_sha256,
                build_kind=build_kind,
                candidate_round=candidate_round,
            )
        started = self._monotonic_clock()
        execution_result: DockerBuildExecutionResult | None = None
        try:
            execution_result = pending.adapter.build(
                capability=pending.result.capability,
                policy=self._policy,
                snapshot=snapshot,
                private_directory=pending.private_directory,
                session_identity_sha256=_session_identity_sha256(session_id),
                build_kind=build_kind,
                candidate_round=candidate_round,
                started_at=self._wall_now(),
            )
            elapsed = self._monotonic_clock() - started
            session = self._authority.finish_build(
                runtime_session.access,
                lease,
                execution_result.artifact,
                actual_build_seconds=elapsed,
            )
        except BaseException as exc:
            elapsed = max(0.0, self._monotonic_clock() - started)
            recoverable = isinstance(exc, PerfLensError) and exc.code in {
                ErrorCode.EXTERNAL_TOOL_FAILED,
                ErrorCode.EXTERNAL_TOOL_TIMEOUT,
            }
            with self._lock:
                with suppress(PerfLensError):
                    self._authority.fail_build(
                        runtime_session.access,
                        lease,
                        actual_build_seconds=elapsed,
                        recoverable=recoverable,
                        reason=(
                            exc.message
                            if isinstance(exc, PerfLensError)
                            else "Docker build failed."
                        ),
                    )
                if build_kind == "candidate":
                    _discard_snapshot(snapshot)
                if execution_result is not None:
                    with suppress(PerfLensError):
                        pending.adapter.cleanup_build(
                            execution_result,
                            session_identity_sha256=_session_identity_sha256(session_id),
                        )
                if self._authority.snapshot(runtime_session.access).state != "active":
                    self._release_runtime_session_locked(session_id, runtime_session)
                    self._schedule_cleanup_locked()
            raise
        with self._lock:
            runtime_session.builds[execution_result.artifact.build_id] = execution_result
            runtime_session.latest_treatment_manifest_sha256 = (
                snapshot.artifact.mutable_manifest_sha256
            )
            if snapshot is not pending.snapshot:
                _discard_snapshot(snapshot)
            if session.state != "active":
                self._release_runtime_session_locked(session_id, runtime_session)
                self._schedule_cleanup_locked()
            return DockerOptimizationBuildResult(
                build=execution_result.artifact,
                session=session,
            )

    def revoke(self, session_id: str) -> DockerOptimizationSessionArtifact:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(
                session_id,
                allow_inactive=True,
            )
            artifact = self._authority.revoke(runtime_session.access)
            self._release_runtime_session_locked(session_id, runtime_session)
            self._schedule_cleanup_locked()
            return artifact

    def finalize_candidate(
        self,
        session_id: str,
        *,
        iteration: DockerOptimizationIterationArtifact,
        disposition: Literal["retain_candidate", "restore_baseline"],
        explicit_unverified_acceptance: str | None = None,
    ) -> DockerOptimizationDispositionResult:
        """Bind the final workspace choice, revoke authority, and clean session resources."""
        with self._lock:
            runtime_session = self._require_runtime_session_locked(session_id)
            self._assert_project_current()
            source_session = self._authority.snapshot(runtime_session.access)
            _verify_contract_content(iteration, "Docker optimization Iteration")
            if (
                iteration.session_id != session_id
                or iteration.session_artifact_id != source_session.session_artifact_id
                or iteration.session_artifact_content_sha256 != source_session.content_sha256
                or iteration.baseline_build_id != source_session.baseline_build_id
                or iteration.candidate_build_id != source_session.latest_candidate_build_id
            ):
                raise _authorization_error(
                    "Docker optimization disposition differs from the current Session"
                )
            baseline = self._bound_iteration_build(
                runtime_session,
                iteration.baseline_build_id,
                iteration.baseline_build_content_sha256,
            )
            candidate = self._bound_iteration_build(
                runtime_session,
                iteration.candidate_build_id,
                iteration.candidate_build_content_sha256,
            )
            retaining = disposition == "retain_candidate"
            requires_acceptance = (
                retaining and iteration.conclusion != "verified_improvement"
            )
            if requires_acceptance:
                if explicit_unverified_acceptance is None or not hmac.compare_digest(
                    explicit_unverified_acceptance,
                    EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE,
                ):
                    raise _authorization_error(
                        "Retaining an unverified Docker candidate requires fresh explicit consent"
                    )
            elif explicit_unverified_acceptance is not None:
                raise _authorization_error(
                    "Docker candidate acceptance was supplied for a disposition that does not "
                    "require it"
                )
            selected = candidate if retaining else baseline
            current = capture_docker_build_context(
                self._policy,
                runtime_session.preview.result.recipe,
                project_root=self._project.path,
                private_directory=runtime_session.preview.private_directory,
                invoking_uid=self._project.owner_uid,
                created_at=self._wall_now(),
            )
            try:
                if (
                    current.artifact.immutable_manifest_sha256
                    != selected.immutable_manifest_sha256
                ):
                    self._authority.revoke(runtime_session.access)
                    self._release_runtime_session_locked(session_id, runtime_session)
                    self._schedule_cleanup_locked()
                    raise _authorization_error(
                        "Docker optimization immutable context changed before finalization"
                    )
                if (
                    current.artifact.mutable_manifest_sha256
                    != selected.treatment_manifest_sha256
                ):
                    raise _authorization_error(
                        "Docker optimization workspace does not match the selected final Build"
                    )
                workspace_manifest = current.artifact.mutable_manifest_sha256
            finally:
                _discard_snapshot(current)

            accepted_at = self._wall_now()
            receipt = (
                _candidate_acceptance_receipt(
                    source_session=source_session,
                    iteration=iteration,
                    selected_build=selected,
                )
                if requires_acceptance
                else None
            )
            final_session = self._authority.revoke(runtime_session.access)
            try:
                artifact = _build_disposition_artifact(
                    created_at=accepted_at,
                    source_session=source_session,
                    final_session=final_session,
                    iteration=iteration,
                    baseline=baseline,
                    candidate=candidate,
                    selected=selected,
                    disposition=disposition,
                    workspace_manifest_sha256=workspace_manifest,
                    explicit_unverified_acceptance=requires_acceptance,
                    authorization_receipt_sha256=receipt,
                )
            finally:
                self._release_runtime_session_locked(session_id, runtime_session)
                self._schedule_cleanup_locked()
            return DockerOptimizationDispositionResult(
                disposition=artifact,
                session=final_session,
            )

    def snapshot(self, session_id: str) -> DockerOptimizationSessionArtifact:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(
                session_id,
                allow_inactive=True,
            )
            return self._authority.snapshot(runtime_session.access)

    def build_result(
        self,
        session_id: str,
        build_id: str,
    ) -> DockerBuildExecutionResult:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(session_id)
            result = runtime_session.builds.get(build_id)
            if result is None:
                raise _authorization_error("Docker Build is outside this optimization session")
            return result

    @staticmethod
    def _bound_iteration_build(
        runtime_session: _OptimizationRuntimeSession,
        build_id: str,
        expected_content_sha256: str,
    ) -> DockerBuildArtifact:
        result = runtime_session.builds.get(build_id)
        if result is None or not hmac.compare_digest(
            result.artifact.content_sha256,
            expected_content_sha256,
        ):
            raise _authorization_error(
                "Docker optimization Iteration Build is outside the current Session"
            )
        _verify_contract_content(result.artifact, "Docker Build")
        return result.artifact

    def build_recipe(self, session_id: str) -> DockerBuildRecipeArtifact:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(session_id)
            return runtime_session.preview.result.recipe

    def begin_workload(
        self,
        session_id: str,
        *,
        build_id: str,
        mode: OptimizationCollectionMode,
        reserve_active_seconds: int,
        reserve_evidence_bytes: int,
    ) -> DockerOptimizationWorkloadLease:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(session_id)
            self._assert_project_current()
            build = self.build_result(session_id, build_id).artifact
            pending = runtime_session.preview
            current = capture_docker_build_context(
                self._policy,
                pending.result.recipe,
                project_root=self._project.path,
                private_directory=pending.private_directory,
                invoking_uid=self._project.owner_uid,
                created_at=self._wall_now(),
            )
            try:
                if (
                    current.artifact.immutable_manifest_sha256
                    != build.immutable_manifest_sha256
                ):
                    self._authority.revoke(runtime_session.access)
                    self._release_runtime_session_locked(session_id, runtime_session)
                    self._schedule_cleanup_locked()
                    raise _authorization_error(
                        "Docker optimization immutable context changed before collection"
                    )
                if (
                    current.artifact.mutable_manifest_sha256
                    != build.treatment_manifest_sha256
                ):
                    raise _authorization_error(
                        "Docker optimization workspace no longer matches the selected Build"
                    )
            finally:
                _discard_snapshot(current)
            return self._authority.begin_workload(
                runtime_session.access,
                project_identity_sha256=self._project.identity_sha256,
                client_connection_identity_sha256=self._client_identity,
                project_policy_sha256=self._policy.sha256,
                preview_content_sha256=pending.result.preview.content_sha256,
                recipe_content_sha256=pending.result.recipe.content_sha256,
                build_id=build_id,
                mode=mode,
                reserve_active_seconds=reserve_active_seconds,
                reserve_evidence_bytes=reserve_evidence_bytes,
            )

    def finish_workload(
        self,
        session_id: str,
        lease: DockerOptimizationWorkloadLease,
        *,
        actual_active_seconds: float,
        actual_evidence_bytes: int,
    ) -> DockerOptimizationSessionArtifact:
        with self._lock:
            runtime_session = self._require_runtime_session_locked(session_id)
            artifact = self._authority.finish_workload(
                runtime_session.access,
                lease,
                actual_active_seconds=actual_active_seconds,
                actual_evidence_bytes=actual_evidence_bytes,
            )
            if artifact.state != "active":
                self._release_runtime_session_locked(session_id, runtime_session)
                self._schedule_cleanup_locked()
            return artifact

    def close(self) -> None:
        """Revoke active authority and conservatively release this connection's resources."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._cleanup_timer is not None:
                self._cleanup_timer.cancel()
                self._cleanup_timer = None
            for session_id, runtime_session in tuple(self._sessions.items()):
                with suppress(PerfLensError):
                    self._authority.revoke(runtime_session.access)
                self._release_runtime_session_locked(session_id, runtime_session)
            self._sessions.clear()
            for pending in tuple(self._pending.values()):
                pending.adapter.close()
                _remove_private_directory(pending.private_directory)
            self._pending.clear()

    def _build_preview_artifact(
        self,
        *,
        runtime: DockerRuntimeCapabilityArtifact,
        capability: DockerBuildCapabilityArtifact,
        recipe: DockerBuildRecipeArtifact,
        context: DockerBuildContextArtifact,
        modes: tuple[OptimizationCollectionMode, ...],
    ) -> DockerOptimizationPreviewResult:
        now = self._wall_now()
        expires = now + timedelta(seconds=_PREVIEW_EXPIRY_SECONDS)
        planned = [
            "Build a fresh baseline from the captured authorized context after consent.",
            "Run correctness and Benchmark checks before accepting performance evidence.",
            "Let the Agent select bounded stat, record, or necessary Trace evidence.",
            "Modify only mutable paths, build at most three candidates, and run matched A/B.",
            "If evidence is not verified, ask once whether to retain the candidate or restore "
            "the baseline without changing the evidence verdict.",
            "Conservatively remove only verified session containers and temporary image tags.",
        ]
        if not capability.base_image_present:
            planned.insert(
                0,
                "After consent, fetch only the administrator-pinned base image digest.",
            )
        warnings: list[str] = []
        if recipe.mutable_dockerfile:
            warnings.append("The Dockerfile is mutable inside this authorization and is high risk.")
        if recipe.mutable_dependency_lock:
            warnings.append(
                "A dependency lock file is mutable inside this authorization and is high risk."
            )
        preview_id = derive_docker_optimization_preview_id(
            self._project.identity_sha256,
            recipe.content_sha256,
            context.content_sha256,
            now.isoformat(),
        )
        summary = _canonical_sha256(
            {
                "preview_id": preview_id,
                "project": self._project.identity_sha256,
                "client": self._client_identity,
                "policy": self._policy.sha256,
                "runtime": runtime.content_sha256,
                "capability": capability.content_sha256,
                "recipe": recipe.content_sha256,
                "context": context.content_sha256,
                "context_paths": self._policy.optimization.context_paths,
                "mutable_paths": self._policy.optimization.mutable_paths,
                "modes": modes,
                "budget": recipe.budget.model_dump(mode="json"),
                "actions": planned,
                "warnings": warnings,
            }
        )
        data = {
            "schema_version": "1.0",
            "perflens_version": __version__,
            "preview_id": preview_id,
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
            "project_identity_sha256": self._project.identity_sha256,
            "client_connection_identity_sha256": self._client_identity,
            "project_policy_sha256": self._policy.sha256,
            "runtime_capability_sha256": runtime.content_sha256,
            "build_capability_id": capability.capability_id,
            "build_capability_content_sha256": capability.content_sha256,
            "recipe_id": recipe.recipe_id,
            "recipe_content_sha256": recipe.content_sha256,
            "baseline_context_id": context.context_id,
            "baseline_context_content_sha256": context.content_sha256,
            "allowed_modes": modes,
            "network_tier": recipe.network_tier,
            "base_image_present": capability.base_image_present,
            "baseline_build_required": True,
            "context_paths": self._policy.optimization.context_paths,
            "mutable_paths": self._policy.optimization.mutable_paths,
            "mutable_dockerfile": recipe.mutable_dockerfile,
            "mutable_dependency_lock": recipe.mutable_dependency_lock,
            "budget": recipe.budget,
            "planned_actions": tuple(planned),
            "warnings": tuple(warnings),
            "authorization_summary_sha256": summary,
            "content_sha256": "0" * 64,
        }
        provisional = DockerOptimizationPreviewArtifact.model_validate(data)
        preview = DockerOptimizationPreviewArtifact.model_validate(
            {
                **provisional.model_dump(mode="json"),
                "content_sha256": contract_content_sha256(
                    provisional,
                    exclude={"content_sha256"},
                ),
            }
        )
        return DockerOptimizationPreviewResult(
            preview=preview,
            capability=capability,
            recipe=recipe,
            context=context,
        )

    def _require_runtime_session_locked(
        self,
        session_id: str,
        *,
        allow_inactive: bool = False,
    ) -> _OptimizationRuntimeSession:
        self._ensure_open_locked()
        runtime_session = self._sessions.get(session_id)
        if runtime_session is None:
            raise _authorization_error("Docker optimization session is unknown to this MCP")
        artifact = self._authority.snapshot(runtime_session.access)
        if artifact.state != "active":
            self._release_runtime_session_locked(session_id, runtime_session)
            self._schedule_cleanup_locked()
            if not allow_inactive:
                raise _authorization_error("Docker optimization session is no longer active")
        return runtime_session

    def _prune_pending_locked(self) -> None:
        now = self._wall_now()
        monotonic_now = self._monotonic_clock()
        expired = [
            preview_id
            for preview_id, pending in self._pending.items()
            if not pending.consumed
            and (
                now >= datetime.fromisoformat(pending.result.preview.expires_at)
                or monotonic_now >= pending.monotonic_expires_at
            )
        ]
        for preview_id in expired:
            pending = self._pending.pop(preview_id)
            pending.adapter.close()
            _remove_private_directory(pending.private_directory)

    def _prune_sessions_locked(self) -> None:
        inactive = [
            session_id
            for session_id, runtime_session in self._sessions.items()
            if self._authority.snapshot(runtime_session.access).state != "active"
        ]
        for session_id in inactive:
            runtime_session = self._sessions.pop(session_id)
            self._release_runtime_session_locked(session_id, runtime_session)

    def _release_runtime_session_locked(
        self,
        session_id: str,
        runtime_session: _OptimizationRuntimeSession,
    ) -> None:
        if runtime_session.resources_released:
            return
        for build in runtime_session.builds.values():
            with suppress(PerfLensError):
                runtime_session.preview.adapter.cleanup_build(
                    build,
                    session_identity_sha256=_session_identity_sha256(session_id),
                )
        runtime_session.preview.adapter.close()
        self._pending.pop(runtime_session.preview.result.preview.preview_id, None)
        _remove_private_directory(runtime_session.preview.private_directory)
        runtime_session.resources_released = True

    def _ensure_open_locked(self) -> None:
        if self._closed:
            raise _authorization_error("Docker optimization runtime is closed")

    def _schedule_cleanup_locked(self) -> None:
        if not self._cleanup_timer_enabled or self._closed:
            return
        if self._cleanup_timer is not None:
            self._cleanup_timer.cancel()
            self._cleanup_timer = None
        monotonic_now = self._monotonic_clock()
        wall_now = self._wall_now()
        delays = [
            max(0.0, pending.monotonic_expires_at - monotonic_now)
            for pending in self._pending.values()
            if not pending.consumed
        ]
        delays.extend(
            max(
                0.0,
                (datetime.fromisoformat(self._authority.snapshot(session.access).expires_at)
                - wall_now).total_seconds(),
            )
            for session in self._sessions.values()
            if self._authority.snapshot(session.access).state == "active"
        )
        if not delays:
            return
        timer = threading.Timer(max(0.01, min(min(delays), 60.0)), self._run_scheduled_cleanup)
        timer.daemon = True
        self._cleanup_timer = timer
        timer.start()

    def _run_scheduled_cleanup(self) -> None:
        with self._lock:
            self._cleanup_timer = None
            if self._closed:
                return
            self._prune_pending_locked()
            self._prune_sessions_locked()
            self._schedule_cleanup_locked()

    def _assert_project_current(self) -> None:
        assert_managed_project_current(self._project)
        assert_docker_project_policy_current(
            self._policy,
            allowed_roots=self._allowed_roots,
        )

    def _wall_now(self) -> datetime:
        value = self._wall_clock()
        if value.tzinfo is None:
            raise ValueError("Docker optimization wall clock must be timezone-aware")
        return value


def _safe_private_root(path: Path, *, uid: int) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _authorization_error("Docker optimization private root is unsafe")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise _authorization_error("Docker optimization private root is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _authorization_error("Docker optimization private root owner or mode is unsafe")
    return resolved


def _new_private_directory(root: Path) -> Path:
    value = Path(tempfile.mkdtemp(prefix="optimization-", dir=root))
    value.chmod(0o700)
    return value


def _remove_private_directory(path: Path) -> None:
    if not path.name.startswith("optimization-") or not path.is_absolute():
        return
    try:
        for child in path.iterdir():
            if child.is_file() and not child.is_symlink():
                child.unlink(missing_ok=True)
            else:
                return
        path.rmdir()
    except OSError:
        return


def _discard_snapshot(snapshot: DockerBuildContextSnapshot) -> None:
    try:
        snapshot.archive_path.unlink(missing_ok=True)
    except OSError:
        return


def _assert_snapshot_current(snapshot: DockerBuildContextSnapshot) -> None:
    from perflens.docker.build_context import assert_docker_build_context_snapshot_current

    assert_docker_build_context_snapshot_current(snapshot)


def _canonical_modes(
    modes: tuple[OptimizationCollectionMode, ...],
) -> tuple[OptimizationCollectionMode, ...]:
    if not modes or len(set(modes)) != len(modes):
        raise _authorization_error("Docker optimization modes must be non-empty and unique")
    try:
        canonical = tuple(sorted(modes, key=_CANONICAL_MODES.index))
    except ValueError as exc:
        raise _authorization_error("Docker optimization contains an unsupported mode") from exc
    if canonical != modes:
        raise _authorization_error("Docker optimization modes must use canonical order")
    return canonical


def _session_identity_sha256(session_id: str) -> str:
    payload = f"perflens-docker-optimization-session-v1\0{session_id}".encode()
    return hashlib.sha256(payload).hexdigest()


def _verify_content(artifact: DockerRuntimeCapabilityArtifact) -> None:
    if artifact.content_sha256 != contract_content_sha256(
        artifact,
        exclude={"content_sha256"},
    ):
        raise _authorization_error("Docker runtime capability content digest does not match")


def _verify_contract_content(artifact: BaseModel, label: str) -> None:
    expected = getattr(artifact, "content_sha256", None)
    if not isinstance(expected, str) or not hmac.compare_digest(
        expected,
        contract_content_sha256(artifact, exclude={"content_sha256"}),
    ):
        raise _authorization_error(f"{label} content digest does not match")


def _candidate_acceptance_receipt(
    *,
    source_session: DockerOptimizationSessionArtifact,
    iteration: DockerOptimizationIterationArtifact,
    selected_build: DockerBuildArtifact,
) -> str:
    return hashlib.sha256(
        b"\0".join(
            (
                b"perflens-unverified-docker-candidate-acceptance-v1",
                secrets.token_bytes(32),
                source_session.authorization_receipt_sha256.encode("ascii"),
                iteration.content_sha256.encode("ascii"),
                selected_build.content_sha256.encode("ascii"),
            )
        )
    ).hexdigest()


def _build_disposition_artifact(
    *,
    created_at: datetime,
    source_session: DockerOptimizationSessionArtifact,
    final_session: DockerOptimizationSessionArtifact,
    iteration: DockerOptimizationIterationArtifact,
    baseline: DockerBuildArtifact,
    candidate: DockerBuildArtifact,
    selected: DockerBuildArtifact,
    disposition: Literal["retain_candidate", "restore_baseline"],
    workspace_manifest_sha256: str,
    explicit_unverified_acceptance: bool,
    authorization_receipt_sha256: str | None,
) -> DockerOptimizationDispositionArtifact:
    if final_session.state != "revoked":
        raise _authorization_error("Docker optimization final Session was not revoked")
    warnings: list[str] = []
    if explicit_unverified_acceptance:
        warnings.append(
            "The user retained an unverified candidate; the original Iteration conclusion "
            "remains authoritative."
        )
    elif disposition == "restore_baseline":
        warnings.append(
            "The final workspace matched the baseline Build when the Session was revoked."
        )
    data: dict[str, object] = {
        "schema_version": "1.0",
        "perflens_version": __version__,
        "disposition_id": derive_docker_optimization_disposition_id(
            source_session.session_id,
            iteration.content_sha256,
            disposition,
            selected.content_sha256,
            final_session.content_sha256,
        ),
        "created_at": created_at.isoformat(),
        "session_id": source_session.session_id,
        "source_session_artifact_id": source_session.session_artifact_id,
        "source_session_artifact_content_sha256": source_session.content_sha256,
        "final_session_artifact_id": final_session.session_artifact_id,
        "final_session_artifact_content_sha256": final_session.content_sha256,
        "final_session_state": "revoked",
        "iteration_id": iteration.iteration_id,
        "iteration_content_sha256": iteration.content_sha256,
        "iteration_conclusion": iteration.conclusion,
        "disposition": disposition,
        "baseline_build_id": baseline.build_id,
        "baseline_build_content_sha256": baseline.content_sha256,
        "candidate_build_id": candidate.build_id,
        "candidate_build_content_sha256": candidate.content_sha256,
        "selected_build_id": selected.build_id,
        "selected_build_content_sha256": selected.content_sha256,
        "selected_treatment_manifest_sha256": selected.treatment_manifest_sha256,
        "workspace_mutable_manifest_sha256": workspace_manifest_sha256,
        "workspace_matches_selected_build": True,
        "explicit_unverified_acceptance": explicit_unverified_acceptance,
        "authorization_receipt_sha256": authorization_receipt_sha256,
        "warnings": tuple(warnings),
        "allowed_conclusions": (
            "This Artifact records only the final workspace choice and Session cleanup.",
            "The bound Iteration remains the authoritative performance verdict.",
        ),
        "forbidden_conclusions": (
            "Human acceptance must not be presented as Verified Improvement.",
            "Retaining or restoring source bytes does not alter the A/B evidence quality.",
        ),
        "content_sha256": "0" * 64,
    }
    provisional = DockerOptimizationDispositionArtifact.model_validate(data)
    return DockerOptimizationDispositionArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise _authorization_error(f"{label} must be a SHA-256 digest")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _authorization_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_optimization_runtime",
        message,
        recoverable=True,
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "docker_optimization_runtime",
        message,
        recoverable=True,
    )
