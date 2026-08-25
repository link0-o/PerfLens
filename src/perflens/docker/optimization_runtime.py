"""Project-bound orchestration for one-confirmation Docker optimization sessions."""

from __future__ import annotations

import hashlib
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

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerBuildContextArtifact,
    DockerBuildRecipeArtifact,
    DockerOptimizationPreviewArtifact,
    DockerOptimizationSessionArtifact,
    OptimizationCollectionMode,
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

    def inspect_capability(self) -> DockerBuildCapabilityArtifact:
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
            self._prune_pending_locked()
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
            raise
        with self._lock:
            runtime_session.builds[execution_result.artifact.build_id] = execution_result
            runtime_session.latest_treatment_manifest_sha256 = (
                snapshot.artifact.mutable_manifest_sha256
            )
            if snapshot is not pending.snapshot:
                _discard_snapshot(snapshot)
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
            for build in runtime_session.builds.values():
                try:
                    runtime_session.preview.adapter.cleanup_build(
                        build,
                        session_identity_sha256=_session_identity_sha256(session_id),
                    )
                except PerfLensError:
                    continue
            runtime_session.preview.adapter.close()
            _remove_private_directory(runtime_session.preview.private_directory)
            return artifact

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
            return self._authority.finish_workload(
                runtime_session.access,
                lease,
                actual_active_seconds=actual_active_seconds,
                actual_evidence_bytes=actual_evidence_bytes,
            )

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
        runtime_session = self._sessions.get(session_id)
        if runtime_session is None:
            raise _authorization_error("Docker optimization session is unknown to this MCP")
        artifact = self._authority.snapshot(runtime_session.access)
        if not allow_inactive and artifact.state != "active":
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
        while len(self._sessions) >= _MAX_ACTIVE_SESSIONS and inactive:
            session_id = inactive.pop(0)
            runtime_session = self._sessions.pop(session_id)
            for build in runtime_session.builds.values():
                with suppress(PerfLensError):
                    runtime_session.preview.adapter.cleanup_build(
                        build,
                        session_identity_sha256=_session_identity_sha256(session_id),
                    )
            runtime_session.preview.adapter.close()
            self._pending.pop(runtime_session.preview.result.preview.preview_id, None)
            _remove_private_directory(runtime_session.preview.private_directory)

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
