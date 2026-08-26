from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerBuilderProjection,
    DockerBuildToolProjection,
    OptimizationCollectionMode,
    derive_docker_build_artifact_id,
)
from perflens.docker.build_adapter import (
    DockerBuildExecutionResult,
    TypedDockerBuildAdapter,
)
from perflens.docker.build_context import DockerBuildContextSnapshot
from perflens.docker.optimization_runtime import DockerOptimizationRuntime
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
)
from perflens.docker.project_config import (
    DockerProjectPolicy,
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError

NOW = datetime(2026, 8, 24, tzinfo=UTC)
BASE_DIGEST = "sha256:" + "d" * 64


class _FakeBuildAdapter:
    def __init__(self, *, base_present: bool = True) -> None:
        self.base_present = base_present
        self.cleaned: list[str] = []
        self.close_count = 0
        self.build_error: BaseException | None = None
        self.cleanup_error: PerfLensError | None = None
        self.base_image_error: PerfLensError | None = None
        self.docker_tool_projection = DockerBuildToolProjection(
            tool="docker",
            version="29.7.2",
            binary_sha256="a" * 64,
        )
        self.buildx_tool_projection = DockerBuildToolProjection(
            tool="buildx",
            version="0.30.1",
            binary_sha256="b" * 64,
        )
        self.builder_projection = DockerBuilderProjection(
            driver="docker",
            identity_sha256="c" * 64,
            root_owned=False,
        )
        self.available_network_tiers = ("local_only",)

    def base_image_present(self, image_digest: str) -> bool:
        assert image_digest == BASE_DIGEST
        if self.base_image_error is not None:
            raise self.base_image_error
        return self.base_present

    def build(
        self,
        *,
        capability: DockerBuildCapabilityArtifact,
        policy: DockerProjectPolicy,
        snapshot: DockerBuildContextSnapshot,
        private_directory: Path,
        session_identity_sha256: str,
        build_kind: Literal["baseline", "candidate"],
        candidate_round: int,
        started_at: datetime | None = None,
    ) -> DockerBuildExecutionResult:
        del capability, private_directory, session_identity_sha256
        if self.build_error is not None:
            raise self.build_error
        assert build_kind in {"baseline", "candidate"}
        assert started_at is not None
        context = snapshot.artifact
        recipe = context.recipe_content_sha256
        digest = "sha256:" + hashlib.sha256(
            f"{context.archive_sha256}:{build_kind}:{candidate_round}".encode()
        ).hexdigest()
        finished_at = started_at
        data = {
            "schema_version": "1.0",
            "perflens_version": "0.3.2",
            "build_id": derive_docker_build_artifact_id(
                context.content_sha256,
                build_kind,
                candidate_round,
                digest,
                started_at.isoformat(),
            ),
            "build_kind": build_kind,
            "candidate_round": candidate_round,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "recipe_id": context.recipe_id,
            "recipe_content_sha256": recipe,
            "context_id": context.context_id,
            "context_content_sha256": context.content_sha256,
            "builder_identity_sha256": self.builder_projection.identity_sha256,
            "network_policy_sha256": "e" * 64,
            "final_image_digest": digest,
            "platform": policy.optimization.platform,
            "image_size_bytes": 4096,
            "iid_file_sha256": "1" * 64,
            "metadata_file_sha256": "2" * 64,
            "provenance_sha256": "3" * 64,
            "immutable_manifest_sha256": context.immutable_manifest_sha256,
            "treatment_manifest_sha256": context.mutable_manifest_sha256,
            "status": "verified",
            "cleanup_eligible": True,
            "limitations": (),
            "content_sha256": "0" * 64,
        }
        provisional = DockerBuildArtifact.model_validate(data)
        artifact = DockerBuildArtifact.model_validate(
            {
                **provisional.model_dump(mode="json"),
                "content_sha256": contract_content_sha256(
                    provisional,
                    exclude={"content_sha256"},
                ),
            }
        )
        return DockerBuildExecutionResult(
            artifact=artifact,
            temporary_tag=f"perflens-opt-{'f' * 20}:{build_kind}-{candidate_round}",
        )

    def cleanup_build(self, result: DockerBuildExecutionResult, **_: object) -> None:
        if self.cleanup_error is not None:
            raise self.cleanup_error
        self.cleaned.append(result.artifact.build_id)

    def close(self) -> None:
        self.close_count += 1


def _policy_text() -> str:
    return (
        render_default_docker_project_policy()
        .replace(
            'default_workflow = "existing_container"',
            'default_workflow = "managed_temporary_container"',
        )
        .replace(
            "allow_managed_temporary_containers = false",
            "allow_managed_temporary_containers = true",
        )
        .replace('entrypoint = ""', 'entrypoint = "/workspace/app"')
        .replace('container_user = ""', 'container_user = "1000:1000"')
        .replace('benchmark_output = ""', 'benchmark_output = "result.json"')
        .replace("enabled = false", "enabled = true")
        .replace("context_paths = []", 'context_paths = ["Dockerfile", "src"]')
        .replace("mutable_paths = []", 'mutable_paths = ["src"]')
        .replace('dockerfile = ""', 'dockerfile = "Dockerfile"')
        .replace('base_image_digest = ""', f'base_image_digest = "{BASE_DIGEST}"')
    )


def _runtime_capability() -> DockerRuntimeCapabilityArtifact:
    data = {
        "schema_version": "1.0",
        "perflens_version": "0.3.2",
        "capability_id": "docker-capability-" + "a" * 20,
        "checked_at": NOW.isoformat(),
        "status": "available",
        "endpoint_kind": "local_rootless",
        "daemon_mode": "rootless",
        "docker_cli": {
            "path": "/usr/bin/docker",
            "version": "29.7.2",
            "binary_sha256": "a" * 64,
        },
        "api_version": "1.55",
        "server_operating_system": "linux",
        "cgroup_version": "v2",
        "existing_container_discovery": True,
        "managed_container_execution": True,
        "content_sha256": "0" * 64,
    }
    provisional = DockerRuntimeCapabilityArtifact.model_validate(data)
    return DockerRuntimeCapabilityArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def make_optimization_runtime(
    tmp_path: Path,
    *,
    collector_modes: tuple[OptimizationCollectionMode, ...] = (
        "stat",
        "record",
        "sched",
        "off_cpu",
        "lock",
    ),
    base_present: bool = True,
    collector_available: bool = True,
    wall_clock: Callable[[], datetime] | None = None,
    monotonic_clock: Callable[[], float] | None = None,
) -> tuple[DockerOptimizationRuntime, Path, _FakeBuildAdapter]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    (project / "Dockerfile").write_text(
        f"FROM registry.example/base@{BASE_DIGEST}\nCOPY src/app /app\n",
        encoding="utf-8",
    )
    source = project / "src"
    source.mkdir()
    (source / "app").write_bytes(b"baseline")
    policy_path = project / "container-workload.toml"
    policy_path.write_text(_policy_text(), encoding="utf-8")
    policy_path.chmod(0o600)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    policy = load_docker_project_policy(policy_path, allowed_roots=(project,))
    identity = inspect_managed_project_root(project, invoking_uid=os.geteuid())
    adapter = _FakeBuildAdapter(base_present=base_present)
    runtime = DockerOptimizationRuntime(
        project=identity,
        project_policy=policy,
        allowed_roots=(project,),
        private_root=private,
        runtime_capability_factory=_runtime_capability,
        build_adapter_factory=lambda _private: cast(TypedDockerBuildAdapter, adapter),
        collector_available=lambda: collector_available,
        collector_modes=collector_modes,
        client_connection_identity_sha256="f" * 64,
        wall_clock=wall_clock or (lambda: NOW),
        monotonic_clock=monotonic_clock or (lambda: 100.0),
    )
    return runtime, project, adapter


def _authorize(runtime: DockerOptimizationRuntime):
    result = runtime.preview(allowed_modes=("stat", "record"))
    session = runtime.authorize(
        preview_id=result.preview.preview_id,
        preview_content_sha256=result.preview.content_sha256,
        authorization_summary_sha256=result.preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    )
    return result, session


def test_runtime_requires_preview_before_build_and_allows_one_consent_flow(
    tmp_path: Path,
) -> None:
    runtime, project, adapter = make_optimization_runtime(tmp_path)
    preview, session = _authorize(runtime)

    baseline = runtime.build(
        session.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate = runtime.build(
        session.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    lease = runtime.begin_workload(
        session.session_id,
        build_id=candidate.build.build_id,
        mode="record",
        reserve_active_seconds=30,
        reserve_evidence_bytes=1 << 20,
    )
    final = runtime.finish_workload(
        session.session_id,
        lease,
        actual_active_seconds=2.1,
        actual_evidence_bytes=1024,
    )

    assert preview.preview.baseline_build_required is True
    assert preview.preview.context_paths == ("Dockerfile", "src")
    assert preview.preview.mutable_paths == ("src",)
    assert baseline.session.baseline_build_id == baseline.build.build_id
    assert candidate.session.candidate_rounds_used == 1
    assert final.workload_runs_used == 1
    assert final.workload_active_seconds_used == 3
    assert final.evidence_bytes_used == 1024
    revoked = runtime.revoke(session.session_id)
    assert revoked.state == "revoked"
    assert adapter.cleaned == [baseline.build.build_id, candidate.build.build_id]


def test_runtime_rejects_changed_immutable_context_and_revokes(tmp_path: Path) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, session = _authorize(runtime)
    runtime.build(session.session_id, build_kind="baseline", candidate_round=0)
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (project / "src/app").write_bytes(b"candidate")

    with pytest.raises(PerfLensError) as captured:
        runtime.build(session.session_id, build_kind="candidate", candidate_round=1)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert runtime.snapshot(session.session_id).state == "revoked"


def test_runtime_rejects_collection_after_workspace_moves_past_build(tmp_path: Path) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, session = _authorize(runtime)
    baseline = runtime.build(session.session_id, build_kind="baseline", candidate_round=0)
    (project / "src/app").write_bytes(b"not-the-baseline")

    with pytest.raises(PerfLensError, match="no longer matches the selected Build"):
        runtime.begin_workload(
            session.session_id,
            build_id=baseline.build.build_id,
            mode="stat",
            reserve_active_seconds=30,
            reserve_evidence_bytes=1 << 20,
        )

    assert runtime.snapshot(session.session_id).state == "active"


def test_runtime_rejects_stale_or_replayed_preview(tmp_path: Path) -> None:
    runtime, _, _ = make_optimization_runtime(tmp_path)
    preview, _ = _authorize(runtime)

    with pytest.raises(PerfLensError):
        runtime.authorize(
            preview_id=preview.preview.preview_id,
            preview_content_sha256=preview.preview.content_sha256,
            authorization_summary_sha256=preview.preview.authorization_summary_sha256,
            explicit_authorization=EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
        )


def test_runtime_rejects_unavailable_collector_modes(tmp_path: Path) -> None:
    runtime, _, _ = make_optimization_runtime(
        tmp_path,
        collector_modes=("stat", "record"),
    )

    with pytest.raises(PerfLensError) as captured:
        runtime.preview(allowed_modes=("lock",))

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_runtime_capability_reports_tools_and_qualifies_adapter_failure(tmp_path: Path) -> None:
    runtime, _, adapter = make_optimization_runtime(tmp_path)

    available = runtime.inspect_capability()
    assert available.status == "available"
    assert available.base_image_present is True
    assert available.docker_tool is not None

    adapter.base_image_error = PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "test",
        "replacement",
        recoverable=False,
    )
    unavailable = runtime.inspect_capability()
    assert unavailable.status == "partial"
    assert unavailable.docker_tool is None
    assert unavailable.available_network_tiers == ()


@pytest.mark.parametrize(
    ("base_present", "collector_available"),
    ((False, True), (True, False)),
)
def test_runtime_preview_rejects_incomplete_capability(
    tmp_path: Path,
    base_present: bool,
    collector_available: bool,
) -> None:
    runtime, _, _ = make_optimization_runtime(
        tmp_path,
        base_present=base_present,
        collector_available=collector_available,
    )

    with pytest.raises(PerfLensError, match="capability is incomplete"):
        runtime.preview(allowed_modes=("stat",))


def test_runtime_preview_cleanup_and_capacity_are_bounded(tmp_path: Path) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    app = project / "src/app"
    app.unlink()
    os.mkfifo(app)
    try:
        with pytest.raises(PerfLensError):
            runtime.preview(allowed_modes=("stat",))
    finally:
        app.unlink()
        app.write_bytes(b"baseline")

    for index in range(16):
        app.write_bytes(f"baseline-{index}".encode())
        runtime.preview(allowed_modes=("stat",))
    app.write_bytes(b"capacity-overflow")
    with pytest.raises(PerfLensError) as captured:
        runtime.preview(allowed_modes=("stat",))
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_runtime_reclaims_expired_preview_on_next_interaction(tmp_path: Path) -> None:
    wall_now = [NOW]
    monotonic_now = [100.0]
    runtime, _, adapter = make_optimization_runtime(
        tmp_path,
        wall_clock=lambda: wall_now[0],
        monotonic_clock=lambda: monotonic_now[0],
    )
    runtime.preview(allowed_modes=("stat",))
    private_directory = next((tmp_path / "private").iterdir())
    assert private_directory.is_dir()

    wall_now[0] += timedelta(seconds=601)
    monotonic_now[0] += 601
    runtime.inspect_capability()

    assert not private_directory.exists()
    assert adapter.close_count >= 2


def test_runtime_reclaims_expired_session_and_close_is_idempotent(tmp_path: Path) -> None:
    wall_now = [NOW]
    monotonic_now = [100.0]
    runtime, _, adapter = make_optimization_runtime(
        tmp_path,
        wall_clock=lambda: wall_now[0],
        monotonic_clock=lambda: monotonic_now[0],
    )
    _, session = _authorize(runtime)
    baseline = runtime.build(session.session_id, build_kind="baseline", candidate_round=0)
    private_directory = next((tmp_path / "private").iterdir())

    wall_now[0] = datetime.fromisoformat(session.expires_at) + timedelta(seconds=1)
    monotonic_now[0] += 7201
    runtime.inspect_capability()

    assert adapter.cleaned == [baseline.build.build_id]
    assert not private_directory.exists()
    with pytest.raises(PerfLensError, match="unknown to this MCP"):
        runtime.snapshot(session.session_id)

    runtime.close()
    runtime.close()
    with pytest.raises(PerfLensError, match="runtime is closed"):
        runtime.inspect_capability()


def test_runtime_rejects_candidate_without_treatment_and_unknown_build(tmp_path: Path) -> None:
    runtime, _, _ = make_optimization_runtime(tmp_path)
    _, session = _authorize(runtime)
    runtime.build(session.session_id, build_kind="baseline", candidate_round=0)

    with pytest.raises(PerfLensError, match="no new authorized Treatment"):
        runtime.build(session.session_id, build_kind="candidate", candidate_round=1)
    with pytest.raises(PerfLensError, match="outside this optimization session"):
        runtime.build_result(session.session_id, "docker-build-" + "f" * 20)


@pytest.mark.parametrize(
    "error",
    (
        PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "test",
            "recoverable build failure",
            recoverable=True,
        ),
        RuntimeError("unexpected build failure"),
    ),
)
def test_runtime_accounts_for_build_failure_and_discards_candidate_snapshot(
    tmp_path: Path,
    error: BaseException,
) -> None:
    runtime, project, adapter = make_optimization_runtime(tmp_path)
    _, session = _authorize(runtime)
    runtime.build(session.session_id, build_kind="baseline", candidate_round=0)
    (project / "src/app").write_bytes(b"candidate")
    adapter.build_error = error

    with pytest.raises(type(error)):
        runtime.build(session.session_id, build_kind="candidate", candidate_round=1)

    snapshot = runtime.snapshot(session.session_id)
    assert snapshot.state == ("active" if isinstance(error, PerfLensError) else "failed")
    assert snapshot.builds_used == 2


def test_runtime_collection_rejects_immutable_drift_and_revokes(tmp_path: Path) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, session = _authorize(runtime)
    baseline = runtime.build(session.session_id, build_kind="baseline", candidate_round=0)
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    with pytest.raises(PerfLensError, match="immutable context changed"):
        runtime.begin_workload(
            session.session_id,
            build_id=baseline.build.build_id,
            mode="stat",
            reserve_active_seconds=1,
            reserve_evidence_bytes=1,
        )
    assert runtime.snapshot(session.session_id).state == "revoked"
    with pytest.raises(PerfLensError, match="no longer active"):
        runtime.build_recipe(session.session_id)


def test_runtime_revoke_is_idempotent_and_ignores_conservative_cleanup_failure(
    tmp_path: Path,
) -> None:
    runtime, _, adapter = make_optimization_runtime(tmp_path)
    _, session = _authorize(runtime)
    runtime.build(session.session_id, build_kind="baseline", candidate_round=0)
    adapter.cleanup_error = PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "test",
        "identity mismatch",
        recoverable=False,
    )

    assert runtime.revoke(session.session_id).state == "revoked"
    assert runtime.revoke(session.session_id).state == "revoked"
    with pytest.raises(PerfLensError, match="unknown to this MCP"):
        runtime.snapshot("docker-optimization-session-" + "0" * 20)


@pytest.mark.parametrize(
    "modes",
    (
        (),
        ("stat", "stat"),
        ("record", "stat"),
        cast(tuple[OptimizationCollectionMode, ...], ("bad",)),
    ),
)
def test_runtime_rejects_noncanonical_modes(
    tmp_path: Path,
    modes: tuple[OptimizationCollectionMode, ...],
) -> None:
    runtime, _, _ = make_optimization_runtime(tmp_path)
    with pytest.raises(PerfLensError):
        runtime.preview(allowed_modes=modes)


def test_runtime_rejects_naive_clock_and_unsafe_private_root(tmp_path: Path) -> None:
    naive_root = tmp_path / "naive"
    naive_root.mkdir()
    with pytest.raises(ValueError, match="timezone-aware"):
        runtime, _, _ = make_optimization_runtime(
            naive_root,
            wall_clock=lambda: datetime(2026, 8, 24),
        )
        runtime.inspect_capability()

    project_root = tmp_path / "unsafe-project"
    project_root.mkdir()
    runtime, _, _ = make_optimization_runtime(project_root)
    del runtime
    private = project_root / "private"
    private.chmod(0o755)
    policy = load_docker_project_policy(
        project_root / "project/container-workload.toml",
        allowed_roots=(project_root / "project",),
    )
    identity = inspect_managed_project_root(
        project_root / "project",
        invoking_uid=os.geteuid(),
    )
    with pytest.raises(PerfLensError, match="private root owner or mode is unsafe"):
        DockerOptimizationRuntime(
            project=identity,
            project_policy=policy,
            allowed_roots=(project_root / "project",),
            private_root=private,
            runtime_capability_factory=_runtime_capability,
            build_adapter_factory=lambda _private: cast(
                TypedDockerBuildAdapter, _FakeBuildAdapter()
            ),
            collector_available=lambda: True,
            collector_modes=("stat",),
        )
