from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
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
        self.cleaned.append(result.artifact.build_id)


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
    adapter = _FakeBuildAdapter()
    runtime = DockerOptimizationRuntime(
        project=identity,
        project_policy=policy,
        allowed_roots=(project,),
        private_root=private,
        runtime_capability_factory=_runtime_capability,
        build_adapter_factory=lambda: cast(TypedDockerBuildAdapter, adapter),
        collector_available=lambda: True,
        collector_modes=collector_modes,
        client_connection_identity_sha256="f" * 64,
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 100.0,
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
