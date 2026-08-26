from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerBuilderProjection,
    DockerBuildToolProjection,
    DockerOptimizationIterationArtifact,
    DockerOptimizationSessionArtifact,
    OptimizationCollectionMode,
    derive_docker_build_artifact_id,
    derive_docker_optimization_iteration_id,
)
from perflens.docker.build_adapter import (
    DockerBuildExecutionResult,
    TypedDockerBuildAdapter,
)
from perflens.docker.build_context import DockerBuildContextSnapshot
from perflens.docker.optimization_runtime import DockerOptimizationRuntime
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE,
)
from perflens.docker.project_config import (
    DockerProjectPolicy,
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy

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
    data: dict[str, object] = {
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


def make_optimization_iteration(
    session: DockerOptimizationSessionArtifact,
    baseline: DockerBuildArtifact,
    candidate: DockerBuildArtifact,
    *,
    conclusion: Literal[
        "verified_improvement",
        "candidate_improvement",
        "candidate_regression",
        "no_material_change",
        "not_comparable",
    ] = "not_comparable",
) -> DockerOptimizationIterationArtifact:
    comparable = conclusion != "not_comparable"
    data: dict[str, object] = {
        "schema_version": "1.0",
        "perflens_version": "0.3.2",
        "iteration_id": derive_docker_optimization_iteration_id(
            session.session_id,
            baseline.build_id,
            candidate.build_id,
            "1" * 64,
            "2" * 64,
        ),
        "created_at": NOW.isoformat(),
        "session_id": session.session_id,
        "session_artifact_id": session.session_artifact_id,
        "session_artifact_content_sha256": session.content_sha256,
        "candidate_round": candidate.candidate_round,
        "baseline_build_id": baseline.build_id,
        "baseline_build_content_sha256": baseline.content_sha256,
        "candidate_build_id": candidate.build_id,
        "candidate_build_content_sha256": candidate.content_sha256,
        "baseline_measurement_id": "container-measurement-" + "1" * 20,
        "baseline_measurement_content_sha256": "1" * 64,
        "candidate_measurement_id": "container-measurement-" + "2" * 20,
        "candidate_measurement_content_sha256": "2" * 64,
        "baseline_analysis_id": "analysis-" + "1" * 16,
        "baseline_analysis_content_sha256": "3" * 64,
        "candidate_analysis_id": "analysis-" + "2" * 16,
        "candidate_analysis_content_sha256": "4" * 64,
        "profile_comparison_id": "profile-comparison-" + "3" * 16,
        "profile_comparison_content_sha256": "5" * 64,
        "baseline_benchmark_id": "benchmark-" + "1" * 16,
        "baseline_benchmark_content_sha256": "6" * 64,
        "candidate_benchmark_id": "benchmark-" + "2" * 16,
        "candidate_benchmark_content_sha256": "7" * 64,
        "benchmark_comparison_id": "benchmark-comparison-" + "4" * 16,
        "benchmark_comparison_content_sha256": "8" * 64,
        "source_container_comparison_id": "container-comparison-" + "5" * 20,
        "source_container_comparison_content_sha256": "9" * 64,
        "fixed_environment_match": True,
        "fixed_environment_differences": {},
        "treatment_changed": True,
        "correctness_status": "passed",
        "actual_event_source_match": True,
        "resource_transfer_status": "no_observed_regression",
        "deterministic_replay_passed": True,
        "comparable": comparable,
        "conclusion": conclusion,
        "improved_metrics": (
            ("wall_time",) if conclusion == "verified_improvement" else ()
        ),
        "regressed_metrics": (),
        "warnings": (),
        "allowed_conclusions": ("Bounded test conclusion.",),
        "forbidden_conclusions": ("No stronger conclusion.",),
        "content_sha256": "0" * 64,
    }
    provisional = DockerOptimizationIterationArtifact.model_validate(data)
    return DockerOptimizationIterationArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


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
    assert any(
        "3 candidate round(s) within 4 total build(s)" in action
        for action in preview.preview.planned_actions
    )
    assert baseline.session.baseline_build_id == baseline.build.build_id
    assert candidate.session.candidate_rounds_used == 1
    assert final.workload_runs_used == 1
    assert final.workload_active_seconds_used == 3
    assert final.evidence_bytes_used == 1024
    revoked = runtime.revoke(session.session_id)
    assert revoked.state == "revoked"
    assert adapter.cleaned == [baseline.build.build_id, candidate.build.build_id]


def test_failed_workload_is_charged_and_blocks_unchanged_session_retries(
    tmp_path: Path,
) -> None:
    runtime, project, adapter = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    lease = runtime.begin_workload(
        authorized.session_id,
        build_id=baseline.build.build_id,
        mode="stat",
        reserve_active_seconds=30,
        reserve_evidence_bytes=1 << 20,
    )

    failed = runtime.fail_workload(
        authorized.session_id,
        lease,
        actual_active_seconds=2.1,
        reason="perf control binding failed",
    )

    assert failed.state == "active"
    assert failed.workload_runs_used == 1
    assert failed.workload_active_seconds_used == 3
    assert failed.evidence_bytes_used == 0
    with pytest.raises(PerfLensError, match="stopped after a failed attempt") as retry:
        runtime.begin_workload(
            authorized.session_id,
            build_id=baseline.build.build_id,
            mode="record",
            reserve_active_seconds=30,
            reserve_evidence_bytes=1 << 20,
        )
    assert retry.value.recoverable is False
    assert retry.value.retryable is False
    assert retry.value.details["automatic_retry_allowed"] is False

    (project / "src/app").write_bytes(b"candidate-after-failure")
    with pytest.raises(PerfLensError, match="stopped after a failed attempt"):
        runtime.build(
            authorized.session_id,
            build_kind="candidate",
            candidate_round=1,
        )

    revoked = runtime.revoke(authorized.session_id)
    assert revoked.state == "revoked"
    assert adapter.cleaned == [baseline.build.build_id]


def test_runtime_finalizes_unevaluated_candidate_after_collection_failure(
    tmp_path: Path,
) -> None:
    runtime, project, adapter = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    lease = runtime.begin_workload(
        authorized.session_id,
        build_id=candidate.build.build_id,
        mode="record",
        reserve_active_seconds=30,
        reserve_evidence_bytes=1 << 20,
    )
    failed_session = runtime.fail_workload(
        authorized.session_id,
        lease,
        actual_active_seconds=1,
        reason="perf control binding failed",
    )

    with pytest.raises(PerfLensError, match="requires fresh explicit consent"):
        runtime.finalize_candidate(
            authorized.session_id,
            candidate_build_id=candidate.build.build_id,
            evaluation_reason="collection_failed",
            disposition="retain_candidate",
        )

    result = runtime.finalize_candidate(
        authorized.session_id,
        candidate_build_id=candidate.build.build_id,
        evaluation_reason="collection_failed",
        disposition="retain_candidate",
        explicit_unverified_acceptance=(
            EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
        ),
    )

    assert failed_session.workload_runs_used == 1
    assert result.session.state == "revoked"
    assert result.disposition.iteration_id is None
    assert result.disposition.iteration_content_sha256 is None
    assert result.disposition.iteration_conclusion == "not_evaluated"
    assert result.disposition.evaluation_reason == "collection_failed"
    assert result.disposition.selected_build_id == candidate.build.build_id
    assert result.disposition.explicit_unverified_acceptance is True
    assert result.disposition.authorization_receipt_sha256 is not None
    assert "No A/B Iteration was created" in result.disposition.allowed_conclusions[1]
    assert (project / "src/app").read_bytes() == b"candidate"
    assert adapter.cleaned == [baseline.build.build_id, candidate.build.build_id]
    payload = result.disposition.model_dump(mode="json")
    for update in (
        {"evaluation_reason": None},
        {"iteration_conclusion": "not_comparable"},
        {"iteration_id": "docker-optimization-iteration-" + "0" * 20},
    ):
        with pytest.raises(ValidationError):
            result.disposition.__class__.model_validate({**payload, **update})
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    store = ArtifactStore(
        artifact_root,
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    store.save(
        failed_session,
        failed_session.session_artifact_id,
        "docker-optimization-session",
    )
    store.save(
        result.session,
        result.session.session_artifact_id,
        "docker-optimization-session",
    )
    store.save(baseline.build, baseline.build.build_id, "docker-build")
    store.save(candidate.build, candidate.build.build_id, "docker-build")
    store.save(
        result.disposition,
        result.disposition.disposition_id,
        "docker-optimization-disposition",
    )
    assert (
        store.load_docker_optimization_disposition(result.disposition.disposition_id)
        == result.disposition
    )


def test_runtime_restores_unevaluated_candidate_without_acceptance(
    tmp_path: Path,
) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    (project / "src/app").write_bytes(b"baseline")

    result = runtime.finalize_candidate(
        authorized.session_id,
        candidate_build_id=candidate.build.build_id,
        evaluation_reason="user_stopped",
        disposition="restore_baseline",
    )

    assert result.session.state == "revoked"
    assert result.disposition.iteration_conclusion == "not_evaluated"
    assert result.disposition.evaluation_reason == "user_stopped"
    assert result.disposition.selected_build_id == baseline.build.build_id
    assert result.disposition.explicit_unverified_acceptance is False
    assert result.disposition.authorization_receipt_sha256 is None


@pytest.mark.parametrize(
    "conclusion",
    (
        "candidate_improvement",
        "candidate_regression",
        "no_material_change",
        "not_comparable",
    ),
)
def test_runtime_requires_fresh_consent_to_retain_unverified_candidate(
    tmp_path: Path,
    conclusion: Literal[
        "candidate_improvement",
        "candidate_regression",
        "no_material_change",
        "not_comparable",
    ],
) -> None:
    runtime, project, adapter = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline_result = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate_result = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    iteration = make_optimization_iteration(
        candidate_result.session,
        baseline_result.build,
        candidate_result.build,
        conclusion=conclusion,
    )

    with pytest.raises(PerfLensError, match="requires fresh explicit consent"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=iteration,
            disposition="retain_candidate",
        )

    assert runtime.snapshot(authorized.session_id).state == "active"
    result = runtime.finalize_candidate(
        authorized.session_id,
        iteration=iteration,
        disposition="retain_candidate",
        explicit_unverified_acceptance=(
            EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
        ),
    )

    assert result.session.state == "revoked"
    assert result.disposition.disposition == "retain_candidate"
    assert result.disposition.iteration_conclusion == conclusion
    assert result.disposition.explicit_unverified_acceptance is True
    assert result.disposition.authorization_receipt_sha256 is not None
    assert result.disposition.selected_build_id == candidate_result.build.build_id
    assert (project / "src/app").read_bytes() == b"candidate"
    assert adapter.cleaned == [
        baseline_result.build.build_id,
        candidate_result.build.build_id,
    ]
    payload = result.disposition.model_dump(mode="json")
    invalid_updates: tuple[dict[str, object], ...] = (
        {"final_session_artifact_id": result.disposition.source_session_artifact_id},
        {"candidate_build_id": result.disposition.baseline_build_id},
        {"selected_build_id": result.disposition.baseline_build_id},
        {"workspace_mutable_manifest_sha256": "0" * 64},
        {"explicit_unverified_acceptance": False},
        {"authorization_receipt_sha256": None},
        {"allowed_conclusions": ()},
        {"disposition_id": "docker-optimization-disposition-" + "0" * 20},
    )
    for update in invalid_updates:
        with pytest.raises(ValidationError):
            result.disposition.__class__.model_validate({**payload, **update})


def test_runtime_finalizes_restored_baseline_without_unverified_acceptance(
    tmp_path: Path,
) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline_result = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate_result = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    iteration = make_optimization_iteration(
        candidate_result.session,
        baseline_result.build,
        candidate_result.build,
    )
    (project / "src/app").write_bytes(b"baseline")

    with pytest.raises(PerfLensError, match="does not require it"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=iteration,
            disposition="restore_baseline",
            explicit_unverified_acceptance=(
                EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
            ),
        )

    result = runtime.finalize_candidate(
        authorized.session_id,
        iteration=iteration,
        disposition="restore_baseline",
    )

    assert result.session.state == "revoked"
    assert result.disposition.disposition == "restore_baseline"
    assert result.disposition.explicit_unverified_acceptance is False
    assert result.disposition.authorization_receipt_sha256 is None
    assert result.disposition.selected_build_id == baseline_result.build.build_id


def test_runtime_rejects_disposition_when_workspace_or_iteration_changed(
    tmp_path: Path,
) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline_result = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate_result = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    iteration = make_optimization_iteration(
        candidate_result.session,
        baseline_result.build,
        candidate_result.build,
    )

    with pytest.raises(PerfLensError, match="does not match the selected final Build"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=iteration,
            disposition="restore_baseline",
        )
    wrong_session = iteration.model_copy(
        update={
            "session_artifact_id": "docker-optimization-session-state-" + "0" * 20,
            "session_artifact_content_sha256": "0" * 64,
            "content_sha256": "0" * 64,
        }
    )
    wrong_session = wrong_session.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                wrong_session,
                exclude={"content_sha256"},
            )
        }
    )
    with pytest.raises(PerfLensError, match="differs from the current Session"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=wrong_session,
            disposition="retain_candidate",
            explicit_unverified_acceptance=(
                EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
            ),
        )
    wrong_build = iteration.model_copy(
        update={
            "baseline_build_content_sha256": "0" * 64,
            "content_sha256": "0" * 64,
        }
    )
    wrong_build = wrong_build.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                wrong_build,
                exclude={"content_sha256"},
            )
        }
    )
    with pytest.raises(PerfLensError, match="Build is outside the current Session"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=wrong_build,
            disposition="retain_candidate",
            explicit_unverified_acceptance=(
                EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
            ),
        )
    forged = iteration.model_copy(update={"content_sha256": "0" * 64})
    with pytest.raises(PerfLensError, match="content digest does not match"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=forged,
            disposition="retain_candidate",
            explicit_unverified_acceptance=(
                EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
            ),
        )
    assert runtime.snapshot(authorized.session_id).state == "active"


def test_runtime_revokes_finalization_after_immutable_context_drift(
    tmp_path: Path,
) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline_result = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate_result = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    iteration = make_optimization_iteration(
        candidate_result.session,
        baseline_result.build,
        candidate_result.build,
    )
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    with pytest.raises(PerfLensError, match="immutable context changed"):
        runtime.finalize_candidate(
            authorized.session_id,
            iteration=iteration,
            disposition="retain_candidate",
            explicit_unverified_acceptance=(
                EXPLICIT_UNVERIFIED_DOCKER_CANDIDATE_ACCEPTANCE
            ),
        )

    assert runtime.snapshot(authorized.session_id).state == "revoked"


def test_runtime_retains_verified_candidate_without_second_acceptance(
    tmp_path: Path,
) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    _, authorized = _authorize(runtime)
    baseline_result = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    (project / "src/app").write_bytes(b"candidate")
    candidate_result = runtime.build(
        authorized.session_id,
        build_kind="candidate",
        candidate_round=1,
    )
    iteration = make_optimization_iteration(
        candidate_result.session,
        baseline_result.build,
        candidate_result.build,
        conclusion="verified_improvement",
    )

    result = runtime.finalize_candidate(
        authorized.session_id,
        iteration=iteration,
        disposition="retain_candidate",
    )

    assert result.disposition.explicit_unverified_acceptance is False
    assert result.disposition.authorization_receipt_sha256 is None


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
