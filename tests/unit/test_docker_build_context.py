from __future__ import annotations

import os
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import perflens.docker.build_context as build_context_module
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerBuildContextArtifact,
    DockerBuilderProjection,
    DockerBuildRecipeArtifact,
    DockerBuildToolProjection,
    derive_docker_build_artifact_id,
)
from perflens.docker.build_capability import project_docker_build_capability
from perflens.docker.build_context import (
    assert_docker_build_context_snapshot_current,
    build_docker_build_recipe,
    capture_docker_build_context,
)
from perflens.docker.project_config import (
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.domain.errors import ErrorCode, PerfLensError

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
NOW = datetime(2026, 8, 24, tzinfo=UTC)


def _enabled_policy_text(*, mutable_paths: str = '["src"]') -> str:
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
        .replace(
            "context_paths = []",
            'context_paths = ["Dockerfile", "src", "uv.lock"]',
        )
        .replace("mutable_paths = []", f"mutable_paths = {mutable_paths}")
        .replace('dockerfile = ""', 'dockerfile = "Dockerfile"')
        .replace(
            'base_image_digest = ""',
            'base_image_digest = "sha256:' + "d" * 64 + '"',
        )
    )


def _project(tmp_path: Path, *, mutable_paths: str = '["src"]') -> tuple[Path, Path, Path]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    (project / "Dockerfile").write_text("FROM scratch\nCOPY src/app /app\n", encoding="utf-8")
    source = project / "src"
    source.mkdir()
    (source / "app").write_bytes(b"binary-v1")
    (source / "current").symlink_to("app")
    (project / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    policy_path = project / "container-workload.toml"
    policy_path.write_text(
        _enabled_policy_text(mutable_paths=mutable_paths),
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return project, policy_path, private


def _recipe_and_policy(tmp_path: Path, *, mutable_paths: str = '["src"]'):
    project, policy_path, private = _project(tmp_path, mutable_paths=mutable_paths)
    policy = load_docker_project_policy(policy_path, allowed_roots=(project,))
    recipe = build_docker_build_recipe(
        policy,
        project_identity_sha256=SHA_A,
        created_at=NOW,
    )
    return project, private, policy, recipe


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
            "version": "29.0",
            "binary_sha256": SHA_A,
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


def test_recipe_and_snapshot_are_content_bound_private_and_deterministic(tmp_path: Path) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)

    first = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=private,
        created_at=NOW,
    )
    second_private = tmp_path / "private-two"
    second_private.mkdir(mode=0o700)
    second = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=second_private,
        created_at=NOW,
    )

    assert recipe.recipe_id.startswith("docker-build-recipe-")
    assert recipe.content_sha256 == contract_content_sha256(recipe, exclude={"content_sha256"})
    assert first.artifact.archive_sha256 == second.artifact.archive_sha256
    assert first.artifact.content_sha256 == second.artifact.content_sha256
    assert first.archive_path.parent == private
    assert first.archive_path.stat().st_mode & 0o777 == 0o400
    assert_docker_build_context_snapshot_current(first)
    assert first.artifact.regular_file_count == 3
    assert first.artifact.mutable_entry_count == 3
    assert len(first.artifact.entries) == 5
    public_json = first.artifact.model_dump_json()
    for private_value in ("Dockerfile", "src/app", str(project), str(first.archive_path)):
        assert private_value not in public_json
    with tarfile.open(first.archive_path, mode="r") as archive:
        assert archive.getnames() == ["Dockerfile", "src", "src/app", "src/current", "uv.lock"]
        assert archive.extractfile("src/app").read() == b"binary-v1"  # type: ignore[union-attr]


def test_snapshot_separates_mutable_and_immutable_manifests(tmp_path: Path) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    baseline = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=private,
        created_at=NOW,
    )
    (project / "src/app").write_bytes(b"binary-v2")
    candidate = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=private,
        created_at=NOW,
    )

    assert baseline.artifact.immutable_manifest_sha256 == (
        candidate.artifact.immutable_manifest_sha256
    )
    assert baseline.artifact.mutable_manifest_sha256 != candidate.artifact.mutable_manifest_sha256
    assert baseline.artifact.archive_sha256 != candidate.artifact.archive_sha256


def test_recipe_marks_mutable_dockerfile_and_dependency_lock_as_high_risk(tmp_path: Path) -> None:
    _, _, _, recipe = _recipe_and_policy(
        tmp_path,
        mutable_paths='["Dockerfile", "src", "uv.lock"]',
    )
    assert recipe.mutable_dockerfile is True
    assert recipe.mutable_dependency_lock is True


@pytest.mark.parametrize(
    "unsafe_kind",
    ("absolute", "outside", "uncaptured", "indirect_uncaptured"),
)
def test_snapshot_rejects_unsafe_symlink_targets(tmp_path: Path, unsafe_kind: str) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    link = project / "src/current"
    link.unlink()
    if unsafe_kind == "absolute":
        link.symlink_to("/etc/passwd")
    elif unsafe_kind == "outside":
        outside = tmp_path / "outside"
        outside.write_text("private", encoding="utf-8")
        link.symlink_to("../../outside")
    elif unsafe_kind == "uncaptured":
        (project / "other").write_text("not captured", encoding="utf-8")
        link.symlink_to("../other")
    else:
        (project / "other").write_text("not captured", encoding="utf-8")
        (project / "src/second").symlink_to("../other")
        link.symlink_to("second")

    with pytest.raises(PerfLensError) as captured:
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_snapshot_rejects_forbidden_metadata_and_special_files(tmp_path: Path) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    forbidden = project / "src/.git"
    forbidden.mkdir()
    (forbidden / "config").write_text("secret", encoding="utf-8")
    with pytest.raises(PerfLensError):
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    for child in forbidden.iterdir():
        child.unlink()
    forbidden.rmdir()
    fifo = project / "src/channel"
    os.mkfifo(fifo)
    with pytest.raises(PerfLensError) as captured:
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_snapshot_rejects_writable_hardlinked_and_oversized_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    source = project / "src/app"
    source.chmod(0o666)
    with pytest.raises(PerfLensError):
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    source.chmod(0o644)
    hardlink = project / "src/hardlink"
    os.link(source, hardlink)
    with pytest.raises(PerfLensError):
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    hardlink.unlink()
    monkeypatch.setattr(build_context_module, "_MAX_CONTEXT_FILE_BYTES", 1)
    with pytest.raises(PerfLensError) as captured:
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_snapshot_rejects_toctou_before_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    source = project / "src/app"
    real_open = os.open
    source_open_count = 0

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal source_open_count
        if os.fsdecode(path) == str(source):
            source_open_count += 1
            if source_open_count == 2:
                source.write_bytes(b"replacement-with-new-identity")
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(build_context_module.os, "open", racing_open)
    with pytest.raises(PerfLensError):
        capture_docker_build_context(
            policy,
            recipe,
            project_root=project,
            private_directory=private,
        )
    assert not tuple(private.glob("*.tar"))


def test_snapshot_revalidation_rejects_replacement_and_content_change(tmp_path: Path) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    snapshot = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=private,
        created_at=NOW,
    )
    snapshot.archive_path.chmod(0o600)
    snapshot.archive_path.write_bytes(b"replacement")
    snapshot.archive_path.chmod(0o400)

    with pytest.raises(PerfLensError) as captured:
        assert_docker_build_context_snapshot_current(snapshot)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_build_contracts_reject_forged_counts_ids_and_unready_capabilities() -> None:
    capability = {
        "schema_version": "1.0",
        "perflens_version": "0.3.2",
        "capability_id": "docker-build-capability-" + "a" * 20,
        "checked_at": NOW.isoformat(),
        "status": "available",
        "runtime_capability_sha256": SHA_A,
        "project_policy_sha256": SHA_B,
        "docker_tool": {"tool": "docker", "version": "29.0", "binary_sha256": SHA_A},
        "buildx_tool": {"tool": "buildx", "version": "0.30", "binary_sha256": SHA_B},
        "builder": {
            "driver": "docker",
            "identity_sha256": SHA_C,
            "root_owned": True,
        },
        "available_network_tiers": ["local_only"],
        "base_image_present": True,
        "benchmark_configured": True,
        "collector_available": True,
        "build_supported": True,
        "content_sha256": SHA_C,
    }
    assert DockerBuildCapabilityArtifact.model_validate(capability).build_supported
    capability["benchmark_configured"] = False
    with pytest.raises(ValidationError):
        DockerBuildCapabilityArtifact.model_validate(capability)
    capability["benchmark_configured"] = True
    capability["available_network_tiers"] = ["local_only", "admin_builder_network"]
    with pytest.raises(ValidationError):
        DockerBuildCapabilityArtifact.model_validate(capability)


def test_build_capability_projection_is_read_only_content_bound_and_explains_limits(
    tmp_path: Path,
) -> None:
    _, _, policy, _ = _recipe_and_policy(tmp_path)
    docker_tool = DockerBuildToolProjection(
        tool="docker",
        version="29.0",
        binary_sha256=SHA_A,
    )
    buildx_tool = DockerBuildToolProjection(
        tool="buildx",
        version="0.30",
        binary_sha256=SHA_B,
    )
    builder = DockerBuilderProjection(
        driver="docker",
        identity_sha256=SHA_C,
        root_owned=True,
    )
    available = project_docker_build_capability(
        runtime=_runtime_capability(),
        policy=policy,
        docker_tool=docker_tool,
        buildx_tool=buildx_tool,
        builder=builder,
        available_network_tiers=("local_only",),
        base_image_present=True,
        collector_available=True,
        checked_at=NOW,
    )
    assert available.status == "available"
    assert available.build_supported is True
    assert available.content_sha256 == contract_content_sha256(
        available,
        exclude={"content_sha256"},
    )
    assert "/usr/bin/docker" not in available.model_dump_json()

    partial = project_docker_build_capability(
        runtime=_runtime_capability(),
        policy=policy,
        docker_tool=docker_tool,
        buildx_tool=buildx_tool,
        builder=builder,
        available_network_tiers=("local_only",),
        base_image_present=False,
        collector_available=True,
        checked_at=NOW,
    )
    assert partial.status == "partial"
    assert partial.build_supported is False
    assert "exact base image digest" in partial.limitations[0]

    tampered_runtime = _runtime_capability().model_copy(update={"content_sha256": SHA_B})
    with pytest.raises(PerfLensError):
        project_docker_build_capability(
            runtime=tampered_runtime,
            policy=policy,
            docker_tool=docker_tool,
            buildx_tool=buildx_tool,
            builder=builder,
            available_network_tiers=("local_only",),
            base_image_present=True,
            collector_available=True,
            checked_at=NOW,
        )


def test_build_artifact_binds_context_round_and_time() -> None:
    context_sha = SHA_A
    payload = {
        "schema_version": "1.0",
        "perflens_version": "0.3.2",
        "build_id": derive_docker_build_artifact_id(
            context_sha,
            "baseline",
            0,
            "sha256:" + "d" * 64,
            NOW.isoformat(),
        ),
        "build_kind": "baseline",
        "candidate_round": 0,
        "started_at": NOW.isoformat(),
        "finished_at": NOW.isoformat(),
        "recipe_id": "docker-build-recipe-" + "a" * 20,
        "recipe_content_sha256": SHA_B,
        "context_id": "docker-build-context-" + "a" * 20,
        "context_content_sha256": context_sha,
        "builder_identity_sha256": SHA_B,
        "network_policy_sha256": SHA_C,
        "final_image_digest": "sha256:" + "d" * 64,
        "platform": "linux/amd64",
        "image_size_bytes": 1024,
        "iid_file_sha256": SHA_A,
        "metadata_file_sha256": SHA_B,
        "provenance_sha256": SHA_C,
        "immutable_manifest_sha256": SHA_A,
        "treatment_manifest_sha256": SHA_B,
        "cleanup_eligible": True,
        "content_sha256": SHA_C,
    }
    assert DockerBuildArtifact.model_validate(payload).build_kind == "baseline"
    payload["candidate_round"] = 1
    with pytest.raises(ValidationError):
        DockerBuildArtifact.model_validate(payload)


def test_context_contract_rejects_forged_entry_count(tmp_path: Path) -> None:
    project, private, policy, recipe = _recipe_and_policy(tmp_path)
    snapshot = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=private,
        created_at=NOW,
    )
    payload = snapshot.artifact.model_dump(mode="json")
    payload["entry_count"] += 1
    with pytest.raises(ValidationError):
        DockerBuildContextArtifact.model_validate(payload)
    payload = snapshot.artifact.model_dump(mode="json")
    payload["total_regular_bytes"] += 1
    with pytest.raises(ValidationError):
        DockerBuildContextArtifact.model_validate(payload)
    payload = snapshot.artifact.model_dump(mode="json")
    payload["mutable_manifest_sha256"] = SHA_B
    with pytest.raises(ValidationError):
        DockerBuildContextArtifact.model_validate(payload)
    with pytest.raises(ValidationError):
        DockerBuildRecipeArtifact.model_validate(
            {**recipe.model_dump(mode="json"), "recipe_id": "docker-build-recipe-" + "f" * 20}
        )
