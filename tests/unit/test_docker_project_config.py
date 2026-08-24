from __future__ import annotations

from pathlib import Path

import pytest

from perflens.docker.project_config import (
    assert_docker_project_policy_current,
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def _policy(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    path = project / "container-workload.toml"
    path.write_text(render_default_docker_project_policy(), encoding="utf-8")
    path.chmod(0o600)
    return path


def _legacy_policy_text() -> str:
    current = render_default_docker_project_policy()
    return current.split("\n[optimization]", 1)[0].replace(
        'schema_version = "1.1"', 'schema_version = "1.0"'
    )


def _enabled_optimization_policy_text() -> str:
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
        .replace('entrypoint = ""', 'entrypoint = "/workspace/bin/workload"')
        .replace('container_user = ""', 'container_user = "1000:1000"')
        .replace('benchmark_output = ""', 'benchmark_output = "result.json"')
        .replace("enabled = false", "enabled = true")
        .replace("context_paths = []", 'context_paths = ["Dockerfile", "src", "lock.txt"]')
        .replace("mutable_paths = []", 'mutable_paths = ["src"]')
        .replace('dockerfile = ""', 'dockerfile = "Dockerfile"')
        .replace(
            'base_image_digest = ""',
            'base_image_digest = "sha256:' + "a" * 64 + '"',
        )
    )


def test_project_policy_is_strict_bounded_and_identity_pinned(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    policy = load_docker_project_policy(path, allowed_roots=(path.parent,))

    assert policy.schema_version == "1.1"
    assert policy.default_workflow == "existing_container"
    assert policy.default_authorization_mode == "per_run"
    assert policy.allow_managed_temporary_containers is False
    assert policy.max_workload_runs == 6
    assert policy.trace_max_duration_seconds == 10
    assert policy.managed.working_directory == "/workspace"
    assert policy.managed.arguments == ()
    assert policy.managed.treatment_paths == ()
    assert policy.managed.benchmark_output == ""
    assert policy.managed.benchmark_format == "auto"
    assert policy.managed.benchmark_name is None
    assert policy.optimization.enabled is False
    assert policy.optimization.max_candidate_rounds == 3
    assert policy.optimization.max_builds == 4
    assert policy.optimization.max_workload_runs == 10
    assert_docker_project_policy_current(policy, allowed_roots=(path.parent,))

    path.write_text(
        render_default_docker_project_policy().replace(
            "max_workload_runs = 6", "max_workload_runs = 5"
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(PerfLensError) as replaced:
        assert_docker_project_policy_current(policy, allowed_roots=(path.parent,))
    assert replaced.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_project_policy_strictly_reads_legacy_schema_1_0(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    path.write_text(_legacy_policy_text(), encoding="utf-8")
    path.chmod(0o600)

    policy = load_docker_project_policy(path, allowed_roots=(path.parent,))

    assert policy.schema_version == "1.0"
    assert policy.optimization.enabled is False
    assert policy.optimization.context_paths == ()
    assert policy.optimization.network_tier == "local_only"

    path.write_text(
        _legacy_policy_text() + "\n[optimization]\nenabled = false\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(PerfLensError):
        load_docker_project_policy(path, allowed_roots=(path.parent,))


def test_project_policy_accepts_bounded_schema_1_1_optimization(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    path.write_text(_enabled_optimization_policy_text(), encoding="utf-8")
    path.chmod(0o600)

    policy = load_docker_project_policy(path, allowed_roots=(path.parent,))

    assert policy.schema_version == "1.1"
    assert policy.managed.image_digest == ""
    assert policy.optimization.enabled is True
    assert policy.optimization.context_paths == ("Dockerfile", "lock.txt", "src")
    assert policy.optimization.mutable_paths == ("src",)
    assert policy.optimization.dockerfile == "Dockerfile"
    assert policy.optimization.base_image_digest == f"sha256:{'a' * 64}"
    assert policy.optimization.record_max_duration_seconds == 30
    assert policy.optimization.record_frequency_hz == 99


@pytest.mark.parametrize(
    ("source", "replacement"),
    (
        ('mutable_paths = ["src"]', 'mutable_paths = ["outside"]'),
        ('dockerfile = "Dockerfile"', 'dockerfile = "outside/Dockerfile"'),
        ('benchmark_output = "result.json"', 'benchmark_output = ""'),
        ('network_tier = "local_only"', 'network_tier = "remote"'),
        ('builder_policy_id = ""', 'builder_policy_id = "unexpected"'),
        ("max_candidate_rounds = 3", "max_candidate_rounds = 4"),
        ("max_builds = 4", "max_builds = 3"),
        ("build_args = []", 'build_args = ["TOKEN", "A=1"]'),
        ("build_args = []", 'build_args = ["API_TOKEN=credential"]'),
        ("build_args = []", 'build_args = ["HTTP_PROXY=http://unreviewed"]'),
        ("build_args = []", 'build_args = ["A=1", "A=2"]'),
    ),
)
def test_project_policy_rejects_unsafe_or_unbounded_optimization(
    tmp_path: Path,
    source: str,
    replacement: str,
) -> None:
    path = _policy(tmp_path)
    path.write_text(
        _enabled_optimization_policy_text().replace(source, replacement),
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(PerfLensError) as captured:
        load_docker_project_policy(path, allowed_roots=(path.parent,))
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_project_policy_requires_admin_policy_for_network_tiers(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    policy_text = _enabled_optimization_policy_text().replace(
        'network_tier = "local_only"', 'network_tier = "pinned_pull"'
    )
    path.write_text(policy_text, encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(PerfLensError):
        load_docker_project_policy(path, allowed_roots=(path.parent,))

    path.write_text(
        policy_text.replace('builder_policy_id = ""', 'builder_policy_id = "corp-pinned"'),
        encoding="utf-8",
    )
    path.chmod(0o600)
    policy = load_docker_project_policy(path, allowed_roots=(path.parent,))
    assert policy.optimization.network_tier == "pinned_pull"
    assert policy.optimization.builder_policy_id == "corp-pinned"


def test_project_policy_rejects_unknown_schema_1_1_optimization_field(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    path.write_text(
        render_default_docker_project_policy() + "\nunknown_optimization = true\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(PerfLensError) as captured:
        load_docker_project_policy(path, allowed_roots=(path.parent,))
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


@pytest.mark.parametrize(
    "mutation",
    (
        "\nunknown = true\n",
        "max_workload_runs = 6\nmax_workload_runs = 7\n",
        "max_workload_runs = 7\n",
        "allow_managed_temporary_containers = true\n",
        'default_authorization_mode = "permanent"\n',
    ),
)
def test_project_policy_rejects_unknown_duplicate_and_expanded_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    path = _policy(tmp_path)
    original = render_default_docker_project_policy()
    if mutation.startswith("\n"):
        content = original + mutation
    elif mutation.startswith("max_workload_runs"):
        content = original.replace("max_workload_runs = 6\n", mutation)
    elif mutation.startswith("allow_managed"):
        content = original.replace("allow_managed_temporary_containers = false\n", mutation)
    else:
        content = original.replace('default_authorization_mode = "per_run"\n', mutation)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(PerfLensError) as captured:
        load_docker_project_policy(path, allowed_roots=(path.parent,))
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_project_policy_rejects_symlink_writable_and_outside_paths(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    link = path.with_name("link.toml")
    link.symlink_to(path.name)
    with pytest.raises(PerfLensError):
        load_docker_project_policy(link, allowed_roots=(path.parent,))

    path.chmod(0o620)
    with pytest.raises(PerfLensError):
        load_docker_project_policy(path, allowed_roots=(path.parent,))

    path.chmod(0o600)
    outside = tmp_path / "other"
    outside.mkdir()
    with pytest.raises(PerfLensError):
        load_docker_project_policy(path, allowed_roots=(outside,))


@pytest.mark.parametrize(
    "value",
    (
        '["/etc/passwd"]',
        '["../outside"]',
        '["src/workload.py", "src/workload.py"]',
        '"src/workload.py"',
    ),
)
def test_project_policy_rejects_unsafe_treatment_paths(
    tmp_path: Path,
    value: str,
) -> None:
    path = _policy(tmp_path)
    path.write_text(
        render_default_docker_project_policy().replace(
            "treatment_paths = []",
            f"treatment_paths = {value}",
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(PerfLensError):
        load_docker_project_policy(path, allowed_roots=(path.parent,))


@pytest.mark.parametrize(
    ("source", "replacement"),
    (
        ('benchmark_output = ""', 'benchmark_output = "../outside.json"'),
        ('benchmark_format = "auto"', 'benchmark_format = "arbitrary"'),
        ('benchmark_format = "auto"', 'benchmark_format = ["auto"]'),
        ('benchmark_name = ""', 'benchmark_name = "throughput"'),
        ('benchmark_name = ""', 'benchmark_name = "bad\\nname"'),
    ),
)
def test_project_policy_rejects_unsafe_benchmark_recipe(
    tmp_path: Path,
    source: str,
    replacement: str,
) -> None:
    path = _policy(tmp_path)
    path.write_text(
        render_default_docker_project_policy().replace(source, replacement),
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(PerfLensError):
        load_docker_project_policy(path, allowed_roots=(path.parent,))
