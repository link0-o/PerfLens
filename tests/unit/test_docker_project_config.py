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


def test_project_policy_is_strict_bounded_and_identity_pinned(tmp_path: Path) -> None:
    path = _policy(tmp_path)
    policy = load_docker_project_policy(path, allowed_roots=(path.parent,))

    assert policy.default_workflow == "existing_container"
    assert policy.default_authorization_mode == "per_run"
    assert policy.allow_managed_temporary_containers is False
    assert policy.max_workload_runs == 6
    assert policy.trace_max_duration_seconds == 10
    assert policy.managed.working_directory == "/workspace"
    assert policy.managed.arguments == ()
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
