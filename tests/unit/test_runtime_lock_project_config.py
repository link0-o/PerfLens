from __future__ import annotations

import os
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.project_config import (
    assert_runtime_lock_project_policy_current,
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)


def _write_policy(path: Path, *, docker_enabled: bool = False) -> Path:
    path.write_text(
        render_default_runtime_lock_project_policy(docker_enabled=docker_enabled),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_runtime_lock_policy_loads_safe_defaults(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")

    policy = load_runtime_lock_project_policy(
        policy_path,
        allowed_roots=(tmp_path,),
        invoking_uid=os.geteuid(),
    )

    assert policy.enabled is True
    assert policy.target_scopes == ("controlled_import", "host_launched_workload")
    assert policy.budget.max_workload_runs == 6
    assert policy.adapter_policy("native_pthread").duration_threshold_ns == 1000
    assert policy.adapter_policy("go_pprof").allowed_semantics == ("cumulative",)


def test_runtime_lock_policy_enables_only_bounded_docker_scopes_when_requested(
    tmp_path: Path,
) -> None:
    policy = load_runtime_lock_project_policy(
        _write_policy(tmp_path / "runtime-locks.toml", docker_enabled=True),
        allowed_roots=(tmp_path,),
    )

    assert policy.target_scopes == (
        "controlled_import",
        "docker_optimization",
        "host_launched_workload",
        "managed_temporary_container",
    )


@pytest.mark.parametrize(
    "needle,replacement",
    [
        ('schema_version = "1.0"', 'schema_version = "2.0"'),
        ("max_workload_runs = 6", "max_workload_runs = 7"),
        ("max_adapter_concurrency = 1", "max_adapter_concurrency = 2"),
        ('import_roots = ["perflens-runtime-locks"]', 'import_roots = ["../private"]'),
        (
            'allowed_semantics = ["cumulative", "exact", "sampled", "thresholded"]',
            'allowed_semantics = ["thresholded", "exact"]',
        ),
    ],
)
def test_runtime_lock_policy_rejects_version_bounds_paths_and_noncanonical_lists(
    tmp_path: Path,
    needle: str,
    replacement: str,
) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(needle, replacement, 1),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError) as captured:
        load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_runtime_lock_policy_rejects_unknown_fields_and_symlink(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            'schema_version = "1.0"',
            'schema_version = "1.0"\nunknown = true',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(PerfLensError, match="unknown top-level"):
        load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))

    policy_path = _write_policy(tmp_path / "runtime-locks-safe.toml")
    symlink = tmp_path / "runtime-locks-link.toml"
    symlink.symlink_to(policy_path)
    with pytest.raises(PerfLensError, match="non-symlink"):
        load_runtime_lock_project_policy(symlink, allowed_roots=(tmp_path,))


def test_runtime_lock_policy_detects_post_startup_replacement(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "preview_ttl_seconds = 600",
            "preview_ttl_seconds = 300",
        ),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError, match="changed after MCP startup"):
        assert_runtime_lock_project_policy_current(policy, allowed_roots=(tmp_path,))
