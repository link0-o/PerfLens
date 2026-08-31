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
    assert policy.schema_version == "1.1"
    assert policy.target_scopes == (
        "controlled_import",
        "host_bound_process",
        "host_launched_workload",
    )
    assert policy.budget.max_workload_runs == 6
    assert policy.adapter_policy("native_pthread").duration_threshold_ns == 1000
    assert policy.adapter_policy("native_pthread").profile is None
    assert policy.adapter_policy("java_jfr").profile == "balanced"
    assert policy.adapter_policy("java_jfr").duration_threshold_ns == 10_000_000
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
        "host_bound_process",
        "host_launched_workload",
        "managed_temporary_container",
    )


@pytest.mark.parametrize(
    "needle,replacement",
    [
        ('schema_version = "1.1"', 'schema_version = "2.0"'),
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
            'schema_version = "1.1"',
            'schema_version = "1.1"\nunknown = true',
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


@pytest.mark.parametrize(
    "profile,threshold",
    [
        ("deep", 1_000_000),
        ("balanced", 10_000_000),
    ],
)
def test_runtime_lock_policy_binds_java_jfr_profile_to_threshold(
    tmp_path: Path,
    profile: str,
    threshold: int,
) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8")
        .replace('profile = "balanced"', f'profile = "{profile}"', 1)
        .replace("duration_threshold_ns = 10000000", f"duration_threshold_ns = {threshold}", 1),
        encoding="utf-8",
    )

    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))

    assert policy.adapter_policy("java_jfr").profile == profile
    assert policy.adapter_policy("java_jfr").duration_threshold_ns == threshold


@pytest.mark.parametrize(
    "profile,threshold",
    [("deep", 10_000_000), ("arbitrary", 10_000_000)],
)
def test_runtime_lock_policy_rejects_java_profile_or_threshold_drift(
    tmp_path: Path,
    profile: str,
    threshold: int,
) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8")
        .replace('profile = "balanced"', f'profile = "{profile}"', 1)
        .replace("duration_threshold_ns = 10000000", f"duration_threshold_ns = {threshold}", 1),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError, match="Java JFR profile"):
        load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))


def test_runtime_lock_policy_rejects_java_profile_on_other_adapter(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "[adapters.native_pthread]\n",
            '[adapters.native_pthread]\nprofile = "balanced"\n',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError, match="unknown fields"):
        load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))


def test_runtime_lock_policy_requires_both_go_startup_profile_rates(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "launch_instrumentation_allowed = false\ncontrolled_import_allowed = false\n"
            "mutex_profile_fraction = 0\nblock_profile_rate_ns = 0\n"
            "file_backend_enabled = false\nloopback_backend_enabled = false",
            "launch_instrumentation_allowed = true\ncontrolled_import_allowed = false\n"
            "mutex_profile_fraction = 1\nblock_profile_rate_ns = 0\n"
            "file_backend_enabled = true\nloopback_backend_enabled = false",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError, match="requires both mutex and block"):
        load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))


def test_runtime_lock_policy_strictly_reads_legacy_1_0_without_java_profile(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(tmp_path / "runtime-locks-v1.toml")
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8")
        .replace('schema_version = "1.1"', 'schema_version = "1.0"', 1)
        .replace(', "host_bound_process"', "", 1)
        .replace('profile = "balanced"\n', "", 1),
        encoding="utf-8",
    )

    # The checked-in schema 1.0 contract exposed Go only through controlled
    # import. Recreate that legacy entry point instead of treating the schema
    # 1.1 discovery-only default as an old policy.
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "[adapters.go_pprof]\n"
            "enabled = true\n"
            'allowed_semantics = ["cumulative"]\n'
            "duration_threshold_ns = 0\n"
            "exact_enabled = false\n"
            "launch_instrumentation_allowed = false\n"
            "controlled_import_allowed = false",
            "[adapters.go_pprof]\n"
            "enabled = true\n"
            'allowed_semantics = ["cumulative"]\n'
            "duration_threshold_ns = 0\n"
            "exact_enabled = false\n"
            "launch_instrumentation_allowed = false\n"
            "controlled_import_allowed = true",
            1,
        ),
        encoding="utf-8",
    )

    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))

    assert policy.schema_version == "1.0"
    assert policy.adapter_policy("java_jfr").profile == "balanced"
    assert policy.adapter_policy("java_jfr").duration_threshold_ns == 10_000_000

    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "duration_threshold_ns = 10000000",
            "duration_threshold_ns = 1000000",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(PerfLensError, match="profile and threshold"):
        load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))


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
