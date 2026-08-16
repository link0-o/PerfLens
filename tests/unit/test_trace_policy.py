from __future__ import annotations

from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.trace_helper.policy import load_trace_policy


def _policy(uid: int = 1000) -> str:
    return f'''[trace]
schema_version = 1
allowed_uid = {uid}
allowed_modes = ["sched", "off_cpu", "lock"]
capture_backend = "target_filtered_kernel_v1"
target_filter_before_userspace = true
max_duration_seconds = 10
max_output_bytes = 67108864
max_concurrent_collections = 1
helper_socket = "/run/perflens-trace-helper/helper.sock"
private_spool = "/var/lib/perflens-trace-helper"
'''


def test_load_trace_policy_binds_fixed_boundary(tmp_path: Path) -> None:
    path = tmp_path / "trace.toml"
    path.write_text(_policy(), encoding="utf-8")
    path.chmod(0o400)

    policy = load_trace_policy(path)

    assert policy.allowed_uid == 1000
    assert policy.allowed_modes == ("sched", "off_cpu", "lock")
    assert policy.max_duration_seconds == 10
    assert policy.max_output_bytes == 64 << 20
    assert len(policy.policy_sha256) == 64


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("schema_version = 1", "schema_version = 2"),
        ("allowed_uid = 1000", "allowed_uid = 0"),
        (
            'allowed_modes = ["sched", "off_cpu", "lock"]',
            'allowed_modes = ["lock", "sched"]',
        ),
        ("max_duration_seconds = 10", "max_duration_seconds = 11"),
        ("max_output_bytes = 67108864", "max_output_bytes = 67108865"),
        ("max_concurrent_collections = 1", "max_concurrent_collections = 2"),
        (
            'helper_socket = "/run/perflens-trace-helper/helper.sock"',
            'helper_socket = "/tmp/helper.sock"',
        ),
        ("target_filter_before_userspace = true", "target_filter_before_userspace = false"),
    ],
)
def test_trace_policy_rejects_expansion_or_noncanonical_values(
    tmp_path: Path,
    old: str,
    new: str,
) -> None:
    path = tmp_path / "trace.toml"
    path.write_text(_policy().replace(old, new), encoding="utf-8")
    path.chmod(0o400)

    with pytest.raises(PerfLensError) as captured:
        load_trace_policy(path)

    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_trace_policy_rejects_writable_symlink_and_unknown_fields(tmp_path: Path) -> None:
    writable = tmp_path / "writable.toml"
    writable.write_text(_policy(), encoding="utf-8")
    writable.chmod(0o600)
    with pytest.raises(PerfLensError) as writable_error:
        load_trace_policy(writable)
    assert writable_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    target = tmp_path / "target.toml"
    target.write_text(_policy(), encoding="utf-8")
    target.chmod(0o400)
    link = tmp_path / "trace.toml"
    link.symlink_to(target)
    with pytest.raises(PerfLensError) as symlink_error:
        load_trace_policy(link)
    assert symlink_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    unknown = tmp_path / "unknown.toml"
    unknown.write_text(_policy() + "extra = true\n", encoding="utf-8")
    unknown.chmod(0o400)
    with pytest.raises(PerfLensError) as unknown_error:
        load_trace_policy(unknown)
    assert unknown_error.value.code is ErrorCode.INVALID_INPUT

