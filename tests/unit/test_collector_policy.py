from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from perflens.collector_broker.policy import (
    CollectorBrokerPolicy,
    load_broker_policy,
    validate_broker_policy,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def _fake_perf(tmp_path: Path) -> Path:
    executable = tmp_path / "perf"
    executable.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    executable.chmod(0o555)
    return executable


def test_policy_must_be_immutable_to_non_root_service_owner(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o750)
    perf = _fake_perf(tmp_path)
    policy_path = tmp_path / "collector.toml"
    policy_path.write_text(
        "[collector]\n"
        f'spool_root = "{spool}"\n'
        f'perf_path = "{perf}"\n'
        f"allowed_uids = [{os.geteuid()}]\n",
        encoding="utf-8",
    )

    if os.geteuid() != 0:
        with pytest.raises(PerfLensError) as captured:
            load_broker_policy(policy_path)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    policy_path.chmod(0o444)
    policy = load_broker_policy(policy_path)
    assert policy.policy_version == 1
    assert policy.allowed_uids == (os.geteuid(),)
    assert policy.allowed_modes == ("record", "stat")
    assert policy.max_spool_bytes == 10 << 30
    assert policy.max_spool_artifacts == 1000
    assert policy.min_free_bytes == 1 << 30


def test_policy_rejects_unknown_fields(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o750)
    perf = _fake_perf(tmp_path)
    policy_path = tmp_path / "collector.toml"
    policy_path.write_text(
        "[collector]\n"
        f'spool_root = "{spool}"\n'
        f'perf_path = "{perf}"\n'
        f"allowed_uids = [{os.geteuid()}]\n"
        'root_command = "anything"\n',
        encoding="utf-8",
    )
    policy_path.chmod(0o444)

    with pytest.raises(PerfLensError, match="unknown fields"):
        load_broker_policy(policy_path)


def test_policy_loader_rejects_untrusted_or_invalid_files(tmp_path: Path) -> None:
    with pytest.raises(PerfLensError):
        load_broker_policy(Path("relative.toml"))
    with pytest.raises(PerfLensError):
        load_broker_policy(tmp_path / "missing.toml")

    invalid = tmp_path / "invalid.toml"
    invalid.write_text("not = [valid", encoding="utf-8")
    invalid.chmod(0o444)
    with pytest.raises(PerfLensError, match="invalid TOML"):
        load_broker_policy(invalid)

    missing_table = tmp_path / "missing-table.toml"
    missing_table.write_text('name = "value"\n', encoding="utf-8")
    missing_table.chmod(0o444)
    with pytest.raises(PerfLensError, match=r"requires a \[collector\] table"):
        load_broker_policy(missing_table)


def test_policy_loader_rejects_invalid_field_types(tmp_path: Path) -> None:
    policy_path = tmp_path / "invalid-fields.toml"
    policy_path.write_text(
        "[collector]\n"
        'spool_root = "/tmp"\n'
        'perf_path = "/bin/true"\n'
        'allowed_uids = ["not-an-integer"]\n'
        'policy_version = "1"\n'
        'allow_other_target_uids = "false"\n',
        encoding="utf-8",
    )
    policy_path.chmod(0o444)
    with pytest.raises(PerfLensError, match="field values"):
        load_broker_policy(policy_path)


@pytest.mark.parametrize(
    "field",
    [
        "max_duration_seconds = true",
        "max_frequency_hz = true",
        "max_output_bytes = true",
        "max_spool_bytes = true",
        "max_spool_artifacts = true",
        "min_free_bytes = false",
        "max_plan_ttl_seconds = true",
        "socket_mode = true",
        "artifact_mode = false",
    ],
)
def test_policy_loader_rejects_boolean_numeric_fields(tmp_path: Path, field: str) -> None:
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o750)
    perf = _fake_perf(tmp_path)
    policy_path = tmp_path / "collector.toml"
    policy_path.write_text(
        "[collector]\n"
        f'spool_root = "{spool}"\n'
        f'perf_path = "{perf}"\n'
        f"allowed_uids = [{os.geteuid()}]\n"
        f"{field}\n",
        encoding="utf-8",
    )
    policy_path.chmod(0o444)

    with pytest.raises(PerfLensError, match="field values"):
        load_broker_policy(policy_path)


def test_broker_policy_limit_validation(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o750)
    base = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=_fake_perf(tmp_path),
        allowed_uids=(os.geteuid(),),
    )
    invalid_policies = (
        replace(base, policy_version=2),
        replace(base, policy_version=True),
        replace(base, allowed_uids=()),
        replace(base, allowed_uids=(-1,)),
        replace(base, allowed_uids=(1000, 1001)),
        replace(base, allowed_modes=()),
        replace(base, max_duration_seconds=0),
        replace(base, max_duration_seconds=float("nan")),
        replace(base, max_frequency_hz=0),
        replace(base, max_frequency_hz=True),
        replace(base, max_output_bytes=0),
        replace(base, max_spool_bytes=(1 << 30) - 1),
        replace(base, max_spool_bytes=(1 << 50) + 1),
        replace(base, max_spool_artifacts=0),
        replace(base, max_spool_artifacts=1_000_001),
        replace(base, min_free_bytes=-1),
        replace(base, min_free_bytes=(1 << 50) + 1),
        replace(base, max_plan_ttl_seconds=0),
        replace(base, max_plan_ttl_seconds=3601),
        replace(base, allowed_stat_events=()),
        replace(base, socket_mode=0o666),
        replace(base, socket_mode=True),
        replace(base, socket_mode=0o400),
        replace(base, artifact_mode=0o644),
        replace(base, artifact_mode=0o600),
        replace(base, artifact_mode=0o620),
        replace(base, artifact_mode=0o540),
        replace(base, artifact_mode=0),
        replace(base, artifact_mode=False),
    )
    for policy in invalid_policies:
        with pytest.raises(ValueError):
            validate_broker_policy(policy)
    assert validate_broker_policy(replace(base, artifact_mode=0o440)).artifact_mode == 0o440


def test_broker_policy_rejects_unsafe_paths(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o750)
    perf = _fake_perf(tmp_path)
    base = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=perf,
        allowed_uids=(os.geteuid(),),
    )
    with pytest.raises(ValueError, match="spool root must be absolute"):
        validate_broker_policy(replace(base, spool_root=Path("relative")))
    with pytest.raises(ValueError, match="already exist"):
        validate_broker_policy(replace(base, spool_root=tmp_path / "missing"))
    with pytest.raises(ValueError, match="perf path must be absolute"):
        validate_broker_policy(replace(base, perf_path=Path("perf")))
    with pytest.raises(ValueError, match="cannot be resolved"):
        validate_broker_policy(replace(base, perf_path=tmp_path / "missing-perf"))
    plain = tmp_path / "plain"
    plain.write_text("plain", encoding="utf-8")
    with pytest.raises(ValueError, match="executable regular file"):
        validate_broker_policy(replace(base, perf_path=plain))
    perf.chmod(0o755)
    if os.geteuid() != 0:
        with pytest.raises(ValueError, match="cannot modify"):
            validate_broker_policy(base)
