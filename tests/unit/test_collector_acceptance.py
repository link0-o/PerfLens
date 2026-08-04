from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionCapabilityArtifact,
    CollectionModeCapability,
    PerfStatMetric,
)
from perflens.distribution import acceptance
from perflens.domain.errors import ErrorCode, PerfLensError


def _capabilities() -> CollectionCapabilityArtifact:
    return CollectionCapabilityArtifact(
        capability_id="capability-acceptance-test",
        platform="Linux",
        kernel_release="test",
        effective_uid=os.geteuid(),
        tracefs_accessible=False,
        modes=tuple(
            CollectionModeCapability(
                mode=mode,
                status="blocked",
                required_privilege="cap_sys_admin_or_policy_change",
                reason="Collector supplies the approved privilege.",
            )
            for mode in ("record", "stat", "sched", "lock", "off_cpu")
        ),
    )


def test_accept_collector_requires_authorization_and_bounded_duration(tmp_path: Path) -> None:
    with pytest.raises(PerfLensError) as unauthorized:
        acceptance.accept_collector(
            tmp_path / "collector.sock",
            duration_seconds=1,
            authorized=False,
            capabilities=_capabilities(),
        )
    assert unauthorized.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    for duration in (float("nan"), 0.09, 5.01):
        with pytest.raises(PerfLensError) as invalid:
            acceptance.accept_collector(
                tmp_path / "collector.sock",
                duration_seconds=duration,
                authorized=True,
                capabilities=_capabilities(),
            )
        assert invalid.value.code is ErrorCode.INVALID_INPUT


def test_accept_collector_cleans_up_probe_when_socket_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    probe = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    monkeypatch.setattr(acceptance, "_start_probe", lambda: probe)

    with pytest.raises(PerfLensError) as captured:
        acceptance.accept_collector(
            tmp_path / "missing.sock",
            duration_seconds=0.1,
            authorized=True,
            capabilities=_capabilities(),
        )

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert probe.poll() is not None


def test_accept_collector_rejects_success_without_a_measured_metric(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    probe = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    monkeypatch.setattr(acceptance, "_start_probe", lambda: probe)

    class UnsupportedMetricClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, _plan: object) -> CollectionArtifact:
            return CollectionArtifact(
                collection_id="collection-no-measured-metric",
                mode="stat",
                target_type="pid",
                target_argument_count=0,
                target_pid=probe.pid,
                output_path=str(tmp_path / "unsupported.stat.csv"),
                output_sha256="a" * 64,
                output_bytes=1,
                output_format="perf_stat_delimited",
                perf_executable="/usr/bin/perf",
                started_at="2026-08-04T00:00:00+00:00",
                finished_at="2026-08-04T00:00:01+00:00",
                duration_seconds=1,
                events=("cycles",),
                metrics=(
                    PerfStatMetric(
                        event="cycles",
                        value=None,
                        unit="",
                        status="not_supported",
                    ),
                ),
            )

    monkeypatch.setattr(acceptance, "CollectorBrokerClient", UnsupportedMetricClient)

    with pytest.raises(PerfLensError) as captured:
        acceptance.accept_collector(
            tmp_path / "collector.sock",
            duration_seconds=0.1,
            authorized=True,
            capabilities=_capabilities(),
        )

    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert captured.value.details["metric_statuses"] == ["not_supported"]
    assert probe.poll() is not None
