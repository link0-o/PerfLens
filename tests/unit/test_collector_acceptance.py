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
    CollectionPlanArtifact,
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
    assert "software perf event support" in captured.value.suggested_actions[0]
    assert probe.poll() is not None


def test_accept_collector_passes_with_software_evidence_when_hardware_pmu_is_unusable(
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

    class FallbackAcceptanceClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, plan: CollectionPlanArtifact) -> CollectionArtifact:
            mode = plan.mode
            source = plan.requested_event_source
            if mode == "record":
                return CollectionArtifact(
                    collection_id="collection-software-record",
                    mode="record",
                    target_type="pid",
                    target_argument_count=0,
                    target_pid=probe.pid,
                    output_path=str(tmp_path / "software.perf.data"),
                    output_sha256="c" * 64,
                    output_bytes=128,
                    output_format="perf_data",
                    perf_executable="/usr/bin/perf",
                    started_at="2026-08-04T00:00:02+00:00",
                    finished_at="2026-08-04T00:00:03+00:00",
                    duration_seconds=1,
                    requested_event_source="software_only",
                    actual_event_source="software",
                )
            hardware = source == "hardware_required"
            event = "cycles" if hardware else "task-clock"
            value = 0.0 if hardware else 1000.0
            return CollectionArtifact(
                collection_id=(
                    "collection-hardware-unusable" if hardware else "collection-software-stat"
                ),
                mode="stat",
                target_type="pid",
                target_argument_count=0,
                target_pid=probe.pid,
                output_path=str(tmp_path / f"{event}.stat.csv"),
                output_sha256=("a" if hardware else "b") * 64,
                output_bytes=64,
                output_format="perf_stat_delimited",
                perf_executable="/usr/bin/perf",
                started_at="2026-08-04T00:00:00+00:00",
                finished_at="2026-08-04T00:00:01+00:00",
                duration_seconds=1,
                events=(event,),
                requested_event_source=("hardware_required" if hardware else "software_only"),
                actual_event_source=("hardware" if hardware else "software"),
                metrics=(
                    PerfStatMetric(event=event, value=value, unit="", status="measured"),
                ),
            )

    monkeypatch.setattr(acceptance, "CollectorBrokerClient", FallbackAcceptanceClient)
    artifact = acceptance.accept_collector(
        tmp_path / "collector.sock",
        duration_seconds=0.1,
        authorized=True,
        capabilities=_capabilities(),
    )

    assert artifact.status == "passed"
    assert artifact.hardware_pmu_status == "unavailable"
    assert artifact.hardware_pmu_reason == "hardware_collection_produced_no_usable_counts"
    assert artifact.hardware_collection_id == "collection-hardware-unusable"
    assert artifact.software_counting_status == "available"
    assert artifact.software_sampling_status == "available"
    assert artifact.software_sampling_collection_id == "collection-software-record"
    assert any("性能优化仍可继续" in warning for warning in artifact.warnings)
    assert probe.poll() is not None


def test_accept_collector_links_no_hardware_artifact_when_hardware_execution_fails(
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

    class FailedHardwareAcceptanceClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(self, plan: CollectionPlanArtifact) -> CollectionArtifact:
            if plan.requested_event_source == "hardware_required":
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "external_tool",
                    "Hardware collection failed",
                )
            record = plan.mode == "record"
            event = "cpu-clock" if record else "task-clock"
            return CollectionArtifact(
                collection_id=(
                    "collection-software-record" if record else "collection-software-stat"
                ),
                mode=plan.mode,
                target_type="pid",
                target_argument_count=0,
                target_pid=probe.pid,
                output_path=str(tmp_path / ("software.perf.data" if record else "software.csv")),
                output_sha256=("c" if record else "b") * 64,
                output_bytes=64,
                output_format="perf_data" if record else "perf_stat_delimited",
                perf_executable="/usr/bin/perf",
                started_at="2026-08-04T00:00:00+00:00",
                finished_at="2026-08-04T00:00:01+00:00",
                duration_seconds=1,
                events=() if record else (event,),
                requested_event_source="software_only",
                actual_event_source="software",
                metrics=(
                    ()
                    if record
                    else (PerfStatMetric(event=event, value=1000, unit="", status="measured"),)
                ),
            )

    monkeypatch.setattr(acceptance, "CollectorBrokerClient", FailedHardwareAcceptanceClient)
    artifact = acceptance.accept_collector(
        tmp_path / "collector.sock",
        duration_seconds=0.1,
        authorized=True,
        capabilities=_capabilities(),
    )

    assert artifact.hardware_pmu_status == "unavailable"
    assert artifact.hardware_pmu_reason == "hardware_collection_failed"
    assert artifact.hardware_collection_id is None
    assert artifact.software_counting_status == "available"
    assert artifact.software_sampling_status == "available"
    assert probe.poll() is not None
