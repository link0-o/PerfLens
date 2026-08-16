# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

import pytest

from perflens.collection.planning import AutomaticCollectionPolicy, CollectionPlanRequest
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionCapabilityArtifact,
    CollectionModeCapability,
    CollectionPlanArtifact,
    CollectorHealthArtifact,
    CollectorTraceModeAcceptance,
    PerfStatMetric,
)
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceEvidenceArtifact,
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


def _health(
    *, feature_profile: Literal["cpu_only", "full_diagnostics"] = "cpu_only"
) -> CollectorHealthArtifact:
    allowed_modes = (
        ("record", "stat", "sched", "off_cpu", "lock")
        if feature_profile == "full_diagnostics"
        else ("record", "stat")
    )
    return CollectorHealthArtifact(
        perflens_version="test",
        policy_version=1,
        service_pid=123,
        service_uid=os.geteuid(),
        peer_uid=os.geteuid(),
        allowed_modes=allowed_modes,
        spool_root="/var/lib/perflens",
        feature_profile=feature_profile,
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

        def health(self) -> CollectorHealthArtifact:
            return _health()

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

        def health(self) -> CollectorHealthArtifact:
            return _health()

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

        def health(self) -> CollectorHealthArtifact:
            return _health()

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


def test_accept_collector_runs_all_trace_modes_for_full_diagnostics(
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

    class FullAcceptanceClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def health(self) -> CollectorHealthArtifact:
            return _health(feature_profile="full_diagnostics")

        def collect(self, plan: CollectionPlanArtifact) -> CollectionArtifact:
            record = plan.mode == "record"
            hardware = plan.requested_event_source == "hardware_required"
            event = "cycles" if hardware else "task-clock"
            return CollectionArtifact(
                collection_id=f"collection-{plan.mode}-{plan.requested_event_source}",
                mode=plan.mode,
                target_type="pid",
                target_argument_count=0,
                target_pid=probe.pid,
                output_path=str(tmp_path / f"{plan.mode}.evidence"),
                output_sha256=("a" if hardware else "b") * 64,
                output_bytes=64,
                output_format="perf_data" if record else "perf_stat_delimited",
                perf_executable="/usr/bin/perf",
                started_at="2026-08-04T00:00:00+00:00",
                finished_at="2026-08-04T00:00:01+00:00",
                duration_seconds=1,
                events=() if record else (event,),
                requested_event_source=plan.requested_event_source,
                actual_event_source=("hardware" if hardware else "software"),
                metrics=(
                    ()
                    if record
                    else (PerfStatMetric(event=event, value=1000, unit="", status="measured"),)
                ),
            )

    trace_calls: list[tuple[int, tuple[str, ...]]] = []

    def fake_trace_acceptance(
        _client: object,
        pid: int,
        *,
        duration_seconds: float,
        policy: AutomaticCollectionPolicy,
        capabilities: object,
    ) -> tuple[CollectorTraceModeAcceptance, ...]:
        del duration_seconds, capabilities
        allowed_modes = policy.allowed_modes
        trace_calls.append((pid, allowed_modes))
        return tuple(
            CollectorTraceModeAcceptance(
                mode=mode,
                trace_evidence_id=f"trace-evidence-{mode}",
                evidence_status="partial",
                emitted_event_count=1,
                analysis_id=f"{mode}-analysis-test",
                analysis_status="partial",
                verification_id=f"trace-verification-{mode}",
                verification_status="partial",
            )
            for mode in ("sched", "off_cpu", "lock")
        )

    monkeypatch.setattr(acceptance, "CollectorBrokerClient", FullAcceptanceClient)
    monkeypatch.setattr(acceptance, "_accept_trace_modes", fake_trace_acceptance)
    artifact = acceptance.accept_collector(
        tmp_path / "collector.sock",
        duration_seconds=0.1,
        authorized=True,
        capabilities=_capabilities(),
    )

    assert artifact.feature_profile == "full_diagnostics"
    assert artifact.trace_backend_status == "available"
    assert tuple(item.mode for item in artifact.trace_modes) == ("sched", "off_cpu", "lock")
    assert trace_calls == [(probe.pid, ("record", "stat", "sched", "off_cpu", "lock"))]
    assert probe.poll() is not None


def test_full_diagnostics_health_must_advertise_every_trace_mode(
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

    class IncompleteFullClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def health(self) -> CollectorHealthArtifact:
            return _health(feature_profile="full_diagnostics").model_copy(
                update={"allowed_modes": ("record", "stat", "sched", "lock")}
            )

    monkeypatch.setattr(acceptance, "CollectorBrokerClient", IncompleteFullClient)

    with pytest.raises(PerfLensError) as captured:
        acceptance.accept_collector(
            tmp_path / "collector.sock",
            duration_seconds=0.1,
            authorized=True,
            capabilities=_capabilities(),
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert captured.value.details["allowed_modes"] == ["record", "stat", "sched", "lock"]
    assert probe.poll() is not None


def test_acceptance_probe_start_failure_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_start(*_args: object, **_kwargs: object) -> object:
        raise OSError("bounded test failure")

    monkeypatch.setattr(acceptance.subprocess, "Popen", fail_start)
    with pytest.raises(PerfLensError) as captured:
        acceptance._start_probe()
    assert captured.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
    assert captured.value.stage == "collector_acceptance"


def test_accept_trace_modes_builds_and_verifies_each_dedicated_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid = 4242
    policy = AutomaticCollectionPolicy(
        enabled=True,
        allowed_modes=("record", "stat", "sched", "off_cpu", "lock"),
        max_duration_seconds=5,
        max_output_bytes=8 << 20,
        plan_ttl_seconds=60,
    )
    collected_modes: list[str] = []
    verified_modes: list[str] = []

    class TraceClient:
        def collect_trace(self, plan: CollectionPlanArtifact) -> TraceEvidenceArtifact:
            collected_modes.append(plan.mode)
            return TraceEvidenceArtifact.model_construct(
                trace_evidence_id=f"trace-evidence-{len(collected_modes):016x}",
                mode=plan.mode,
                status="partial",
                quality=SimpleNamespace(emitted_event_count=1),
            )

    def build(evidence: TraceEvidenceArtifact) -> object:
        if evidence.mode == "sched":
            return SchedulerAnalysisArtifact.model_construct(
                scheduler_analysis_id="scheduler-analysis-aaaaaaaaaaaaaaaa",
                status="partial",
                total_context_switch_count=1,
            )
        if evidence.mode == "off_cpu":
            return OffCpuAnalysisArtifact.model_construct(
                off_cpu_analysis_id="off-cpu-analysis-bbbbbbbbbbbbbbbb",
                status="partial",
                total_complete_interval_count=1,
                total_incomplete_interval_count=0,
            )
        return LockAnalysisArtifact.model_construct(
            lock_analysis_id="lock-analysis-cccccccccccccccc",
            status="partial",
            total_exact_wait_count=1,
            total_candidate_wait_event_count=0,
        )

    def verify(analysis: object, evidence: TraceEvidenceArtifact) -> SimpleNamespace:
        del analysis
        verified_modes.append(evidence.mode)
        return SimpleNamespace(
            verification_id=f"trace-verification-{len(verified_modes):016x}",
            verification_status="partial",
        )

    def accept_verification(_item: object) -> None:
        return None

    def create_plan(
        request: CollectionPlanRequest,
        **_kwargs: object,
    ) -> CollectionPlanArtifact:
        return CollectionPlanArtifact.model_construct(
            mode=request.mode,
            policy_status="allowed",
            warnings=(),
        )

    monkeypatch.setattr(acceptance, "build_trace_analysis", build)
    monkeypatch.setattr(acceptance, "verify_trace_analysis_artifact", verify)
    monkeypatch.setattr(acceptance, "require_usable_trace_analysis", accept_verification)
    monkeypatch.setattr(acceptance, "create_collection_plan", create_plan)

    results = acceptance._accept_trace_modes(
        TraceClient(),  # type: ignore[arg-type]
        pid,
        duration_seconds=0.1,
        policy=policy,
        capabilities=_capabilities(),
    )

    assert collected_modes == ["sched", "off_cpu", "lock"]
    assert verified_modes == collected_modes
    assert tuple(item.mode for item in results) == ("sched", "off_cpu", "lock")
    assert tuple(item.emitted_event_count for item in results) == (1, 1, 1)


@pytest.mark.parametrize(
    ("mode", "analysis"),
    (
        (
            "sched",
            SchedulerAnalysisArtifact.model_construct(total_context_switch_count=0),
        ),
        (
            "off_cpu",
            OffCpuAnalysisArtifact.model_construct(
                total_complete_interval_count=0,
                total_incomplete_interval_count=0,
            ),
        ),
        (
            "lock",
            LockAnalysisArtifact.model_construct(
                total_exact_wait_count=0,
                total_candidate_wait_event_count=0,
            ),
        ),
    ),
)
def test_advanced_acceptance_rejects_empty_or_non_substantive_evidence(
    mode: str,
    analysis: SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact,
) -> None:
    evidence = TraceEvidenceArtifact.model_construct(
        trace_evidence_id="trace-evidence-aaaaaaaaaaaaaaaa",
        quality=SimpleNamespace(emitted_event_count=0),
    )
    with pytest.raises(PerfLensError) as captured:
        acceptance._require_substantive_trace(mode, evidence, analysis)
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert captured.value.details["mode"] == mode


def test_denied_acceptance_plan_and_analysis_id_dispatch_are_explicit() -> None:
    denied = CollectionPlanArtifact.model_construct(
        policy_status="denied",
        warnings=("policy denied the fixed mode",),
    )
    with pytest.raises(PerfLensError) as captured:
        acceptance._require_allowed_plan(denied)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    assert acceptance._trace_analysis_id(
        SchedulerAnalysisArtifact.model_construct(
            scheduler_analysis_id="scheduler-analysis-aaaaaaaaaaaaaaaa"
        )
    ) == "scheduler-analysis-aaaaaaaaaaaaaaaa"
    assert acceptance._trace_analysis_id(
        OffCpuAnalysisArtifact.model_construct(
            off_cpu_analysis_id="off-cpu-analysis-bbbbbbbbbbbbbbbb"
        )
    ) == "off-cpu-analysis-bbbbbbbbbbbbbbbb"
    assert acceptance._trace_analysis_id(
        LockAnalysisArtifact.model_construct(lock_analysis_id="lock-analysis-cccccccccccccccc")
    ) == "lock-analysis-cccccccccccccccc"
