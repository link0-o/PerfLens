from __future__ import annotations

import os
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    PID_ATTACH_AUTHORIZATION,
    CollectionRequest,
    CollectionTarget,
    collect_profile,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def _fake_perf(tmp_path: Path) -> Path:
    executable = tmp_path / "perf"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "if 'stat' in args:\n"
        "    output.write_text('100;;cycles;10;100.0\\n200;;instructions;10;100.0\\n')\n"
        "else:\n"
        "    output.write_bytes(b'PERFILE2' + bytes(args[0], 'utf-8'))\n"
        "print('bounded diagnostic', file=sys.stderr)\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def test_collect_record_command_requires_explicit_authorization(tmp_path: Path) -> None:
    target = Path(sys.executable).resolve()
    output = tmp_path / "profile.data"
    request = CollectionRequest(
        mode="record",
        target=CollectionTarget(executable=target, arguments=("--version",)),
        output_path=output,
        authorization="not-authorized",
        perf_path=_fake_perf(tmp_path),
    )
    with pytest.raises(PerfLensError) as captured:
        collect_profile(request)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert not output.exists()


@pytest.mark.parametrize(
    "collection_request",
    [
        CollectionRequest(
            mode="record",
            target=CollectionTarget(executable=Path(sys.executable)),
            output_path=Path("/tmp/fallback-missing-reason.data"),
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            requested_event_source="auto",
            record_event="cpu-clock",
            fallback_used=True,
        ),
        CollectionRequest(
            mode="record",
            target=CollectionTarget(executable=Path(sys.executable)),
            output_path=Path("/tmp/fallback-forged-reason.data"),
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            requested_event_source="auto",
            record_event="cpu-clock",
            fallback_used=True,
            fallback_reason="forged",
        ),
        CollectionRequest(
            mode="record",
            target=CollectionTarget(executable=Path(sys.executable)),
            output_path=Path("/tmp/fallback-hardware-record.data"),
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            requested_event_source="auto",
            fallback_used=True,
            fallback_reason="hardware_probe_failed",
        ),
        CollectionRequest(
            mode="stat",
            target=CollectionTarget(executable=Path(sys.executable)),
            output_path=Path("/tmp/fallback-hardware-stat.csv"),
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            requested_event_source="auto",
            events=("cycles",),
            fallback_used=True,
            fallback_reason="hardware_probe_failed",
        ),
    ],
)
def test_collection_rejects_inconsistent_software_fallback(
    collection_request: CollectionRequest,
    tmp_path: Path,
) -> None:
    with pytest.raises(PerfLensError) as captured:
        collect_profile(replace(collection_request, perf_path=_fake_perf(tmp_path)))
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_collect_record_command_publishes_new_bounded_artifact(tmp_path: Path) -> None:
    output = tmp_path / "profile.data"
    artifact = collect_profile(
        CollectionRequest(
            mode="record",
            target=CollectionTarget(executable=Path(sys.executable), arguments=("--version",)),
            output_path=output,
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            perf_path=_fake_perf(tmp_path),
            max_output_bytes=1024,
        )
    )
    assert artifact.schema_version == "1.0"
    assert artifact.target_type == "command"
    assert artifact.target_executable == str(Path(sys.executable).resolve())
    assert artifact.target_argument_count == 1
    assert artifact.output_format == "perf_data"
    assert artifact.diagnostics == ("bounded diagnostic",)
    assert output.read_bytes().startswith(b"PERFILE2")

    with pytest.raises(PerfLensError) as captured:
        collect_profile(
            CollectionRequest(
                mode="record",
                target=CollectionTarget(executable=Path(sys.executable)),
                output_path=output,
                authorization=ACTIVE_COLLECTION_AUTHORIZATION,
                perf_path=_fake_perf(tmp_path),
            )
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_collect_stat_parses_metrics_and_ipc(tmp_path: Path) -> None:
    artifact = collect_profile(
        CollectionRequest(
            mode="stat",
            target=CollectionTarget(executable=Path(sys.executable), arguments=("--version",)),
            output_path=tmp_path / "stat.csv",
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            perf_path=_fake_perf(tmp_path),
        )
    )
    assert artifact.output_format == "perf_stat_delimited"
    assert [metric.event for metric in artifact.metrics] == [
        "cycles",
        "instructions",
        "instructions-per-cycle",
    ]
    assert artifact.metrics[-1].value == 2.0


def test_pid_attach_requires_separate_authorization(tmp_path: Path) -> None:
    request = CollectionRequest(
        mode="sched",
        target=CollectionTarget(pid=os.getppid(), duration_seconds=0.01),
        output_path=tmp_path / "sched.data",
        authorization=ACTIVE_COLLECTION_AUTHORIZATION,
        perf_path=_fake_perf(tmp_path),
    )
    with pytest.raises(PerfLensError) as captured:
        collect_profile(request)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    artifact = collect_profile(
        CollectionRequest(
            mode="sched",
            target=request.target,
            output_path=request.output_path,
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            pid_authorization=PID_ATTACH_AUTHORIZATION,
            perf_path=request.perf_path,
        )
    )
    assert artifact.target_type == "pid"
    assert artifact.target_pid == os.getppid()


def test_collection_output_size_is_enforced_while_process_runs(tmp_path: Path) -> None:
    request = CollectionRequest(
        mode="lock",
        target=CollectionTarget(executable=Path(sys.executable)),
        output_path=tmp_path / "lock.data",
        authorization=ACTIVE_COLLECTION_AUTHORIZATION,
        perf_path=_fake_perf(tmp_path),
        max_output_bytes=2,
    )
    with pytest.raises(PerfLensError) as captured:
        collect_profile(request)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert not request.output_path.exists()


def test_off_cpu_collection_is_labeled_as_sched_switch_evidence(tmp_path: Path) -> None:
    artifact = collect_profile(
        CollectionRequest(
            mode="off_cpu",
            target=CollectionTarget(executable=Path(sys.executable)),
            output_path=tmp_path / "off-cpu.data",
            authorization=ACTIVE_COLLECTION_AUTHORIZATION,
            perf_path=_fake_perf(tmp_path),
        )
    )
    assert artifact.output_format == "perf_data"
    assert any("sched:sched_switch" in warning for warning in artifact.warnings)
