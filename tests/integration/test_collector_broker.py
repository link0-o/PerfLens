from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from mcp.client import Client
from typer.testing import CliRunner

from perflens.cli.app import app
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    PID_ATTACH_AUTHORIZATION,
    SOFTWARE_STAT_EVENTS,
)
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.collector_broker.policy import CollectorBrokerPolicy
from perflens.collector_broker.server import CollectorBrokerServer
from perflens.collector_broker.state import collection_artifact_name, replay_marker_name
from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectionModeCapability,
    CollectionPlanArtifact,
)
from perflens.distribution.onboarding import run_project_setup
from perflens.distribution.status import inspect_runtime_status
from perflens.domain.errors import ErrorCode, PerfLensError, stable_error_id
from perflens.mcp.server import ServerConfig, create_server
from perflens.privileged_helper.client import HelperClient
from perflens.privileged_helper.protocol import HelperCollectionResult
from perflens.workloads.project import PROJECT_EXECUTION_AUTHORIZATION


def _fake_perf(tmp_path: Path) -> Path:
    executable = tmp_path / "perf"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "time.sleep(0.35)\n"
        "if 'stat' in args:\n"
        "    selected = args[args.index('-e') + 1]\n"
        "    if 'task-clock' in selected:\n"
        "        output.write_text('100;;task-clock;10;100.0\\n2;;context-switches;10;100.0\\n')\n"
        "    else:\n"
        "        output.write_text('100;;cycles;10;100.0\\n200;;instructions;10;100.0\\n')\n"
        "else:\n"
        "    output.write_bytes(b'PERFILE2-broker')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _fake_perf_with_unusable_hardware_pmu(tmp_path: Path) -> Path:
    executable = tmp_path / "perf-fallback"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "events = args[args.index('-e') + 1]\n"
        "if events == 'cycles,instructions':\n"
        "    output.write_text('0;;cycles;10;100.0\\n0;;instructions;10;100.0\\n')\n"
        "else:\n"
        "    output.write_text('100;;task-clock;10;100.0\\n2;;context-switches;10;100.0\\n')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _fake_perf_with_failed_hardware_probe(tmp_path: Path) -> Path:
    executable = tmp_path / "perf-failed-probe"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "events = args[args.index('-e') + 1]\n"
        "if events == 'cycles,instructions':\n"
        "    raise SystemExit(1)\n"
        "output.write_text('100;;task-clock;10;100.0\\n2;;context-switches;10;100.0\\n')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _fake_perf_with_failed_hardware_record_after_probe(tmp_path: Path) -> Path:
    executable = tmp_path / "perf-failed-hardware-record"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "event = args[args.index('-e') + 1]\n"
        "if args[0] == 'stat':\n"
        "    output.write_text('100;;cycles;10;100.0\\n200;;instructions;10;100.0\\n')\n"
        "elif event == 'cycles':\n"
        "    raise SystemExit(1)\n"
        "else:\n"
        "    output.write_bytes(b'PERFILE2-software-record')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _fake_perf_exceeding_output_after_hardware_probe(tmp_path: Path) -> Path:
    executable = tmp_path / "perf-oversized-hardware-record"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "event = args[args.index('-e') + 1]\n"
        "if args[0] == 'stat':\n"
        "    output.write_text('100;;cycles;10;100.0\\n200;;instructions;10;100.0\\n')\n"
        "elif event == 'cycles':\n"
        "    output.write_bytes(b'x' * 2048)\n"
        "else:\n"
        "    output.write_bytes(b'PERFILE2-software-record')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _fake_perf_exhausting_window_after_hardware_probe(tmp_path: Path) -> Path:
    executable = tmp_path / "perf-slow-failed-hardware-record"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "event = args[args.index('-e') + 1]\n"
        "if args[0] == 'stat':\n"
        "    output.write_text('100;;cycles;10;100.0\\n200;;instructions;10;100.0\\n')\n"
        "elif event == 'cycles':\n"
        "    time.sleep(0.28)\n"
        "    raise SystemExit(1)\n"
        "else:\n"
        "    output.write_bytes(b'PERFILE2-unexpected-software-retry')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _fake_perf_exceeding_hardware_probe_limit(tmp_path: Path) -> Path:
    executable = tmp_path / "perf-oversized-hardware-probe"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path(args[args.index('-o') + 1])\n"
        "events = args[args.index('-e') + 1]\n"
        "if events == 'cycles,instructions':\n"
        "    output.write_bytes(b'x' * 2048)\n"
        "else:\n"
        "    output.write_text('100;;task-clock;10;100.0\\n')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


def _collection_artifacts(spool: Path) -> tuple[Path, ...]:
    return tuple(path for path in spool.iterdir() if collection_artifact_name(path.name))


def _capabilities() -> CollectionCapabilityArtifact:
    return CollectionCapabilityArtifact(
        capability_id="capability-broker-test",
        platform="Linux",
        kernel_release="test",
        effective_uid=os.geteuid(),
        tracefs_accessible=False,
        modes=tuple(
            CollectionModeCapability(
                mode=mode,
                status="blocked",
                required_privilege="cap_sys_admin_or_policy_change",
                reason="broker supplies privilege",
            )
            for mode in ("record", "stat", "sched", "lock", "off_cpu")
        ),
    )


def _prepare_status_setup(project: Path, fake_perf: Path) -> None:
    project.mkdir()
    mcp = project / "perflens-mcp"
    mcp.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    mcp.chmod(0o500)
    collector = project / "perflens-collector"
    collector.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    collector.chmod(0o500)
    run_project_setup(
        project,
        mcp_command=mcp,
        perf_path=fake_perf,
        collector_command=collector,
        prepare_collector=True,
        automatic_collection=True,
    )


def test_broker_health_is_authenticated_versioned_and_read_only(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=_fake_perf(tmp_path),
        allowed_uids=(os.geteuid(),),
        allowed_modes=("record", "stat"),
    )
    with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
        worker = threading.Thread(target=server.serve_once, daemon=True)
        worker.start()
        health = CollectorBrokerClient(server.socket_path, timeout_seconds=5).health(
            expected_service_uid=os.geteuid()
        )
        worker.join(timeout=5)

        mismatch_worker = threading.Thread(target=server.serve_once, daemon=True)
        mismatch_worker.start()
        with pytest.raises(PerfLensError) as mismatch:
            CollectorBrokerClient(server.socket_path, timeout_seconds=5).health(
                expected_service_uid=os.geteuid() + 1
            )
        mismatch_worker.join(timeout=5)

    assert not worker.is_alive()
    assert not mismatch_worker.is_alive()
    assert mismatch.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert health.schema_version == "1.0"
    assert health.status == "ready"
    assert health.policy_version == 1
    assert health.service_pid == os.getpid()
    assert health.service_uid == os.geteuid()
    assert health.peer_uid == os.geteuid()
    assert health.allowed_modes == ("record", "stat")
    assert health.spool_root == str(spool.resolve())
    assert list(spool.iterdir()) == []


def test_broker_times_out_incomplete_frames_and_remains_available(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=_fake_perf(tmp_path),
        allowed_uids=(os.geteuid(),),
    )
    with CollectorBrokerServer(
        runtime / "collector.sock",
        policy,
        request_timeout_seconds=0.05,
    ) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stalled_client:
            stalled_client.settimeout(2)
            stalled_client.connect(str(server.socket_path))
            stalled_client.sendall(b'{"type":"health"')
            response = json.loads(stalled_client.recv(4096))

        health = CollectorBrokerClient(server.socket_path, timeout_seconds=2).health(
            expected_service_uid=os.geteuid()
        )

    worker.join(timeout=2)
    assert response["ok"] is False
    assert response["error"]["code"] == ErrorCode.INVALID_INPUT.value
    assert response["error"]["recoverable"] is True
    assert "timed out" in response["error"]["message"]
    assert health.status == "ready"
    assert not worker.is_alive()
    assert not server.socket_path.exists()


def test_collector_process_handles_sigterm_and_removes_socket(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    fake_perf = _fake_perf(tmp_path)
    policy_path = tmp_path / "collector.toml"
    policy_path.write_text(
        "[collector]\n"
        f'spool_root = "{spool}"\n'
        f'perf_path = "{fake_perf}"\n'
        f"allowed_uids = [{os.geteuid()}]\n",
        encoding="utf-8",
    )
    policy_path.chmod(0o444)
    socket_path = runtime / "collector.sock"
    project_root = Path(__file__).resolve().parents[2]
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and module entry point
        [
            sys.executable,
            "-m",
            "perflens.collector_broker.server",
            "--socket",
            str(socket_path),
            "--policy",
            str(policy_path),
        ],
        env={**os.environ, "PYTHONPATH": str(project_root / "src")},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not socket_path.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail(f"Collector exited during startup: {stdout=} {stderr=}")
            if time.monotonic() >= deadline:
                pytest.fail("Collector did not create its Unix socket within five seconds")
            time.sleep(0.01)

        health = CollectorBrokerClient(socket_path, timeout_seconds=2).health(
            expected_service_uid=os.geteuid()
        )
        denied_plan = CollectionPlanArtifact(
            plan_id="plan-abcdef012345678abcde",
            mode="record",
            target_type="pid",
            target_pid=99_999_999,
            target_uid=os.geteuid(),
            target_start_time_ticks=1,
            backend="privileged_broker",
            duration_seconds=0.1,
            frequency_hz=99,
            call_graph="dwarf",
            max_output_bytes=1024,
            expires_at=(datetime.now(tz=UTC) + timedelta(seconds=30)).isoformat(),
            policy_status="denied",
            required_privilege="cap_perfmon",
        )
        with pytest.raises(PerfLensError) as typed_rejection:
            CollectorBrokerClient(socket_path, timeout_seconds=2).collect(denied_plan)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as invalid_client:
            invalid_client.settimeout(2)
            invalid_client.connect(str(socket_path))
            invalid_client.sendall(b"{}\n")
            invalid_response = json.loads(invalid_client.recv(4096))
        process.send_signal(signal.SIGTERM)
        return_code = process.wait(timeout=5)
        stdout, stderr = process.communicate()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    assert health.status == "ready"
    assert invalid_response["ok"] is False
    assert invalid_response["error"]["code"] == ErrorCode.INVALID_INPUT.value
    assert return_code == 0
    assert stdout == ""
    assert not socket_path.exists()
    events = [json.loads(line) for line in stderr.splitlines()]
    assert [event["event"] for event in events] == [
        "collector_started",
        "request_rejected",
        "request_rejected",
        "collector_stopped",
    ]
    assert all(event["event_schema_version"] == "1.0" for event in events)
    assert all(len(line.encode("utf-8")) <= 2048 for line in stderr.splitlines())
    typed_event = events[1]
    assert typed_event["severity"] == "warning"
    assert typed_event["request_id"] == typed_rejection.value.details["request_id"]
    assert typed_event["error_id"] == stable_error_id(typed_rejection.value)
    assert typed_event["operation"] == "collect_pid"
    assert typed_event["plan_id"] == denied_plan.plan_id
    assert typed_event["peer_uid"] == os.geteuid()
    assert typed_event["error_code"] == ErrorCode.PATH_SAFETY_VIOLATION.value
    assert typed_event["stage"] == "authorization"
    assert typed_event["recoverable"] is True
    rejection = events[2]
    assert rejection["severity"] == "warning"
    assert rejection["request_id"] == "unknown"
    assert rejection["operation"] == "unknown"
    assert rejection["peer_uid"] == os.geteuid()
    assert rejection["error_code"] == ErrorCode.INVALID_INPUT.value
    assert rejection["stage"] == "collector_broker"
    assert rejection["recoverable"] is True
    assert str(denied_plan.target_pid) not in stderr
    assert str(tmp_path) not in stderr
    assert "Traceback" not in stderr


def test_collector_startup_failure_is_bounded_structured_and_path_free(tmp_path: Path) -> None:
    runtime = tmp_path / "run"
    runtime.mkdir()
    runtime.chmod(0o750)
    invalid_policy = tmp_path / "invalid-collector.toml"
    invalid_policy.write_text("[collector]\n", encoding="utf-8")
    invalid_policy.chmod(0o444)
    socket_path = runtime / "collector.sock"
    project_root = Path(__file__).resolve().parents[2]

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and module entry point
        [
            sys.executable,
            "-m",
            "perflens.collector_broker.server",
            "--socket",
            str(socket_path),
            "--policy",
            str(invalid_policy),
        ],
        env={**os.environ, "PYTHONPATH": str(project_root / "src")},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert not socket_path.exists()
    assert "Traceback" not in completed.stderr
    assert str(tmp_path) not in completed.stderr
    lines = completed.stderr.splitlines()
    assert len(lines) == 1
    assert len(lines[0].encode("utf-8")) <= 2048
    event = json.loads(lines[0])
    assert event["event_schema_version"] == "1.0"
    assert event["event"] == "collector_start_failed"
    assert event["severity"] == "error"
    assert event["error_code"] == ErrorCode.INVALID_INPUT.value
    assert event["stage"] == "collector_policy"
    assert event["recoverable"] is False


def test_runtime_status_requires_authenticated_broker_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    project = tmp_path / "project"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    fake_perf = _fake_perf(tmp_path)
    _prepare_status_setup(project, fake_perf)
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=fake_perf,
        allowed_uids=(os.geteuid(),),
        allowed_modes=("record", "stat"),
    )
    monkeypatch.setattr("perflens.distribution.status._collector_group_status", lambda: "member")
    with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
        monkeypatch.setattr("perflens.distribution.status._collector_service_uid", os.geteuid)
        worker = threading.Thread(target=server.serve_once, daemon=True)
        worker.start()
        accepted = inspect_runtime_status(
            project,
            collector_socket=server.socket_path,
            perf_path=fake_perf,
        )
        worker.join(timeout=5)

        monkeypatch.setattr(
            "perflens.distribution.status._collector_service_uid",
            lambda: os.geteuid() + 1,
        )
        rejected_worker = threading.Thread(target=server.serve_once, daemon=True)
        rejected_worker.start()
        rejected = inspect_runtime_status(
            project,
            collector_socket=server.socket_path,
            perf_path=fake_perf,
        )
        rejected_worker.join(timeout=5)

    assert not worker.is_alive()
    assert accepted.collector_health_status == "ready"
    assert accepted.collector_service_pid == os.getpid()
    assert accepted.collector_service_uid == os.geteuid()
    assert accepted.collector_policy_version == 1
    assert accepted.collector_allowed_modes == ("record", "stat")
    assert accepted.collector_spool_root == str(spool.resolve())
    assert accepted.automatic_collection_status == "ready_for_verification"
    assert list(spool.iterdir()) == []

    assert not rejected_worker.is_alive()
    assert rejected.collector_health_status == "rejected"
    assert rejected.collector_health_error_code == ErrorCode.PATH_SAFETY_VIOLATION.value
    assert rejected.automatic_collection_status == "collector_unavailable"
    assert "collector_health_rejected" in rejected.issues


def test_broker_health_rejects_unauthorized_peer_end_to_end(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=_fake_perf(tmp_path),
        allowed_uids=(os.geteuid() + 1,),
    )
    with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
        worker = threading.Thread(target=server.serve_once, daemon=True)
        worker.start()
        with pytest.raises(PerfLensError) as denied:
            CollectorBrokerClient(server.socket_path, timeout_seconds=5).health()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert denied.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert denied.value.stage == "authorization"
    assert list(spool.iterdir()) == []


def test_broker_collects_verified_pid_to_fixed_spool(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.1,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf(tmp_path),
            allowed_uids=(os.geteuid(),),
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            artifact = CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

            replay_worker = threading.Thread(target=server.serve_once, daemon=True)
            replay_worker.start()
            with pytest.raises(PerfLensError, match="already consumed"):
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            replay_worker.join(timeout=5)

        assert not worker.is_alive()
        assert not replay_worker.is_alive()
        assert artifact.target_pid == target.pid
        assert artifact.actual_event_source == "hardware"
        assert artifact.fallback_used is False
        assert any("disabled by Collector policy" in warning for warning in artifact.warnings)
        assert artifact.output_path.startswith(str(spool))
        assert Path(artifact.output_path).read_bytes() == b"PERFILE2-broker"
        assert Path(artifact.output_path).stat().st_mode & 0o777 == 0o640
        assert _collection_artifacts(spool) == (Path(artifact.output_path),)
        assert (spool / replay_marker_name(plan.plan_id)).is_file()
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_auto_falls_back_when_hardware_probe_has_no_counts(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=target.pid,
                duration_seconds=0.4,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf_with_unusable_hardware_pmu(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            artifact = CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert artifact.actual_event_source == "software"
        assert artifact.fallback_used is True
        assert artifact.fallback_reason == "hardware_probe_produced_no_usable_counts"
        assert artifact.events == SOFTWARE_STAT_EVENTS
        assert any("instructions-per-cycle" in item for item in artifact.evidence_limitations)
        assert {metric.event for metric in artifact.metrics}.issuperset(
            {"task-clock", "context-switches"}
        )
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
        assert len(_collection_artifacts(spool)) == 1
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_short_auto_collection_skips_hardware_probe(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=target.pid,
                duration_seconds=0.1,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            artifact = CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert artifact.actual_event_source == "software"
        assert artifact.fallback_reason == "hardware_probe_skipped_for_short_collection"
        assert artifact.events == SOFTWARE_STAT_EVENTS
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
    finally:
        target.terminate()
        target.wait(timeout=5)


@pytest.mark.parametrize(
    ("perf_factory", "expected_source", "expected_reason"),
    [
        (_fake_perf, "hardware", None),
        (_fake_perf_with_failed_hardware_probe, "software", "hardware_probe_failed"),
    ],
)
def test_cap_perfmon_broker_auto_selects_verified_event_source(
    tmp_path: Path,
    perf_factory: Any,
    expected_source: str,
    expected_reason: str | None,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=target.pid,
                duration_seconds=0.4,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=perf_factory(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            artifact = CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert artifact.actual_event_source == expected_source
        assert artifact.fallback_used is (expected_reason is not None)
        assert artifact.fallback_reason == expected_reason
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_retries_software_record_when_hardware_execution_fails(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.5,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf_with_failed_hardware_record_after_probe(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            artifact = CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert artifact.actual_event_source == "software"
        assert artifact.fallback_used is True
        assert artifact.fallback_reason == "hardware_execution_failed_after_probe"
        assert artifact.output_path.endswith(".perf.data")
        assert Path(artifact.output_path).read_bytes() == b"PERFILE2-software-record"
        assert len(_collection_artifacts(spool)) == 1
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_revalidates_pid_identity_before_software_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.5,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf_with_failed_hardware_record_after_probe(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        from perflens.collector_broker import server as broker_server

        real_assert_plan_current = broker_server.assert_plan_current
        validations = 0

        def revalidate(changing_plan: CollectionPlanArtifact) -> None:
            nonlocal validations
            validations += 1
            if validations == 3:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "authorization",
                    "Target PID identity changed before fallback",
                )
            real_assert_plan_current(changing_plan)

        monkeypatch.setattr(broker_server, "assert_plan_current", revalidate)
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError) as failure:
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert validations == 3
        assert failure.value.code is ErrorCode.PATH_SAFETY_VIOLATION
        assert not _collection_artifacts(spool)
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_does_not_hide_hardware_output_limit_with_fallback(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.5,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf_exceeding_output_after_hardware_probe(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError) as failure:
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert failure.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
        assert not _collection_artifacts(spool)
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_does_not_extend_exhausted_window_for_fallback(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.4,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf_exhausting_window_after_hardware_probe(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError) as failure:
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert failure.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
        assert not _collection_artifacts(spool)
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_does_not_hide_hardware_probe_output_limit(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=target.pid,
                duration_seconds=0.4,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf_exceeding_hardware_probe_limit(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError) as failure:
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert failure.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
        assert not _collection_artifacts(spool)
        assert not tuple(runtime.glob(".perflens-pmu-probe-*"))
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_cap_perfmon_broker_removes_artifact_when_permission_application_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=target.pid,
                duration_seconds=0.1,
                max_output_bytes=1024,
                event_source="software_only",
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf(tmp_path),
            allowed_uids=(os.geteuid(),),
            allow_software_fallback=True,
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            def fail_chmod(*_args: object, **_kwargs: object) -> None:
                raise OSError

            monkeypatch.setattr(os, "chmod", fail_chmod)
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError) as failure:
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert failure.value.code is ErrorCode.OUTPUT_WRITE_FAILED
        assert not _collection_artifacts(spool)
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_broker_delegates_paranoid3_collection_to_typed_helper(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    helper_spool = tmp_path / "helper-spool"
    runtime = tmp_path / "run"
    for directory in (spool, helper_spool, runtime):
        directory.mkdir()
        directory.chmod(0o750)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )

    class FakeHelper:
        def collect(
            self,
            plan: CollectionPlanArtifact,
            *,
            caller_uid: int,
        ) -> HelperCollectionResult:
            assert caller_uid == os.geteuid()
            payload = b"100;;cycles;10;100.0\n200;;instructions;10;100.0\n"
            output = helper_spool / f"{plan.plan_id}.stat.csv"
            output.write_bytes(payload)
            output.chmod(0o640)
            return HelperCollectionResult(
                kind="collection",
                plan_id=plan.plan_id,
                mode="stat",
                target_pid=plan.target_pid,
                artifact_name=output.name,
                output_bytes=len(payload),
                output_sha256=hashlib.sha256(payload).hexdigest(),
                output_format="perf_stat_delimited",
                actual_event_source="hardware",
                fallback_used=False,
                events=plan.events,
                started_at_unix_milliseconds=1_000,
                finished_at_unix_milliseconds=1_100,
            )

    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=target.pid,
                duration_seconds=0.1,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf(tmp_path),
            allowed_uids=(os.geteuid(),),
            privilege_mode="paranoid3_helper",
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        server = CollectorBrokerServer(
            runtime / "collector.sock",
            policy,
            helper_client=cast(HelperClient, FakeHelper()),
            helper_spool_root=helper_spool,
            expected_helper_uid=os.geteuid(),
        )
        with server:
            health_worker = threading.Thread(target=server.serve_once, daemon=True)
            health_worker.start()
            health = CollectorBrokerClient(server.socket_path, timeout_seconds=5).health()
            health_worker.join(timeout=5)
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            artifact = CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert not health_worker.is_alive()
        assert health.privilege_mode == "paranoid3_helper"
        assert health.spool_root == str(helper_spool)
        assert not worker.is_alive()
        assert artifact.output_path.startswith(str(helper_spool))
        assert artifact.output_owner_uid == os.geteuid()
        assert {metric.event for metric in artifact.metrics} == {
            "cycles",
            "instructions",
            "instructions-per-cycle",
        }
        assert list(spool.iterdir()) == []
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_failed_plan_cannot_be_replayed_after_broker_restart(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    invocation_count = tmp_path / "perf-invocations"
    failing_perf = tmp_path / "failing-perf"
    failing_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib\n"
        f"counter = pathlib.Path({str(invocation_count)!r})\n"
        "count = int(counter.read_text() or '0') if counter.exists() else 0\n"
        "counter.write_text(str(count + 1))\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    failing_perf.chmod(0o555)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.1,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=failing_perf,
            allowed_uids=(os.geteuid(),),
            max_duration_seconds=1,
            max_output_bytes=1024,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as first_server:
            worker = threading.Thread(target=first_server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError):
                CollectorBrokerClient(first_server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert invocation_count.read_text(encoding="utf-8") == "1"
        assert _collection_artifacts(spool) == ()
        assert (spool / replay_marker_name(plan.plan_id)).is_file()

        with CollectorBrokerServer(runtime / "collector.sock", policy) as restarted_server:
            replay_worker = threading.Thread(target=restarted_server.serve_once, daemon=True)
            replay_worker.start()
            with pytest.raises(PerfLensError, match="already consumed") as replayed:
                CollectorBrokerClient(restarted_server.socket_path, timeout_seconds=5).collect(plan)
            replay_worker.join(timeout=5)

        assert replayed.value.code is ErrorCode.PATH_SAFETY_VIOLATION
        assert invocation_count.read_text(encoding="utf-8") == "1"
        assert not worker.is_alive()
        assert not replay_worker.is_alive()
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_broker_rejects_collection_when_spool_quota_cannot_reserve_output(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    filler = spool / "plan-00000000000000000001.perf.data"
    filler.write_bytes(b"x")
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    try:
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=target.pid,
                duration_seconds=0.1,
                max_output_bytes=1024,
            ),
            policy=AutomaticCollectionPolicy(enabled=True, max_output_bytes=1024),
            capabilities=_capabilities(),
        )
        policy = CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf(tmp_path),
            allowed_uids=(os.geteuid(),),
            max_duration_seconds=1,
            max_output_bytes=1024,
            max_spool_bytes=1024,
            min_free_bytes=0,
        )
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            with pytest.raises(PerfLensError) as captured:
                CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
            worker.join(timeout=5)

        assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
        assert not worker.is_alive()
        assert list(spool.iterdir()) == [filler]
        assert filler.read_bytes() == b"x"
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_broker_policy_rejects_forged_target_owner(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    plan = create_collection_plan(
        CollectionPlanRequest(mode="record", pid=os.getppid(), duration_seconds=0.1),
        policy=AutomaticCollectionPolicy(enabled=True),
        capabilities=_capabilities(),
    ).model_copy(update={"target_uid": os.geteuid() + 1})
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=_fake_perf(tmp_path),
        allowed_uids=(os.geteuid(),),
        max_duration_seconds=1,
    )
    with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
        worker = threading.Thread(target=server.serve_once, daemon=True)
        worker.start()
        with pytest.raises(PerfLensError) as captured:
            CollectorBrokerClient(server.socket_path, timeout_seconds=5).collect(plan)
        worker.join(timeout=5)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert list(spool.iterdir()) == []


@pytest.mark.parametrize("output_mode", ["summary", "json", "file"])
def test_cli_verifies_real_broker_path_with_bounded_stat_probe(
    tmp_path: Path,
    output_mode: Literal["summary", "json", "file"],
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    fake_perf = _fake_perf(tmp_path)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=fake_perf,
        allowed_uids=(os.geteuid(),),
        allowed_modes=("record", "stat"),
        max_duration_seconds=5,
        max_output_bytes=8 << 20,
    )
    try:
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            arguments = [
                "verify-collector",
                "--socket",
                str(server.socket_path),
                "--pid",
                str(target.pid),
                "--duration-seconds",
                "0.1",
                "--perf-path",
                str(fake_perf),
                "--authorize-target",
                "--authorization",
                ACTIVE_COLLECTION_AUTHORIZATION,
                "--authorize-pid-attach",
                "--pid-authorization",
                PID_ATTACH_AUTHORIZATION,
            ]
            metadata_output = tmp_path / "verification.json"
            if output_mode == "json":
                arguments.append("--json")
            elif output_mode == "file":
                arguments.extend(("--output", str(metadata_output)))
            result = CliRunner().invoke(app, arguments)
            worker.join(timeout=5)

        assert result.exit_code == 0, result.output
        if output_mode == "summary":
            assert "PerfLens Collector 已有 PID 真实采集验证" in result.output
            assert f"目标 PID: {target.pid}" in result.output
            assert "状态: 采集完成" in result.output
            assert "指标: 实测" in result.output
            assert "结论边界:" in result.output
        else:
            raw = (
                result.output
                if output_mode == "json"
                else metadata_output.read_text(encoding="utf-8")
            )
            payload = json.loads(raw)
            assert payload["schema_version"] == "1.0"
            assert payload["mode"] == "stat"
            assert payload["target_pid"] == target.pid
            assert Path(payload["output_path"]).parent == spool
        assert not worker.is_alive()
    finally:
        target.terminate()
        target.wait(timeout=5)


@pytest.mark.parametrize("output_mode", ["summary", "json", "file"])
def test_cli_accepts_collector_without_user_supplied_pid(
    tmp_path: Path,
    *,
    output_mode: Literal["summary", "json", "file"],
) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    spool.mkdir()
    runtime.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    fake_perf = _fake_perf(tmp_path)
    policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=fake_perf,
        allowed_uids=(os.geteuid(),),
        allowed_modes=("record", "stat"),
        max_duration_seconds=5,
        max_output_bytes=8 << 20,
    )
    with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        arguments = [
            "accept-collector",
            "--socket",
            str(server.socket_path),
            "--duration-seconds",
            "0.1",
            "--perf-path",
            str(fake_perf),
            "--authorize-host-acceptance",
        ]
        acceptance_output = tmp_path / "collector-acceptance.json"
        if output_mode == "json":
            arguments.append("--json")
        elif output_mode == "file":
            arguments.extend(("--output", str(acceptance_output)))
        result = CliRunner().invoke(app, arguments)
    worker.join(timeout=5)

    assert result.exit_code == 0, result.output
    if output_mode in {"json", "file"}:
        raw_payload = (
            result.output
            if output_mode == "json"
            else acceptance_output.read_text(encoding="utf-8")
        )
        payload = json.loads(raw_payload)
        assert payload["schema_version"] == "1.0"
        assert payload["status"] == "passed"
        assert payload["probe_kind"] == "built_in_cpu"
        assert payload["metric_count"] >= 2
        assert Path(payload["output_path"]).parent == spool
        assert not Path(f"/proc/{payload['target_pid']}").exists()
        if output_mode == "file":
            assert f"证据已写入 {acceptance_output}" in result.output
    else:
        assert "PerfLens Collector 真实采集验收" in result.output
        assert "状态: 通过" in result.output
        assert "当前用户、Collector 策略和内核权限" in result.output
        assert "需要机器可读输出时使用 --json" in result.output
        assert len(tuple(spool.glob("plan-*.stat.csv"))) == 2
        assert len(tuple(spool.glob("plan-*.perf.data"))) == 1
    assert not worker.is_alive()


def test_mcp_plans_and_executes_single_use_automatic_collection(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    artifacts = tmp_path / "artifacts"
    spool.mkdir()
    runtime.mkdir()
    artifacts.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    fake_perf = _fake_perf(tmp_path)
    target = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        start_new_session=True,
    )
    broker_policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=fake_perf,
        allowed_uids=(os.geteuid(),),
        max_duration_seconds=1,
        max_output_bytes=1024,
    )
    try:
        with CollectorBrokerServer(runtime / "collector.sock", broker_policy) as broker:
            worker = threading.Thread(target=broker.serve_once, daemon=True)
            worker.start()
            mcp_server = create_server(
                ServerConfig(
                    allowed_roots=(tmp_path,),
                    artifact_root=artifacts,
                    allow_writes=True,
                    allow_process_execution=True,
                    allow_active_collection=True,
                    allow_pid_attach=True,
                    allow_automatic_collection=True,
                    collector_socket=broker.socket_path,
                    automatic_collection_policy=AutomaticCollectionPolicy(
                        enabled=True,
                        max_duration_seconds=1,
                        max_output_bytes=1024,
                    ),
                    perf_path=fake_perf,
                )
            )

            async def exercise() -> None:
                async with Client(mcp_server, raise_exceptions=True) as client:
                    planned = await client.call_tool(
                        "plan_automatic_collection",
                        {
                            "pid": target.pid,
                            "mode": "record",
                            "duration_seconds": 0.1,
                            "max_output_bytes": 1024,
                        },
                    )
                    plan = planned.structured_content
                    assert isinstance(plan, dict)
                    assert plan["policy_status"] == "allowed"
                    executed = await client.call_tool(
                        "execute_collection_plan",
                        {"plan_id": plan["plan_id"]},
                    )
                    result = executed.structured_content
                    assert isinstance(result, dict)
                    assert result["artifact_type"] == "collection"

                async with Client(mcp_server) as client:
                    repeated = await client.call_tool(
                        "execute_collection_plan",
                        {"plan_id": plan["plan_id"]},
                    )
                    assert repeated.is_error

            asyncio.run(exercise())
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert len(_collection_artifacts(spool)) == 1
        assert len(list(artifacts.glob("*.collection.json"))) == 1
    finally:
        target.terminate()
        target.wait(timeout=5)


def test_mcp_launches_exact_project_workload_then_collects_bound_pid(tmp_path: Path) -> None:
    project = tmp_path / "project"
    spool = tmp_path / "spool"
    runtime = tmp_path / "run"
    artifacts = project / "artifacts"
    for directory in (project, spool, runtime, artifacts):
        directory.mkdir()
    spool.chmod(0o750)
    runtime.chmod(0o750)
    marker = project / "started.txt"
    workload = project / "workload"
    workload.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys, time\n"
        "pathlib.Path(sys.argv[1]).write_text('started', encoding='utf-8')\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    workload.chmod(0o555)
    fake_perf = _fake_perf(tmp_path)
    broker_policy = CollectorBrokerPolicy(
        spool_root=spool,
        perf_path=fake_perf,
        allowed_uids=(os.geteuid(),),
        allowed_modes=("record",),
        max_duration_seconds=1,
        max_output_bytes=1024,
    )
    with CollectorBrokerServer(runtime / "collector.sock", broker_policy) as broker:
        worker = threading.Thread(target=broker.serve_once, daemon=True)
        worker.start()
        mcp_server = create_server(
            ServerConfig(
                allowed_roots=(project, spool),
                artifact_root=artifacts,
                allow_writes=True,
                allow_process_execution=True,
                allow_active_collection=True,
                allow_pid_attach=False,
                allow_automatic_collection=True,
                allow_project_execution=True,
                collector_socket=broker.socket_path,
                automatic_collection_policy=AutomaticCollectionPolicy(
                    enabled=True,
                    allowed_modes=("record",),
                    max_duration_seconds=1,
                    max_output_bytes=1024,
                ),
                perf_path=fake_perf,
            )
        )

        async def exercise() -> dict[str, object]:
            async with Client(mcp_server, raise_exceptions=True) as client:
                result = await client.call_tool(
                    "collect_project_workload",
                    {
                        "project_root": str(project),
                        "executable": str(workload),
                        "arguments": [str(marker)],
                        "authorization": PROJECT_EXECUTION_AUTHORIZATION,
                        "mode": "record",
                        "duration_seconds": 0.1,
                        "max_output_bytes": 1024,
                    },
                )
                payload = result.structured_content
                assert isinstance(payload, dict)
                return cast(dict[str, Any], payload)

        payload = asyncio.run(exercise())
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert marker.read_text(encoding="utf-8") == "started"
    assert payload["artifact_type"] == "project-run"
    summary = payload["summary"]
    assert isinstance(summary, dict)
    assert summary["workload_status"] == "terminated_after_collection"
    assert isinstance(summary["target_pid"], int)
    assert not Path(f"/proc/{summary['target_pid']}").exists()
    assert len(list(artifacts.glob("*.project-run.json"))) == 1
    assert len(list(artifacts.glob("*.collection.json"))) == 1
    assert len(_collection_artifacts(spool)) == 1
