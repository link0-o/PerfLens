from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from mcp.client import Client
from typer.testing import CliRunner

from perflens.cli.app import app
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    PID_ATTACH_AUTHORIZATION,
)
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.collector_broker.policy import CollectorBrokerPolicy
from perflens.collector_broker.server import CollectorBrokerServer
from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectionModeCapability,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.server import ServerConfig, create_server
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
        "    output.write_text('100;;cycles;10;100.0\\n200;;instructions;10;100.0\\n')\n"
        "else:\n"
        "    output.write_bytes(b'PERFILE2-broker')\n",
        encoding="utf-8",
    )
    executable.chmod(0o555)
    return executable


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
        assert artifact.output_path.startswith(str(spool))
        assert Path(artifact.output_path).read_bytes() == b"PERFILE2-broker"
        assert list(spool.iterdir()) == [Path(artifact.output_path)]
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


def test_cli_verifies_real_broker_path_with_bounded_stat_probe(tmp_path: Path) -> None:
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
        allowed_modes=("stat",),
        max_duration_seconds=5,
        max_output_bytes=8 << 20,
    )
    try:
        with CollectorBrokerServer(runtime / "collector.sock", policy) as server:
            worker = threading.Thread(target=server.serve_once, daemon=True)
            worker.start()
            result = CliRunner().invoke(
                app,
                [
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
                ],
            )
            worker.join(timeout=5)

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["schema_version"] == "1.0"
        assert payload["mode"] == "stat"
        assert payload["target_pid"] == target.pid
        assert Path(payload["output_path"]).parent == spool
        assert not worker.is_alive()
    finally:
        target.terminate()
        target.wait(timeout=5)


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
        assert len(list(spool.iterdir())) == 1
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
                allow_pid_attach=True,
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
    assert len(list(spool.iterdir())) == 1
