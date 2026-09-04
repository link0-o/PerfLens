from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from mcp.client import Client
from tests.unit.test_go_pprof_launcher import GO_WORKLOAD

from perflens.docker.workload import inspect_managed_project_root
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.go_pprof_adapter import (
    GoToolIdentity,
    build_go_pprof_adapter_bridge,
    inspect_go_pprof_installation,
)
from perflens.runtime_locks.go_pprof_converter import GoProfileKind
from perflens.runtime_locks.go_pprof_launcher import GoPprofLauncher
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)
from perflens.runtime_locks.supervisor import RuntimeSupervisorClient


def _structured(result: object) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    return cast(dict[str, Any], structured)


def _enabled_policy() -> str:
    return render_default_runtime_lock_project_policy().replace(
        "launch_instrumentation_allowed = false\ncontrolled_import_allowed = false\n"
        "mutex_profile_fraction = 0\nblock_profile_rate_ns = 0\n"
        "file_backend_enabled = false\nloopback_backend_enabled = false",
        "launch_instrumentation_allowed = true\ncontrolled_import_allowed = false\n"
        "mutex_profile_fraction = 1\nblock_profile_rate_ns = 1\n"
        "file_backend_enabled = true\nloopback_backend_enabled = false",
        1,
    )


def _loopback_policy() -> str:
    return _enabled_policy().replace(
        "file_backend_enabled = true\nloopback_backend_enabled = false",
        "file_backend_enabled = true\nloopback_backend_enabled = true",
        1,
    )


def _build_go_workload(project: Path) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain is unavailable")
    source = project / "workload.go"
    executable = project / "workload"
    source.write_text(GO_WORKLOAD, encoding="utf-8")
    source.chmod(0o600)
    subprocess.run(  # noqa: S603 - fixed test source and output in tmp_path
        (go, "build", "-o", str(executable), str(source)),
        check=True,
        capture_output=True,
        timeout=120,
        env={
            "PATH": os.environ.get("PATH", ""),
            "GOCACHE": str(project.parent / "go-cache"),
            "GOPATH": str(project.parent / "go-path"),
            "HOME": str(project.parent),
        },
    )
    executable.chmod(0o700)
    return executable


def _server(
    tmp_path: Path,
    supervisor: RuntimeSupervisorClient,
    *,
    policy_text: str | None = None,
) -> tuple[object, Path, Path]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    _build_go_workload(project)
    setup = project / "perflens-setup"
    setup.mkdir()
    policy_path = setup / "runtime-locks.toml"
    policy_path.write_text(policy_text or _enabled_policy(), encoding="utf-8")
    policy_path.chmod(0o600)
    artifacts = project / "artifacts"
    artifacts.mkdir()
    go_path = Path(shutil.which("go") or "").resolve(strict=True)
    installation = inspect_go_pprof_installation(
        go_path=go_path,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid(), go_path.stat().st_uid))),
    )
    assert installation.tool is not None
    assert installation.pprof_tool is not None
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(project,))
    bridge = build_go_pprof_adapter_bridge(
        policy,
        installation,
        created_at=datetime(2026, 8, 31, tzinfo=UTC).isoformat(),
    )
    inspection = inspect_runtime_lock_capability(
        policy,
        project_identity_sha256=inspect_managed_project_root(project).identity_sha256,
        go_pprof_bridge=bridge,
        created_at=datetime(2026, 8, 31, tzinfo=UTC),
    )

    def launcher_factory(
        project_root: Path,
        private_root: Path,
        go_tool: GoToolIdentity,
        pprof_tool: GoToolIdentity,
    ) -> GoPprofLauncher:
        return GoPprofLauncher(
            project_root=project_root,
            private_output_root=private_root,
            go_tool=go_tool,
            pprof_tool=pprof_tool,
            supervisor_client=supervisor,
        )

    server = create_server(
        ServerConfig(
            allowed_roots=(project,),
            artifact_root=artifacts,
            allow_writes=True,
            allow_process_execution=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy_path,
            runtime_lock_capability_factory=lambda: inspection,
            runtime_lock_go_bridge_factory=lambda: bridge,
            runtime_lock_go_launcher_factory=launcher_factory,
        )
    )
    return server, project, artifacts


GO_LOOPBACK_WORKLOAD = r"""
package main

import (
    "fmt"
    "net/http"
    _ "net/http/pprof"
    "os"
    "runtime"
    "strconv"
    "sync"
    "time"
)

func main() {
    if len(os.Args) != 2 { os.Exit(2) }
    port, err := strconv.Atoi(os.Args[1]); if err != nil { os.Exit(2) }
    runtime.SetMutexProfileFraction(1)
    runtime.SetBlockProfileRate(1)
    listenerReady := make(chan struct{})
    server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port)}
    go func() { close(listenerReady); _ = server.ListenAndServe() }()
    <-listenerReady
    var lock sync.Mutex
    for i := 0; i < 20; i++ {
        var wait sync.WaitGroup
        wait.Add(2)
        for j := 0; j < 2; j++ {
            go func() {
                defer wait.Done()
                for k := 0; k < 100; k++ {
                    lock.Lock(); time.Sleep(100 * time.Microsecond); lock.Unlock()
                }
            }()
        }
        wait.Wait()
    }
    time.Sleep(30 * time.Second)
}
"""


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _build_loopback_workload(project: Path) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain is unavailable")
    source = project / "loopback.go"
    executable = project / "loopback"
    source.write_text(GO_LOOPBACK_WORKLOAD, encoding="utf-8")
    source.chmod(0o600)
    subprocess.run(  # noqa: S603 - fixed test source and output in tmp_path
        (go, "build", "-o", str(executable), str(source)),
        check=True,
        capture_output=True,
        timeout=120,
        env={
            "PATH": os.environ.get("PATH", ""),
            "GOCACHE": str(project.parent / "go-loopback-cache"),
            "GOPATH": str(project.parent / "go-loopback-path"),
            "HOME": str(project.parent),
        },
    )
    executable.chmod(0o700)
    return executable


@pytest.mark.timeout(30)
@pytest.mark.parametrize("profile_kind", ("mutex", "block"))
def test_go_preview_authorize_collect_profile_and_reload(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    profile_kind: GoProfileKind,
) -> None:
    # A cold, real Go build plus one supervised profile collection may exceed
    # the repository-wide 10 second unit-test guard on slower CI workers.
    server, project, artifacts = _server(tmp_path, runtime_supervisor_client)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview_result = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["go_pprof"],
                    "allowed_semantics": ["cumulative"],
                    "executable": "workload",
                    "arguments": [],
                },
            )
            assert not preview_result.is_error, preview_result.content
            preview = _structured(preview_result)
            assert preview["workload"]["workload_kind"] == "go_elf"
            assert [tool["name"] for tool in preview["adapter_execution_bindings"][0]["tools"]] == [
                "go",
                "pprof",
            ]
            authorization = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview[
                        "authorization_summary_sha256"
                    ],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
                    ),
                },
            )
            assert not authorization.is_error, authorization.content
            session = _structured(authorization)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "cumulative",
                    "duration_seconds": 10,
                    "max_events": 500,
                    "profile_kind": profile_kind,
                },
            )
            assert not collected.is_error, collected.content
            reference = _structured(collected)
            assert reference["summary"]["adapter_id"] == "go_pprof"
            assert reference["summary"]["profile_kind"] == profile_kind
            assert reference["summary"]["private_source_replay_status"] == "passed"

    asyncio.run(exercise())
    assert not list(artifacts.glob(".runtime-lock-go-*/*"))
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    run_paths = sorted(artifacts.glob("*.runtime-lock-run.json"))
    assert len(run_paths) == 1
    runs = [
        store.load_runtime_lock_run(path.name.removesuffix(".runtime-lock-run.json"))
        for path in run_paths
    ]
    assert all(run.adapter_id == "go_pprof" for run in runs)
    assert all(run.measurement_semantics == "cumulative" for run in runs)
    assert all(run.correctness_status == "passed" for run in runs)


def test_go_rejects_non_cumulative_collection_before_launch(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    server, _project, artifacts = _server(tmp_path, runtime_supervisor_client)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview_result = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["go_pprof"],
                    "allowed_semantics": ["cumulative"],
                    "executable": "workload",
                    "arguments": [],
                },
            )
            preview = _structured(preview_result)
            authorization = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview[
                        "authorization_summary_sha256"
                    ],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
                    ),
                },
            )
            session = _structured(authorization)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 100,
                },
            )
            assert rejected.is_error
            assert "requires cumulative" in str(rejected.content)

    asyncio.run(exercise())
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


@pytest.mark.timeout(60)
def test_go_loopback_preview_binds_pid_socket_and_collects_cumulative_profile(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    server, project, artifacts = _server(
        tmp_path,
        runtime_supervisor_client,
        policy_text=_loopback_policy(),
    )
    executable = _build_loopback_workload(project)
    port = _free_loopback_port()
    process = subprocess.Popen(  # noqa: S603 - fixed test binary and numeric loopback port
        (str(executable), str(port)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for _ in range(200):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                    break
            except OSError:
                if process.poll() is not None:
                    pytest.fail(f"Go loopback workload exited: {process.stderr}")
                asyncio.run(asyncio.sleep(0.01))
        else:
            pytest.fail("Go loopback workload did not listen")

        async def exercise() -> None:
            async with Client(cast(Any, server)) as client:
                preview_result = await client.call_tool(
                    "preview_runtime_lock_session",
                    {
                        "target_scope": "host_bound_process",
                        "allowed_adapters": ["go_pprof"],
                        "allowed_semantics": ["cumulative"],
                        "target_pid": process.pid,
                        "loopback_port": port,
                    },
                )
                assert not preview_result.is_error, preview_result.content
                preview = _structured(preview_result)
                assert preview["process_target"]["target_pid"] == process.pid
                assert preview["process_target"]["loopback_port"] == port
                authorization = await client.call_tool(
                    "authorize_runtime_lock_session",
                    {
                        "preview_id": preview["preview_id"],
                        "preview_content_sha256": preview["content_sha256"],
                        "authorization_summary_sha256": preview[
                            "authorization_summary_sha256"
                        ],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
                        ),
                    },
                )
                assert not authorization.is_error, authorization.content
                session = _structured(authorization)
                collected = await client.call_tool(
                    "collect_runtime_lock_evidence",
                    {
                        "session_id": session["session_id"],
                        "measurement_semantics": "cumulative",
                        "duration_seconds": 10,
                        "max_events": 500,
                        "profile_kind": "mutex",
                    },
                )
                assert not collected.is_error, collected.content
                summary = _structured(collected)["summary"]
                assert summary["backend"] == "same_uid_loopback"
                assert summary["target_pid"] == process.pid

        asyncio.run(exercise())
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    assert not list(artifacts.glob(".runtime-lock-go-*/*"))
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    run_path = next(artifacts.glob("*.runtime-lock-run.json"))
    run = store.load_runtime_lock_run(run_path.name.removesuffix(".runtime-lock-run.json"))
    assert run.target_scope == "host_bound_process"
    assert run.correctness_status == "unavailable"
