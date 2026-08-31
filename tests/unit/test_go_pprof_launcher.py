from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import go_pprof_launcher as launcher_module
from perflens.runtime_locks.go_pprof_adapter import (
    GoPprofInstallation,
    build_go_pprof_adapter_bridge,
    inspect_go_pprof_installation,
)
from perflens.runtime_locks.go_pprof_converter import convert_go_pprof_raw
from perflens.runtime_locks.go_pprof_launcher import (
    GoPprofLauncher,
    GoPprofLaunchRequest,
    GoPprofRawResult,
    cleanup_go_pprof_result,
    open_go_pprof_raw,
)
from perflens.runtime_locks.project_config import (
    RuntimeLockProjectPolicy,
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)
from perflens.runtime_locks.supervisor import RuntimeSupervisorClient

GO_WORKLOAD = r'''
package main

import (
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
)

func writeProfile(name, destination string) {
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil { panic(err) }
	defer f.Close()
	if err := pprof.Lookup(name).WriteTo(f, 0); err != nil { panic(err) }
}

func main() {
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
	var lock sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < 20000; n++ {
				lock.Lock()
				for spin := 0; spin < 100; spin++ {}
				lock.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	writeProfile("mutex", os.Getenv("PERFLENS_GO_MUTEX_PROFILE"))
	writeProfile("block", os.Getenv("PERFLENS_GO_BLOCK_PROFILE"))
}
'''


def _go_installation() -> GoPprofInstallation:
    go = Path(shutil.which("go") or "")
    if not go:
        pytest.skip("Go toolchain is unavailable")
    owner = go.resolve(strict=True).stat().st_uid
    installation = inspect_go_pprof_installation(
        go_path=go,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid(), owner))),
    )
    if installation.tool is None:
        pytest.skip("Go toolchain cannot be safely inspected")
    assert installation.pprof_tool is not None
    return installation


def _policy(tmp_path: Path) -> RuntimeLockProjectPolicy:
    text = render_default_runtime_lock_project_policy()
    text = text.replace(
        "launch_instrumentation_allowed = false\ncontrolled_import_allowed = false\n"
        "mutex_profile_fraction = 0\nblock_profile_rate_ns = 0\n"
        "file_backend_enabled = false\nloopback_backend_enabled = false",
        "launch_instrumentation_allowed = true\ncontrolled_import_allowed = false\n"
        "mutex_profile_fraction = 1\nblock_profile_rate_ns = 1\n"
        "file_backend_enabled = true\nloopback_backend_enabled = false",
        1,
    )
    path = tmp_path / "runtime-locks.toml"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return load_runtime_lock_project_policy(path, allowed_roots=(tmp_path,))


def _build_workload(project: Path) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain is unavailable")
    source = project / "workload.go"
    target = project / "workload"
    source.write_text(GO_WORKLOAD, encoding="utf-8")
    source.chmod(0o600)
    subprocess.run(  # noqa: S603 - fixed test source and output in tmp_path
        (go, "build", "-o", str(target), str(source)),
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
    target.chmod(0o700)
    return target


def test_real_supervisor_collects_mutex_and_block_profiles(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    installation = _go_installation()
    bridge = build_go_pprof_adapter_bridge(_policy(tmp_path), installation)
    assert bridge.execution_binding is not None
    assert bridge.tool is not None
    assert bridge.pprof_tool is not None
    project = tmp_path / "project"
    private = tmp_path / "private"
    project.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    target_path = _build_workload(project)
    launcher = GoPprofLauncher(
        project_root=project,
        private_output_root=private,
        go_tool=bridge.tool,
        pprof_tool=bridge.pprof_tool,
        supervisor_client=runtime_supervisor_client,
    )
    target = launcher.inspect_target(target_path)
    launch = launcher.launch(
        target_path,
        GoPprofLaunchRequest(arguments=(), duration_seconds=10),
        expected_target_identity_sha256=target.identity_sha256,
    )

    assert launch.exit_code == 0
    assert launch.termination_reason == "exited"
    raw_results: list[GoPprofRawResult] = []
    for kind in ("mutex", "block"):
        raw = launcher.render_raw(launch, kind)
        raw_results.append(raw)
        raw_fd = open_go_pprof_raw(raw)
        try:
            with os.fdopen(os.dup(raw_fd), "rb") as stream:
                receipt = convert_go_pprof_raw(
                    stream,
                    execution_binding=bridge.execution_binding,
                    profile_kind=kind,
                    target_pid=launch.target_pid,
                    target_uid=launch.target_uid,
                    target_start_time_ticks=launch.target_start_ticks,
                    mutex_profile_fraction=(1 if kind == "mutex" else None),
                    block_profile_rate_ns=(1 if kind == "block" else None),
                )
        finally:
            os.close(raw_fd)
        assert receipt.evidence.events
        assert receipt.evidence.execution_contexts[0].kind == "process_aggregate"
        assert all("owner" not in event.model_dump() for event in receipt.evidence.events)
    foreign_root = tmp_path / "foreign"
    foreign_root.mkdir(mode=0o700)
    with pytest.raises(PerfLensError, match="different private root"):
        open_go_pprof_raw(replace(raw_results[0], private_root=foreign_root))
    cleanup_go_pprof_result(launch, tuple(raw_results))
    assert not launch.mutex_profile_path.exists()
    assert not launch.block_profile_path.exists()


def test_launcher_rejects_symlink_capability_and_identity_change(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installation = _go_installation()
    assert installation.tool is not None
    assert installation.pprof_tool is not None
    project = tmp_path / "project"
    private = tmp_path / "private"
    project.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    target_path = _build_workload(project)
    launcher = GoPprofLauncher(
        project_root=project,
        private_output_root=private,
        go_tool=installation.tool,
        pprof_tool=installation.pprof_tool,
        supervisor_client=runtime_supervisor_client,
    )
    alias = project / "alias"
    alias.symlink_to(target_path.name)
    with pytest.raises(PerfLensError, match="symlink"):
        launcher.inspect_target(alias)

    def fake_getxattr(*_args: object) -> bytes:
        return b"capability"

    monkeypatch.setattr(launcher_module.os, "getxattr", fake_getxattr)
    with pytest.raises(PerfLensError, match="file capabilities"):
        launcher.inspect_target(target_path)
    monkeypatch.undo()

    target = launcher.inspect_target(target_path)
    target_path.write_bytes(target_path.read_bytes() + b"changed")
    with pytest.raises(PerfLensError, match="differs from the authorized Preview"):
        launcher.launch(
            target_path,
            GoPprofLaunchRequest(arguments=(), duration_seconds=3),
            expected_target_identity_sha256=target.identity_sha256,
        )


def test_launch_request_is_bounded() -> None:
    with pytest.raises(PerfLensError, match="30 second"):
        GoPprofLaunchRequest(arguments=(), duration_seconds=31)
    with pytest.raises(PerfLensError, match="safe bound"):
        GoPprofLaunchRequest(arguments=("bad\0argument",), duration_seconds=1)
