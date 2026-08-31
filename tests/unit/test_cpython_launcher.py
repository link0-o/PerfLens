from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import cpython_launcher as launcher_module
from perflens.runtime_locks.cpython_adapter import (
    CpythonAdapterBridge,
    build_cpython_adapter_bridge,
    inspect_cpython_installation,
)
from perflens.runtime_locks.cpython_converter import convert_cpython_threading_stream
from perflens.runtime_locks.cpython_launcher import (
    CpythonLaunchRequest,
    CpythonThreadingLauncher,
    cleanup_cpython_launch_result,
    open_cpython_private_stream,
)
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)
from perflens.runtime_locks.supervisor import RuntimeSupervisorClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (
    PROJECT_ROOT / "src/perflens/runtime_locks/cpython/cpython_threading_bootstrap.py"
)

WORKLOAD = """
import threading

lock = threading.Lock()
with lock:
    pass
worker = threading.Thread(target=lambda: (lock.acquire(), lock.release()))
worker.start()
worker.join()
rlock = threading.RLock()
rlock.acquire()
rlock.acquire()
rlock.release()
rlock.release()
condition = threading.Condition()
with condition:
    condition.wait(timeout=0.001)
with threading.Semaphore(1):
    pass
with threading.BoundedSemaphore(1):
    pass
"""


def _policy(tmp_path: Path):
    path = tmp_path / "runtime-locks.toml"
    path.write_text(render_default_runtime_lock_project_policy(), encoding="utf-8")
    path.chmod(0o600)
    return load_runtime_lock_project_policy(path, allowed_roots=(tmp_path,))


def _launcher(
    tmp_path: Path, supervisor: RuntimeSupervisorClient
) -> tuple[CpythonThreadingLauncher, CpythonAdapterBridge]:
    interpreter = Path(sys.executable).resolve(strict=True)
    installed_bootstrap = tmp_path / "installed-bootstrap.py"
    shutil.copyfile(BOOTSTRAP, installed_bootstrap)
    installed_bootstrap.chmod(0o644)
    trusted_owners = tuple(
        dict.fromkeys((0, os.geteuid(), interpreter.stat(follow_symlinks=False).st_uid))
    )
    installation = inspect_cpython_installation(
        interpreter_path=interpreter,
        bootstrap_path=installed_bootstrap,
        trusted_owner_uids=trusted_owners,
    )
    assert installation.availability == "available"
    bridge = build_cpython_adapter_bridge(_policy(tmp_path), installation)
    assert bridge.launch_policy is not None
    project = tmp_path / "project"
    output = tmp_path / "private"
    project.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    return (
        CpythonThreadingLauncher(
            project_root=project,
            private_output_root=output,
            policy=bridge.launch_policy,
            supervisor_client=supervisor,
        ),
        bridge,
    )


def test_real_supervisor_runs_public_threading_surface_and_cleans_private_stream(
    tmp_path: Path, runtime_supervisor_client: RuntimeSupervisorClient
) -> None:
    launcher, bridge = _launcher(tmp_path, runtime_supervisor_client)
    script = tmp_path / "project/workload.py"
    script.write_text(WORKLOAD, encoding="utf-8")
    script.chmod(0o600)
    target = launcher.inspect_target(script)

    result = launcher.launch(
        script,
        CpythonLaunchRequest(
            arguments=(),
            semantics="exact",
            threshold_ns=None,
            duration_seconds=3,
            max_events=2_000,
        ),
        expected_target_identity_sha256=target.identity_sha256,
    )
    binding = bridge.binding_for("exact")
    assert binding is not None
    source_fd = open_cpython_private_stream(result)
    try:
        with os.fdopen(os.dup(source_fd), "rb") as source:
            evidence = convert_cpython_threading_stream(
                source,
                execution_binding=binding,
                created_at="2026-08-31T00:00:00+00:00",
            ).evidence
    finally:
        os.close(source_fd)

    assert result.exit_code == 0
    assert result.termination_reason == "exited"
    assert {event.lock_kind for event in evidence.events} == {
        "condition",
        "mutex",
        "recursive_mutex",
        "semaphore",
    }
    assert {event.event_kind for event in evidence.events} == {
        "acquire",
        "release",
        "wait_begin",
        "wait_end",
    }
    assert len(evidence.execution_contexts) >= 2
    assert any(
        frame.source_file == "workload.py"
        for stack in evidence.stacks
        for frame in stack.frames
    )
    cleanup_cpython_launch_result(result)
    assert not result.stream_path.exists()


def test_fork_child_is_not_allowed_to_write_parent_runtime_lock_evidence(
    tmp_path: Path, runtime_supervisor_client: RuntimeSupervisorClient
) -> None:
    launcher, bridge = _launcher(tmp_path, runtime_supervisor_client)
    script = tmp_path / "project/forked.py"
    script.write_text(
        "import os, threading\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    with threading.Lock():\n"
        "        pass\n"
        "    os._exit(0)\n"
        "_, status = os.waitpid(child, 0)\n"
        "assert os.waitstatus_to_exitcode(status) == 0\n"
        "with threading.Lock():\n"
        "    pass\n",
        encoding="utf-8",
    )
    script.chmod(0o600)
    target = launcher.inspect_target(script)
    result = launcher.launch(
        script,
        CpythonLaunchRequest((), "exact", None, 3, 500),
        expected_target_identity_sha256=target.identity_sha256,
    )
    binding = bridge.binding_for("exact")
    assert binding is not None
    source_fd = open_cpython_private_stream(result)
    try:
        with os.fdopen(os.dup(source_fd), "rb") as source:
            evidence = convert_cpython_threading_stream(
                source, execution_binding=binding
            ).evidence
    finally:
        os.close(source_fd)
    assert result.exit_code == 0
    assert evidence.target.observed_target_tids == (result.target_pid,)
    assert len(evidence.events) == 4
    cleanup_cpython_launch_result(result)


def test_thresholded_bootstrap_never_emits_release_for_an_omitted_acquire(
    tmp_path: Path, runtime_supervisor_client: RuntimeSupervisorClient
) -> None:
    launcher, bridge = _launcher(tmp_path, runtime_supervisor_client)
    script = tmp_path / "project/thresholded.py"
    script.write_text(
        "import threading\n"
        "lock = threading.Lock()\n"
        "for _ in range(100):\n"
        "    lock.acquire()\n"
        "    lock.release()\n"
        "condition = threading.Condition()\n"
        "with condition:\n"
        "    condition.wait(timeout=0.001)\n",
        encoding="utf-8",
    )
    script.chmod(0o600)
    target = launcher.inspect_target(script)
    result = launcher.launch(
        script,
        CpythonLaunchRequest((), "thresholded", 10_000, 30, 500),
        expected_target_identity_sha256=target.identity_sha256,
    )
    binding = bridge.binding_for("thresholded")
    assert binding is not None
    source_fd = open_cpython_private_stream(result)
    try:
        with os.fdopen(os.dup(source_fd), "rb") as source:
            evidence = convert_cpython_threading_stream(
                source, execution_binding=binding
            ).evidence
    finally:
        os.close(source_fd)
    acquired: set[str] = set()
    for event in evidence.events:
        if event.event_kind == "acquire" and event.lock_id is not None:
            acquired.add(event.lock_id)
        if event.event_kind == "release":
            assert event.lock_id in acquired
    assert all(
        event.duration_ns >= 10_000
        for event in evidence.events
        if event.event_kind == "wait_end"
    )
    cleanup_cpython_launch_result(result)


def test_launcher_rejects_symlink_target_and_file_capabilities(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher, _bridge = _launcher(tmp_path, runtime_supervisor_client)
    script = tmp_path / "project/workload.py"
    script.write_text("pass\n", encoding="utf-8")
    script.chmod(0o600)
    alias = tmp_path / "project/alias.py"
    alias.symlink_to(script.name)
    with pytest.raises(PerfLensError, match="symlink"):
        launcher.inspect_target(alias)

    def fixed_capability(*_args: object, **_kwargs: object) -> bytes:
        return b"capability"

    monkeypatch.setattr(launcher_module.os, "getxattr", fixed_capability)
    with pytest.raises(PerfLensError, match="file capabilities"):
        launcher.inspect_target(script)


def test_launch_request_has_fixed_exact_and_threshold_budgets() -> None:
    with pytest.raises(PerfLensError, match="exact launch controls"):
        CpythonLaunchRequest(
            arguments=(),
            semantics="exact",
            threshold_ns=None,
            duration_seconds=4,
            max_events=20_000,
        )
    with pytest.raises(PerfLensError, match="fixed 10 us"):
        CpythonLaunchRequest(
            arguments=(),
            semantics="thresholded",
            threshold_ns=9_999,
            duration_seconds=30,
            max_events=20_000,
        )
    with pytest.raises(PerfLensError, match="contains NUL"):
        CpythonLaunchRequest(
            arguments=("bad\0arg",),
            semantics="thresholded",
            threshold_ns=10_000,
            duration_seconds=30,
            max_events=20_000,
        )
