from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from perflens.runtime_locks import cpython_adapter as adapter
from perflens.runtime_locks.cpython_adapter import (
    build_cpython_adapter_bridge,
    inspect_cpython_installation,
)
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)


def _policy(tmp_path: Path, *, disabled: bool = False):
    payload = render_default_runtime_lock_project_policy()
    if disabled:
        payload = payload.replace("enabled = true", "enabled = false", 1)
    path = tmp_path / "runtime-locks.toml"
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return load_runtime_lock_project_policy(path, allowed_roots=(tmp_path,))


def _installation(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    interpreter = tmp_path / "python3"
    runtime_home = tmp_path / "runtime-home"
    bootstrap = tmp_path / "bootstrap.py"
    runtime_home.mkdir(mode=0o755)
    interpreter.write_bytes(b"fixed interpreter identity")
    bootstrap.write_bytes(b"fixed bootstrap identity")
    interpreter.chmod(0o755)
    bootstrap.chmod(0o644)
    return inspect_cpython_installation(
        interpreter_path=interpreter,
        runtime_home_path=runtime_home,
        bootstrap_path=bootstrap,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )


def test_bridge_binds_exact_and_thresholded_startup_controls(tmp_path: Path) -> None:
    installation = _installation(tmp_path)
    bridge = build_cpython_adapter_bridge(
        _policy(tmp_path), installation, created_at="2026-08-31T00:00:00+00:00"
    )

    assert bridge.capability.availability == "available"
    assert bridge.launch_policy is not None
    assert tuple(item.measurement_semantics for item in bridge.execution_bindings) == (
        "exact",
        "thresholded",
    )
    exact = bridge.binding_for("exact")
    thresholded = bridge.binding_for("thresholded")
    assert exact is not None and exact.duration_threshold_ns is None
    assert thresholded is not None and thresholded.duration_threshold_ns == 10_000
    public = bridge.capability.model_dump_json() + "".join(
        item.model_dump_json() for item in bridge.execution_bindings
    )
    assert str(tmp_path) not in public
    assert "traditional_gil_conclusion" not in public
    assert "GIL event surface" in public


def test_free_threaded_runtime_is_explicit_and_forbids_traditional_gil_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = adapter.sysconfig.get_config_var

    def free_threaded_config(name: str) -> object:
        return 1 if name == "Py_GIL_DISABLED" else original(name)

    monkeypatch.setattr(
        adapter.sysconfig,
        "get_config_var",
        free_threaded_config,
    )

    installation = _installation(tmp_path)
    bridge = build_cpython_adapter_bridge(_policy(tmp_path), installation)

    assert installation.free_threaded is True
    assert bridge.launch_policy is not None and bridge.launch_policy.free_threaded is True
    assert any("traditional GIL conclusions" in item for item in bridge.capability.limitations)


def test_disabled_policy_and_unsafe_runtime_files_never_offer_active_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installation = _installation(tmp_path)
    disabled = build_cpython_adapter_bridge(_policy(tmp_path, disabled=True), installation)
    assert disabled.capability.availability == "disabled"
    assert disabled.execution_bindings == ()
    assert disabled.launch_policy is None

    def fixed_capability(*_args: object, **_kwargs: object) -> bytes:
        return b"capability"

    monkeypatch.setattr(adapter.os, "getxattr", fixed_capability)
    unsafe = _installation(tmp_path / "unsafe")
    assert unsafe.availability == "unavailable"
    assert any("file capabilities" in item for item in unsafe.limitations)


def test_default_discovery_canonicalizes_distribution_python_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = tmp_path / "python3.13"
    interpreter.write_bytes(b"fixed interpreter identity")
    interpreter.chmod(0o755)
    alias = tmp_path / "python3"
    alias.symlink_to(interpreter.name)
    bootstrap = tmp_path / "bootstrap.py"
    runtime_home = tmp_path / "runtime-home"
    runtime_home.mkdir(mode=0o755)
    bootstrap.write_bytes(b"fixed bootstrap identity")
    bootstrap.chmod(0o644)
    monkeypatch.setattr(adapter.sys, "executable", str(alias))

    installation = inspect_cpython_installation(
        bootstrap_path=bootstrap,
        runtime_home_path=runtime_home,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )

    assert installation.availability == "available"
    assert installation.interpreter is not None
    assert installation.interpreter.path == interpreter


def test_explicit_cpython_interpreter_symlink_remains_rejected(tmp_path: Path) -> None:
    interpreter = tmp_path / "python3.13"
    interpreter.write_bytes(b"fixed interpreter identity")
    interpreter.chmod(0o755)
    alias = tmp_path / "python3"
    alias.symlink_to(interpreter.name)
    bootstrap = tmp_path / "bootstrap.py"
    runtime_home = tmp_path / "runtime-home"
    runtime_home.mkdir(mode=0o755)
    bootstrap.write_bytes(b"fixed bootstrap identity")
    bootstrap.chmod(0o644)

    installation = inspect_cpython_installation(
        interpreter_path=alias,
        runtime_home_path=runtime_home,
        bootstrap_path=bootstrap,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )

    assert installation.availability == "unavailable"
    assert any("absolute non-symlink" in item for item in installation.limitations)


def test_runtime_home_is_content_bound_without_exposing_its_path(tmp_path: Path) -> None:
    installation = _installation(tmp_path)
    assert installation.runtime_home is not None
    bridge = build_cpython_adapter_bridge(_policy(tmp_path), installation)
    assert bridge.launch_policy is not None
    assert bridge.launch_policy.runtime_home == installation.runtime_home
    assert str(installation.runtime_home.path) not in bridge.capability.model_dump_json()

    installation.runtime_home.path.chmod(0o775)
    with pytest.raises(adapter.PerfLensError, match="runtime home owner or mode"):
        adapter.assert_cpython_launch_policy_current(bridge.launch_policy)


def _configured_target_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    interpreter = tmp_path / "python3.13t"
    runtime_home = tmp_path / "runtime-home"
    bootstrap = tmp_path / "bootstrap.py"
    interpreter.write_bytes(b"pinned target interpreter")
    interpreter.chmod(0o755)
    runtime_home.mkdir(mode=0o755)
    bootstrap.write_bytes(b"pinned package bootstrap")
    bootstrap.chmod(0o644)
    payload: dict[str, object] = {
        "implementation": "cpython",
        "executable": str(interpreter),
        "version": [3, 13, 5],
        "runtime_home": str(runtime_home),
        "free_threaded": True,
        "cache_tag": "cpython-313t",
        "soabi": "cpython-313t-x86_64-linux-gnu",
        "abiflags": "t",
    }
    return interpreter, runtime_home, bootstrap, payload


@pytest.mark.parametrize(
    "minor,micro,free_threaded", ((12, 13, False), (13, 5, False), (13, 5, True))
)
def test_configured_target_uses_its_own_pinned_runtime_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, minor: int, micro: int, free_threaded: bool
) -> None:
    interpreter, runtime_home, bootstrap, payload = _configured_target_fixture(tmp_path)
    abi = "t" if free_threaded else ""
    payload.update(
        version=[3, minor, micro],
        free_threaded=free_threaded,
        cache_tag=f"cpython-3{minor}{abi}",
        soabi=f"cpython-3{minor}{abi}-x86_64-linux-gnu",
        abiflags=abi,
    )

    def probe(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert args[:4] == [str(interpreter), "-I", "-S", "-c"]
        assert isinstance(args[4], str) and args[4]
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode(), b"")

    monkeypatch.setattr(adapter.subprocess, "run", probe)
    installation = adapter.inspect_configured_cpython_installation(
        interpreter,
        bootstrap_path=bootstrap,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )

    assert installation.availability == "available"
    assert installation.runtime_version == f"3.{minor}.{micro}"
    assert installation.free_threaded is free_threaded
    assert installation.interpreter is not None
    assert installation.runtime_home is not None
    assert installation.runtime_home.path == runtime_home
    bridge = build_cpython_adapter_bridge(_policy(tmp_path), installation)
    assert bridge.launch_policy is not None
    assert bridge.launch_policy.interpreter.sha256 == installation.interpreter.sha256
    assert bridge.launch_policy.free_threaded is free_threaded
    assert {item.runtime_version for item in bridge.execution_bindings} == {f"3.{minor}.{micro}"}
    if free_threaded:
        assert any("traditional GIL conclusions" in item for item in bridge.capability.limitations)


@pytest.mark.parametrize(
    "invalid",
    (
        "unsupported_version",
        "wrong_executable",
        "unknown_field",
        "abi_control",
        "abi_oversized",
        "abi_non_string",
    ),
)
def test_configured_target_rejects_unreviewed_or_inconsistent_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    interpreter, _runtime_home, bootstrap, payload = _configured_target_fixture(tmp_path)
    if invalid == "unsupported_version":
        payload["version"] = [3, 14, 0]
    elif invalid == "wrong_executable":
        payload["executable"] = str(tmp_path / "other-python")
    elif invalid == "abi_control":
        payload["abiflags"] = "t\n"
    elif invalid == "abi_oversized":
        payload["abiflags"] = "t" * 17
    elif invalid == "abi_non_string":
        payload["abiflags"] = 0
    else:
        payload["extra"] = "not allowed"

    def probe(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode(), b"")

    monkeypatch.setattr(adapter.subprocess, "run", probe)
    installation = adapter.inspect_configured_cpython_installation(
        interpreter,
        bootstrap_path=bootstrap,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )

    assert installation.availability == "unavailable"
    assert installation.interpreter is None


def test_configured_target_rejects_replacement_after_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter, _runtime_home, bootstrap, payload = _configured_target_fixture(tmp_path)

    def probe(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        interpreter.write_bytes(b"replaced after probe")
        return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode(), b"")

    monkeypatch.setattr(adapter.subprocess, "run", probe)
    installation = adapter.inspect_configured_cpython_installation(
        interpreter,
        bootstrap_path=bootstrap,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )

    assert installation.availability == "unavailable"
    assert any("changed during its version probe" in item for item in installation.limitations)


def test_configured_target_rejects_symlink_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter, _runtime_home, bootstrap, _payload = _configured_target_fixture(tmp_path)
    alias = tmp_path / "python-target"
    alias.symlink_to(interpreter.name)

    def forbidden_probe(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unsafe executable must not be probed")

    monkeypatch.setattr(adapter.subprocess, "run", forbidden_probe)
    installation = adapter.inspect_configured_cpython_installation(
        alias,
        bootstrap_path=bootstrap,
        trusted_owner_uids=tuple(dict.fromkeys((0, os.geteuid()))),
    )

    assert installation.availability == "unavailable"
    assert any("absolute non-symlink" in item for item in installation.limitations)
