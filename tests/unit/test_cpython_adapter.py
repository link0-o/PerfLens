from __future__ import annotations

import os
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
    bootstrap = tmp_path / "bootstrap.py"
    interpreter.write_bytes(b"fixed interpreter identity")
    bootstrap.write_bytes(b"fixed bootstrap identity")
    interpreter.chmod(0o755)
    bootstrap.chmod(0o644)
    return inspect_cpython_installation(
        interpreter_path=interpreter,
        bootstrap_path=bootstrap,
        trusted_owner_uids=(os.geteuid(),),
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
