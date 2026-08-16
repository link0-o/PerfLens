from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import pytest

import perflens.admin.profile as profile_module
from perflens.admin.profile import (
    FeatureProfileSnapshot,
    TraceBackendCapability,
    load_feature_profile,
    plan_feature_profile_switch,
    render_feature_profile,
    require_actionable_profile_switch,
)
from perflens.contracts.artifacts import CollectorProfileSwitchArtifact
from perflens.domain.errors import ErrorCode, PerfLensError


def _plan(
    tmp_path: Path,
    target: Literal["cpu_only", "full_diagnostics"],
    *,
    capability: TraceBackendCapability | None = None,
):
    current = load_feature_profile(
        tmp_path / "missing-profile.toml",
        require_root_owner=False,
    )
    return plan_feature_profile_switch(
        target,
        current=current,
        privilege_mode="cap_perfmon",
        profile_path=tmp_path / "profile.toml",
        trace_helper_service_path=tmp_path / "perflens-trace-helper.service",
        trace_socket_path=tmp_path / "helper.sock",
        trace_private_spool=tmp_path / "private-spool",
        capability=capability,
        dry_run=True,
    )


def test_missing_profile_maps_to_v02_cpu_only_without_writing(tmp_path: Path) -> None:
    path = tmp_path / "profile.toml"
    snapshot = load_feature_profile(path, require_root_owner=False)

    assert snapshot == FeatureProfileSnapshot(
        feature_profile="cpu_only",
        source="implicit_v0_2_compatibility",
        path=path,
        raw=None,
        sha256=None,
    )
    assert not path.exists()


def test_managed_profile_is_strict_bounded_and_permission_checked(tmp_path: Path) -> None:
    path = tmp_path / "profile.toml"
    path.write_text(render_feature_profile("full_diagnostics"), encoding="utf-8")
    path.chmod(0o600)

    snapshot = load_feature_profile(
        path,
        require_root_owner=False,
        invoking_uid=os.geteuid(),
    )
    assert snapshot.feature_profile == "full_diagnostics"
    assert snapshot.source == "managed"
    assert snapshot.sha256 is not None

    path.chmod(0o666)
    with pytest.raises(PerfLensError, match="permissions") as unsafe:
        load_feature_profile(path, require_root_owner=False)
    assert unsafe.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_managed_profile_rejects_unknown_fields_and_symlink(tmp_path: Path) -> None:
    path = tmp_path / "profile.toml"
    path.write_text(
        '[profile]\nschema_version = 1\nfeature_profile = "cpu_only"\nextra = true\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(PerfLensError, match="unknown"):
        load_feature_profile(path, require_root_owner=False)

    target = tmp_path / "target.toml"
    target.write_text(render_feature_profile("cpu_only"), encoding="utf-8")
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    with pytest.raises(PerfLensError, match="unsafe"):
        load_feature_profile(link, require_root_owner=False)


def test_managed_profile_wraps_open_race_without_exposing_os_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "profile.toml"
    path.write_text(render_feature_profile("cpu_only"), encoding="utf-8")
    path.chmod(0o600)

    def denied(*_args: object, **_kwargs: object) -> int:
        raise PermissionError("simulated race")

    monkeypatch.setattr(profile_module.os, "open", denied)
    with pytest.raises(PerfLensError, match="opened safely"):
        load_feature_profile(path, require_root_owner=False)


def test_existing_relative_profile_path_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path("profile.toml")
    path.write_text(render_feature_profile("cpu_only"), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(PerfLensError, match="path is unsafe"):
        load_feature_profile(path, require_root_owner=False)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"\xff", "bounded valid TOML"),
        (b"[other]\nvalue = 1\n", "exactly one"),
        (
            b'[profile]\nschema_version = 2\nfeature_profile = "cpu_only"\n',
            "schema version",
        ),
        (
            b'[profile]\nschema_version = 1\nfeature_profile = "everything"\n',
            "name is unsupported",
        ),
    ],
)
def test_managed_profile_rejects_invalid_contracts(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    path = tmp_path / "profile.toml"
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(PerfLensError, match=message):
        load_feature_profile(path, require_root_owner=False)


def test_full_profile_is_blocked_when_kernel_target_filter_is_unavailable(
    tmp_path: Path,
) -> None:
    artifact = _plan(tmp_path, "full_diagnostics")

    assert artifact.status == "blocked"
    assert artifact.current_profile == "cpu_only"
    assert artifact.target_profile == "full_diagnostics"
    assert artifact.profile_source == "implicit_v0_2_compatibility"
    assert artifact.trace_backend_status == "unavailable"
    assert not artifact.target_filter_before_userspace
    assert artifact.planned_commands == ()
    with pytest.raises(PerfLensError) as blocked:
        require_actionable_profile_switch(artifact)
    assert blocked.value.code is ErrorCode.UNSUPPORTED_FORMAT


def test_cpu_profile_is_idempotent_and_capability_claims_fail_closed(tmp_path: Path) -> None:
    artifact = _plan(tmp_path, "cpu_only")
    assert artifact.status == "unchanged"
    assert not artifact.profile_update_required
    assert require_actionable_profile_switch(artifact) is artifact

    available = TraceBackendCapability(
        status="available",
        target_filter_before_userspace=True,
        supported_modes=("sched", "off_cpu", "lock"),
        reason="host acceptance passed",
    )
    topology_ready = _plan(
        tmp_path,
        "full_diagnostics",
        capability=available,
    )
    assert topology_ready.status == "dry_run"
    assert topology_ready.trace_backend_status == "available"
    assert topology_ready.target_filter_before_userspace
    assert require_actionable_profile_switch(topology_ready) is topology_ready

    with pytest.raises(ValueError, match="all target-filtered modes"):
        TraceBackendCapability(
            status="available",
            target_filter_before_userspace=False,
            supported_modes=("sched",),
            reason="forged",
        )


def test_profile_switch_artifact_rejects_forged_backend_claims(tmp_path: Path) -> None:
    base = _plan(tmp_path, "full_diagnostics").model_dump(mode="python")

    available_without_modes = {
        **base,
        "trace_backend_status": "available",
        "target_filter_before_userspace": False,
        "supported_trace_modes": (),
    }
    with pytest.raises(ValueError, match="all target-filtered modes"):
        CollectorProfileSwitchArtifact.model_validate(available_without_modes)

    unavailable_with_modes = {
        **base,
        "trace_backend_status": "unavailable",
        "target_filter_before_userspace": True,
        "supported_trace_modes": ("sched",),
    }
    with pytest.raises(ValueError, match="cannot claim"):
        CollectorProfileSwitchArtifact.model_validate(unavailable_with_modes)

    switched_without_backend = {
        **base,
        "status": "switched",
        "trace_backend_status": "unavailable",
        "target_filter_before_userspace": False,
        "supported_trace_modes": (),
    }
    with pytest.raises(ValueError, match="cannot activate"):
        CollectorProfileSwitchArtifact.model_validate(switched_without_backend)
    with pytest.raises(ValueError, match="cannot claim"):
        TraceBackendCapability(
            status="unavailable",
            target_filter_before_userspace=True,
            supported_modes=(),
            reason="forged",
        )
