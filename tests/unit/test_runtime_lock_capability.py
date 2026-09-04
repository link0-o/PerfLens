from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from perflens.contracts.runtime_locks import RuntimeAdapterCapabilityArtifact
from perflens.runtime_locks import (
    NativeLaunchCapability,
    inspect_native_pthread_installation,
)
from perflens.runtime_locks.capability import (
    RuntimeLockCapabilityInspection,
    inspect_runtime_lock_capability,
)
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)

_CREATED_AT = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
_PROJECT_IDENTITY = "1" * 64


def _policy(
    tmp_path: Path,
    *,
    policy_enabled: bool = True,
    native_launch_enabled: bool = True,
):
    rendered = render_default_runtime_lock_project_policy()
    if not policy_enabled:
        rendered = rendered.replace(
            "enabled = true",
            "enabled = false",
            1,
        )
    if not native_launch_enabled:
        native_section, remainder = rendered.split("[adapters.native_pthread]", 1)
        remainder = remainder.replace(
            "launch_instrumentation_allowed = true",
            "launch_instrumentation_allowed = false",
            1,
        )
        rendered = native_section + "[adapters.native_pthread]" + remainder
    path = tmp_path / "runtime-locks.toml"
    path.write_text(rendered, encoding="utf-8")
    path.chmod(0o600)
    return load_runtime_lock_project_policy(
        path,
        allowed_roots=(tmp_path,),
        invoking_uid=os.geteuid(),
    )


def _native_capability(
    *,
    availability: str = "available",
) -> NativeLaunchCapability:
    assert availability in {"available", "partial"}
    return NativeLaunchCapability(
        target_scope="host_launched_workload",
        launch_backend="host_launcher",
        availability=availability,  # type: ignore[arg-type]
        target_identity_sha256=None,
        target_label="native-pthread",
        probe_sha256="2" * 64,
        runtime_glibc_version="2.41",
        supported_semantics=("exact", "thresholded"),
        supported_lock_surfaces=(
            "condition",
            "mutex",
            "rwlock_read",
            "rwlock_write",
        ),
        limitations=(
            "Fast paths below the configured threshold are not emitted."
            if availability == "partial"
            else "Only reviewed dynamically linked glibc targets are accepted.",
        ),
    )


def _adapters(
    inspection: RuntimeLockCapabilityInspection,
) -> dict[str, RuntimeAdapterCapabilityArtifact]:
    return {item.adapter_id: item for item in inspection.adapter_capabilities}


def test_runtime_lock_capability_reports_safely_discovered_native_backend(
    tmp_path: Path,
) -> None:
    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path),
        project_identity_sha256=_PROJECT_IDENTITY,
        native_pthread_capability=_native_capability(),
        created_at=_CREATED_AT,
    )

    native = _adapters(inspection)["native_pthread"]
    assert inspection.capability.status == "available"
    assert native.availability == "available"
    assert native.runtime_version == "2.41"
    assert native.backend_id == "host_launcher"
    assert native.measurement_semantics == ("exact", "thresholded")
    assert native.supported_lock_kinds == (
        "condition",
        "mutex",
        "recursive_mutex",
        "rwlock_read",
        "rwlock_write",
    )
    assert native.supported_event_kinds == (
        "acquire",
        "release",
        "wait_begin",
        "wait_end",
    )
    assert native.launch_instrumentation_required is True
    assert native.attach_required is False
    assert native.privileged_backend_required is False
    assert any("cooperatively" in limitation for limitation in native.limitations)
    assert any("not tamper-proof" in limitation for limitation in native.limitations)
    assert any("host_launched_workload" in limitation for limitation in native.limitations)
    assert any("managed Docker optimization" in limitation for limitation in native.limitations)
    assert any(
        "launched workload" in limitation for limitation in inspection.capability.limitations
    )


def test_runtime_lock_capability_preserves_partial_native_limitations(
    tmp_path: Path,
) -> None:
    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path),
        project_identity_sha256=_PROJECT_IDENTITY,
        native_pthread_capability=_native_capability(availability="partial"),
        created_at=_CREATED_AT,
    )

    native = _adapters(inspection)["native_pthread"]
    assert inspection.capability.status == "available"
    assert native.availability == "partial"
    assert native.measurement_semantics == ("exact", "thresholded")
    assert native.limitations[0] == "Fast paths below the configured threshold are not emitted."
    assert any("not tamper-proof" in limitation for limitation in native.limitations)
    assert any("existing process or container" in limitation for limitation in native.limitations)


def test_runtime_lock_capability_does_not_assume_native_probe_when_absent(
    tmp_path: Path,
) -> None:
    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path),
        project_identity_sha256=_PROJECT_IDENTITY,
        created_at=_CREATED_AT,
    )

    adapters = _adapters(inspection)
    assert adapters["native_pthread"].availability == "unavailable"
    assert "safely discovered" in adapters["native_pthread"].limitations[0]
    assert adapters["generic_ndjson_import"].availability == "available"
    assert inspection.capability.status == "available"


def test_runtime_lock_capability_reports_wheel_only_native_as_unavailable(
    tmp_path: Path,
) -> None:
    wheel_only = inspect_native_pthread_installation(None)

    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path),
        project_identity_sha256=_PROJECT_IDENTITY,
        native_pthread_capability=wheel_only,
        created_at=_CREATED_AT,
    )

    native = _adapters(inspection)["native_pthread"]
    assert native.availability == "unavailable"
    assert native.measurement_semantics == ()
    assert "main DEB packaged probe" in native.limitations[0]
    assert _adapters(inspection)["generic_ndjson_import"].availability == "available"


def test_runtime_lock_capability_never_overrides_native_policy_disable(
    tmp_path: Path,
) -> None:
    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path, policy_enabled=False),
        project_identity_sha256=_PROJECT_IDENTITY,
        native_pthread_capability=_native_capability(),
        created_at=_CREATED_AT,
    )

    native = _adapters(inspection)["native_pthread"]
    assert native.availability == "disabled"
    assert native.measurement_semantics == ()
    assert native.limitations == ("This Runtime Lock Adapter is disabled by project policy.",)


def test_runtime_lock_capability_never_overrides_launch_policy_disable(
    tmp_path: Path,
) -> None:
    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path, native_launch_enabled=False),
        project_identity_sha256=_PROJECT_IDENTITY,
        native_pthread_capability=_native_capability(),
        created_at=_CREATED_AT,
    )

    native = _adapters(inspection)["native_pthread"]
    assert native.availability == "unavailable"
    assert native.measurement_semantics == ()
    assert "disabled by project policy" in native.limitations[0]
