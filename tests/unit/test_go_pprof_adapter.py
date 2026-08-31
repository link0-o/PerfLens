from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterId,
    RuntimeLockSessionBudget,
)
from perflens.runtime_locks.go_pprof_adapter import (
    GoPprofInstallation,
    GoToolIdentity,
    build_go_pprof_adapter_bridge,
)
from perflens.runtime_locks.project_config import (
    RuntimeLockAdapterProjectPolicy,
    RuntimeLockProjectPolicy,
)


def _policy(tmp_path: Path) -> RuntimeLockProjectPolicy:
    adapters: list[tuple[RuntimeLockAdapterId, RuntimeLockAdapterProjectPolicy]] = []
    for adapter_id in (
        "cpython_threading",
        "generic_ndjson_import",
        "go_pprof",
        "java_jfr",
        "native_pthread",
    ):
        adapters.append(
            (
                adapter_id,
                RuntimeLockAdapterProjectPolicy(
                    enabled=adapter_id == "go_pprof",
                    allowed_semantics=("cumulative",) if adapter_id == "go_pprof" else (),
                    duration_threshold_ns=None,
                    exact_enabled=False,
                    launch_instrumentation_allowed=adapter_id == "go_pprof",
                    controlled_import_allowed=False,
                    mutex_profile_fraction=1 if adapter_id == "go_pprof" else None,
                    block_profile_rate_ns=1 if adapter_id == "go_pprof" else None,
                    file_backend_enabled=adapter_id == "go_pprof",
                ),
            )
        )
    return RuntimeLockProjectPolicy(
        schema_version="1.1",
        path=tmp_path / "runtime-locks.toml",
        device=1,
        inode=2,
        owner_uid=os.geteuid(),
        size=1,
        modified_ns=1,
        sha256="1" * 64,
        enabled=True,
        target_scopes=("controlled_import", "host_launched_workload"),
        allowed_adapters=("go_pprof",),
        allowed_semantics=("cumulative",),
        import_roots=("perflens-runtime-locks",),
        preview_ttl_seconds=600,
        budget=RuntimeLockSessionBudget(),
        adapters=tuple(adapters),
    )


def _installation(tmp_path: Path, version: str = "1.24.4") -> GoPprofInstallation:
    tool_path = tmp_path / "go"
    tool_path.write_bytes(b"go-tool")
    tool_path.chmod(0o755)
    digest = hashlib.sha256(b"go-tool").hexdigest()
    metadata = hashlib.sha256(f"metadata:{version}".encode()).hexdigest()
    tool = GoToolIdentity(
        path=tool_path,
        version=version,
        minor_version=".".join(version.split(".")[:2]),
        sha256=digest,
        device=1,
        inode=2,
        owner_uid=os.geteuid(),
        mode=0o755,
        links=1,
        size=7,
        modified_ns=1,
    )
    return GoPprofInstallation(
        availability="available",
        tool=tool,
        pprof_tool=tool,
        runtime_version=version,
        metadata_sha256=metadata,
        limitations=("cumulative only",),
    )


def test_go_bridge_binds_tool_rates_and_cumulative_semantics(tmp_path: Path) -> None:
    bridge = build_go_pprof_adapter_bridge(
        _policy(tmp_path),
        _installation(tmp_path),
        created_at="2026-08-31T00:00:00+00:00",
    )

    assert bridge.capability.availability == "available"
    assert bridge.capability.measurement_semantics == ("cumulative",)
    assert bridge.execution_binding is not None
    assert bridge.execution_binding.tools[0].name == "go"
    assert bridge.execution_binding.tools[1].name == "pprof"
    assert bridge.execution_binding.backend_id == "pprof"


def test_go_bridge_is_unavailable_without_declared_profile_rate(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    adapters = tuple(
        (
            adapter_id,
            replace(adapter, mutex_profile_fraction=None, block_profile_rate_ns=None),
        )
        if adapter_id == "go_pprof"
        else (adapter_id, adapter)
        for adapter_id, adapter in policy.adapters
    )
    policy = replace(policy, adapters=adapters)

    bridge = build_go_pprof_adapter_bridge(
        policy,
        _installation(tmp_path),
        created_at="2026-08-31T00:00:00+00:00",
    )

    assert bridge.capability.availability == "unavailable"
    assert bridge.execution_binding is None


def test_go_bridge_accepts_loopback_without_startup_file_backend(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    adapters = tuple(
        (
            adapter_id,
            replace(
                adapter,
                launch_instrumentation_allowed=False,
                file_backend_enabled=False,
                loopback_backend_enabled=True,
            ),
        )
        if adapter_id == "go_pprof"
        else (adapter_id, adapter)
        for adapter_id, adapter in policy.adapters
    )
    bridge = build_go_pprof_adapter_bridge(
        replace(policy, adapters=adapters),
        _installation(tmp_path),
        created_at="2026-08-31T00:00:00+00:00",
    )

    assert bridge.capability.availability == "available"
    assert bridge.execution_binding is not None
