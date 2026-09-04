from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from perflens.runtime_locks import java_jfr_capability as capability_module
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.java_jfr_adapter import build_java_jfr_adapter_bridge
from perflens.runtime_locks.java_jfr_capability import (
    JavaJfrCapability,
    JavaJfrDirectoryIdentity,
    JavaJfrEventSurface,
    JavaJfrNativeLibraryIdentity,
    JavaJfrPayloadFileIdentity,
    JavaJfrRuntimePayloadIdentity,
    JavaJfrToolIdentity,
)
from perflens.runtime_locks.java_jfr_profiles import load_java_jfr_profiles
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)

PROFILE_ROOT = Path(__file__).parents[2] / "src/perflens/runtime_locks/jfr"
NOW = datetime(2026, 8, 30, tzinfo=UTC).isoformat()


def _identity_transform(value: str) -> str:
    return value


def _policy(
    tmp_path: Path,
    *,
    transform: Callable[[str], str] = _identity_transform,
):
    path = tmp_path / "runtime-locks.toml"
    path.write_text(transform(render_default_runtime_lock_project_policy()), encoding="utf-8")
    path.chmod(0o600)
    return load_runtime_lock_project_policy(path, allowed_roots=(tmp_path,))


def _identity(path: Path, digest: str) -> JavaJfrToolIdentity:
    value = path.stat()
    return JavaJfrToolIdentity(
        path=path,
        sha256=digest,
        device=value.st_dev,
        inode=value.st_ino,
        owner_uid=value.st_uid,
        mode=value.st_mode & 0o777,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _directory_identity(path: Path) -> JavaJfrDirectoryIdentity:
    value = path.stat()
    return JavaJfrDirectoryIdentity(
        path=path,
        device=value.st_dev,
        inode=value.st_ino,
        owner_uid=value.st_uid,
        mode=value.st_mode & 0o777,
        links=value.st_nlink,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _payload_identity(path: Path) -> JavaJfrPayloadFileIdentity:
    value = path.stat()
    import hashlib

    return JavaJfrPayloadFileIdentity(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        device=value.st_dev,
        inode=value.st_ino,
        owner_uid=value.st_uid,
        mode=value.st_mode & 0o777,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _native_identity(path: Path, relative_path: str) -> JavaJfrNativeLibraryIdentity:
    value = path.stat()
    import hashlib

    return JavaJfrNativeLibraryIdentity(
        relative_path=relative_path,
        named_path=path,
        resolved_path=path,
        source_kind="regular",
        link_target_sha256=None,
        link_device=None,
        link_inode=None,
        link_owner_uid=None,
        link_mode=None,
        link_links=None,
        link_size=None,
        link_modified_ns=None,
        link_changed_ns=None,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        device=value.st_dev,
        inode=value.st_ino,
        owner_uid=value.st_uid,
        mode=value.st_mode & 0o777,
        links=value.st_nlink,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _discovered(tmp_path: Path) -> JavaJfrCapability:
    jdk_root = tmp_path / "jdk"
    root = jdk_root / "bin"
    lib = jdk_root / "lib"
    root.mkdir(parents=True)
    lib.mkdir()
    java = root / "java"
    jfr = root / "jfr"
    for item in (java, jfr):
        item.write_bytes(b"trusted tool")
        item.chmod(0o755)
    release = jdk_root / "release"
    modules = lib / "modules"
    release.write_bytes(b"JAVA_VERSION=25.0.4.1\n")
    modules.write_bytes(b"fixed-runtime-modules")
    (lib / "server").mkdir()
    (lib / "libjli.so").write_bytes(b"fixed-jli")
    (lib / "server/libjvm.so").write_bytes(b"fixed-jvm")
    release.chmod(0o644)
    modules.chmod(0o644)
    (lib / "libjli.so").chmod(0o644)
    (lib / "server/libjvm.so").chmod(0o644)
    (lib / "server").chmod(0o755)
    jdk_root.chmod(0o755)
    root.chmod(0o755)
    lib.chmod(0o755)
    directories = (
        _directory_identity(jdk_root),
        _directory_identity(root),
        _directory_identity(lib),
    )
    payload_files = (_payload_identity(release), _payload_identity(modules))
    native_libraries = (
        _native_identity(lib / "libjli.so", "libjli.so"),
        _native_identity(lib / "server/libjvm.so", "server/libjvm.so"),
    )
    native_manifest = capability_module._derive_native_library_manifest_identity(  # pyright: ignore[reportPrivateUsage]
        native_libraries
    )
    runtime_payload = JavaJfrRuntimePayloadIdentity(
        jdk_root=directories[0],
        bin_directory=directories[1],
        lib_directory=directories[2],
        release_file=payload_files[0],
        modules_file=payload_files[1],
        native_libraries=native_libraries,
        native_library_bytes=sum(item.size for item in native_libraries),
        native_library_manifest_sha256=native_manifest,
        identity_sha256=capability_module._derive_runtime_payload_identity(  # pyright: ignore[reportPrivateUsage]
            directories,
            payload_files,
            native_libraries,
        ),
    )
    profiles = tuple(
        item
        for item in load_java_jfr_profiles(PROFILE_ROOT, trusted_owner_uids=(os.getuid(),))
        if item.jdk_major == 25
    )
    surface = JavaJfrEventSurface(
        events=(
            "jdk.DataLoss",
            "jdk.JVMInformation",
            "jdk.JavaMonitorEnter",
            "jdk.JavaMonitorWait",
            "jdk.ThreadPark",
        ),
        fields=(),
        raw_metadata_sha256="3" * 64,
        canonical_metadata_sha256="4" * 64,
        data_loss_disclosed=True,
    )
    return JavaJfrCapability(
        availability="available",
        jdk_root=jdk_root,
        jdk_major=25,
        java_version="25.0.4.1",
        java_build="25.0.4.1+1",
        java_tool=_identity(java, "1" * 64),
        jfr_tool=_identity(jfr, "2" * 64),
        profiles=profiles,
        event_surface=surface,
        measurement_semantics=("thresholded",),
        active_launch_supported=True,
        live_attach_supported=False,
        limitations=("Thresholded evidence.",),
        runtime_payload=runtime_payload,
    )


def test_java_jfr_bridge_binds_tools_profile_and_metadata_without_public_paths(
    tmp_path: Path,
) -> None:
    bridge = build_java_jfr_adapter_bridge(_policy(tmp_path), _discovered(tmp_path), created_at=NOW)

    assert bridge.capability.availability == "available"
    assert bridge.capability.measurement_semantics == ("thresholded",)
    assert bridge.execution_binding is not None
    assert bridge.launch_policy is not None
    assert bridge.execution_binding.profile == "balanced"
    assert bridge.execution_binding.configuration_sha256 == bridge.launch_policy.jfc_profile.sha256
    assert bridge.execution_binding.metadata_sha256 == "4" * 64
    assert (
        bridge.launch_policy.runtime_payload.identity_sha256
        == bridge.execution_binding.runtime_payload_identity_sha256
    )
    assert tuple(tool.name for tool in bridge.execution_binding.tools) == ("java", "jfr")
    assert tuple(tool.path for tool in bridge.capability.tools) == ("java", "jfr")
    public = bridge.capability.model_dump_json() + bridge.execution_binding.model_dump_json()
    assert str(tmp_path) not in public
    assert "/java" not in public and "/jfr" not in public


def test_java_jfr_deep_profile_discloses_collection_overhead(tmp_path: Path) -> None:
    policy = _policy(
        tmp_path,
        transform=lambda value: value.replace(
            'duration_threshold_ns = 10000000\nprofile = "balanced"',
            'duration_threshold_ns = 1000000\nprofile = "deep"',
            1,
        ),
    )
    bridge = build_java_jfr_adapter_bridge(policy, _discovered(tmp_path), created_at=NOW)

    assert bridge.capability.availability == "available"
    assert bridge.execution_binding is not None
    assert bridge.execution_binding.profile == "deep"
    assert any("material collection overhead" in item for item in bridge.capability.limitations)
    assert any(
        "material collection overhead" in item for item in bridge.execution_binding.limitations
    )


def test_java_jfr_bridge_respects_disabled_policy(tmp_path: Path) -> None:
    policy = _policy(
        tmp_path,
        transform=lambda value: value.replace("enabled = true", "enabled = false", 1),
    )
    bridge = build_java_jfr_adapter_bridge(policy, _discovered(tmp_path), created_at=NOW)

    assert bridge.capability.availability == "disabled"
    assert bridge.execution_binding is None
    assert bridge.launch_policy is None


def test_java_jfr_bridge_rejects_missing_discovery_or_launch_scope(tmp_path: Path) -> None:
    missing = build_java_jfr_adapter_bridge(_policy(tmp_path), None, created_at=NOW)
    assert missing.capability.availability == "unavailable"

    no_launch = _policy(
        tmp_path,
        transform=lambda value: value.replace(
            "launch_instrumentation_allowed = true\ncontrolled_import_allowed = true\n\n"
            "[adapters.cpython_threading]",
            "launch_instrumentation_allowed = false\ncontrolled_import_allowed = true\n\n"
            "[adapters.cpython_threading]",
            1,
        ),
    )
    blocked = build_java_jfr_adapter_bridge(no_launch, _discovered(tmp_path), created_at=NOW)
    assert blocked.capability.availability == "unavailable"
    assert blocked.execution_binding is None


def test_public_runtime_capability_reports_java_without_claiming_import_only(
    tmp_path: Path,
) -> None:
    inspection = inspect_runtime_lock_capability(
        _policy(tmp_path),
        project_identity_sha256="a" * 64,
        java_jfr_capability=_discovered(tmp_path),
        created_at=datetime(2026, 8, 30, tzinfo=UTC),
    )

    java = next(item for item in inspection.adapter_capabilities if item.adapter_id == "java_jfr")
    assert java.availability == "available"
    assert java.runtime_version == "25.0.4.1"
    assert java.supported_lock_kinds == ("condition", "mutex", "park")
    assert "Only controlled NDJSON import is available" not in inspection.capability.limitations


def test_java_jfr_bridge_does_not_publish_unavailable_local_paths(tmp_path: Path) -> None:
    discovered = JavaJfrCapability(
        availability="unavailable",
        jdk_root=Path("/private/jdk"),
        jdk_major=None,
        java_version=None,
        java_build=None,
        java_tool=None,
        jfr_tool=None,
        profiles=(),
        event_surface=None,
        measurement_semantics=(),
        active_launch_supported=False,
        live_attach_supported=False,
        limitations=("Failed to open /private/jdk/bin/java",),
    )
    bridge = build_java_jfr_adapter_bridge(_policy(tmp_path), discovered, created_at=NOW)
    assert "/private" not in bridge.capability.model_dump_json()
