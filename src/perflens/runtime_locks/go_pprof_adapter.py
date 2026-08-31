"""Capability and path-free execution binding for the Go pprof Adapter."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeAdapterCapabilityArtifact, RuntimeToolIdentity
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.project_config import RuntimeLockProjectPolicy
from perflens.runtime_locks.supervisor import discover_runtime_supervisor_policy

GO_PPROF_ADAPTER_VERSION = "go-pprof-adapter-v1"
_GO_VERSION = re.compile(r"^go version go(1\.(?:24|25|26|27))(?:\.[0-9]+)? linux/amd64$")
_GO_ANY_VERSION = re.compile(r"^go version go(1\.[0-9]+)(?:\.[0-9]+)? linux/amd64$")
# Only versions with checked-in, real ``pprof -raw`` Goldens may be marked
# available. The remaining reviewed versions stay partial until their matrix
# job contributes a matching Golden instead of being trusted by version text.
_GOLDEN_VALIDATED_GO_MINOR = frozenset({"1.24"})
_MAX_GO_BYTES = 512 << 20


@dataclass(frozen=True, slots=True)
class GoToolIdentity:
    path: Path
    version: str
    minor_version: str
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int
    size: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class GoPprofInstallation:
    availability: Literal["available", "partial", "unavailable"]
    tool: GoToolIdentity | None
    pprof_tool: GoToolIdentity | None
    runtime_version: str | None
    metadata_sha256: str | None
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GoPprofAdapterBridge:
    capability: RuntimeAdapterCapabilityArtifact
    execution_binding: RuntimeLockAdapterExecutionBinding | None
    tool: GoToolIdentity | None
    pprof_tool: GoToolIdentity | None


def inspect_go_pprof_installation(
    *,
    go_path: Path | None = None,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> GoPprofInstallation:
    """Inspect the local Go command without opening a profile or target."""

    candidate_text = str(go_path) if go_path is not None else shutil.which("go")
    if candidate_text is None or platform.system() != "Linux" or platform.machine() != "x86_64":
        return GoPprofInstallation(
            availability="unavailable",
            tool=None,
            pprof_tool=None,
            runtime_version=None,
            metadata_sha256=None,
            limitations=("Go pprof requires a local Linux amd64 Go toolchain.",),
        )
    try:
        tool = _inspect_go_tool(Path(candidate_text), trusted_owner_uids=trusted_owner_uids)
        pprof_tool = _inspect_pprof_tool(tool, trusted_owner_uids=trusted_owner_uids)
    except PerfLensError as exc:
        return GoPprofInstallation(
            availability="unavailable",
            tool=None,
            pprof_tool=None,
            runtime_version=None,
            metadata_sha256=None,
            limitations=(f"Go pprof tool discovery failed: {exc.message}",),
        )
    availability: Literal["available", "partial", "unavailable"] = (
        "available" if tool.minor_version in _GOLDEN_VALIDATED_GO_MINOR else "partial"
    )
    limitations = (
        "Go mutex and block profiles are cumulative profiles, not exact contention logs.",
        "Go pprof does not expose a real OS TID, lock object, owner relation, or exact hold time.",
        "Applications must explicitly enable and write the configured profiles; PerfLens does "
        "not change SetMutexProfileFraction or SetBlockProfileRate.",
        "Profile kind and sampling controls are application-declared and are not independently "
        "attested by the Go profile payload.",
    )
    if availability == "partial":
        limitations = (
            *limitations,
            "This Go version is outside the reviewed 1.24-1.27 Golden matrix; output remains "
            "partial until a matching Golden is accepted.",
        )
    metadata_sha256 = hashlib.sha256(
        "\0".join(
            (
                "perflens-go-pprof-metadata-v1",
                tool.version,
                tool.sha256,
                "linux",
                "amd64",
            )
        ).encode("utf-8")
    ).hexdigest()
    return GoPprofInstallation(
        availability=availability,
        tool=tool,
        pprof_tool=pprof_tool,
        runtime_version=tool.version,
        metadata_sha256=metadata_sha256,
        limitations=limitations,
    )


def build_go_pprof_adapter_bridge(
    policy: RuntimeLockProjectPolicy,
    installation: GoPprofInstallation | None,
    *,
    created_at: str | None = None,
    supervisor_available: bool = True,
) -> GoPprofAdapterBridge:
    timestamp = created_at or datetime.now(tz=UTC).isoformat()
    adapter_policy = policy.adapter_policy("go_pprof")
    enabled = policy.enabled and adapter_policy.enabled
    backend_allowed = (
        adapter_policy.file_backend_enabled or adapter_policy.loopback_backend_enabled
    )
    rates_declared = bool(
        adapter_policy.mutex_profile_fraction or adapter_policy.block_profile_rate_ns
    )
    if not enabled:
        availability = "disabled"
        limitations = ("The Go pprof Adapter is disabled by project policy.",)
    elif not backend_allowed:
        availability = "unavailable"
        limitations = (
            "No Go pprof startup-file or same-UID PID/socket-bound loopback backend is enabled.",
        )
    elif not rates_declared:
        availability = "unavailable"
        limitations = (
            "Go pprof collection requires the application's exact mutex fraction or block "
            "profile rate in project policy.",
        )
    elif installation is None or installation.availability == "unavailable":
        availability = "unavailable"
        limitations = (
            installation.limitations
            if installation is not None
            else ("No safely inspected Go toolchain was supplied.",)
        )
    elif not supervisor_available:
        availability = "unavailable"
        limitations = ("The fixed Runtime Lock supervisor is unavailable.",)
    else:
        availability = installation.availability
        limitations = installation.limitations

    binding: RuntimeLockAdapterExecutionBinding | None = None
    if availability in {"available", "partial"}:
        assert installation is not None
        assert installation.tool is not None
        assert installation.pprof_tool is not None
        assert installation.runtime_version is not None
        assert installation.metadata_sha256 is not None
        tool = RuntimeLockAdapterToolBinding(
            name="go",
            version=installation.runtime_version,
            binary_sha256=installation.tool.sha256,
        )
        pprof = RuntimeLockAdapterToolBinding(
            name="pprof",
            version=installation.runtime_version,
            binary_sha256=installation.pprof_tool.sha256,
        )
        tools = (tool, pprof)
        toolchain_sha256 = derive_runtime_lock_toolchain_identity(tools)
        configuration_sha256 = hashlib.sha256(
            "\0".join(
                (
                    "perflens-go-pprof-configuration-v1",
                    str(adapter_policy.mutex_profile_fraction or 0),
                    str(adapter_policy.block_profile_rate_ns or 0),
                    str(int(adapter_policy.file_backend_enabled)),
                    str(int(adapter_policy.loopback_backend_enabled)),
                )
            ).encode("utf-8")
        ).hexdigest()
        execution_identity = derive_runtime_lock_adapter_execution_identity(
            "go_pprof",
            GO_PPROF_ADAPTER_VERSION,
            "pprof",
            installation.runtime_version,
            "mutex_and_block",
            "cumulative",
            None,
            toolchain_sha256,
            configuration_sha256,
            installation.metadata_sha256,
        )
        binding = RuntimeLockAdapterExecutionBinding(
            adapter_id="go_pprof",
            adapter_version=GO_PPROF_ADAPTER_VERSION,
            backend_id="pprof",
            runtime_version=installation.runtime_version,
            profile="mutex_and_block",
            measurement_semantics="cumulative",
            tools=tools,
            toolchain_identity_sha256=toolchain_sha256,
            configuration_sha256=configuration_sha256,
            metadata_sha256=installation.metadata_sha256,
            execution_identity_sha256=execution_identity,
            limitations=limitations,
        )
    material = "\0".join(
        (
            "perflens-runtime-adapter-capability-v1",
            policy.sha256,
            "go_pprof",
            availability,
            binding.execution_identity_sha256 if binding is not None else "no-binding",
            timestamp,
        )
    )
    provisional = RuntimeAdapterCapabilityArtifact(
        schema_version="1.1",
        capability_id=(
            "runtime-adapter-capability-"
            + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        ),
        created_at=timestamp,
        runtime="go",
        runtime_name="Go runtime/pprof",
        runtime_version=(installation.runtime_version if installation is not None else None),
        adapter_id="go_pprof",
        adapter_version=GO_PPROF_ADAPTER_VERSION,
        backend_id="pprof",
        availability=availability,
        supported_lock_kinds=(
            ("channel", "condition", "mutex", "runtime_internal", "wait_group")
            if binding is not None
            else ()
        ),
        supported_event_kinds=(("sampled_contention",) if binding is not None else ()),
        measurement_semantics=(("cumulative",) if binding is not None else ()),
        fast_path_visibility="none",
        owner_visibility="unavailable",
        hold_time_visibility="unavailable",
        launch_instrumentation_required=False,
        attach_required=False,
        privileged_backend_required=False,
        tools=(
            (
                RuntimeToolIdentity(
                    name="go",
                    version=installation.runtime_version,
                    path="go",
                    binary_sha256=installation.tool.sha256,
                    status="available",
                ),
                RuntimeToolIdentity(
                    name="pprof",
                    version=installation.runtime_version,
                    path="pprof",
                    binary_sha256=installation.pprof_tool.sha256,
                    status="available",
                ),
            )
            if installation is not None
            and installation.tool is not None
            and installation.pprof_tool is not None
            else ()
        ),
        limitations=limitations,
        next_steps=(
            (
                "Preview one cumulative Go pprof Session for a configured file or loopback "
                "backend."
                if binding is not None
                else "Configure one profile rate and an authorized Go pprof backend."
            ),
        ),
        content_sha256="0" * 64,
    )
    capability = provisional.model_copy(
        update={"content_sha256": contract_content_sha256(provisional, exclude={"content_sha256"})}
    )
    return GoPprofAdapterBridge(
        capability=capability,
        execution_binding=binding,
        tool=(installation.tool if installation is not None else None),
        pprof_tool=(installation.pprof_tool if installation is not None else None),
    )


def discover_go_pprof_adapter_bridge(
    policy: RuntimeLockProjectPolicy,
    *,
    go_path: Path | None = None,
    trusted_owner_uids: tuple[int, ...] = (0,),
    created_at: str | None = None,
) -> GoPprofAdapterBridge:
    installation = inspect_go_pprof_installation(
        go_path=go_path,
        trusted_owner_uids=trusted_owner_uids,
    )
    return build_go_pprof_adapter_bridge(
        policy,
        installation,
        created_at=created_at,
        supervisor_available=discover_runtime_supervisor_policy().policy is not None,
    )


def _inspect_go_tool(path: Path, *, trusted_owner_uids: tuple[int, ...]) -> GoToolIdentity:
    if not path.is_absolute():
        path = Path(shutil.which(str(path)) or str(path))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _error("Go executable cannot be resolved") from exc
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(resolved, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted_owner_uids
            or stat.S_IMODE(before.st_mode) not in {0o555, 0o755}
            or before.st_size <= 0
            or before.st_size > _MAX_GO_BYTES
        ):
            raise _error("Go executable owner, links, mode, or size are unsafe")
        digest = _hash_fd(descriptor)
        completed = subprocess.run(
            ("go", "version"),  # noqa: S607 - argv0 is paired with executable FD
            executable=f"/proc/self/fd/{descriptor}",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
            pass_fds=(descriptor,),
            env={"LANG": "C", "LC_ALL": "C"},
        )
        after = os.fstat(descriptor)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error("Go executable could not be inspected deterministically") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        _stable_file_identity(before) != _stable_file_identity(after)
        or completed.returncode != 0
        or completed.stderr
    ):
        raise _error("Go executable changed or failed its fixed version probe")
    try:
        output = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise _error("Go version output is not UTF-8") from exc
    match = _GO_VERSION.fullmatch(output) or _GO_ANY_VERSION.fullmatch(output)
    if match is None:
        raise _error("Go version output is outside the supported Linux amd64 format")
    version = output.removeprefix("go version go").removesuffix(" linux/amd64")
    return GoToolIdentity(
        path=resolved,
        version=version,
        minor_version=match.group(1),
        sha256=digest,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        mode=stat.S_IMODE(before.st_mode),
        links=before.st_nlink,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
    )


def _inspect_pprof_tool(
    go_tool: GoToolIdentity,
    *,
    trusted_owner_uids: tuple[int, ...],
) -> GoToolIdentity:
    descriptor = os.open(
        go_tool.path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        completed = subprocess.run(
            ("go", "env", "GOTOOLDIR"),  # noqa: S607
            executable=f"/proc/self/fd/{descriptor}",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
            pass_fds=(descriptor,),
            env={"LANG": "C", "LC_ALL": "C"},
        )
        after = os.fstat(descriptor)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error("Go tool directory could not be inspected deterministically") from exc
    finally:
        os.close(descriptor)
    if (
        _stable_file_identity(before) != _stable_file_identity(after)
        or completed.returncode != 0
        or completed.stderr
    ):
        raise _error("Go executable changed or failed its fixed tool-directory probe")
    try:
        tool_directory = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise _error("Go tool directory output is not UTF-8") from exc
    directory = Path(tool_directory)
    if not directory.is_absolute() or "\n" in tool_directory or "\x00" in tool_directory:
        raise _error("Go tool directory output is not one absolute path")
    return _inspect_fixed_binary(
        directory / "pprof",
        version=go_tool.version,
        minor_version=go_tool.minor_version,
        trusted_owner_uids=trusted_owner_uids,
    )


def _inspect_fixed_binary(
    path: Path,
    *,
    version: str,
    minor_version: str,
    trusted_owner_uids: tuple[int, ...],
) -> GoToolIdentity:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _error("Go pprof executable cannot be resolved") from exc
    descriptor = os.open(
        resolved,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted_owner_uids
            or stat.S_IMODE(before.st_mode) not in {0o555, 0o755}
            or not 1 <= before.st_size <= _MAX_GO_BYTES
        ):
            raise _error("Go pprof executable owner, links, mode, or size are unsafe")
        digest = _hash_fd(descriptor)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _stable_file_identity(before) != _stable_file_identity(after):
        raise _error("Go pprof executable changed during inspection")
    return GoToolIdentity(
        path=resolved,
        version=version,
        minor_version=minor_version,
        sha256=digest,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        mode=stat.S_IMODE(before.st_mode),
        links=before.st_nlink,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
    )


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Exclude atime, which may change merely because the executable was read."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1 << 20):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_go_pprof",
        message,
        recoverable=True,
    )
