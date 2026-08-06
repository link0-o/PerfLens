"""Read-only inspection of Linux perf collection prerequisites."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import tempfile
from pathlib import Path

from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectionModeCapability,
)
from perflens.domain.errors import PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner

_CAPABILITY_BITS = {
    14: "cap_ipc_lock",
    19: "cap_sys_ptrace",
    21: "cap_sys_admin",
    34: "cap_syslog",
    38: "cap_perfmon",
}
_TRACE_MODES = ("sched", "lock", "off_cpu")


def inspect_collection_capabilities(perf_path: Path | None = None) -> CollectionCapabilityArtifact:
    """Return a bounded, side-effect-free snapshot of collection permissions."""
    warnings: list[str] = []
    selected_perf = _resolve_optional_executable(perf_path, "perf", warnings)
    perf_version = _read_perf_version(selected_perf, warnings)
    paranoid = _read_kernel_integer("/proc/sys/kernel/perf_event_paranoid", warnings)
    kptr_restrict = _read_kernel_integer("/proc/sys/kernel/kptr_restrict", warnings)
    ptrace_scope = _read_kernel_integer("/proc/sys/kernel/yama/ptrace_scope", warnings)
    process_capabilities = _process_capabilities(warnings)
    file_capabilities = _file_capabilities(selected_perf, warnings)
    tracefs_accessible = _tracefs_accessible()
    modes = _mode_capabilities(
        paranoid=paranoid,
        effective_uid=os.geteuid(),
        capabilities=frozenset((*process_capabilities, *file_capabilities)),
        tracefs_accessible=tracefs_accessible,
        perf_available=selected_perf is not None,
    )
    recommendations = _recommendations(
        paranoid=paranoid,
        perf_available=selected_perf is not None,
        modes=modes,
    )
    identity = "\0".join(
        (
            platform.system(),
            platform.release(),
            str(os.geteuid()),
            str(selected_perf),
            str(paranoid),
            ",".join(process_capabilities),
            ",".join(file_capabilities),
        )
    )
    return CollectionCapabilityArtifact(
        capability_id=f"capability-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        platform=platform.system(),
        kernel_release=platform.release(),
        effective_uid=os.geteuid(),
        perf_executable=str(selected_perf) if selected_perf is not None else None,
        perf_version=perf_version,
        perf_event_paranoid=paranoid,
        kptr_restrict=kptr_restrict,
        ptrace_scope=ptrace_scope,
        effective_capabilities=process_capabilities,
        perf_file_capabilities=file_capabilities,
        tracefs_accessible=tracefs_accessible,
        modes=modes,
        warnings=tuple(warnings[:32]),
        recommendations=recommendations,
    )


def _resolve_optional_executable(
    explicit: Path | None, name: str, warnings: list[str]
) -> Path | None:
    candidate = explicit
    if candidate is None:
        discovered = shutil.which(name)
        candidate = Path(discovered) if discovered is not None else None
    if candidate is None:
        warnings.append(f"System {name} executable was not found.")
        return None
    try:
        resolved = candidate.expanduser().resolve(strict=True)
    except OSError:
        warnings.append(f"Configured {name} executable cannot be resolved.")
        return None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        warnings.append(f"Configured {name} path is not an executable regular file.")
        return None
    return resolved


def _read_perf_version(perf_path: Path | None, warnings: list[str]) -> str | None:
    if perf_path is None:
        return None
    try:
        with tempfile.TemporaryFile(mode="w+b") as output:
            CommandRunner({perf_path}).run_to_file(
                (str(perf_path), "--version"),
                output,
                limits=CommandLimits(
                    timeout_seconds=5,
                    max_stdout_bytes=4096,
                    max_stderr_bytes=4096,
                ),
            )
            output.seek(0)
            return output.read(4096).decode("utf-8", errors="replace").strip() or None
    except PerfLensError:
        warnings.append("Unable to query the selected perf version.")
        return None


def _read_kernel_integer(path: str, warnings: list[str]) -> int | None:
    try:
        value = Path(path).read_text(encoding="ascii")[:64].strip()
        return int(value)
    except (OSError, ValueError):
        warnings.append(f"Unable to read {path}.")
        return None


def _process_capabilities(warnings: list[str]) -> tuple[str, ...]:
    try:
        lines = Path("/proc/self/status").read_text(encoding="ascii", errors="replace").splitlines()
        raw = next(
            line.split(":", maxsplit=1)[1].strip() for line in lines if line.startswith("CapEff:")
        )
        mask = int(raw, 16)
    except (OSError, StopIteration, ValueError):
        warnings.append("Unable to inspect effective process capabilities.")
        return ()
    return tuple(name for bit, name in _CAPABILITY_BITS.items() if mask & (1 << bit))


def _file_capabilities(perf_path: Path | None, warnings: list[str]) -> tuple[str, ...]:
    if perf_path is None:
        return ()
    discovered = shutil.which("getcap")
    if discovered is None:
        return ()
    getcap = Path(discovered).resolve(strict=True)
    try:
        with tempfile.TemporaryFile(mode="w+b") as output:
            CommandRunner({getcap}).run_to_file(
                (str(getcap), str(perf_path)),
                output,
                limits=CommandLimits(
                    timeout_seconds=5,
                    max_stdout_bytes=4096,
                    max_stderr_bytes=4096,
                ),
            )
            output.seek(0)
            text = output.read(4096).decode("utf-8", errors="replace").lower()
    except PerfLensError:
        warnings.append("Unable to inspect perf file capabilities.")
        return ()
    return tuple(name for name in _CAPABILITY_BITS.values() if name in text)


def _tracefs_accessible() -> bool:
    candidates = (
        Path("/sys/kernel/tracing/events/sched/sched_switch/id"),
        Path("/sys/kernel/debug/tracing/events/sched/sched_switch/id"),
    )
    for path in candidates:
        try:
            if path.is_file() and os.access(path, os.R_OK):
                return True
        except OSError:
            continue
    return False


def _mode_capabilities(
    *,
    paranoid: int | None,
    effective_uid: int,
    capabilities: frozenset[str],
    tracefs_accessible: bool,
    perf_available: bool,
) -> tuple[CollectionModeCapability, ...]:
    if not perf_available:
        return tuple(
            CollectionModeCapability(
                mode=mode,
                status="blocked",
                required_privilege="none",
                reason="The system perf executable is unavailable.",
            )
            for mode in ("record", "stat", *_TRACE_MODES)
        )
    broad_privilege = effective_uid == 0 or "cap_sys_admin" in capabilities
    perfmon = broad_privilege or "cap_perfmon" in capabilities
    if paranoid is not None and paranoid > 2 and not broad_privilege:
        return tuple(
            CollectionModeCapability(
                mode=mode,
                status="blocked",
                required_privilege="cap_sys_admin_or_policy_change",
                reason=(
                    "perf_event_paranoid is greater than 2; this Debian-style policy blocks "
                    "unprivileged perf_event_open before normal CAP_PERFMON scope checks."
                ),
            )
            for mode in ("record", "stat", *_TRACE_MODES)
        )

    common_status = "available" if perfmon else "conditional"
    common_required = "none" if perfmon else "cap_perfmon"
    common_reason = (
        "The current credential has a perf monitoring privilege."
        if perfmon
        else "Own-process user-space collection depends on the selected events and kernel policy."
    )
    result = [
        CollectionModeCapability(
            mode=mode,
            status=common_status,
            required_privilege=common_required,
            reason=common_reason,
        )
        for mode in ("record", "stat")
    ]
    for mode in _TRACE_MODES:
        if perfmon and tracefs_accessible:
            status = "available"
            required = "none"
            reason = "Perf monitoring privilege and readable sched tracepoint metadata are present."
        elif perfmon:
            status = "conditional"
            required = "none"
            reason = "Perf monitoring privilege is present, but tracefs metadata is not readable."
        elif paranoid is not None and paranoid < 0 and tracefs_accessible:
            status = "conditional"
            required = "none"
            reason = "The tracepoint appears readable, but a real bounded probe is still required."
        else:
            status = "blocked"
            required = "cap_perfmon"
            reason = "Tracepoint collection requires CAP_PERFMON or an equivalent host policy."
        result.append(
            CollectionModeCapability(
                mode=mode,
                status=status,
                required_privilege=required,
                reason=reason,
            )
        )
    return tuple(result)


def _recommendations(
    *,
    paranoid: int | None,
    perf_available: bool,
    modes: tuple[CollectionModeCapability, ...],
) -> tuple[str, ...]:
    recommendations: list[str] = []
    if not perf_available:
        recommendations.append("Install a perf build matching the running Linux kernel.")
    if paranoid is not None and paranoid > 2:
        recommendations.append(
            "Have an administrator review perf_event_paranoid; do not weaken it automatically."
        )
    if any(mode.status == "blocked" for mode in modes):
        recommendations.append(
            "Prefer a dedicated collector service with a narrow policy over running the MCP "
            "server as root."
        )
    recommendations.append(
        "Run a short authorized real probe before claiming a mode is operational."
    )
    return tuple(recommendations)
