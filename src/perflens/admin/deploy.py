"""Validated one-command deployment for the optional system Collector."""

from __future__ import annotations

import math
import os
import pwd
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from perflens import __version__
from perflens.artifacts.filesystem import write_text_atomic
from perflens.collector_broker.policy import COLLECTOR_POLICY_VERSION
from perflens.contracts.artifacts import CollectorDeploymentArtifact
from perflens.distribution.collector import install_collector_assets
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_CONFIG_BYTES = 256 << 10
_SUPPORTED_MODES = {"record", "stat", "sched", "lock", "off_cpu"}


@dataclass(frozen=True, slots=True)
class CollectorSystemLayout:
    config_directory: Path = Path("/etc/perflens")
    config_path: Path = Path("/etc/perflens/collector.toml")
    service_path: Path = Path("/etc/systemd/system/perflens-collector.service")
    state_directory: Path = Path("/var/lib/perflens")
    socket_path: Path = Path("/run/perflens/collector.sock")


@dataclass(frozen=True, slots=True)
class _DeploymentPolicy:
    raw_text: str
    spool_root: Path
    perf_path: Path
    allowed_uids: tuple[int, ...]
    allowed_modes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ConfigSource:
    path: Path
    raw_text: str


CommandExecutor = Callable[[tuple[str, ...]], None]
SocketWaiter = Callable[[Path], None]


def deploy_collector(
    config_path: Path,
    *,
    dry_run: bool = False,
    layout: CollectorSystemLayout | None = None,
    collector_command: Path | None = None,
    require_root: bool = True,
    command_executor: CommandExecutor | None = None,
    socket_waiter: SocketWaiter | None = None,
    service_identity: tuple[int, int] | None = None,
) -> CollectorDeploymentArtifact:
    """Deploy fixed Collector assets from one strictly validated data-only policy."""
    effective_layout = layout or CollectorSystemLayout()
    source = _candidate_config(config_path)
    policy = _parse_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
    )
    command = _collector_command(
        collector_command,
        require_root_owner=require_root,
    )
    commands = _planned_commands(policy.allowed_uids)
    warnings = (
        "Host perf/kernel policy is not changed; a real collection can still be blocked.",
        "Users added to the perflens group must start a new login session.",
    )
    next_steps = (
        "Start a new login session for every newly authorized user.",
        "Run perflens verify-collector as an authorized ordinary user.",
        "Enable automatic collection in the generated Codex MCP configuration.",
    )
    if dry_run:
        return _result(
            "dry_run",
            source.path,
            effective_layout,
            command,
            policy.allowed_uids,
            commands,
            warnings,
            next_steps,
        )
    if require_root and os.geteuid() != 0:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Collector deployment must be started explicitly by an administrator",
            recoverable=True,
            suggested_actions=("Run sudo perflens-admin deploy --config <reviewed-config>.",),
        )

    executor = command_executor or _run_admin_command
    wait_for_socket = socket_waiter or _wait_for_socket
    identity = service_identity
    staged: Path | None = None
    installed_config = False
    installed_service = False
    try:
        with tempfile.TemporaryDirectory(prefix="perflens-admin-") as temporary:
            staged = install_collector_assets(
                Path(temporary) / "assets",
                allowed_uids=policy.allowed_uids,
                collector_command=command,
                perf_path=policy.perf_path,
            )
            executor((commands[0][0], str(staged / "perflens.sysusers")))
            if identity is None:
                try:
                    account = pwd.getpwnam("perflens")
                except KeyError as exc:
                    raise PerfLensError(
                        ErrorCode.EXTERNAL_TOOL_FAILED,
                        "collector_deploy",
                        "systemd-sysusers did not create the perflens service account",
                    ) from exc
                identity = (account.pw_uid, account.pw_gid)
            _prepare_system_directories(effective_layout, identity)
            installed_config = _install_new_or_identical_text(
                source.raw_text,
                effective_layout.config_path,
                mode=0o644,
            )
            service_text = (staged / "perflens-collector.service").read_text(encoding="utf-8")
            installed_service = _install_new_or_identical_text(
                service_text,
                effective_layout.service_path,
                mode=0o644,
            )
            for group_command in commands[1:-2]:
                executor(group_command)
            executor(commands[-2])
            executor(commands[-1])
            wait_for_socket(effective_layout.socket_path)
    except BaseException:
        if installed_service:
            effective_layout.service_path.unlink(missing_ok=True)
        if installed_config:
            effective_layout.config_path.unlink(missing_ok=True)
        raise

    return _result(
        "deployed",
        source.path,
        effective_layout,
        command,
        policy.allowed_uids,
        commands,
        warnings,
        next_steps,
    )


def _candidate_config(path: Path) -> _ConfigSource:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Collector deployment config must not be a symbolic link",
        )
    descriptor = -1
    try:
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config cannot be resolved",
            details={"path": str(path)},
        ) from exc
    invoking_uid = _invoking_uid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, invoking_uid}
        or metadata.st_mode & 0o022
        or metadata.st_size > _MAX_CONFIG_BYTES
    ):
        os.close(descriptor)
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Collector config must be invoking-user/root owned, non-writable by group/other, "
            "and bounded",
            details={"path": str(resolved)},
        )
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config cannot be read as bounded UTF-8",
            details={"path": str(resolved)},
        ) from exc
    if len(raw) > _MAX_CONFIG_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "collector_deploy",
            "Collector deployment config exceeds its size limit",
        )
    return _ConfigSource(path=resolved, raw_text=text)


def _parse_deployment_policy(
    text: str,
    *,
    expected_spool: Path,
    require_root_owned_tools: bool,
) -> _DeploymentPolicy:
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config is not valid bounded UTF-8 TOML",
        ) from exc
    if set(payload) != {"collector"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config must contain only one [collector] table",
        )
    section = payload["collector"]
    if not isinstance(section, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config requires a [collector] table",
        )
    values = cast(dict[str, Any], section)
    allowed_keys = {
        "policy_version",
        "spool_root",
        "perf_path",
        "allowed_uids",
        "allowed_modes",
        "allow_other_target_uids",
        "max_duration_seconds",
        "max_frequency_hz",
        "max_output_bytes",
        "max_plan_ttl_seconds",
        "allowed_stat_events",
        "socket_mode",
        "artifact_mode",
    }
    if set(values) - allowed_keys:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config contains unsupported fields",
            details={"fields": sorted(set(values) - allowed_keys)},
        )
    try:
        policy_version = values.get("policy_version", COLLECTOR_POLICY_VERSION)
        if isinstance(policy_version, bool) or not isinstance(policy_version, int):
            raise TypeError("policy_version must be an integer")
        spool = Path(str(values["spool_root"])).expanduser().resolve(strict=False)
        perf_candidate = Path(str(values["perf_path"])).expanduser()
        perf = perf_candidate.resolve(strict=True)
        uids = tuple(sorted(set(int(value) for value in values["allowed_uids"])))
        modes = tuple(dict.fromkeys(str(value) for value in values["allowed_modes"]))
        duration = float(values.get("max_duration_seconds", 30.0))
        frequency = int(values.get("max_frequency_hz", 99))
        output_bytes = int(values.get("max_output_bytes", 1 << 30))
        plan_ttl = int(values.get("max_plan_ttl_seconds", 300))
        events = tuple(str(value) for value in values.get("allowed_stat_events", ()))
        socket_mode_raw = values.get("socket_mode", "0660")
        artifact_mode_raw = values.get("artifact_mode", "0640")
        socket_mode = (
            int(socket_mode_raw, 8)
            if isinstance(socket_mode_raw, str)
            else int(socket_mode_raw)
        )
        artifact_mode = (
            int(artifact_mode_raw, 8)
            if isinstance(artifact_mode_raw, str)
            else int(artifact_mode_raw)
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Collector deployment config has missing or invalid values",
        ) from exc
    perf_metadata = perf.stat()
    allow_other = values.get("allow_other_target_uids", False)
    if (
        policy_version != COLLECTOR_POLICY_VERSION
        or spool != expected_spool.resolve(strict=False)
        or not perf.is_file()
        or not os.access(perf, os.X_OK)
        or perf_candidate.name != "perf"
        or perf_metadata.st_uid not in ({0} if require_root_owned_tools else {os.geteuid()})
        or perf_metadata.st_mode & 0o022
        or not uids
        or len(uids) > 64
        or any(uid <= 0 for uid in uids)
        or not modes
        or any(mode not in _SUPPORTED_MODES for mode in modes)
        or allow_other is not False
        or not math.isfinite(duration)
        or not 0 < duration <= 86_400
        or not 1 <= frequency <= 10_000
        or output_bytes < 1
        or not 1 <= plan_ttl <= 3600
        or (events and (len(events) > 64 or any(not event or "\0" in event for event in events)))
        or socket_mode < 0
        or socket_mode > 0o660
        or socket_mode & 0o007
        or socket_mode & 0o600 != 0o600
        or artifact_mode < 0
        or artifact_mode > 0o640
        or artifact_mode & 0o007
        or artifact_mode & 0o400 != 0o400
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Collector deployment config violates fixed paths or bounded policy",
        )
    return _DeploymentPolicy(
        raw_text=text,
        spool_root=spool,
        perf_path=perf,
        allowed_uids=uids,
        allowed_modes=modes,
    )


def _collector_command(explicit: Path | None, *, require_root_owner: bool) -> Path:
    candidate = explicit or Path(sys.executable).resolve().parent / "perflens-collector"
    try:
        resolved = candidate.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_deploy",
            "Trusted perflens-collector executable cannot be resolved",
            details={"path": str(candidate)},
        ) from exc
    expected_owners = {0} if require_root_owner else {os.geteuid()}
    if (
        not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or metadata.st_uid not in expected_owners
        or metadata.st_mode & 0o022
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "perflens-collector must be a trusted-owner executable not writable by group or "
            "other",
            details={"path": str(resolved)},
        )
    return resolved


def _planned_commands(allowed_uids: tuple[int, ...]) -> tuple[tuple[str, ...], ...]:
    commands: list[tuple[str, ...]] = [
        ("/usr/bin/systemd-sysusers", "perflens.sysusers"),
    ]
    for uid in allowed_uids:
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collector_deploy",
                "An allowed UID has no local user account",
                details={"uid": uid},
            ) from exc
        commands.append(("/usr/sbin/usermod", "-aG", "perflens", username))
    commands.extend(
        (
            ("/usr/bin/systemctl", "daemon-reload"),
            ("/usr/bin/systemctl", "enable", "--now", "perflens-collector.service"),
        )
    )
    return tuple(commands)


def _prepare_system_directories(
    layout: CollectorSystemLayout,
    identity: tuple[int, int],
) -> None:
    uid, gid = identity
    try:
        _ensure_directory(layout.config_directory, mode=0o755)
        _ensure_directory(layout.state_directory, mode=0o750)
        os.chown(layout.state_directory, uid, gid)
        _ensure_directory(layout.service_path.parent, mode=0o755)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "collector_deploy",
            "Unable to prepare fixed Collector system directories",
        ) from exc


def _ensure_directory(path: Path, *, mode: int) -> None:
    if path.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Collector system directory must not be a symbolic link",
            details={"path": str(path)},
        )
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if not path.is_dir():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Collector system path is not a directory",
            details={"path": str(path)},
        )
    os.chmod(path, mode)


def _install_new_or_identical_text(text: str, destination: Path, *, mode: int) -> bool:
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_deploy",
                "Collector destination is not a safe regular file",
                details={"path": str(destination)},
            )
        metadata = destination.stat()
        if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_deploy",
                "Existing Collector file has unsafe ownership or permissions",
                details={"path": str(destination)},
            )
        if destination.read_text(encoding="utf-8") != text:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_deploy",
                "Collector destination differs and will not be overwritten",
                recoverable=True,
                details={"path": str(destination)},
                suggested_actions=("Review the difference and use a future explicit update flow.",),
            )
        os.chmod(destination, mode)
        return False
    write_text_atomic(text, destination, max_output_bytes=_MAX_CONFIG_BYTES)
    os.chmod(destination, mode)
    return True


def _run_admin_command(command: tuple[str, ...]) -> None:
    executable = Path(command[0])
    allowed = {"/usr/bin/systemd-sysusers", "/usr/sbin/usermod", "/usr/bin/systemctl"}
    if command[0] not in allowed:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "Administrative command is outside the fixed deployment allowlist",
        )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed absolute administrative allowlist
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
            shell=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "collector_deploy",
            "Unable to run a fixed administrative deployment command",
            details={"executable": str(executable)},
        ) from exc
    if completed.returncode != 0:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "collector_deploy",
            "Administrative deployment command failed",
            recoverable=True,
            details={
                "executable": str(executable),
                "exit_code": completed.returncode,
                "stderr": completed.stderr[-4096:],
            },
        )


def _wait_for_socket(path: Path) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            if stat.S_ISSOCK(path.stat().st_mode):
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise PerfLensError(
        ErrorCode.EXTERNAL_TOOL_FAILED,
        "collector_deploy",
        "Collector service did not create its Unix socket",
        recoverable=True,
        details={"socket": str(path)},
        suggested_actions=(
            "Inspect systemctl status and journalctl for perflens-collector.service.",
        ),
    )


def _invoking_uid() -> int:
    raw = os.environ.get("SUDO_UID")
    if raw is None:
        return os.geteuid()
    try:
        value = int(raw)
    except ValueError:
        return os.geteuid()
    return value if value >= 0 else os.geteuid()


def _result(
    status: Literal["dry_run", "deployed"],
    source: Path,
    layout: CollectorSystemLayout,
    command: Path,
    allowed_uids: tuple[int, ...],
    commands: tuple[tuple[str, ...], ...],
    warnings: tuple[str, ...],
    next_steps: tuple[str, ...],
) -> CollectorDeploymentArtifact:
    return CollectorDeploymentArtifact(
        perflens_version=__version__,
        status=status,
        config_source=str(source),
        config_path=str(layout.config_path),
        service_path=str(layout.service_path),
        collector_command=str(command),
        allowed_uids=allowed_uids,
        planned_commands=commands,
        warnings=warnings,
        next_steps=next_steps,
    )
