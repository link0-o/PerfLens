"""Validated one-command deployment for the optional system Collector."""

from __future__ import annotations

import hashlib
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
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from perflens import __version__
from perflens.artifacts.filesystem import write_text_atomic
from perflens.collection.collector import DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_STAT_EVENTS
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.collector_broker.policy import (
    COLLECTOR_POLICY_VERSION,
    DEFAULT_MAX_PLAN_TTL_SECONDS,
    DEFAULT_MAX_SPOOL_ARTIFACTS,
    DEFAULT_MAX_SPOOL_BYTES,
    DEFAULT_MIN_FREE_BYTES,
    PARANOID3_HELPER_MAX_DURATION_SECONDS,
    PARANOID3_HELPER_MAX_FREQUENCY_HZ,
    PARANOID3_HELPER_MAX_OUTPUT_BYTES,
    PARANOID3_HELPER_MODES,
)
from perflens.collector_broker.state import (
    collection_artifact_name,
    replay_marker,
    safe_replay_marker_metadata,
)
from perflens.contracts.artifacts import (
    CollectorDeploymentArtifact,
    CollectorPolicyUpdateArtifact,
    CollectorSpoolStatusArtifact,
    CollectorUndeploymentArtifact,
    CollectorUpgradeArtifact,
)
from perflens.distribution.collector import install_collector_assets
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_CONFIG_BYTES = 256 << 10
_MAX_SERVICE_BYTES = 256 << 10
_SUPPORTED_MODES = {"record", "stat", "sched", "lock", "off_cpu"}
_MANAGED_SERVICE_MARKER = "# Managed by PerfLens."


@dataclass(frozen=True, slots=True)
class CollectorSystemLayout:
    config_directory: Path = Path("/etc/perflens")
    config_path: Path = Path("/etc/perflens/collector.toml")
    service_path: Path = Path("/etc/systemd/system/perflens-collector.service")
    state_directory: Path = Path("/var/lib/perflens")
    socket_path: Path = Path("/run/perflens/collector.sock")
    helper_service_path: Path = Path("/etc/systemd/system/perflens-privileged-helper.service")
    helper_state_directory: Path = Path("/var/lib/perflens-helper")
    helper_socket_path: Path = Path("/run/perflens-helper/helper.sock")


@dataclass(frozen=True, slots=True)
class CollectorDeploymentPolicy:
    raw_text: str
    spool_root: Path
    perf_path: Path
    allowed_uids: tuple[int, ...]
    privilege_mode: Literal["cap_perfmon", "paranoid3_helper"]
    allowed_modes: tuple[str, ...]
    max_output_bytes: int
    max_spool_bytes: int
    max_spool_artifacts: int
    min_free_bytes: int


@dataclass(frozen=True, slots=True)
class CollectorConfigSource:
    path: Path
    raw_text: str
    metadata: os.stat_result


@dataclass(frozen=True, slots=True)
class _ManagedServiceSnapshot:
    metadata: os.stat_result
    raw: bytes


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
    acknowledge_cap_sys_admin_risk: bool = False,
) -> CollectorDeploymentArtifact:
    """Deploy fixed Collector assets from one strictly validated data-only policy."""
    effective_layout = layout or CollectorSystemLayout()
    source = load_collector_config(config_path)
    policy = parse_collector_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
    )
    command = _collector_command(
        collector_command,
        require_root_owner=require_root,
    )
    commands = _planned_commands(policy.allowed_uids, policy.privilege_mode)
    warnings = [
        "Host perf/kernel policy is not changed; a real collection can still be blocked.",
        "Users added to the perflens group must start a new login session.",
    ]
    if policy.privilege_mode == "paranoid3_helper":
        warnings.append(
            "The Rust Helper runs in a root service with only CAP_PERFMON/CAP_SYS_ADMIN in its "
            "capability bounding set; this is a larger host-security boundary."
        )
    next_steps = (
        "Start a new login session for every newly authorized user.",
        "Run perflens accept-collector --authorize-host-acceptance as an ordinary user.",
        "Enable automatic collection in the generated Codex MCP configuration.",
    )
    if dry_run:
        return _result(
            "dry_run",
            source.path,
            effective_layout,
            command,
            policy.allowed_uids,
            policy.privilege_mode,
            commands,
            tuple(warnings),
            next_steps,
        )
    if policy.privilege_mode == "paranoid3_helper" and not acknowledge_cap_sys_admin_risk:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_deploy",
            "paranoid3_helper deployment requires explicit CAP_SYS_ADMIN risk acknowledgement",
            recoverable=True,
            suggested_actions=(
                "Review the dry-run and security guide, then add --acknowledge-cap-sys-admin-risk.",
            ),
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
    identity = service_identity
    staged: Path | None = None
    installed_config = False
    installed_service = False
    installed_helper_service = False
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
            service_asset = (
                "perflens-collector-helper.service"
                if policy.privilege_mode == "paranoid3_helper"
                else "perflens-collector.service"
            )
            service_text = (staged / service_asset).read_text(encoding="utf-8")
            installed_service = _install_new_or_identical_text(
                service_text,
                effective_layout.service_path,
                mode=0o644,
            )
            if policy.privilege_mode == "paranoid3_helper":
                helper_text = (staged / "perflens-privileged-helper.service").read_text(
                    encoding="utf-8"
                )
                helper_text = helper_text.replace(
                    "@PERFLENS_BROKER_UID@",
                    str(identity[0]),
                )
                helper_text = helper_text.replace(
                    "@PERFLENS_ARTIFACT_GID@",
                    str(identity[1]),
                )
                if "@PERFLENS_" in helper_text:
                    raise PerfLensError(
                        ErrorCode.INTERNAL_ERROR,
                        "collector_deploy",
                        "Privileged Helper unit contains an unresolved identity marker",
                    )
                installed_helper_service = _install_new_or_identical_text(
                    helper_text,
                    effective_layout.helper_service_path,
                    mode=0o644,
                )
            for group_command in commands[1:-2]:
                executor(group_command)
            executor(commands[-2])
            executor(commands[-1])
            if socket_waiter is not None:
                socket_waiter(effective_layout.socket_path)
            else:
                _wait_for_socket(
                    effective_layout.socket_path,
                    expected_service_uid=identity[0],
                )
    except BaseException:
        if installed_service:
            effective_layout.service_path.unlink(missing_ok=True)
        if installed_helper_service:
            effective_layout.helper_service_path.unlink(missing_ok=True)
        if installed_config:
            effective_layout.config_path.unlink(missing_ok=True)
        raise

    return _result(
        "deployed",
        source.path,
        effective_layout,
        command,
        policy.allowed_uids,
        policy.privilege_mode,
        commands,
        tuple(warnings),
        next_steps,
    )


def upgrade_collector(
    config_path: Path = Path("/etc/perflens/collector.toml"),
    *,
    dry_run: bool = False,
    layout: CollectorSystemLayout | None = None,
    collector_command: Path | None = None,
    require_root: bool = True,
    command_executor: CommandExecutor | None = None,
    socket_waiter: SocketWaiter | None = None,
) -> CollectorUpgradeArtifact:
    """Upgrade only a verified managed unit while preserving policy and evidence."""
    stage = "collector_upgrade"
    effective_layout = layout or CollectorSystemLayout()
    source = load_collector_config(config_path, stage=stage)
    try:
        deployed_config = effective_layout.config_path.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Deployed Collector policy cannot be resolved",
            details={"path": str(effective_layout.config_path)},
            suggested_actions=("Deploy the Collector before running upgrade.",),
        ) from exc
    if source.path != deployed_config:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector upgrade must preserve the fixed deployed policy",
            details={
                "provided_config": str(source.path),
                "deployed_config": str(deployed_config),
            },
            suggested_actions=(
                "Edit and validate the deployed policy separately; do not replace it "
                "during upgrade.",
            ),
        )
    policy = parse_collector_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
        stage=stage,
    )
    command = _collector_command(
        collector_command,
        require_root_owner=require_root,
        stage=stage,
    )
    previous = _verify_managed_service(
        effective_layout.service_path,
        require_root_owner=require_root,
        stage=stage,
    )
    commands: list[tuple[str, ...]] = [("/usr/bin/systemctl", "daemon-reload")]
    if policy.privilege_mode == "paranoid3_helper":
        commands.append(("/usr/bin/systemctl", "restart", "perflens-privileged-helper.service"))
    commands.append(("/usr/bin/systemctl", "restart", "perflens-collector.service"))
    planned_commands = tuple(commands)
    warnings = (
        "Administrator policy and collected artifacts are preserved.",
        "Package installation must complete before this command is run.",
        "Host perf/kernel policy is not changed.",
    )
    next_steps = (
        "Run perflens accept-collector --authorize-host-acceptance as an ordinary user.",
        "Run perflens-admin spool-status to check retained evidence capacity.",
    )

    with tempfile.TemporaryDirectory(prefix="perflens-admin-upgrade-") as temporary:
        staged = install_collector_assets(
            Path(temporary) / "assets",
            allowed_uids=policy.allowed_uids,
            collector_command=command,
            perf_path=policy.perf_path,
        )
        service_asset = (
            "perflens-collector-helper.service"
            if policy.privilege_mode == "paranoid3_helper"
            else "perflens-collector.service"
        )
        candidate = (staged / service_asset).read_bytes()
        if len(candidate) > _MAX_SERVICE_BYTES:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                stage,
                "Bundled Collector service exceeds its upgrade size limit",
            )
        update_required = previous.raw != candidate
        if dry_run:
            return _upgrade_result(
                "dry_run",
                deployed_config,
                effective_layout,
                command,
                previous.raw,
                candidate,
                update_required=update_required,
                service_updated=False,
                commands=planned_commands,
                warnings=warnings,
                next_steps=next_steps,
            )
        if require_root and os.geteuid() != 0:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "Collector upgrade must be started explicitly by an administrator",
                recoverable=True,
                suggested_actions=("Run sudo perflens-admin upgrade --dry-run first.",),
            )

        executor = command_executor or _run_admin_upgrade_command
        expected_service_uid: int | None = None
        if socket_waiter is None:
            try:
                expected_service_uid = pwd.getpwnam("perflens").pw_uid
            except KeyError as exc:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    stage,
                    "Dedicated perflens service account does not exist",
                    suggested_actions=("Deploy the Collector before running upgrade.",),
                ) from exc
        service_updated = False
        try:
            if update_required:
                service_updated = True
                _replace_verified_managed_service(
                    effective_layout.service_path,
                    previous,
                    candidate,
                    stage=stage,
                )
            for planned in planned_commands:
                executor(planned)
            if socket_waiter is not None:
                socket_waiter(effective_layout.socket_path)
            else:
                _wait_for_upgrade_socket(
                    effective_layout.socket_path,
                    expected_service_uid=expected_service_uid,
                )
        except BaseException as exc:
            rollback_errors: list[str] = []
            if service_updated:
                try:
                    current = _verify_managed_service(
                        effective_layout.service_path,
                        require_root_owner=require_root,
                        stage=stage,
                    )
                    if current.raw == previous.raw:
                        service_updated = False
                    elif current.raw != candidate:
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            stage,
                            "Collector service changed before upgrade rollback",
                        )
                    else:
                        _replace_verified_managed_service(
                            effective_layout.service_path,
                            current,
                            previous.raw,
                            stage=stage,
                            mode=stat.S_IMODE(previous.metadata.st_mode),
                        )
                    for rollback_command in commands:
                        executor(rollback_command)
                except BaseException as rollback_exc:
                    rollback_errors.append(type(rollback_exc).__name__)
            if rollback_errors:
                raise PerfLensError(
                    ErrorCode.OUTPUT_WRITE_FAILED,
                    stage,
                    "Collector upgrade failed and the managed unit could not be fully restored",
                    recoverable=True,
                    details={"rollback_errors": rollback_errors},
                    suggested_actions=(
                        "Inspect the service unit, systemctl status, and journal before retrying.",
                    ),
                ) from exc
            raise

    return _upgrade_result(
        "upgraded" if update_required else "restarted",
        deployed_config,
        effective_layout,
        command,
        previous.raw,
        candidate,
        update_required=update_required,
        service_updated=service_updated,
        commands=planned_commands,
        warnings=warnings,
        next_steps=next_steps,
    )


def update_collector_policy(
    config_path: Path,
    *,
    dry_run: bool = False,
    layout: CollectorSystemLayout | None = None,
    require_root: bool = True,
    command_executor: CommandExecutor | None = None,
    socket_waiter: SocketWaiter | None = None,
) -> CollectorPolicyUpdateArtifact:
    """Validate and atomically apply a bounded Collector policy update."""
    stage = "collector_policy_update"
    effective_layout = layout or CollectorSystemLayout()
    candidate = load_collector_config(config_path, stage=stage)
    current = load_collector_config(effective_layout.config_path, stage=stage)
    if candidate.path == current.path:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector policy update requires a separate candidate file",
            recoverable=True,
            details={"config_path": str(current.path)},
            suggested_actions=(
                "Copy the deployed policy, edit the copy, then pass that copy to --config.",
            ),
        )
    if require_root and current.metadata.st_uid != 0:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Deployed Collector policy must be root owned",
            details={"config_path": str(current.path)},
        )
    current_policy = parse_collector_deployment_policy(
        current.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
        stage=stage,
    )
    candidate_policy = parse_collector_deployment_policy(
        candidate.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
        stage=stage,
    )
    if candidate_policy.allowed_uids != current_policy.allowed_uids:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector policy update cannot change the authorized user UID",
            recoverable=True,
            details={
                "deployed_allowed_uids": current_policy.allowed_uids,
                "candidate_allowed_uids": candidate_policy.allowed_uids,
            },
            suggested_actions=(
                "Use an explicit administrator identity-migration procedure instead.",
            ),
        )
    if candidate_policy.privilege_mode != current_policy.privilege_mode:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector policy update cannot change the deployed privilege mode",
            recoverable=True,
            details={
                "deployed_privilege_mode": current_policy.privilege_mode,
                "candidate_privilege_mode": candidate_policy.privilege_mode,
            },
            suggested_actions=(
                "Use an explicit administrator undeploy and reviewed redeployment instead.",
            ),
        )
    _verify_managed_service(
        effective_layout.service_path,
        require_root_owner=require_root,
        stage=stage,
    )
    previous_raw = current.raw_text.encode("utf-8")
    candidate_raw = candidate.raw_text.encode("utf-8")
    change_required = previous_raw != candidate_raw
    commands = (("/usr/bin/systemctl", "restart", "perflens-collector.service"),)
    warnings = (
        "Authorized UID, fixed spool, service unit, and retained artifacts are preserved.",
        "Host perf/kernel policy is not changed.",
    )
    next_steps = (
        "Run perflens-admin spool-status after changing storage quotas.",
        "Run perflens accept-collector --authorize-host-acceptance as an ordinary user.",
    )
    if dry_run:
        return _policy_update_result(
            "dry_run",
            candidate,
            current.path,
            previous_raw,
            candidate_raw,
            candidate_policy,
            change_required=change_required,
            policy_updated=False,
            service_restarted=False,
            commands=commands if change_required else (),
            warnings=warnings,
            next_steps=next_steps,
        )
    if not change_required:
        return _policy_update_result(
            "unchanged",
            candidate,
            current.path,
            previous_raw,
            candidate_raw,
            candidate_policy,
            change_required=False,
            policy_updated=False,
            service_restarted=False,
            commands=(),
            warnings=warnings,
            next_steps=next_steps,
        )
    if require_root and os.geteuid() != 0:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector policy update must be started explicitly by an administrator",
            recoverable=True,
            suggested_actions=(
                "Run sudo perflens-admin update-policy --config <reviewed-candidate>.",
            ),
        )

    executor = command_executor or _run_admin_policy_update_command
    expected_service_uid: int | None = None
    if socket_waiter is None:
        try:
            expected_service_uid = pwd.getpwnam("perflens").pw_uid
        except KeyError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                stage,
                "Dedicated perflens service account does not exist",
                suggested_actions=("Deploy the Collector before updating its policy.",),
            ) from exc

    replacement_attempted = False
    try:
        replacement_attempted = True
        _replace_verified_config(
            current.path,
            current,
            candidate_raw,
            stage=stage,
        )
        executor(commands[0])
        if socket_waiter is not None:
            socket_waiter(effective_layout.socket_path)
        else:
            _wait_for_policy_update_socket(
                effective_layout.socket_path,
                expected_service_uid=expected_service_uid,
            )
    except BaseException as exc:
        rollback_errors: list[str] = []
        if replacement_attempted:
            try:
                deployed_candidate = load_collector_config(current.path, stage=stage)
                deployed_raw = deployed_candidate.raw_text.encode("utf-8")
                if deployed_raw != previous_raw:
                    if deployed_raw != candidate_raw:
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            stage,
                            "Collector policy changed before update rollback",
                        )
                    _replace_verified_config(
                        current.path,
                        deployed_candidate,
                        previous_raw,
                        stage=stage,
                        mode=stat.S_IMODE(current.metadata.st_mode),
                    )
                    executor(commands[0])
                    if socket_waiter is not None:
                        socket_waiter(effective_layout.socket_path)
                    else:
                        _wait_for_policy_update_socket(
                            effective_layout.socket_path,
                            expected_service_uid=expected_service_uid,
                        )
            except BaseException as rollback_exc:
                rollback_errors.append(type(rollback_exc).__name__)
        if rollback_errors:
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                stage,
                "Collector policy update failed and the previous policy could not be "
                "fully restored",
                recoverable=True,
                details={"rollback_errors": rollback_errors},
                suggested_actions=(
                    "Inspect the policy, systemctl status, and journal before retrying.",
                ),
            ) from exc
        raise

    return _policy_update_result(
        "updated",
        candidate,
        current.path,
        previous_raw,
        candidate_raw,
        candidate_policy,
        change_required=True,
        policy_updated=True,
        service_restarted=True,
        commands=commands,
        warnings=warnings,
        next_steps=next_steps,
    )


def undeploy_collector(
    *,
    dry_run: bool = False,
    layout: CollectorSystemLayout | None = None,
    require_root: bool = True,
    command_executor: CommandExecutor | None = None,
) -> CollectorUndeploymentArtifact:
    """Stop and remove only a verified PerfLens-managed service unit.

    Administrator policy and collected artifacts are intentionally preserved.
    """
    effective_layout = layout or CollectorSystemLayout()
    service = effective_layout.service_path
    helper_service = effective_layout.helper_service_path
    helper_present = helper_service.exists() or helper_service.is_symlink()
    commands: list[tuple[str, ...]] = [
        ("/usr/bin/systemctl", "disable", "--now", "perflens-collector.service")
    ]
    if helper_present:
        commands.append(
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "perflens-privileged-helper.service",
            )
        )
    commands.append(("/usr/bin/systemctl", "daemon-reload"))
    planned_commands = tuple(commands)
    warnings = (
        "Collector policy and collected artifacts are preserved.",
        "The perflens system user and group are preserved for artifact ownership.",
    )
    next_steps = (
        f"Review and remove {effective_layout.config_path} only if its policy is no longer needed.",
        f"Review {effective_layout.state_directory} before deleting any performance artifacts.",
    )
    if not service.exists() and not service.is_symlink() and not helper_present:
        return _undeployment_result("already_absent", effective_layout, (), warnings, next_steps)
    service_present = service.exists() or service.is_symlink()
    if service_present:
        _verify_managed_service(service, require_root_owner=require_root)
    if helper_present:
        _verify_managed_service(helper_service, require_root_owner=require_root)
    if dry_run:
        return _undeployment_result(
            "dry_run", effective_layout, planned_commands, warnings, next_steps
        )
    if require_root and os.geteuid() != 0:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_undeploy",
            "Collector removal must be started explicitly by an administrator",
            recoverable=True,
            suggested_actions=("Run sudo perflens-admin undeploy.",),
        )
    executor = command_executor or _run_admin_undeploy_command
    executor(planned_commands[0])
    if helper_present:
        executor(planned_commands[1])
    if service_present:
        _unlink_verified_managed_service(service, require_root_owner=require_root)
    if helper_present:
        _unlink_verified_managed_service(helper_service, require_root_owner=require_root)
    executor(planned_commands[-1])
    return _undeployment_result("removed", effective_layout, planned_commands, warnings, next_steps)


def inspect_collector_spool(
    config_path: Path = Path("/etc/perflens/collector.toml"),
    *,
    layout: CollectorSystemLayout | None = None,
    require_root_owned_tools: bool = True,
) -> CollectorSpoolStatusArtifact:
    """Inspect fixed Collector spool capacity without changing host state."""
    effective_layout = layout or CollectorSystemLayout()
    source = load_collector_config(config_path, stage="collector_spool_status")
    policy = parse_collector_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root_owned_tools,
        stage="collector_spool_status",
    )
    if policy.privilege_mode == "paranoid3_helper":
        policy = replace(policy, spool_root=effective_layout.helper_state_directory)
    return _inspect_spool(source.path, policy)


def load_collector_config(
    path: Path,
    *,
    stage: str = "collector_deploy",
) -> CollectorConfigSource:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
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
            stage,
            "Collector deployment config cannot be resolved",
            details={"path": str(path)},
        ) from exc
    candidate_owner_uid = invoking_uid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, candidate_owner_uid}
        or metadata.st_mode & 0o022
        or metadata.st_size > _MAX_CONFIG_BYTES
    ):
        os.close(descriptor)
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
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
            stage,
            "Collector deployment config cannot be read as bounded UTF-8",
            details={"path": str(resolved)},
        ) from exc
    if len(raw) > _MAX_CONFIG_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            stage,
            "Collector deployment config exceeds its size limit",
        )
    return CollectorConfigSource(path=resolved, raw_text=text, metadata=metadata)


def parse_collector_deployment_policy(
    text: str,
    *,
    expected_spool: Path,
    require_root_owned_tools: bool,
    stage: str = "collector_deploy",
) -> CollectorDeploymentPolicy:
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector deployment config is not valid bounded UTF-8 TOML",
        ) from exc
    if set(payload) != {"collector"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector deployment config must contain only one [collector] table",
        )
    section = payload["collector"]
    if not isinstance(section, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector deployment config requires a [collector] table",
        )
    values = cast(dict[str, Any], section)
    allowed_keys = {
        "policy_version",
        "spool_root",
        "perf_path",
        "allowed_uids",
        "privilege_mode",
        "allowed_modes",
        "allow_other_target_uids",
        "max_duration_seconds",
        "max_frequency_hz",
        "max_output_bytes",
        "max_spool_bytes",
        "max_spool_artifacts",
        "min_free_bytes",
        "max_plan_ttl_seconds",
        "allowed_stat_events",
        "socket_mode",
        "artifact_mode",
    }
    if set(values) - allowed_keys:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector deployment config contains unsupported fields",
            details={"fields": sorted(set(values) - allowed_keys)},
        )
    try:
        policy_version = values.get("policy_version", COLLECTOR_POLICY_VERSION)
        if isinstance(policy_version, bool) or not isinstance(policy_version, int):
            raise TypeError("policy_version must be an integer")
        spool = Path(_strict_string(values["spool_root"])).expanduser().resolve(strict=False)
        privilege_mode = _strict_string(values.get("privilege_mode", "cap_perfmon"))
        perf_candidate = Path(_strict_string(values["perf_path"])).expanduser()
        perf = perf_candidate.resolve(strict=True)
        uids = tuple(sorted(set(_strict_integer(value) for value in values["allowed_uids"])))
        modes = tuple(dict.fromkeys(_strict_string(value) for value in values["allowed_modes"]))
        duration = _strict_number(values.get("max_duration_seconds", 30.0))
        frequency = _strict_integer(values.get("max_frequency_hz", 99))
        output_bytes = _strict_integer(values.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES))
        spool_bytes = _strict_integer(values.get("max_spool_bytes", DEFAULT_MAX_SPOOL_BYTES))
        spool_artifacts = _strict_integer(
            values.get("max_spool_artifacts", DEFAULT_MAX_SPOOL_ARTIFACTS)
        )
        min_free_bytes = _strict_integer(values.get("min_free_bytes", DEFAULT_MIN_FREE_BYTES))
        plan_ttl = _strict_integer(values.get("max_plan_ttl_seconds", DEFAULT_MAX_PLAN_TTL_SECONDS))
        events = tuple(_strict_string(value) for value in values.get("allowed_stat_events", ()))
        socket_mode_raw = values.get("socket_mode", "0660")
        artifact_mode_raw = values.get("artifact_mode", "0640")
        socket_mode = _strict_mode(socket_mode_raw)
        artifact_mode = _strict_mode(artifact_mode_raw)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector deployment config has missing or invalid values",
        ) from exc
    perf_metadata = perf.stat()
    allow_other = values.get("allow_other_target_uids", False)
    if (
        policy_version != COLLECTOR_POLICY_VERSION
        or privilege_mode not in {"cap_perfmon", "paranoid3_helper"}
        or spool != expected_spool.resolve(strict=False)
        or not perf.is_file()
        or not os.access(perf, os.X_OK)
        or perf_candidate.name != "perf"
        or perf_metadata.st_uid not in ({0} if require_root_owned_tools else {os.geteuid()})
        or perf_metadata.st_mode & 0o022
        or len(uids) != 1
        or any(uid <= 0 for uid in uids)
        or not modes
        or any(mode not in _SUPPORTED_MODES for mode in modes)
        or allow_other is not False
        or not math.isfinite(duration)
        or not 0 < duration <= 86_400
        or not 1 <= frequency <= 10_000
        or output_bytes < 1
        or not output_bytes <= spool_bytes <= 1 << 50
        or not 1 <= spool_artifacts <= 1_000_000
        or not 0 <= min_free_bytes <= 1 << 50
        or not 1 <= plan_ttl <= 3600
        or (events and (len(events) > 64 or any(not event or "\0" in event for event in events)))
        or socket_mode < 0
        or socket_mode > 0o660
        or socket_mode & 0o007
        or socket_mode & 0o600 != 0o600
        or artifact_mode not in {0o440, 0o640}
        or (
            privilege_mode == "paranoid3_helper"
            and (
                set(modes) - PARANOID3_HELPER_MODES
                or duration > PARANOID3_HELPER_MAX_DURATION_SECONDS
                or frequency > PARANOID3_HELPER_MAX_FREQUENCY_HZ
                or output_bytes > PARANOID3_HELPER_MAX_OUTPUT_BYTES
                or plan_ttl > DEFAULT_MAX_PLAN_TTL_SECONDS
                or spool_bytes != DEFAULT_MAX_SPOOL_BYTES
                or spool_artifacts != DEFAULT_MAX_SPOOL_ARTIFACTS
                or min_free_bytes != DEFAULT_MIN_FREE_BYTES
                or any(event not in DEFAULT_STAT_EVENTS for event in events)
            )
        )
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector deployment config violates fixed paths or bounded policy",
        )
    return CollectorDeploymentPolicy(
        raw_text=text,
        spool_root=spool,
        perf_path=perf,
        allowed_uids=uids,
        privilege_mode=cast(
            Literal["cap_perfmon", "paranoid3_helper"],
            privilege_mode,
        ),
        allowed_modes=modes,
        max_output_bytes=output_bytes,
        max_spool_bytes=spool_bytes,
        max_spool_artifacts=spool_artifacts,
        min_free_bytes=min_free_bytes,
    )


def _inspect_spool(
    config_path: Path,
    policy: CollectorDeploymentPolicy,
) -> CollectorSpoolStatusArtifact:
    artifact_count = 0
    logical_bytes = 0
    free_bytes: int | None = None
    scan_complete = False
    issues: list[str] = []
    descriptor = -1
    status: Literal["ready", "warning", "exhausted", "unsafe", "unavailable"] = "unavailable"
    try:
        descriptor = os.open(
            policy.spool_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
    except OSError:
        return _spool_status_result(
            config_path,
            policy,
            status="unavailable",
            scan_complete=False,
            artifact_count=0,
            logical_bytes=0,
            free_bytes=None,
            issues=("spool_unavailable",),
        )

    try:
        spool_metadata = os.fstat(descriptor)
        with os.scandir(descriptor) as entries:
            for entry in entries:
                try:
                    metadata = entry.stat(follow_symlinks=False)
                    if replay_marker(entry.name):
                        if not safe_replay_marker_metadata(
                            metadata,
                            expected_uid=spool_metadata.st_uid,
                            expected_gid=spool_metadata.st_gid,
                        ):
                            issues.append("unsafe_replay_marker")
                            status = "unsafe"
                            break
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        issues.append("unexpected_non_regular_entry")
                        status = "unsafe"
                        break
                    if not collection_artifact_name(entry.name):
                        issues.append("unmanaged_spool_entry")
                        status = "unsafe"
                        break
                    size = metadata.st_size
                except OSError:
                    issues.append("spool_entry_changed_during_scan")
                    status = "unsafe"
                    break
                artifact_count += 1
                logical_bytes += size
                if artifact_count >= policy.max_spool_artifacts:
                    issues.append("artifact_count_quota_exhausted")
                    status = "exhausted"
                    break
                if logical_bytes >= policy.max_spool_bytes:
                    issues.append("spool_byte_quota_exhausted")
                    status = "exhausted"
                    break
            else:
                scan_complete = True
                status = "ready"
        filesystem = os.fstatvfs(descriptor)
        block_size = filesystem.f_frsize or filesystem.f_bsize
        free_bytes = filesystem.f_bavail * block_size
    except OSError:
        issues.append("spool_capacity_inspection_failed")
        if status not in {"unsafe", "exhausted"}:
            status = "unavailable"
    finally:
        os.close(descriptor)

    if status == "ready" and free_bytes is not None:
        remaining_bytes = max(0, policy.max_spool_bytes - logical_bytes)
        free_above_reserve = max(0, free_bytes - policy.min_free_bytes)
        collectable_bytes = min(
            policy.max_output_bytes,
            remaining_bytes,
            free_above_reserve,
        )
        if collectable_bytes == 0:
            status = "exhausted"
            if free_bytes <= policy.min_free_bytes:
                issues.append("filesystem_free_space_reserve_exhausted")
        elif (
            collectable_bytes < policy.max_output_bytes
            or logical_bytes * 5 >= policy.max_spool_bytes * 4
            or artifact_count * 5 >= policy.max_spool_artifacts * 4
        ):
            status = "warning"
            if collectable_bytes < policy.max_output_bytes:
                issues.append("full_size_collection_cannot_be_reserved")
            if logical_bytes * 5 >= policy.max_spool_bytes * 4:
                issues.append("spool_byte_quota_above_80_percent")
            if artifact_count * 5 >= policy.max_spool_artifacts * 4:
                issues.append("artifact_count_quota_above_80_percent")

    return _spool_status_result(
        config_path,
        policy,
        status=status,
        scan_complete=scan_complete,
        artifact_count=artifact_count,
        logical_bytes=logical_bytes,
        free_bytes=free_bytes,
        issues=tuple(dict.fromkeys(issues)),
    )


def _spool_status_result(
    config_path: Path,
    policy: CollectorDeploymentPolicy,
    *,
    status: Literal["ready", "warning", "exhausted", "unsafe", "unavailable"],
    scan_complete: bool,
    artifact_count: int,
    logical_bytes: int,
    free_bytes: int | None,
    issues: tuple[str, ...],
) -> CollectorSpoolStatusArtifact:
    byte_quota_exhausted = "spool_byte_quota_exhausted" in issues
    count_quota_exhausted = "artifact_count_quota_exhausted" in issues
    remaining_bytes = (
        max(0, policy.max_spool_bytes - logical_bytes)
        if scan_complete or byte_quota_exhausted
        else None
    )
    remaining_slots = (
        max(0, policy.max_spool_artifacts - artifact_count)
        if scan_complete or count_quota_exhausted
        else None
    )
    free_above_reserve = None if free_bytes is None else max(0, free_bytes - policy.min_free_bytes)
    collectable_bytes: int | None = None
    if (
        scan_complete
        and free_above_reserve is not None
        and remaining_bytes is not None
        and status not in {"unsafe", "unavailable"}
    ):
        collectable_bytes = min(
            policy.max_output_bytes,
            remaining_bytes,
            free_above_reserve,
        )
    if remaining_slots == 0 or remaining_bytes == 0:
        collectable_bytes = 0
    checked_at = datetime.now(tz=UTC).isoformat()
    identity = "\0".join(
        (
            checked_at,
            str(config_path),
            str(policy.spool_root),
            status,
            str(scan_complete),
            str(artifact_count),
            str(logical_bytes),
            str(free_bytes),
        )
    )
    next_steps = {
        "ready": ("Continue monitoring spool capacity before long collection sessions.",),
        "warning": ("Review and archive old evidence before the remaining capacity is exhausted.",),
        "exhausted": (
            "Review and archive old evidence, then explicitly remove only files no longer needed.",
        ),
        "unsafe": (
            "Stop the Collector and inspect unexpected spool entries without following links.",
        ),
        "unavailable": (
            "Verify the deployed policy, spool path, permissions, and filesystem availability.",
        ),
    }[status]
    if policy.privilege_mode == "paranoid3_helper" and status in {"warning", "exhausted"}:
        next_steps = (
            "Preserve the Rust Helper private spool and stop new collection if capacity is low.",
            "The v0.2.0 archive/prune workflow does not support this private spool.",
        )
    return CollectorSpoolStatusArtifact(
        perflens_version=__version__,
        status_id=f"spool-status-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        checked_at=checked_at,
        status=status,
        config_path=str(config_path),
        spool_root=str(policy.spool_root),
        scan_complete=scan_complete,
        observed_artifact_count=artifact_count,
        observed_logical_bytes=logical_bytes,
        filesystem_free_bytes=free_bytes,
        max_output_bytes=policy.max_output_bytes,
        max_spool_bytes=policy.max_spool_bytes,
        max_spool_artifacts=policy.max_spool_artifacts,
        min_free_bytes=policy.min_free_bytes,
        remaining_spool_bytes=remaining_bytes,
        remaining_artifact_slots=remaining_slots,
        free_bytes_above_reserve=free_above_reserve,
        max_collectable_output_bytes=collectable_bytes,
        issues=issues,
        next_steps=next_steps,
    )


def _strict_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("expected an integer, not a boolean")
    return value


def _strict_number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("expected a number, not a boolean")
    return float(value)


def _strict_string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("expected a string")
    return value


def _strict_mode(value: object) -> int:
    if isinstance(value, str):
        return int(value, 8)
    return _strict_integer(value)


def _collector_command(
    explicit: Path | None,
    *,
    require_root_owner: bool,
    stage: str = "collector_deploy",
) -> Path:
    candidate = explicit or Path(sys.executable).resolve().parent / "perflens-collector"
    lexical = Path(os.path.abspath(candidate.expanduser()))
    try:
        entry_metadata = lexical.lstat()
        resolved = lexical.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Trusted perflens-collector executable cannot be resolved",
            details={"path": str(lexical)},
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
            stage,
            "perflens-collector must be a trusted-owner executable not writable by group or other",
            details={"path": str(resolved)},
        )
    if stat.S_ISLNK(entry_metadata.st_mode):
        parent = lexical.parent
        try:
            resolved_parent = parent.resolve(strict=True)
            parent_metadata = parent.stat()
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "perflens-collector entry-point parent cannot be verified safely",
                details={"path": str(parent)},
            ) from exc
        if (
            entry_metadata.st_uid not in expected_owners
            or resolved_parent != parent
            or parent_metadata.st_uid not in expected_owners
            or parent_metadata.st_mode & 0o022
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "perflens-collector symbolic entry point is not in a trusted directory",
                details={"path": str(lexical), "parent": str(parent)},
            )
        return lexical
    return resolved


def _planned_commands(
    allowed_uids: tuple[int, ...],
    privilege_mode: Literal["cap_perfmon", "paranoid3_helper"],
) -> tuple[tuple[str, ...], ...]:
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
    commands.append(("/usr/bin/systemctl", "daemon-reload"))
    if privilege_mode == "paranoid3_helper":
        commands.append(
            (
                "/usr/bin/systemctl",
                "enable",
                "--now",
                "perflens-privileged-helper.service",
            )
        )
    commands.append(("/usr/bin/systemctl", "enable", "--now", "perflens-collector.service"))
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
                suggested_actions=(
                    "Review the difference; use perflens-admin upgrade only for a managed "
                    "service update, and edit policy separately.",
                ),
            )
        os.chmod(destination, mode)
        return False
    write_text_atomic(text, destination, max_output_bytes=_MAX_CONFIG_BYTES)
    os.chmod(destination, mode)
    return True


def _verify_managed_service(
    path: Path,
    *,
    require_root_owner: bool,
    stage: str = "collector_undeploy",
) -> _ManagedServiceSnapshot:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector service unit must not be a symbolic link",
            details={"path": str(candidate)},
        )
    descriptor = -1
    try:
        descriptor = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        raw = os.read(descriptor, _MAX_SERVICE_BYTES + 1)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector service unit cannot be inspected safely",
            details={"path": str(candidate)},
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    expected_owners = {0} if require_root_owner else {os.geteuid()}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in expected_owners
        or metadata.st_mode & 0o022
        or len(raw) > _MAX_SERVICE_BYTES
        or not raw.startswith(_MANAGED_SERVICE_MARKER.encode())
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Service unit is not a bounded, trusted PerfLens-managed file",
            details={"path": str(candidate)},
        )
    return _ManagedServiceSnapshot(metadata=metadata, raw=raw)


def _unlink_verified_managed_service(path: Path, *, require_root_owner: bool) -> None:
    inspected = _verify_managed_service(path, require_root_owner=require_root_owner)
    try:
        current = path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            inspected.metadata.st_dev,
            inspected.metadata.st_ino,
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_undeploy",
                "Collector service unit changed during removal",
                details={"path": str(path)},
            )
        path.unlink()
    except PerfLensError:
        raise
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "collector_undeploy",
            "Unable to remove the verified Collector service unit",
            details={"path": str(path)},
        ) from exc


def _replace_verified_managed_service(
    path: Path,
    inspected: _ManagedServiceSnapshot,
    replacement: bytes,
    *,
    stage: str,
    mode: int = 0o644,
) -> None:
    try:
        current = path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            inspected.metadata.st_dev,
            inspected.metadata.st_ino,
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "Collector service unit changed during upgrade",
                details={"path": str(path)},
            )
        text = replacement.decode("utf-8")
        write_text_atomic(text, path, max_output_bytes=_MAX_SERVICE_BYTES)
        os.chmod(path, mode)
    except PerfLensError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to replace the verified Collector service unit",
            details={"path": str(path)},
        ) from exc


def _replace_verified_config(
    path: Path,
    inspected: CollectorConfigSource,
    replacement: bytes,
    *,
    stage: str,
    mode: int = 0o644,
) -> None:
    try:
        current = path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            inspected.metadata.st_dev,
            inspected.metadata.st_ino,
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "Collector policy changed during update",
                details={"path": str(path)},
            )
        text = replacement.decode("utf-8")
        write_text_atomic(text, path, max_output_bytes=_MAX_CONFIG_BYTES)
        os.chmod(path, mode)
    except PerfLensError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to replace the verified Collector policy",
            details={"path": str(path)},
        ) from exc


def _run_admin_command(
    command: tuple[str, ...],
    *,
    stage: Literal[
        "collector_deploy",
        "collector_undeploy",
        "collector_upgrade",
        "collector_policy_update",
    ] = "collector_deploy",
) -> None:
    executable = Path(command[0])
    allowed = {"/usr/bin/systemd-sysusers", "/usr/sbin/usermod", "/usr/bin/systemctl"}
    if command[0] not in allowed:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
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
            stage,
            "Unable to run a fixed administrative deployment command",
            details={"executable": str(executable)},
        ) from exc
    if completed.returncode != 0:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            stage,
            "Administrative deployment command failed",
            recoverable=True,
            details={
                "executable": str(executable),
                "exit_code": completed.returncode,
                "stderr": completed.stderr[-4096:],
            },
        )


def _run_admin_undeploy_command(command: tuple[str, ...]) -> None:
    _run_admin_command(command, stage="collector_undeploy")


def _run_admin_upgrade_command(command: tuple[str, ...]) -> None:
    _run_admin_command(command, stage="collector_upgrade")


def _run_admin_policy_update_command(command: tuple[str, ...]) -> None:
    _run_admin_command(command, stage="collector_policy_update")


def _wait_for_socket(path: Path, *, expected_service_uid: int | None = None) -> None:
    deadline = time.monotonic() + 5.0
    last_error = "Collector socket has not appeared"
    while time.monotonic() < deadline:
        try:
            health = CollectorBrokerClient(path, timeout_seconds=0.5).health(
                expected_service_uid=expected_service_uid
            )
            if health.status == "ready":
                return
        except (PerfLensError, ValueError) as exc:
            last_error = str(exc)[:512]
        time.sleep(0.05)
    raise PerfLensError(
        ErrorCode.EXTERNAL_TOOL_FAILED,
        "collector_deploy",
        "Collector service did not pass its authenticated Unix-socket health check",
        recoverable=True,
        details={"socket": str(path), "last_error": last_error},
        suggested_actions=(
            "Inspect systemctl status and journalctl for perflens-collector.service.",
        ),
    )


def _wait_for_upgrade_socket(
    path: Path,
    *,
    expected_service_uid: int | None = None,
) -> None:
    try:
        _wait_for_socket(path, expected_service_uid=expected_service_uid)
    except PerfLensError as exc:
        raise PerfLensError(
            exc.code,
            "collector_upgrade",
            exc.message,
            recoverable=exc.recoverable,
            details=exc.details,
            suggested_actions=exc.suggested_actions,
        ) from exc


def _wait_for_policy_update_socket(
    path: Path,
    *,
    expected_service_uid: int | None = None,
) -> None:
    try:
        _wait_for_socket(path, expected_service_uid=expected_service_uid)
    except PerfLensError as exc:
        raise PerfLensError(
            exc.code,
            "collector_policy_update",
            exc.message,
            recoverable=exc.recoverable,
            details=exc.details,
            suggested_actions=exc.suggested_actions,
        ) from exc


def invoking_uid() -> int:
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
    privilege_mode: Literal["cap_perfmon", "paranoid3_helper"],
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
        privilege_mode=privilege_mode,
        planned_commands=commands,
        warnings=warnings,
        next_steps=next_steps,
    )


def _upgrade_result(
    status: Literal["dry_run", "restarted", "upgraded"],
    config_path: Path,
    layout: CollectorSystemLayout,
    command: Path,
    previous: bytes,
    candidate: bytes,
    *,
    update_required: bool,
    service_updated: bool,
    commands: tuple[tuple[str, ...], ...],
    warnings: tuple[str, ...],
    next_steps: tuple[str, ...],
) -> CollectorUpgradeArtifact:
    return CollectorUpgradeArtifact(
        perflens_version=__version__,
        status=status,
        config_path=str(config_path),
        service_path=str(layout.service_path),
        collector_command=str(command),
        previous_service_sha256=hashlib.sha256(previous).hexdigest(),
        candidate_service_sha256=hashlib.sha256(candidate).hexdigest(),
        service_update_required=update_required,
        service_updated=service_updated,
        planned_commands=commands,
        warnings=warnings,
        next_steps=next_steps,
    )


def _undeployment_result(
    status: Literal["dry_run", "removed", "already_absent"],
    layout: CollectorSystemLayout,
    commands: tuple[tuple[str, ...], ...],
    warnings: tuple[str, ...],
    next_steps: tuple[str, ...],
) -> CollectorUndeploymentArtifact:
    return CollectorUndeploymentArtifact(
        perflens_version=__version__,
        status=status,
        service_path=str(layout.service_path),
        config_path=str(layout.config_path),
        state_directory=str(layout.state_directory),
        planned_commands=commands,
        warnings=warnings,
        next_steps=next_steps,
    )


def _policy_update_result(
    status: Literal["dry_run", "unchanged", "updated"],
    candidate: CollectorConfigSource,
    config_path: Path,
    previous: bytes,
    candidate_raw: bytes,
    policy: CollectorDeploymentPolicy,
    *,
    change_required: bool,
    policy_updated: bool,
    service_restarted: bool,
    commands: tuple[tuple[str, ...], ...],
    warnings: tuple[str, ...],
    next_steps: tuple[str, ...],
) -> CollectorPolicyUpdateArtifact:
    return CollectorPolicyUpdateArtifact(
        perflens_version=__version__,
        status=status,
        candidate_source=str(candidate.path),
        config_path=str(config_path),
        previous_policy_sha256=hashlib.sha256(previous).hexdigest(),
        candidate_policy_sha256=hashlib.sha256(candidate_raw).hexdigest(),
        policy_change_required=change_required,
        policy_updated=policy_updated,
        service_restarted=service_restarted,
        allowed_uid=policy.allowed_uids[0],
        allowed_modes=policy.allowed_modes,
        planned_commands=commands,
        warnings=warnings,
        next_steps=next_steps,
    )
