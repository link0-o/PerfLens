"""Read-only project and Collector readiness diagnostics."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import stat
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import ValidationError

from perflens import __version__
from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectorHealthArtifact,
    RuntimeStatusArtifact,
    SetupArtifact,
)
from perflens.distribution.codex import validate_mcp_executable
from perflens.distribution.skill import recorded_project_skill_path
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_SETUP_BYTES = 1 << 20
SetupStatus = Literal["missing", "incomplete", "ready"]
SkillStatus = Literal["missing", "incomplete", "ready"]
McpStatus = Literal["missing", "incomplete", "ready"]
AssetsStatus = Literal["not_requested", "missing", "incomplete", "ready"]
SocketStatus = Literal["missing", "invalid", "inaccessible", "ready"]
GroupStatus = Literal["missing", "not_member", "member"]
HealthStatus = Literal["not_checked", "ready", "unreachable", "rejected"]
HostStatus = Literal["available", "conditional", "blocked"]
AutomaticStatus = Literal[
    "not_configured",
    "configuration_incomplete",
    "collector_unavailable",
    "access_denied",
    "ready_for_verification",
]


@dataclass(frozen=True, slots=True)
class _HealthSnapshot:
    status: HealthStatus = "not_checked"
    artifact: CollectorHealthArtifact | None = None
    error_code: str | None = None
    issue: str | None = None


def inspect_runtime_status(
    project_root: Path,
    *,
    setup_directory: Path = Path("perflens-setup"),
    collector_socket: Path = Path("/run/perflens/collector.sock"),
    perf_path: Path | None = None,
) -> RuntimeStatusArtifact:
    """Inspect generated onboarding and local Collector access without sampling."""
    project = _project_directory(project_root)
    setup = _setup_path(project, setup_directory)
    setup_status, automatic_requested, setup_issues, setup_artifact = _inspect_setup(project, setup)
    selected_clients = _selected_clients(setup_artifact) if setup_artifact is not None else ()
    skill_status = _inspect_selected_skills(project, setup_artifact)
    mcp_status = _inspect_selected_project_configs(project, setup, setup_artifact)
    assets_status = _inspect_assets(setup, automatic_requested=automatic_requested)
    socket_status = _inspect_socket(collector_socket)
    group_status = _collector_group_status()
    health = _HealthSnapshot()
    if (
        automatic_requested
        and setup_status == "ready"
        and assets_status in {"ready", "not_requested"}
        and socket_status == "ready"
        and group_status == "member"
    ):
        health = _inspect_collector_health(
            collector_socket,
            expected_service_uid=_collector_service_uid(),
        )
    capabilities = inspect_collection_capabilities(perf_path)
    host_status = _host_collection_status(capabilities)
    requested_feature_profile = (
        setup_artifact.collector_feature_profile
        if setup_artifact is not None
        else "cpu_only"
    )
    feature_profile = (
        health.artifact.feature_profile
        if health.artifact is not None
        else requested_feature_profile
    )
    docker_runtime_enabled = bool(
        setup_artifact is not None and setup_artifact.docker_runtime_enabled
    )
    docker_optimization_enabled = bool(
        setup_artifact is not None and setup_artifact.docker_optimization_enabled
    )
    trace_modes_ready = health.artifact is not None and {
        "sched",
        "off_cpu",
        "lock",
    }.issubset(health.artifact.allowed_modes)
    trace_backend_status: Literal["not_checked", "available", "unavailable"] = (
        ("available" if trace_modes_ready else "unavailable")
        if feature_profile == "full_diagnostics"
        else "not_checked"
    )

    issues = list(setup_issues)
    if skill_status != "ready":
        issues.append(f"skill_{skill_status}")
    if mcp_status != "ready":
        issues.append(f"mcp_project_config_{mcp_status}")
    if automatic_requested and assets_status not in {"ready", "not_requested"}:
        issues.append(f"collector_assets_{assets_status}")
    if automatic_requested and socket_status != "ready":
        issues.append(f"collector_socket_{socket_status}")
    if automatic_requested and group_status != "member":
        issues.append(f"collector_group_{group_status}")
    if health.issue is not None:
        issues.append(health.issue)
    if (
        health.artifact is not None
        and health.artifact.feature_profile != requested_feature_profile
    ):
        issues.append("collector_feature_profile_mismatch")
    if feature_profile == "full_diagnostics" and trace_backend_status != "available":
        issues.append("collector_trace_backend_unavailable")
    if host_status != "available":
        issues.append(f"host_collection_{host_status}")

    automatic_status = _automatic_status(
        requested=automatic_requested,
        setup_status=setup_status,
        mcp_status=mcp_status,
        assets_status=assets_status,
        socket_status=socket_status,
        group_status=group_status,
        health_status=health.status,
    )
    next_steps = _next_steps(
        setup_status=setup_status,
        skill_status=skill_status,
        mcp_status=mcp_status,
        automatic_status=automatic_status,
    )
    checked_at = datetime.now(tz=UTC).isoformat()
    identity = "\0".join(
        (
            str(project),
            str(setup),
            setup_status,
            skill_status,
            mcp_status,
            ",".join(selected_clients),
            str(automatic_requested),
            str(docker_runtime_enabled),
            str(docker_optimization_enabled),
            assets_status,
            socket_status,
            group_status,
            health.status,
            health.error_code or "",
            str(health.artifact.service_pid if health.artifact is not None else ""),
            str(health.artifact.service_uid if health.artifact is not None else ""),
            str(health.artifact.policy_version if health.artifact is not None else ""),
            (",".join(health.artifact.allowed_modes) if health.artifact is not None else ""),
            health.artifact.spool_root if health.artifact is not None else "",
            capabilities.capability_id,
            feature_profile,
            trace_backend_status,
        )
    )
    return RuntimeStatusArtifact(
        perflens_version=__version__,
        status_id=f"status-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        checked_at=checked_at,
        project_root=str(project),
        setup_directory=str(setup),
        selected_clients=selected_clients,
        setup_status=setup_status,
        skill_status=skill_status,
        mcp_config_status=mcp_status,
        automatic_collection_requested=automatic_requested,
        docker_runtime_enabled=docker_runtime_enabled,
        docker_optimization_enabled=docker_optimization_enabled,
        collector_assets_status=assets_status,
        collector_socket=str(collector_socket),
        collector_socket_status=socket_status,
        collector_group_status=group_status,
        collector_health_status=health.status,
        collector_health_error_code=health.error_code,
        collector_service_pid=(
            health.artifact.service_pid if health.artifact is not None else None
        ),
        collector_service_uid=(
            health.artifact.service_uid if health.artifact is not None else None
        ),
        collector_policy_version=(
            health.artifact.policy_version if health.artifact is not None else None
        ),
        collector_allowed_modes=(
            health.artifact.allowed_modes if health.artifact is not None else ()
        ),
        collector_spool_root=(health.artifact.spool_root if health.artifact is not None else None),
        feature_profile=feature_profile,
        trace_backend_status=trace_backend_status,
        capability_id=capabilities.capability_id,
        host_collection_status=host_status,
        automatic_collection_status=automatic_status,
        issues=tuple(dict.fromkeys(issues)),
        next_steps=next_steps,
    )


def _project_directory(path: Path) -> Path:
    try:
        project = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "status",
            "Project directory does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not project.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "status",
            "Project path must be a directory",
            details={"path": str(project)},
        )
    return project


def _setup_path(project: Path, requested: Path) -> Path:
    candidate = requested.expanduser()
    if not candidate.is_absolute():
        candidate = project / candidate
    if candidate.is_symlink():
        lexical = Path(os.path.abspath(candidate))
        if not lexical.is_relative_to(project):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "status",
                "Setup directory symbolic link is outside the selected project",
                details={"path": str(lexical), "project": str(project)},
            )
        return lexical
    try:
        setup = candidate.resolve(strict=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "status",
            "Setup directory cannot be resolved safely",
            details={"path": str(candidate)},
        ) from exc
    if not setup.is_relative_to(project):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "status",
            "Setup directory must remain inside the selected project",
            details={"path": str(setup), "project": str(project)},
        )
    return setup


def _inspect_setup(
    project: Path,
    setup: Path,
) -> tuple[SetupStatus, bool, tuple[str, ...], SetupArtifact | None]:
    if not setup.exists() and not setup.is_symlink():
        return "missing", False, ("setup_missing",), None
    if setup.is_symlink() or not setup.is_dir():
        return "incomplete", False, ("setup_unsafe",), None
    artifact_path = setup / "setup.json"
    if artifact_path.is_symlink() or not artifact_path.is_file():
        return "incomplete", False, ("setup_artifact_missing",), None
    try:
        with artifact_path.open("rb") as handle:
            raw = handle.read(_MAX_SETUP_BYTES + 1)
        if len(raw) > _MAX_SETUP_BYTES:
            raise ValueError("setup artifact exceeds its size limit")
        artifact = SetupArtifact.model_validate_json(raw)
        recorded_project = Path(artifact.project_root).resolve(strict=True)
        recorded_output = Path(artifact.output_directory).resolve(strict=True)
    except (OSError, ValueError, ValidationError):
        return "incomplete", False, ("setup_artifact_invalid",), None
    if recorded_project != project or recorded_output != setup:
        return (
            "incomplete",
            artifact.automatic_collection_enabled,
            ("setup_identity_mismatch",),
            artifact,
        )
    return "ready", artifact.automatic_collection_enabled, (), artifact


def _inspect_selected_skills(
    project: Path,
    artifact: SetupArtifact | None,
) -> SkillStatus:
    clients: list[Literal["codex", "claude-code"]] = []
    selected = set(_selected_clients(artifact)) if artifact is not None else {"codex"}
    if selected & {"codex", "opencode", "copilot"}:
        clients.append("codex")
    if "claude-code" in selected:
        clients.append("claude-code")
    if not clients:
        return "missing"
    statuses = tuple(
        _inspect_skill(
            project,
            client=client,
            recorded_path=(
                None
                if artifact is None
                else (artifact.skill_path if client == "codex" else artifact.claude_skill_path)
            ),
        )
        for client in clients
    )
    if all(status == "ready" for status in statuses):
        return "ready"
    return "incomplete" if "incomplete" in statuses else "missing"


def _inspect_skill(
    project: Path,
    *,
    client: Literal["codex", "claude-code"] = "codex",
    recorded_path: str | None = None,
) -> SkillStatus:
    try:
        root = recorded_project_skill_path(
            project,
            client=client,
            recorded_path=recorded_path,
        )
    except PerfLensError:
        return "incomplete"
    skill = root / "SKILL.md"
    if not root.exists() and not root.is_symlink():
        return "missing"
    if root.is_symlink() or not root.is_dir() or skill.is_symlink() or not skill.is_file():
        return "incomplete"
    return "ready"


def _inspect_selected_project_configs(
    project: Path,
    setup: Path,
    artifact: SetupArtifact | None,
) -> McpStatus:
    statuses: list[McpStatus] = []
    selected = set(_selected_clients(artifact)) if artifact is not None else {"codex"}
    if "codex" in selected:
        statuses.append(_inspect_codex_project_config(project, setup))
    if "claude-code" in selected:
        statuses.append(
            _inspect_json_project_config(
                project / ".mcp.json", setup / "claude-mcp.json", "mcpServers"
            )
        )
    if "opencode" in selected:
        statuses.append(_inspect_opencode_project_config(project, setup, artifact))
    if "copilot" in selected:
        statuses.append(
            _inspect_json_project_config(
                project / ".mcp.json", setup / "copilot-mcp.json", "mcpServers"
            )
        )
        statuses.append(
            _inspect_json_project_config(
                project / ".vscode/mcp.json",
                setup / "copilot-vscode-mcp.json",
                "servers",
            )
        )
    if not statuses:
        return "missing"
    if all(status == "ready" for status in statuses):
        return "ready"
    return "incomplete" if "incomplete" in statuses else "missing"


def _inspect_codex_project_config(project: Path, setup: Path) -> McpStatus:
    parent = project / ".codex"
    path = parent / "config.toml"
    if not path.exists() and not path.is_symlink():
        return "missing"
    if parent.is_symlink() or not parent.is_dir() or path.is_symlink() or not path.is_file():
        return "incomplete"
    project_status, project_table = _read_perflens_mcp_table(path)
    if project_status != "ready" or project_table is None:
        return project_status
    snippet = setup / "codex-mcp.toml"
    if snippet.is_symlink() or not snippet.is_file():
        return "incomplete"
    expected_status, expected_table = _read_perflens_mcp_table(snippet)
    if expected_status != "ready":
        return "incomplete"
    matches = expected_table is not None and project_table == expected_table
    if not matches:
        return "incomplete"
    command = project_table.get("command")
    if not isinstance(command, str) or not Path(command).is_absolute():
        return "incomplete"
    try:
        validated_command = validate_mcp_executable(Path(command))
    except PerfLensError:
        return "incomplete"
    return "ready" if str(validated_command) == command else "incomplete"


def _inspect_json_project_config(path: Path, snippet: Path, server_key: str) -> McpStatus:
    if not path.exists() and not path.is_symlink():
        return "missing"
    if path.is_symlink() or not path.is_file():
        return "incomplete"
    project_status, project_table = _read_json_perflens_table(path, server_key)
    if project_status != "ready" or project_table is None:
        return project_status
    if snippet.is_symlink() or not snippet.is_file():
        return "incomplete"
    expected_status, expected_table = _read_json_perflens_table(snippet, server_key)
    if expected_status != "ready" or expected_table != project_table:
        return "incomplete"
    command = project_table.get("command")
    if not isinstance(command, str) or not Path(command).is_absolute():
        return "incomplete"
    try:
        validated_command = validate_mcp_executable(Path(command))
    except PerfLensError:
        return "incomplete"
    return "ready" if str(validated_command) == command else "incomplete"


def _read_json_perflens_table(
    path: Path,
    server_key: str,
) -> tuple[McpStatus, dict[str, object] | None]:
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SETUP_BYTES:
            return "incomplete", None
        parsed: object = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return "incomplete", None
    if not isinstance(parsed, dict):
        return "incomplete", None
    servers = cast(dict[str, object], parsed).get(server_key)
    if not isinstance(servers, dict):
        return "missing", None
    table = cast(dict[str, object], servers).get("perflens")
    if not isinstance(table, dict):
        return "missing", None
    return "ready", cast(dict[str, object], table)


def _inspect_opencode_project_config(
    project: Path,
    setup: Path,
    artifact: SetupArtifact | None,
) -> McpStatus:
    recorded = artifact.opencode_project_config_path if artifact is not None else None
    path = Path(recorded) if recorded is not None else project / ".opencode/opencode.json"
    if not path.is_relative_to(project):
        return "incomplete"
    if not path.exists() and not path.is_symlink():
        return "missing"
    if path.is_symlink() or not path.is_file():
        return "incomplete"
    actual = _read_opencode_perflens_table(path)
    expected = _read_opencode_perflens_table(setup / "opencode-mcp.json")
    if actual[0] != "ready" or expected[0] != "ready" or actual[1] != expected[1]:
        return "incomplete"
    assert actual[1] is not None
    command = actual[1].get("command")
    if (
        not isinstance(command, list)
        or not command
        or not isinstance(command[0], str)
        or not Path(command[0]).is_absolute()
    ):
        return "incomplete"
    try:
        validated = validate_mcp_executable(Path(command[0]))
    except PerfLensError:
        return "incomplete"
    return "ready" if str(validated) == command[0] else "incomplete"


def _read_opencode_perflens_table(
    path: Path,
) -> tuple[McpStatus, dict[str, object] | None]:
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SETUP_BYTES:
            return "incomplete", None
        parsed: object = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return "incomplete", None
    if not isinstance(parsed, dict):
        return "incomplete", None
    mcp = cast(dict[str, object], parsed).get("mcp")
    if not isinstance(mcp, dict):
        return "missing", None
    servers = cast(dict[str, object], mcp).get("servers")
    if not isinstance(servers, dict):
        return "missing", None
    table = cast(dict[str, object], servers).get("perflens")
    if not isinstance(table, dict):
        return "missing", None
    return "ready", cast(dict[str, object], table)


def _selected_clients(
    artifact: SetupArtifact,
) -> tuple[Literal["codex", "claude-code", "opencode", "copilot"], ...]:
    if artifact.selected_clients:
        return artifact.selected_clients
    selected: list[Literal["codex", "claude-code", "opencode", "copilot"]] = []
    if artifact.codex_project_config_status != "skipped" or artifact.skill_status != "skipped":
        selected.append("codex")
    if (
        artifact.claude_project_config_status != "skipped"
        or artifact.claude_skill_status != "skipped"
    ):
        selected.append("claude-code")
    return tuple(selected)


def _read_perflens_mcp_table(
    path: Path,
) -> tuple[McpStatus, dict[str, object] | None]:
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SETUP_BYTES:
            return "incomplete", None
        payload = cast(dict[str, object], tomllib.loads(raw.decode("utf-8")))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return "incomplete", None
    servers = payload.get("mcp_servers")
    if not isinstance(servers, dict):
        return "missing", None
    table = cast(dict[str, object], servers).get("perflens")
    if not isinstance(table, dict):
        return "missing", None
    return "ready", cast(dict[str, object], table)


def _inspect_assets(setup: Path, *, automatic_requested: bool) -> AssetsStatus:
    root = setup / "collector-assets"
    if not root.exists() and not root.is_symlink():
        return "not_requested"
    required = (
        root / "collector.toml",
        root / "perflens-collector.service",
        root / "perflens.sysusers",
    )
    if (
        root.is_symlink()
        or not root.is_dir()
        or any(path.is_symlink() or not path.is_file() for path in required)
    ):
        return "incomplete"
    return "ready"


def _inspect_socket(path: Path) -> SocketStatus:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        return "invalid"
    try:
        metadata = candidate.stat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "inaccessible"
    if not stat.S_ISSOCK(metadata.st_mode):
        return "invalid"
    return "ready" if os.access(candidate, os.R_OK | os.W_OK) else "inaccessible"


def _collector_group_status() -> GroupStatus:
    try:
        group = grp.getgrnam("perflens")
    except KeyError:
        return "missing"
    return "member" if group.gr_gid in {*os.getgroups(), os.getegid()} else "not_member"


def _collector_service_uid() -> int | None:
    try:
        return pwd.getpwnam("perflens").pw_uid
    except KeyError:
        return None


def _inspect_collector_health(
    path: Path,
    *,
    expected_service_uid: int | None,
) -> _HealthSnapshot:
    if expected_service_uid is None:
        return _HealthSnapshot(
            status="rejected",
            error_code=ErrorCode.PATH_SAFETY_VIOLATION.value,
            issue="collector_service_user_missing",
        )
    try:
        artifact = CollectorBrokerClient(path, timeout_seconds=0.5).health(
            expected_service_uid=expected_service_uid
        )
    except ValueError:
        return _HealthSnapshot(
            status="unreachable",
            error_code=ErrorCode.EXTERNAL_TOOL_FAILED.value,
            issue="collector_health_unreachable",
        )
    except PerfLensError as exc:
        if exc.code in {ErrorCode.EXTERNAL_TOOL_FAILED, ErrorCode.EXTERNAL_TOOL_TIMEOUT}:
            return _HealthSnapshot(
                status="unreachable",
                error_code=exc.code.value,
                issue="collector_health_unreachable",
            )
        return _HealthSnapshot(
            status="rejected",
            error_code=exc.code.value,
            issue="collector_health_rejected",
        )
    return _HealthSnapshot(status="ready", artifact=artifact)


def _host_collection_status(capabilities: CollectionCapabilityArtifact) -> HostStatus:
    statuses = tuple(mode.status for mode in capabilities.modes)
    if statuses and all(status == "available" for status in statuses):
        return "available"
    if statuses and any(status != "blocked" for status in statuses):
        return "conditional"
    return "blocked"


def _automatic_status(
    *,
    requested: bool,
    setup_status: SetupStatus,
    mcp_status: McpStatus,
    assets_status: AssetsStatus,
    socket_status: SocketStatus,
    group_status: GroupStatus,
    health_status: HealthStatus,
) -> AutomaticStatus:
    if not requested:
        return "not_configured"
    if (
        setup_status != "ready"
        or mcp_status != "ready"
        or assets_status not in {"ready", "not_requested"}
    ):
        return "configuration_incomplete"
    if socket_status in {"missing", "invalid"}:
        return "collector_unavailable"
    if socket_status == "inaccessible" or group_status != "member":
        return "access_denied"
    if health_status != "ready":
        return "collector_unavailable"
    return "ready_for_verification"


def _next_steps(
    *,
    setup_status: SetupStatus,
    skill_status: SkillStatus,
    mcp_status: McpStatus,
    automatic_status: AutomaticStatus,
) -> tuple[str, ...]:
    steps: list[str] = []
    if setup_status != "ready":
        steps.append("Run perflens init in the selected project.")
    if skill_status != "ready":
        steps.append("Install or repair the project PerfLens Skill.")
    if mcp_status != "ready":
        steps.append("Generate and merge the selected client MCP configuration.")
    if automatic_status == "configuration_incomplete":
        steps.append("Regenerate setup with --prepare-collector --automatic-collection.")
    elif automatic_status == "collector_unavailable":
        steps.append("Have an administrator deploy the Collector and inspect its service logs.")
    elif automatic_status == "access_denied":
        steps.append("Start a new login session after joining the perflens group.")
    elif automatic_status == "ready_for_verification":
        steps.append("Run perflens accept-collector --authorize-host-acceptance.")
    return tuple(steps)
