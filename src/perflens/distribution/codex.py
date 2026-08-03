"""Render a project-scoped Codex MCP configuration without mutating user config."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError


def render_codex_config(
    workspace: Path,
    *,
    artifact_root: Path | None = None,
    allow_process_execution: bool = False,
    automatic_collection: bool = False,
    allow_project_execution: bool = False,
    collector_socket: Path = Path("/run/perflens/collector.sock"),
    collector_spool_root: Path = Path("/var/lib/perflens"),
    automatic_modes: tuple[str, ...] = ("stat", "record"),
    automatic_max_duration_seconds: float = 30.0,
    mcp_command: Path | None = None,
) -> str:
    """Return a project-scoped TOML snippet for the installed MCP executable."""
    safe_workspace = _existing_directory(workspace, label="Workspace")
    safe_artifact_root = _artifact_directory(safe_workspace, artifact_root)
    safe_command = _mcp_executable(mcp_command)
    if allow_project_execution and not automatic_collection:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "Project execution requires automatic collection",
        )
    arguments = [
        "--allowed-root",
        str(safe_workspace),
        "--artifact-root",
        str(safe_artifact_root),
        "--allow-writes",
    ]
    if allow_process_execution or automatic_collection:
        arguments.append("--allow-process-execution")
    if automatic_collection:
        safe_socket = _absolute_deployment_path(collector_socket, label="Collector socket")
        safe_spool = _absolute_deployment_path(
            collector_spool_root,
            label="Collector spool root",
        )
        modes = _automatic_modes(automatic_modes)
        if not 0 < automatic_max_duration_seconds <= 86_400:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "codex_config",
                "Automatic collection duration limit must be positive and at most one day",
            )
        arguments[2:2] = ["--allowed-root", str(safe_spool)]
        arguments.extend(
            [
                "--allow-active-collection",
                "--allow-pid-attach",
                "--allow-automatic-collection",
                "--collector-socket",
                str(safe_socket),
                "--automatic-max-duration-seconds",
                str(automatic_max_duration_seconds),
            ]
        )
        for mode in modes:
            arguments.extend(("--automatic-mode", mode))
        if allow_project_execution:
            arguments.append("--allow-project-execution")
    formatted_arguments = ",\n".join(f"  {_toml_string(value)}" for value in arguments)
    return (
        "[mcp_servers.perflens]\n"
        f"command = {_toml_string(str(safe_command))}\n"
        "args = [\n"
        f"{formatted_arguments},\n"
        "]\n"
        "required = true\n"
        'default_tools_approval_mode = "writes"\n'
        "tool_timeout_sec = 300\n"
    )


def _existing_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            f"{label} does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            f"{label} must be a directory",
            details={"path": str(resolved)},
        )
    return resolved


def _artifact_directory(workspace: Path, artifact_root: Path | None) -> Path:
    candidate = artifact_root if artifact_root is not None else workspace / "perflens-results"
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        resolved = candidate.expanduser().resolve(strict=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "codex_config",
            "Artifact root cannot be resolved safely",
            details={"path": str(candidate)},
        ) from exc
    if not resolved.is_relative_to(workspace):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "codex_config",
            "Artifact root must be inside the selected workspace",
            details={"path": str(resolved), "workspace": str(workspace)},
        )
    if resolved.exists() and not resolved.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "Artifact root must be a directory",
            details={"path": str(resolved)},
        )
    return resolved


def _mcp_executable(explicit: Path | None) -> Path:
    candidate: Path | None = explicit
    if candidate is None:
        found = shutil.which("perflens-mcp")
        candidate = Path(found) if found is not None else None
    if candidate is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "Unable to locate the perflens-mcp executable",
            suggested_actions=(
                "Install PerfLens with pipx or uv tool, or pass --mcp-command explicitly.",
            ),
        )
    try:
        resolved = candidate.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "MCP executable does not exist or cannot be resolved",
            details={"path": str(candidate)},
        ) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "MCP command must be an executable file",
            details={"path": str(resolved)},
        )
    return resolved


def _absolute_deployment_path(path: Path, *, label: str) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "codex_config",
            f"{label} path must be absolute",
            details={"path": str(path)},
        )
    try:
        return candidate.resolve(strict=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "codex_config",
            f"{label} path cannot be resolved safely",
            details={"path": str(path)},
        ) from exc


def _automatic_modes(modes: tuple[str, ...]) -> tuple[str, ...]:
    supported = {"record", "stat", "sched", "lock", "off_cpu"}
    unique = tuple(dict.fromkeys(modes))
    if not unique or any(mode not in supported for mode in unique):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "Automatic collection modes are empty or unsupported",
            details={"modes": list(unique)},
        )
    return unique


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
