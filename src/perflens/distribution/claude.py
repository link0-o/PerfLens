"""Render and safely install a project-scoped Claude Code MCP configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from perflens.artifacts.filesystem import write_text_atomic, write_text_new_atomic
from perflens.distribution.codex import build_mcp_launch_configuration
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_CLAUDE_CONFIG_BYTES = 1 << 20
ClaudeConfigInstallStatus = Literal["installed", "updated", "existing"]


@dataclass(frozen=True, slots=True)
class ClaudeConfigInstallPlan:
    """A checked project .mcp.json change applied after onboarding is staged."""

    path: Path
    status: ClaudeConfigInstallStatus
    content: str
    expected_content: str | None

    def apply(self) -> None:
        if self.status == "existing":
            _assert_config_unchanged(self.path, self.expected_content)
            return
        _assert_config_unchanged(self.path, self.expected_content)
        if self.expected_content is None:
            write_text_new_atomic(
                self.content,
                self.path,
                max_output_bytes=_MAX_CLAUDE_CONFIG_BYTES,
            )
        else:
            write_text_atomic(
                self.content,
                self.path,
                max_output_bytes=_MAX_CLAUDE_CONFIG_BYTES,
            )


@dataclass(frozen=True, slots=True)
class ClaudeConfigRemovalPlan:
    """A checked removal of only the previously generated PerfLens server."""

    path: Path
    content: str
    expected_content: str

    def apply(self) -> None:
        _assert_config_unchanged(self.path, self.expected_content)
        write_text_atomic(
            self.content,
            self.path,
            max_output_bytes=_MAX_CLAUDE_CONFIG_BYTES,
        )


def render_claude_config(
    workspace: Path,
    *,
    artifact_root: Path | None = None,
    allow_process_execution: bool = False,
    automatic_collection: bool = False,
    allow_project_execution: bool = False,
    allow_pid_attach: bool = False,
    collector_socket: Path = Path("/run/perflens/collector.sock"),
    collector_spool_root: Path = Path("/var/lib/perflens"),
    automatic_modes: tuple[str, ...] = ("stat", "record"),
    automatic_max_duration_seconds: float = 30.0,
    automatic_max_frequency_hz: int = 99,
    automatic_max_output_bytes: int = 256 << 20,
    automatic_plan_ttl_seconds: int = 120,
    allow_docker_targets: bool = False,
    docker_project_config: Path | None = None,
    mcp_command: Path | None = None,
) -> str:
    """Return a standalone Claude Code project MCP JSON document."""
    launch = build_mcp_launch_configuration(
        workspace,
        artifact_root=artifact_root,
        allow_process_execution=allow_process_execution,
        automatic_collection=automatic_collection,
        allow_project_execution=allow_project_execution,
        allow_pid_attach=allow_pid_attach,
        collector_socket=collector_socket,
        collector_spool_root=collector_spool_root,
        automatic_modes=automatic_modes,
        automatic_max_duration_seconds=automatic_max_duration_seconds,
        automatic_max_frequency_hz=automatic_max_frequency_hz,
        automatic_max_output_bytes=automatic_max_output_bytes,
        automatic_plan_ttl_seconds=automatic_plan_ttl_seconds,
        allow_docker_targets=allow_docker_targets,
        docker_project_config=docker_project_config,
        mcp_command=mcp_command,
    )
    return _render_document(
        {
            "mcpServers": {
                "perflens": {
                    "type": "stdio",
                    "command": str(launch.command),
                    "args": list(launch.arguments),
                    "env": {},
                }
            }
        }
    )


def plan_claude_project_config(
    workspace: Path,
    configuration: str,
    *,
    managed_configuration: str | None = None,
) -> ClaudeConfigInstallPlan:
    """Merge only a missing PerfLens server into PROJECT/.mcp.json."""
    project = _existing_directory(workspace)
    target = project / ".mcp.json"
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise _unsafe_claude_path(target)
    desired_root = _parse_document(configuration, label="Generated Claude MCP configuration")
    desired_servers = desired_root.get("mcpServers")
    if not isinstance(desired_servers, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            "Generated Claude MCP configuration has an unexpected shape",
        )
    typed_desired_servers = cast(dict[str, object], desired_servers)
    if set(typed_desired_servers) != {"perflens"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            "Generated Claude MCP configuration has an unexpected shape",
        )
    desired = typed_desired_servers["perflens"]

    expected: str | None = None
    if target.exists():
        expected = _read_config(target)
        payload = _parse_document(expected, label="Existing Claude MCP configuration")
        servers = payload.get("mcpServers")
        if servers is None:
            servers = {}
            payload["mcpServers"] = servers
        if not isinstance(servers, dict):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "claude_config",
                "Existing .mcp.json mcpServers value must be an object",
                recoverable=True,
                details={"path": str(target)},
            )
        current = cast(dict[str, object], servers).get("perflens")
        if current is not None:
            if current == desired:
                return ClaudeConfigInstallPlan(target, "existing", expected, expected)
            previous = _managed_server(managed_configuration)
            if previous is not None and current == previous:
                cast(dict[str, object], servers)["perflens"] = desired
                return ClaudeConfigInstallPlan(
                    target,
                    "updated",
                    _render_document(payload),
                    expected,
                )
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "claude_config",
                "Existing user-managed PerfLens Claude MCP configuration was preserved",
                recoverable=True,
                details={"path": str(target)},
                suggested_actions=("Review perflens-setup/claude-mcp.json and merge it manually.",),
            )
        cast(dict[str, object], servers)["perflens"] = desired
        return ClaudeConfigInstallPlan(target, "updated", _render_document(payload), expected)
    return ClaudeConfigInstallPlan(target, "installed", configuration, None)


def plan_claude_project_config_removal(
    workspace: Path,
    *,
    managed_configuration: str | None,
) -> ClaudeConfigRemovalPlan | None:
    """Remove only a PerfLens entry matching the recorded generated configuration."""
    project = _existing_directory(workspace)
    target = project / ".mcp.json"
    if not target.exists() and not target.is_symlink():
        return None
    if target.is_symlink() or not target.is_file():
        raise _unsafe_claude_path(target)
    expected = _read_config(target)
    payload = _parse_document(expected, label="Existing Claude MCP configuration")
    servers = payload.get("mcpServers")
    if servers is None:
        return None
    if not isinstance(servers, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            "Existing .mcp.json mcpServers value must be an object",
            recoverable=True,
            details={"path": str(target)},
        )
    typed_servers = cast(dict[str, object], servers)
    current = typed_servers.get("perflens")
    if current is None:
        return None
    managed = _managed_server(managed_configuration)
    if managed is None or current != managed:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "claude_config",
            "User-modified or unverified PerfLens Claude MCP configuration was preserved",
            recoverable=True,
            details={"path": str(target)},
            suggested_actions=(
                "Review .mcp.json and remove the perflens entry manually if intended.",
            ),
        )
    del typed_servers["perflens"]
    return ClaudeConfigRemovalPlan(target, _render_document(payload), expected)


def _managed_server(configuration: str | None) -> object | None:
    if configuration is None:
        return None
    payload = _parse_document(configuration, label="Recorded Claude MCP configuration")
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    return cast(dict[str, object], servers).get("perflens")


def _existing_directory(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            "Workspace does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            "Workspace must be a directory",
            details={"path": str(resolved)},
        )
    return resolved


def _read_config(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _unsafe_claude_path(path) from exc
    if len(raw) > _MAX_CLAUDE_CONFIG_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "claude_config",
            "Existing Claude MCP configuration exceeds its size limit",
            details={"path": str(path)},
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            "Existing Claude MCP configuration is not UTF-8",
            details={"path": str(path)},
        ) from exc


def _parse_document(content: str, *, label: str) -> dict[str, object]:
    try:
        parsed: object = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            f"{label} is not valid JSON",
            recoverable=True,
        ) from exc
    if not isinstance(parsed, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "claude_config",
            f"{label} must be a JSON object",
            recoverable=True,
        )
    return cast(dict[str, object], parsed)


def _render_document(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _assert_config_unchanged(path: Path, expected: str | None) -> None:
    if path.is_symlink():
        raise _unsafe_claude_path(path)
    try:
        current = path.read_text(encoding="utf-8") if path.exists() else None
    except OSError as exc:
        raise _unsafe_claude_path(path) from exc
    if current != expected:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "claude_config",
            "Project Claude MCP configuration changed during setup and was not overwritten",
            recoverable=True,
            details={"path": str(path)},
        )


def _unsafe_claude_path(path: Path) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "claude_config",
        "Project Claude MCP configuration path is unsafe",
        details={"path": str(path)},
    )
