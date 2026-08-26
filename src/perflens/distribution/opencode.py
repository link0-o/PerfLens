"""Render and safely install a project-scoped OpenCode MCP configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from perflens.artifacts.filesystem import write_text_atomic, write_text_new_atomic
from perflens.distribution.codex import build_mcp_launch_configuration
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_OPENCODE_CONFIG_BYTES = 1 << 20
OpenCodeConfigInstallStatus = Literal["installed", "updated", "existing"]


@dataclass(frozen=True, slots=True)
class OpenCodeConfigInstallPlan:
    """A checked project OpenCode JSON change applied once during setup."""

    path: Path
    status: OpenCodeConfigInstallStatus
    content: str
    expected_content: str | None

    def apply(self) -> None:
        if self.status == "existing":
            _assert_config_unchanged(self.path, self.expected_content)
            return
        parent = self.path.parent
        if parent.exists() or parent.is_symlink():
            if parent.is_symlink() or not parent.is_dir():
                raise _unsafe_opencode_path(parent)
        else:
            parent.mkdir(mode=0o700)
        _assert_config_unchanged(self.path, self.expected_content)
        if self.expected_content is None:
            write_text_new_atomic(
                self.content,
                self.path,
                max_output_bytes=_MAX_OPENCODE_CONFIG_BYTES,
            )
        else:
            write_text_atomic(
                self.content,
                self.path,
                max_output_bytes=_MAX_OPENCODE_CONFIG_BYTES,
            )


@dataclass(frozen=True, slots=True)
class OpenCodeConfigRemovalPlan:
    """A checked removal of only the recorded PerfLens OpenCode server."""

    path: Path
    content: str
    expected_content: str

    def apply(self) -> None:
        _assert_config_unchanged(self.path, self.expected_content)
        write_text_atomic(
            self.content,
            self.path,
            max_output_bytes=_MAX_OPENCODE_CONFIG_BYTES,
        )


def render_opencode_config(
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
    allow_docker_optimization: bool = False,
    docker_project_config: Path | None = None,
    mcp_command: Path | None = None,
) -> str:
    """Return a standalone current OpenCode project MCP JSON document."""
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
        allow_docker_optimization=allow_docker_optimization,
        docker_project_config=docker_project_config,
        mcp_command=mcp_command,
    )
    return _render_document(
        {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "perflens": {
                    "type": "local",
                    "command": [str(launch.command), *launch.arguments],
                    "enabled": True,
                }
            },
        }
    )


def plan_opencode_project_config(
    workspace: Path,
    configuration: str,
    *,
    managed_configuration: str | None = None,
    recorded_path: str | None = None,
) -> OpenCodeConfigInstallPlan:
    """Safely merge the PerfLens server into one unambiguous OpenCode JSON config."""
    project = _existing_directory(workspace)
    target = _select_project_config(project, recorded_path=recorded_path)
    desired_root = _parse_document(configuration, label="Generated OpenCode configuration")
    desired = _perflens_server(desired_root, label="Generated OpenCode configuration")

    expected: str | None = None
    if target.exists():
        expected = _read_config(target)
        payload = _parse_document(expected, label="Existing OpenCode configuration")
        server_view = _servers(payload, create=True, label="Existing OpenCode configuration")
        assert server_view is not None
        servers, layout = server_view
        desired_for_layout = _server_for_layout(desired, layout=layout)
        current = servers.get("perflens")
        if current is not None:
            if current == desired_for_layout:
                return OpenCodeConfigInstallPlan(target, "existing", expected, expected)
            previous = _managed_server(managed_configuration, layout=layout)
            if previous is None or current != previous:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "opencode_config",
                    "Existing user-managed PerfLens OpenCode configuration was preserved",
                    recoverable=True,
                    details={"path": str(target)},
                    suggested_actions=(
                        "Review perflens-setup/opencode-mcp.json and merge it manually.",
                    ),
                )
        servers["perflens"] = desired_for_layout
        return OpenCodeConfigInstallPlan(target, "updated", _render_document(payload), expected)
    return OpenCodeConfigInstallPlan(target, "installed", configuration, None)


def plan_opencode_project_config_removal(
    workspace: Path,
    *,
    managed_configuration: str | None,
    recorded_path: str | None = None,
) -> OpenCodeConfigRemovalPlan | None:
    """Remove only a PerfLens entry matching the recorded OpenCode ownership copy."""
    project = _existing_directory(workspace)
    target = _select_project_config(
        project,
        recorded_path=recorded_path,
    )
    if not target.exists() and not target.is_symlink():
        return None
    expected = _read_config(target)
    payload = _parse_document(expected, label="Existing OpenCode configuration")
    server_view = _servers(payload, create=False, label="Existing OpenCode configuration")
    if server_view is None:
        return None
    servers, layout = server_view
    if "perflens" not in servers:
        return None
    managed = _managed_server(managed_configuration, layout=layout)
    if managed is None or servers["perflens"] != managed:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "opencode_config",
            "User-modified or unverified PerfLens OpenCode configuration was preserved",
            recoverable=True,
            details={"path": str(target)},
            suggested_actions=(
                "Review the OpenCode project config and remove only its perflens server manually.",
            ),
        )
    del servers["perflens"]
    return OpenCodeConfigRemovalPlan(target, _render_document(payload), expected)


def opencode_project_config_candidates(project: Path) -> tuple[Path, ...]:
    """Return all project OpenCode config locations that could affect this workspace."""
    root = _existing_directory(project)
    return (
        root / "opencode.json",
        root / "opencode.jsonc",
        root / ".opencode" / "opencode.json",
        root / ".opencode" / "opencode.jsonc",
    )


def _select_project_config(
    project: Path,
    *,
    recorded_path: str | None,
) -> Path:
    candidates = opencode_project_config_candidates(project)
    if recorded_path is not None:
        recorded = Path(recorded_path)
        if recorded not in candidates or recorded.suffix == ".jsonc":
            raise _unsafe_opencode_path(recorded)
        target = recorded
    else:
        existing = tuple(path for path in candidates if path.exists() or path.is_symlink())
        if len(existing) > 1:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "opencode_config",
                "Multiple OpenCode project configuration files are ambiguous",
                recoverable=True,
                details={"paths": [str(path) for path in existing]},
                suggested_actions=(
                    "Keep one project OpenCode config before running perflens init.",
                ),
            )
        if existing and existing[0].suffix == ".jsonc":
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "opencode_config",
                "Existing OpenCode JSONC was preserved because comments cannot be merged safely",
                recoverable=True,
                details={"path": str(existing[0])},
                suggested_actions=(
                    "Merge perflens-setup/opencode-mcp.json manually, or convert the file to JSON.",
                ),
            )
        target = existing[0] if existing else project / ".opencode" / "opencode.json"
    parent = target.parent
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise _unsafe_opencode_path(target)
    if parent.exists() or parent.is_symlink():
        if parent.is_symlink() or not parent.is_dir():
            raise _unsafe_opencode_path(parent)
        try:
            if not parent.resolve(strict=True).is_relative_to(project):
                raise _unsafe_opencode_path(parent)
        except OSError as exc:
            raise _unsafe_opencode_path(parent) from exc
    elif parent != project / ".opencode":
        raise _unsafe_opencode_path(parent)
    return target


def _managed_server(
    configuration: str | None,
    *,
    layout: Literal["current", "legacy_v2"],
) -> object | None:
    if configuration is None:
        return None
    payload = _parse_document(configuration, label="Recorded OpenCode configuration")
    server = _perflens_server(payload, label="Recorded OpenCode configuration")
    return _server_for_layout(server, layout=layout)


def _perflens_server(payload: dict[str, object], *, label: str) -> object:
    server_view = _servers(payload, create=False, label=label)
    if server_view is None or set(server_view[0]) != {"perflens"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            f"{label} has an unexpected MCP server shape",
        )
    return server_view[0]["perflens"]


def _servers(
    payload: dict[str, object],
    *,
    create: bool,
    label: str,
) -> tuple[dict[str, object], Literal["current", "legacy_v2"]] | None:
    mcp = payload.get("mcp")
    if mcp is None and create:
        mcp = {}
        payload["mcp"] = mcp
    if mcp is None:
        return None
    if not isinstance(mcp, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            f"{label} mcp value must be an object",
            recoverable=True,
        )
    typed_mcp = cast(dict[str, object], mcp)
    if "servers" not in typed_mcp:
        return typed_mcp, "current"
    if len(typed_mcp) != 1:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            f"{label} mixes current and legacy MCP server layouts",
            recoverable=True,
        )
    servers = typed_mcp["servers"]
    if not isinstance(servers, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            f"{label} legacy mcp.servers value must be an object",
            recoverable=True,
        )
    return cast(dict[str, object], servers), "legacy_v2"


def _server_for_layout(
    server: object,
    *,
    layout: Literal["current", "legacy_v2"],
) -> object:
    if not isinstance(server, dict):
        return server
    typed = cast(dict[str, object], server)
    if layout == "current":
        if "disabled" not in typed and "codemode" not in typed:
            return typed
        converted = dict(typed)
        disabled = converted.pop("disabled", False)
        converted.pop("codemode", None)
        converted["enabled"] = not bool(disabled)
        return converted
    if "enabled" not in typed:
        return typed
    converted = dict(typed)
    enabled = converted.pop("enabled")
    converted["codemode"] = False
    converted["disabled"] = not bool(enabled)
    return converted


def _existing_directory(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            "Workspace does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            "Workspace must be a directory",
            details={"path": str(resolved)},
        )
    return resolved


def _read_config(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise _unsafe_opencode_path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _unsafe_opencode_path(path) from exc
    if len(raw) > _MAX_OPENCODE_CONFIG_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "opencode_config",
            "Existing OpenCode configuration exceeds its size limit",
            details={"path": str(path)},
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            "Existing OpenCode configuration is not UTF-8",
            details={"path": str(path)},
        ) from exc


def _parse_document(content: str, *, label: str) -> dict[str, object]:
    try:
        parsed: object = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            f"{label} is not valid JSON",
            recoverable=True,
        ) from exc
    if not isinstance(parsed, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "opencode_config",
            f"{label} must be a JSON object",
            recoverable=True,
        )
    return cast(dict[str, object], parsed)


def _render_document(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _assert_config_unchanged(path: Path, expected: str | None) -> None:
    if path.is_symlink():
        raise _unsafe_opencode_path(path)
    try:
        current = path.read_text(encoding="utf-8") if path.exists() else None
    except OSError as exc:
        raise _unsafe_opencode_path(path) from exc
    if current != expected:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "opencode_config",
            "Project OpenCode configuration changed during setup and was not overwritten",
            recoverable=True,
            details={"path": str(path)},
        )


def _unsafe_opencode_path(path: Path) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "opencode_config",
        "Project OpenCode configuration path is unsafe",
        details={"path": str(path)},
    )
