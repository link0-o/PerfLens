"""Render a project-scoped Codex MCP configuration without mutating user config."""

from __future__ import annotations

import json
import os
import shutil
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from perflens.artifacts.filesystem import write_text_atomic, write_text_new_atomic
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_CODEX_CONFIG_BYTES = 1 << 20
_MANAGED_BEGIN = "# BEGIN PerfLens managed MCP configuration"
_MANAGED_END = "# END PerfLens managed MCP configuration"
CodexConfigInstallStatus = Literal["installed", "updated", "existing"]


@dataclass(frozen=True, slots=True)
class CodexConfigInstallPlan:
    """A checked, project-local Codex configuration change applied once at setup commit."""

    path: Path
    status: CodexConfigInstallStatus
    content: str
    expected_content: str | None

    def apply(self) -> None:
        if self.status == "existing":
            _assert_config_unchanged(self.path, self.expected_content)
            return
        parent = self.path.parent
        if parent.exists() or parent.is_symlink():
            if parent.is_symlink() or not parent.is_dir():
                raise _unsafe_codex_path(parent)
        else:
            parent.mkdir(mode=0o700)
        _assert_config_unchanged(self.path, self.expected_content)
        if self.expected_content is None:
            write_text_new_atomic(
                self.content,
                self.path,
                max_output_bytes=_MAX_CODEX_CONFIG_BYTES,
            )
        else:
            write_text_atomic(
                self.content,
                self.path,
                max_output_bytes=_MAX_CODEX_CONFIG_BYTES,
            )


@dataclass(frozen=True, slots=True)
class CodexConfigRemovalPlan:
    """A checked removal of only PerfLens's marked project configuration block."""

    path: Path
    content: str
    expected_content: str

    def apply(self) -> None:
        _assert_config_unchanged(self.path, self.expected_content)
        write_text_atomic(
            self.content,
            self.path,
            max_output_bytes=_MAX_CODEX_CONFIG_BYTES,
        )


def plan_codex_project_config(
    workspace: Path,
    configuration: str,
) -> CodexConfigInstallPlan:
    """Plan a non-destructive project-level Codex MCP configuration install."""
    project = _existing_directory(workspace, label="Workspace")
    target = project / ".codex" / "config.toml"
    parent = target.parent
    if parent.exists() or parent.is_symlink():
        if parent.is_symlink() or not parent.is_dir():
            raise _unsafe_codex_path(parent)
        if parent.resolve(strict=True) != parent or not parent.is_relative_to(project):
            raise _unsafe_codex_path(parent)
    if target.is_symlink():
        raise _unsafe_codex_path(target)

    managed = f"{_MANAGED_BEGIN}\n{configuration.rstrip()}\n{_MANAGED_END}\n"
    expected: str | None = None
    if target.exists():
        if not target.is_file():
            raise _unsafe_codex_path(target)
        try:
            raw = target.read_bytes()
            if len(raw) > _MAX_CODEX_CONFIG_BYTES:
                raise ValueError("Codex configuration exceeds its size limit")
            expected = raw.decode("utf-8")
            parsed = cast(dict[str, object], tomllib.loads(expected))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "codex_config",
                "Existing project Codex configuration is invalid or too large",
                recoverable=True,
                details={"path": str(target)},
                suggested_actions=(
                    "Repair .codex/config.toml, or rerun setup with --skip-codex-config.",
                ),
            ) from exc
        lines = expected.splitlines(keepends=True)
        begins, ends = _managed_marker_lines(lines)
        if begins or ends:
            if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
                raise _managed_block_error(target)
            _validate_managed_block(lines, begins[0], ends[0], target)
            replacement = "".join(lines[: begins[0]]) + managed + "".join(
                lines[ends[0] + 1 :]
            )
            try:
                tomllib.loads(replacement)
            except tomllib.TOMLDecodeError as exc:
                raise _managed_block_error(target) from exc
            status: CodexConfigInstallStatus = (
                "existing" if replacement == expected else "updated"
            )
            return CodexConfigInstallPlan(target, status, replacement, expected)

        current = parsed.get("mcp_servers")
        perflens = (
            cast(dict[str, object], current).get("perflens")
            if isinstance(current, dict)
            else None
        )
        desired_root = cast(dict[str, object], tomllib.loads(configuration))
        desired_servers = cast(dict[str, object], desired_root["mcp_servers"])
        desired = desired_servers["perflens"]
        if perflens is not None:
            if perflens == desired:
                return CodexConfigInstallPlan(target, "existing", expected, expected)
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "codex_config",
                "Existing user-managed PerfLens MCP configuration will not be overwritten",
                recoverable=True,
                details={"path": str(target)},
                suggested_actions=(
                    "Review the generated codex-mcp.toml and update the existing table manually.",
                    "Or rerun setup with --skip-codex-config to generate files only.",
                ),
            )
        separator = "" if not expected else ("" if expected.endswith("\n\n") else "\n")
        return CodexConfigInstallPlan(
            target,
            "updated",
            f"{expected}{separator}{managed}",
            expected,
        )
    return CodexConfigInstallPlan(target, "installed", managed, None)


def plan_codex_project_config_removal(
    workspace: Path,
) -> CodexConfigRemovalPlan | None:
    """Plan removal of a structurally valid PerfLens-managed project block."""
    project = _existing_directory(workspace, label="Workspace")
    parent = project / ".codex"
    target = parent / "config.toml"
    if not target.exists() and not target.is_symlink():
        return None
    if (
        parent.is_symlink()
        or not parent.is_dir()
        or parent.resolve(strict=True) != parent
        or target.is_symlink()
        or not target.is_file()
    ):
        raise _unsafe_codex_path(target)
    try:
        raw = target.read_bytes()
        if len(raw) > _MAX_CODEX_CONFIG_BYTES:
            raise ValueError("Codex configuration exceeds its size limit")
        expected = raw.decode("utf-8")
        parsed = cast(dict[str, object], tomllib.loads(expected))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "Existing project Codex configuration is invalid or too large",
            recoverable=True,
            details={"path": str(target)},
            suggested_actions=("Repair .codex/config.toml before detaching PerfLens.",),
        ) from exc
    lines = expected.splitlines(keepends=True)
    begins, ends = _managed_marker_lines(lines)
    if not begins and not ends:
        servers = parsed.get("mcp_servers")
        perflens = (
            cast(dict[str, object], servers).get("perflens")
            if isinstance(servers, dict)
            else None
        )
        if perflens is None:
            return None
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "codex_config",
            "User-managed PerfLens MCP configuration was preserved",
            recoverable=True,
            details={"path": str(target)},
            suggested_actions=(
                "Review and remove the unmarked [mcp_servers.perflens] table manually.",
            ),
        )
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise _managed_block_error(target)
    _validate_managed_block(lines, begins[0], ends[0], target)
    content = "".join(lines[: begins[0]] + lines[ends[0] + 1 :])
    try:
        if content.strip():
            tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise _managed_block_error(target) from exc
    return CodexConfigRemovalPlan(target, content, expected)


def _managed_marker_lines(lines: list[str]) -> tuple[list[int], list[int]]:
    begins = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == _MANAGED_BEGIN
    ]
    ends = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == _MANAGED_END
    ]
    return begins, ends


def _validate_managed_block(
    lines: list[str],
    begin: int,
    end: int,
    path: Path,
) -> None:
    fragment = "".join(lines[begin + 1 : end])
    try:
        payload = cast(dict[str, object], tomllib.loads(fragment))
    except tomllib.TOMLDecodeError as exc:
        raise _managed_block_error(path) from exc
    if set(payload) != {"mcp_servers"}:
        raise _managed_block_error(path)
    servers = payload["mcp_servers"]
    if not isinstance(servers, dict):
        raise _managed_block_error(path)
    server_table = cast(dict[str, object], servers)
    if set(server_table) != {"perflens"}:
        raise _managed_block_error(path)
    if not isinstance(server_table["perflens"], dict):
        raise _managed_block_error(path)


def _assert_config_unchanged(path: Path, expected: str | None) -> None:
    if path.is_symlink():
        raise _unsafe_codex_path(path)
    try:
        current = path.read_text(encoding="utf-8") if path.exists() else None
    except OSError as exc:
        raise _unsafe_codex_path(path) from exc
    if current != expected:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "codex_config",
            "Project Codex configuration changed during setup and was not overwritten",
            recoverable=True,
            details={"path": str(path)},
            suggested_actions=("Review the file and rerun setup in a new output directory.",),
        )


def _unsafe_codex_path(path: Path) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "codex_config",
        "Project Codex configuration path is unsafe",
        details={"path": str(path)},
    )


def _managed_block_error(path: Path) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "codex_config",
        "PerfLens managed configuration markers are incomplete or duplicated",
        recoverable=True,
        details={"path": str(path)},
        suggested_actions=("Repair the managed block, or use --skip-codex-config.",),
    )


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
    lexical = Path(os.path.abspath(candidate.expanduser()))
    try:
        entry_metadata = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "MCP executable does not exist or cannot be resolved",
            details={"path": str(lexical)},
        ) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "codex_config",
            "MCP command must be an executable file",
            details={"path": str(resolved)},
        )
    if stat.S_ISLNK(entry_metadata.st_mode) and resolved.name == "perflens-launcher":
        parent = lexical.parent
        try:
            resolved_parent = parent.resolve(strict=True)
            parent_metadata = parent.stat()
            target_metadata = resolved.stat()
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "codex_config",
                "MCP launcher entry-point parent cannot be verified safely",
                details={"path": str(parent)},
            ) from exc
        if (
            resolved_parent != parent
            or entry_metadata.st_uid != parent_metadata.st_uid
            or parent_metadata.st_mode & 0o022
            or target_metadata.st_mode & 0o022
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "codex_config",
                "MCP launcher symbolic entry point is not in a trusted directory",
                details={"path": str(lexical), "parent": str(parent)},
            )
        return lexical
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
