"""Safely detach project-level AI client integrations."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal, Protocol

from perflens import __version__
from perflens.contracts.artifacts import ProjectDetachmentArtifact, SetupArtifact
from perflens.distribution.claude import plan_claude_project_config_removal
from perflens.distribution.codex import plan_codex_project_config_removal
from perflens.distribution.opencode import plan_opencode_project_config_removal
from perflens.distribution.skill import (
    SkillClient,
    plan_project_skill_removal,
    project_skill_candidates,
    project_skill_path,
)
from perflens.distribution.vscode import plan_vscode_copilot_project_config_removal
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_SETUP_BYTES = 1 << 20
DetachClient = Literal["all", "codex", "claude-code", "opencode", "copilot"]


class _ApplyPlan(Protocol):
    @property
    def path(self) -> Path: ...

    def apply(self) -> None: ...


def detach_project_integration(
    project_root: Path,
    *,
    client: DetachClient = "all",
    remove_skills: bool = True,
    setup_directory: Path = Path("perflens-setup"),
    dry_run: bool = False,
) -> ProjectDetachmentArtifact:
    """Remove only verified project MCP entries and unchanged managed Skills."""
    project = project_root.expanduser().resolve(strict=True)
    if not project.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "detach",
            "Project path must be a directory",
            details={"path": str(project)},
        )
    setup = _load_setup_artifact(project, setup_directory)
    configured = _configured_clients(setup)
    selected: tuple[SkillClient, ...] = configured if client == "all" else (client,)
    managed_claude = _recorded_claude_configuration(project, setup)
    managed_opencode = _recorded_configuration(project, setup, "opencode-mcp.json")
    managed_copilot = _recorded_configuration(project, setup, "copilot-mcp.json")
    managed_copilot_vscode = _recorded_configuration(
        project, setup, "copilot-vscode-mcp.json"
    )
    selected_set = set(selected)
    remaining_clients = set(configured) - selected_set
    shared_mcp_selected = selected_set & {"claude-code", "copilot"}
    preserve_shared_mcp = bool(
        shared_mcp_selected and remaining_clients & {"claude-code", "copilot"}
    )

    codex_config_plan = plan_codex_project_config_removal(project) if "codex" in selected else None
    shared_mcp_plan = None
    if shared_mcp_selected and not preserve_shared_mcp:
        if (
            len(shared_mcp_selected) == 2
            and managed_claude is not None
            and managed_copilot is not None
            and managed_claude != managed_copilot
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "detach",
                "Recorded Claude Code and Copilot ownership copies disagree",
                recoverable=True,
            )
        shared_mcp_plan = plan_claude_project_config_removal(
            project,
            managed_configuration=managed_claude or managed_copilot,
        )
    claude_config_plan = shared_mcp_plan if "claude-code" in selected else None
    opencode_config_plan = (
        plan_opencode_project_config_removal(
            project,
            managed_configuration=managed_opencode,
            recorded_path=(setup.opencode_project_config_path if setup is not None else None),
        )
        if "opencode" in selected
        else None
    )
    copilot_config_plan = shared_mcp_plan if "copilot" in selected else None
    copilot_vscode_config_plan = (
        plan_vscode_copilot_project_config_removal(
            project,
            managed_configuration=managed_copilot_vscode,
        )
        if "copilot" in selected
        else None
    )
    shared_clients = {"codex", "opencode", "copilot"}
    remove_shared_skill = remove_skills and not (
        (set(configured) - set(selected)) & shared_clients
    )
    shared_skill_plan = (
        plan_project_skill_removal(
            project,
            client="codex",
            expected_fingerprint=(setup.skill_fingerprint if setup is not None else None),
            recorded_path=(setup.skill_path if setup is not None else None),
        )
        if remove_shared_skill and bool(set(selected) & shared_clients)
        else None
    )
    claude_skill_plan = (
        plan_project_skill_removal(
            project,
            client="claude-code",
            expected_fingerprint=(setup.claude_skill_fingerprint if setup is not None else None),
            recorded_path=(setup.claude_skill_path if setup is not None else None),
        )
        if remove_skills and "claude-code" in selected
        else None
    )

    codex_config_status = _planned_status(
        selected="codex" in selected,
        plan=codex_config_plan,
        dry_run=dry_run,
    )
    claude_config_status = (
        "skipped"
        if "claude-code" in selected and preserve_shared_mcp
        else _planned_status(
            selected="claude-code" in selected,
            plan=claude_config_plan,
            dry_run=dry_run,
        )
    )
    opencode_config_status = _planned_status(
        selected="opencode" in selected,
        plan=opencode_config_plan,
        dry_run=dry_run,
    )
    copilot_config_status = (
        "skipped"
        if "copilot" in selected and preserve_shared_mcp
        else _planned_status(
            selected="copilot" in selected,
            plan=copilot_config_plan,
            dry_run=dry_run,
        )
    )
    copilot_vscode_config_status = _planned_status(
        selected="copilot" in selected,
        plan=copilot_vscode_config_plan,
        dry_run=dry_run,
    )
    shared_skill_status = _skill_status(
        selected=bool(set(selected) & shared_clients),
        remove_skills=remove_shared_skill,
        plan=shared_skill_plan,
        dry_run=dry_run,
    )
    codex_skill_status = _skill_status(
        selected="codex" in selected,
        remove_skills=remove_shared_skill,
        plan=shared_skill_plan,
        dry_run=dry_run,
    )
    claude_skill_status = _skill_status(
        selected="claude-code" in selected,
        remove_skills=remove_skills,
        plan=claude_skill_plan,
        dry_run=dry_run,
    )

    plans: list[_ApplyPlan] = []
    for plan in (
        codex_config_plan,
        claude_config_plan,
        opencode_config_plan,
        copilot_config_plan,
        copilot_vscode_config_plan,
        shared_skill_plan,
        claude_skill_plan,
    ):
        if plan is not None and all(existing is not plan for existing in plans):
            plans.append(plan)
    if not dry_run:
        for plan in plans:
            plan.apply()

    removed_paths = tuple(str(plan.path) for plan in plans) if not dry_run else ()
    preserved = _preserved_paths(
        project,
        setup_path=(Path(setup.output_directory) if setup is not None else None),
        remove_shared_skill=remove_shared_skill,
        remove_claude_skill=remove_skills and "claude-code" in selected,
    )
    identity = "\0".join(
        (
            str(project),
            client,
            ",".join(selected),
            str(remove_skills),
            codex_config_status,
            claude_config_status,
            opencode_config_status,
            copilot_config_status,
            copilot_vscode_config_status,
            shared_skill_status,
            claude_skill_status,
            str(dry_run),
        )
    )
    next_steps = ["Restart the selected AI clients so they stop using PerfLens."]
    next_steps.append(
        "Setup guidance and performance evidence were preserved for audit or later re-init."
    )
    next_steps.append("Uninstall PerfLens only after detaching every configured project.")
    return ProjectDetachmentArtifact(
        perflens_version=__version__,
        detachment_id=f"detachment-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        project_root=str(project),
        dry_run=dry_run,
        selected_clients=selected,
        remove_skills=remove_skills,
        setup_directory=(
            setup.output_directory if setup is not None else str(project / setup_directory)
        ),
        codex_config_path=str(project / ".codex/config.toml"),
        codex_config_status=codex_config_status,
        claude_config_path=str(project / ".mcp.json"),
        claude_config_status=claude_config_status,
        opencode_config_path=(
            str(opencode_config_plan.path)
            if opencode_config_plan is not None
            else (setup.opencode_project_config_path if setup is not None else None)
        ),
        opencode_config_status=opencode_config_status,
        copilot_config_path=str(project / ".mcp.json"),
        copilot_config_status=copilot_config_status,
        copilot_vscode_config_path=str(project / ".vscode/mcp.json"),
        copilot_vscode_config_status=copilot_vscode_config_status,
        codex_skill_path=str(
            shared_skill_plan.path
            if shared_skill_plan is not None
            else project_skill_path(project, client="codex")
        ),
        codex_skill_status=codex_skill_status,
        claude_skill_path=str(
            claude_skill_plan.path
            if claude_skill_plan is not None
            else project_skill_path(project, client="claude-code")
        ),
        claude_skill_status=claude_skill_status,
        opencode_skill_path=str(project_skill_path(project, client="opencode")),
        opencode_skill_status=(
            shared_skill_status if "opencode" in selected else "skipped"
        ),
        copilot_skill_path=str(project_skill_path(project, client="copilot")),
        copilot_skill_status=(shared_skill_status if "copilot" in selected else "skipped"),
        removed_paths=removed_paths,
        preserved_paths=preserved,
        next_steps=tuple(next_steps),
    )


def _planned_status(
    *,
    selected: bool,
    plan: object | None,
    dry_run: bool,
) -> Literal["not_found", "planned", "removed", "skipped"]:
    if not selected:
        return "skipped"
    if plan is None:
        return "not_found"
    return "planned" if dry_run else "removed"


def _skill_status(
    *,
    selected: bool,
    remove_skills: bool,
    plan: object | None,
    dry_run: bool,
) -> Literal["not_found", "planned", "removed", "preserved", "skipped"]:
    if not selected:
        return "skipped"
    if not remove_skills:
        return "preserved"
    if plan is None:
        return "not_found"
    return "planned" if dry_run else "removed"


def _load_setup_artifact(
    project: Path,
    requested: Path,
) -> SetupArtifact | None:
    candidate = requested.expanduser()
    if not candidate.is_absolute():
        candidate = project / candidate
    if candidate.is_symlink():
        raise _unsafe_setup(candidate)
    try:
        setup = candidate.resolve(strict=False)
    except OSError as exc:
        raise _unsafe_setup(candidate) from exc
    if not setup.is_relative_to(project):
        raise _unsafe_setup(setup)
    if not setup.exists():
        return None
    artifact_path = setup / "setup.json"
    if not setup.is_dir() or artifact_path.is_symlink() or not artifact_path.is_file():
        raise _unsafe_setup(setup)
    try:
        raw = artifact_path.read_bytes()
        if len(raw) > _MAX_SETUP_BYTES:
            raise ValueError("setup artifact exceeds its size limit")
        artifact = SetupArtifact.model_validate_json(raw)
        recorded_project = Path(artifact.project_root).resolve(strict=True)
        recorded_output = Path(artifact.output_directory).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise _unsafe_setup(artifact_path) from exc
    if recorded_project != project or recorded_output != setup:
        raise _unsafe_setup(artifact_path)
    return artifact


def _recorded_claude_configuration(
    project: Path,
    setup: SetupArtifact | None,
) -> str | None:
    if setup is None or not setup.claude_project_config_managed:
        return None
    path = Path(setup.output_directory) / "claude-mcp.json"
    if not path.is_relative_to(project) or path.is_symlink() or not path.is_file():
        raise _unsafe_setup(path)
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SETUP_BYTES:
            raise ValueError("Claude MCP ownership file exceeds its size limit")
        return raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _unsafe_setup(path) from exc


def _recorded_configuration(
    project: Path,
    setup: SetupArtifact | None,
    filename: str,
) -> str | None:
    if setup is None:
        return None
    managed = {
        "opencode-mcp.json": setup.opencode_project_config_managed,
        "copilot-mcp.json": setup.copilot_project_config_managed,
        "copilot-vscode-mcp.json": setup.copilot_vscode_project_config_managed,
    }[filename]
    if not managed:
        return None
    path = Path(setup.output_directory) / filename
    if not path.is_relative_to(project) or path.is_symlink() or not path.is_file():
        raise _unsafe_setup(path)
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SETUP_BYTES:
            raise ValueError("MCP ownership file exceeds its size limit")
        return raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _unsafe_setup(path) from exc


def _configured_clients(setup: SetupArtifact | None) -> tuple[SkillClient, ...]:
    if setup is None:
        return ("codex", "claude-code")
    if setup.selected_clients:
        return setup.selected_clients
    selected: list[SkillClient] = []
    if setup.codex_project_config_status != "skipped" or setup.skill_status != "skipped":
        selected.append("codex")
    if (
        setup.claude_project_config_status != "skipped"
        or setup.claude_skill_status != "skipped"
    ):
        selected.append("claude-code")
    return tuple(selected)


def _preserved_paths(
    project: Path,
    *,
    setup_path: Path | None,
    remove_shared_skill: bool,
    remove_claude_skill: bool,
) -> tuple[str, ...]:
    candidates = [setup_path or project / "perflens-setup", project / "perflens-results"]
    if not remove_shared_skill:
        candidates.extend(project_skill_candidates(project, client="codex"))
    if not remove_claude_skill:
        candidates.extend(project_skill_candidates(project, client="claude-code"))
    return tuple(str(path) for path in candidates if path.exists() or path.is_symlink())


def _unsafe_setup(path: Path) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "detach",
        "PerfLens setup ownership record is missing, invalid, or unsafe",
        recoverable=True,
        details={"path": str(path)},
    )
