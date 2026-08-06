"""Safely detach project-level Codex and Claude Code integrations."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal, Protocol

from perflens import __version__
from perflens.contracts.artifacts import ProjectDetachmentArtifact, SetupArtifact
from perflens.distribution.claude import plan_claude_project_config_removal
from perflens.distribution.codex import plan_codex_project_config_removal
from perflens.distribution.skill import (
    SkillClient,
    plan_project_skill_removal,
    project_skill_candidates,
    project_skill_path,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_SETUP_BYTES = 1 << 20
DetachClient = Literal["all", "codex", "claude-code"]


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
    selected: tuple[SkillClient, ...] = ("codex", "claude-code") if client == "all" else (client,)
    managed_claude = _recorded_claude_configuration(project, setup)

    codex_config_plan = plan_codex_project_config_removal(project) if "codex" in selected else None
    claude_config_plan = (
        plan_claude_project_config_removal(
            project,
            managed_configuration=managed_claude,
        )
        if "claude-code" in selected
        else None
    )
    codex_skill_plan = (
        plan_project_skill_removal(
            project,
            client="codex",
            expected_fingerprint=(setup.skill_fingerprint if setup is not None else None),
            recorded_path=(setup.skill_path if setup is not None else None),
        )
        if remove_skills and "codex" in selected
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
    claude_config_status = _planned_status(
        selected="claude-code" in selected,
        plan=claude_config_plan,
        dry_run=dry_run,
    )
    codex_skill_status = _skill_status(
        selected="codex" in selected,
        remove_skills=remove_skills,
        plan=codex_skill_plan,
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
        codex_skill_plan,
        claude_skill_plan,
    ):
        if plan is not None:
            plans.append(plan)
    if not dry_run:
        for plan in plans:
            plan.apply()

    removed_paths = tuple(str(plan.path) for plan in plans) if not dry_run else ()
    preserved = _preserved_paths(
        project,
        setup_path=(Path(setup.output_directory) if setup is not None else None),
        selected=selected,
        remove_skills=remove_skills,
    )
    identity = "\0".join(
        (
            str(project),
            client,
            str(remove_skills),
            codex_config_status,
            claude_config_status,
            codex_skill_status,
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
        codex_skill_path=str(
            codex_skill_plan.path
            if codex_skill_plan is not None
            else project_skill_path(project, client="codex")
        ),
        codex_skill_status=codex_skill_status,
        claude_skill_path=str(
            claude_skill_plan.path
            if claude_skill_plan is not None
            else project_skill_path(project, client="claude-code")
        ),
        claude_skill_status=claude_skill_status,
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


def _preserved_paths(
    project: Path,
    *,
    setup_path: Path | None,
    selected: tuple[SkillClient, ...],
    remove_skills: bool,
) -> tuple[str, ...]:
    candidates = [setup_path or project / "perflens-setup", project / "perflens-results"]
    if not remove_skills or "codex" not in selected:
        candidates.extend(project_skill_candidates(project, client="codex"))
    if not remove_skills or "claude-code" not in selected:
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
