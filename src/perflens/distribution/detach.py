"""Safely detach the project-level Codex MCP integration without deleting evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path

from perflens import __version__
from perflens.contracts.artifacts import ProjectDetachmentArtifact
from perflens.distribution.codex import plan_codex_project_config_removal


def detach_project_integration(
    project_root: Path,
    *,
    dry_run: bool = False,
) -> ProjectDetachmentArtifact:
    """Remove only the structurally owned PerfLens MCP block from one project."""
    plan = plan_codex_project_config_removal(project_root)
    project = project_root.expanduser().resolve(strict=True)
    config_path = project / ".codex" / "config.toml"
    if plan is None:
        config_status = "not_found"
    elif dry_run:
        config_status = "planned"
    else:
        plan.apply()
        config_status = "removed"

    preserved = tuple(
        str(path)
        for path in (
            project / ".agents" / "skills" / "perflens-performance-analysis",
            project / "perflens-setup",
            project / "perflens-results",
        )
        if path.exists() or path.is_symlink()
    )
    identity = "\0".join((str(project), str(config_path), config_status, str(dry_run)))
    next_steps = ["Restart Codex so it stops using the detached project MCP server."]
    if preserved:
        next_steps.append(
            "Review preserved Skill, onboarding, and result paths before removing any of them."
        )
    next_steps.append(
        "Uninstall the PerfLens package only after detaching every configured project."
    )
    return ProjectDetachmentArtifact(
        perflens_version=__version__,
        detachment_id=f"detachment-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        project_root=str(project),
        dry_run=dry_run,
        codex_config_path=str(config_path),
        codex_config_status=config_status,
        preserved_paths=preserved,
        next_steps=tuple(next_steps),
    )
