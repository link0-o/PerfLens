"""Install the bundled PerfLens Skill into a project without overwriting files."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Literal, Protocol

from perflens.domain.errors import ErrorCode, PerfLensError

SKILL_NAME = "perflens"
SKILL_ARCHIVE_BASENAME = "perflens-skill"
LEGACY_SKILL_NAMES = ("perflens-performance-analysis",)
SkillClient = Literal["codex", "claude-code"]
_MAX_SKILL_FILES = 64
_MAX_SKILL_BYTES = 2 << 20


@dataclass(slots=True)
class _CopyBudget:
    files: int = 0
    bytes: int = 0


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


@dataclass(frozen=True, slots=True)
class SkillRemovalPlan:
    """A bounded removal plan for one unchanged project Skill tree."""

    path: Path
    expected_fingerprint: str

    def apply(self) -> None:
        current = project_skill_fingerprint(self.path)
        if current != self.expected_fingerprint:
            raise _modified_skill_error(self.path)
        shutil.rmtree(self.path)


def project_skill_path(project_root: Path, *, client: SkillClient = "codex") -> Path:
    """Return the client-specific project Skill path without creating it."""
    root = _existing_directory(project_root, label="Project root")
    parents = (".agents", "skills") if client == "codex" else (".claude", "skills")
    return root.joinpath(*parents, SKILL_NAME)


def project_skill_candidates(
    project_root: Path,
    *,
    client: SkillClient = "codex",
) -> tuple[Path, ...]:
    """Return current and legacy managed Skill paths for one client."""
    root = _existing_directory(project_root, label="Project root")
    parents = (".agents", "skills") if client == "codex" else (".claude", "skills")
    return tuple(root.joinpath(*parents, name) for name in (SKILL_NAME, *LEGACY_SKILL_NAMES))


def recorded_project_skill_path(
    project_root: Path,
    *,
    client: SkillClient,
    recorded_path: str | None,
) -> Path:
    """Resolve only a current or legacy path that could have been managed by PerfLens."""
    candidates = project_skill_candidates(project_root, client=client)
    if recorded_path is not None:
        candidate = Path(recorded_path)
        if candidate not in candidates:
            raise _modified_skill_error(candidate)
        return candidate
    existing = tuple(path for path in candidates if path.exists() or path.is_symlink())
    if len(existing) > 1:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "Multiple current or legacy PerfLens Skill paths exist",
            details={"paths": [str(path) for path in existing]},
        )
    return existing[0] if existing else candidates[0]


def install_project_skill(
    project_root: Path,
    *,
    client: SkillClient = "codex",
) -> Path:
    """Install the bundled Skill in one selected client's project directory."""
    root = _existing_directory(project_root, label="Project root")
    client_directory = ".agents" if client == "codex" else ".claude"
    agents_root = _safe_child_directory(root, client_directory)
    skills_root = _safe_child_directory(agents_root, "skills")
    target = skills_root / SKILL_NAME
    occupied = next(
        (
            path
            for path in (target, *(skills_root / name for name in LEGACY_SKILL_NAMES))
            if path.exists() or path.is_symlink()
        ),
        None,
    )
    if occupied is not None:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "A current or legacy PerfLens Skill destination already exists",
            recoverable=True,
            details={"path": str(occupied)},
            suggested_actions=(
                "Use perflens init --update to migrate an unchanged legacy Skill, or preserve "
                "user-modified content for manual review.",
            ),
        )

    source = _bundled_skill_root()
    created = False
    try:
        target.mkdir()
        created = True
        _copy_resource_tree(source, target, budget=_CopyBudget())
    except PerfLensError:
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise
    except OSError as exc:
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "skill_install",
            "Unable to install the PerfLens Skill",
            details={"path": str(target)},
            suggested_actions=("Check project directory permissions and free space.",),
        ) from exc
    return target


def bundled_skill_fingerprint() -> str:
    """Return a deterministic fingerprint for the packaged Skill files."""
    return _resource_fingerprint(_bundled_skill_root(), budget=_CopyBudget())


def project_skill_fingerprint(path: Path) -> str:
    """Fingerprint one bounded, symlink-free installed Skill directory."""
    if path.is_symlink() or not path.is_dir():
        raise _modified_skill_error(path)
    return _path_fingerprint(path, path, budget=_CopyBudget())


def refresh_project_skill(
    project_root: Path,
    *,
    client: SkillClient,
    expected_fingerprint: str,
    current_path: Path | None = None,
) -> tuple[Path, Literal["existing", "updated"]]:
    """Replace an unchanged managed Skill with the currently bundled version."""
    target = project_skill_path(project_root, client=client)
    source = current_path or target
    if source not in project_skill_candidates(project_root, client=client):
        raise _modified_skill_error(source)
    if source != target and (target.exists() or target.is_symlink()):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "Current and legacy PerfLens Skill paths both exist",
            details={"current": str(target), "legacy": str(source)},
        )
    current = project_skill_fingerprint(source)
    if current != expected_fingerprint:
        raise _modified_skill_error(target)
    bundled = bundled_skill_fingerprint()
    if source == target and current == bundled:
        return target, "existing"

    backup = source.with_name(f".{source.name}.perflens-backup")
    if backup.exists() or backup.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "PerfLens Skill update backup path already exists",
            details={"path": str(backup)},
        )
    source.rename(backup)
    try:
        if project_skill_fingerprint(backup) != expected_fingerprint:
            raise _modified_skill_error(backup)
        installed = install_project_skill(project_root, client=client)
    except BaseException:
        if target.exists() and not target.is_symlink():
            shutil.rmtree(target, ignore_errors=True)
        backup.rename(source)
        raise
    shutil.rmtree(backup)
    return installed, "updated"


def plan_project_skill_removal(
    project_root: Path,
    *,
    client: SkillClient,
    expected_fingerprint: str | None,
    recorded_path: str | None = None,
) -> SkillRemovalPlan | None:
    """Plan removal only when the project Skill still matches its recorded owner."""
    target = recorded_project_skill_path(
        project_root,
        client=client,
        recorded_path=recorded_path,
    )
    if not target.exists() and not target.is_symlink():
        return None
    current = project_skill_fingerprint(target)
    expected = expected_fingerprint or bundled_skill_fingerprint()
    if current != expected:
        raise _modified_skill_error(target)
    return SkillRemovalPlan(target, current)


def _bundled_skill_root() -> Traversable:
    packaged = (
        resources.files("perflens")
        .joinpath("_bundled")
        .joinpath("skills")
        .joinpath(SKILL_NAME)
    )
    if packaged.joinpath("SKILL.md").is_file():
        return packaged

    repository_copy = (
        Path(__file__).resolve().parents[3] / ".agents" / "skills" / SKILL_NAME
    )
    if (repository_copy / "SKILL.md").is_file():
        return repository_copy
    raise PerfLensError(
        ErrorCode.INTERNAL_ERROR,
        "skill_install",
        "The installed package does not contain the PerfLens Skill",
        suggested_actions=("Reinstall PerfLens from an official wheel or source distribution.",),
    )


def _existing_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "skill_install",
            f"{label} does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "skill_install",
            f"{label} must be a directory",
            details={"path": str(resolved)},
        )
    return resolved


def _safe_child_directory(parent: Path, name: str) -> Path:
    candidate = parent / name
    if not candidate.exists() and not candidate.is_symlink():
        try:
            candidate.mkdir()
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "skill_install",
                "Unable to create the Skill parent directory",
                details={"path": str(candidate)},
            ) from exc
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "Skill parent directory cannot be resolved safely",
            details={"path": str(candidate)},
        ) from exc
    if not resolved.is_dir() or not resolved.is_relative_to(parent):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "Skill parent directory escapes the selected project",
            details={"path": str(resolved), "project_root": str(parent)},
        )
    return resolved


def _copy_resource_tree(source: Traversable, target: Path, *, budget: _CopyBudget) -> None:
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        destination = target / child.name
        if child.is_dir():
            destination.mkdir()
            _copy_resource_tree(child, destination, budget=budget)
            continue
        if not child.is_file():
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "skill_install",
                "Bundled Skill contains an unsupported resource",
                details={"name": child.name},
            )
        data = child.read_bytes()
        budget.files += 1
        budget.bytes += len(data)
        if budget.files > _MAX_SKILL_FILES or budget.bytes > _MAX_SKILL_BYTES:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "skill_install",
                "Bundled Skill exceeds the installation resource limits",
                details={
                    "files": budget.files,
                    "bytes": budget.bytes,
                    "max_files": _MAX_SKILL_FILES,
                    "max_bytes": _MAX_SKILL_BYTES,
                },
            )
        with destination.open("xb") as handle:
            handle.write(data)


def _resource_fingerprint(source: Traversable, *, budget: _CopyBudget) -> str:
    digest = hashlib.sha256()
    _update_resource_fingerprint(source, "", digest, budget=budget)
    return digest.hexdigest()


def _update_resource_fingerprint(
    source: Traversable,
    prefix: str,
    digest: _Digest,
    *,
    budget: _CopyBudget,
) -> None:
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        relative = f"{prefix}/{child.name}" if prefix else child.name
        if child.is_dir():
            _update_resource_fingerprint(child, relative, digest, budget=budget)
            continue
        if not child.is_file():
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "skill_install",
                "Bundled Skill contains an unsupported resource",
                details={"name": relative},
            )
        data = child.read_bytes()
        _update_fingerprint_budget(budget, len(data))
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")


def _path_fingerprint(
    root: Path,
    directory: Path,
    *,
    budget: _CopyBudget,
) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise _modified_skill_error(path)
        if path.is_dir():
            continue
        if not path.is_file():
            raise _modified_skill_error(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise _modified_skill_error(path) from exc
        _update_fingerprint_budget(budget, len(data))
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _update_fingerprint_budget(budget: _CopyBudget, size: int) -> None:
    budget.files += 1
    budget.bytes += size
    if budget.files > _MAX_SKILL_FILES or budget.bytes > _MAX_SKILL_BYTES:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "skill_install",
            "PerfLens Skill exceeds the verification resource limits",
            details={"files": budget.files, "bytes": budget.bytes},
        )


def _modified_skill_error(path: Path) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "skill_install",
        "Project PerfLens Skill is modified, unverified, or unsafe and was preserved",
        recoverable=True,
        details={"path": str(path)},
        suggested_actions=(
            "Review the Skill directory and remove it manually only if the changes are disposable.",
        ),
    )
