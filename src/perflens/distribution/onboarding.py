"""Safe, project-scoped onboarding without modifying host privilege settings."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
from pathlib import Path
from typing import Literal

from perflens import __version__
from perflens.artifacts.filesystem import write_json_new_atomic, write_text_atomic
from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.contracts.artifacts import CollectionCapabilityArtifact, SetupArtifact
from perflens.distribution.claude import (
    ClaudeConfigInstallPlan,
    plan_claude_project_config,
    plan_claude_project_config_removal,
    render_claude_config,
)
from perflens.distribution.codex import (
    CodexConfigInstallPlan,
    plan_codex_project_config,
    plan_codex_project_config_removal,
    render_codex_config,
)
from perflens.distribution.collector import install_collector_assets
from perflens.distribution.skill import (
    SKILL_NAME,
    SkillClient,
    bundled_skill_fingerprint,
    install_project_skill,
    project_skill_candidates,
    project_skill_fingerprint,
    project_skill_path,
    recorded_project_skill_path,
    refresh_project_skill,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_GUIDE_BYTES = 256 << 10
_MAX_SETUP_JSON_BYTES = 1 << 20
_NATIVE_MAIN_COMMAND = Path("/usr/bin/perflens")
_NATIVE_COLLECTOR_COMMAND = Path("/usr/bin/perflens-collector")
_WHEEL_COLLECTOR_COMMAND = Path("/opt/perflens/bin/perflens-collector")
_COLLECTOR_SPOOL_ROOT = Path("/var/lib/perflens")
_HELPER_SPOOL_ROOT = Path("/var/lib/perflens-helper")


def run_project_setup(
    project_root: Path,
    *,
    output_directory: Path | None = None,
    install_skill: bool = True,
    install_codex_config: bool = True,
    install_claude_skill: bool = False,
    install_claude_config: bool = False,
    codex_enabled: bool = True,
    claude_enabled: bool = False,
    allow_process_execution: bool = False,
    mcp_command: Path | None = None,
    prepare_collector: bool = False,
    automatic_collection: bool = False,
    allow_pid_attach: bool = False,
    automatic_modes: tuple[str, ...] = ("stat", "record"),
    automatic_max_duration_seconds: float = 30.0,
    automatic_max_frequency_hz: int = 99,
    automatic_max_output_bytes: int = 256 << 20,
    automatic_plan_ttl_seconds: int = 120,
    collector_uid: int | None = None,
    collector_command: Path | None = None,
    perf_path: Path = Path("/usr/bin/perf"),
    collector_privilege_mode: Literal["cap_perfmon", "paranoid3_helper"] = "cap_perfmon",
    update_existing: bool = False,
) -> SetupArtifact:
    """Create a bounded onboarding bundle inside one selected project."""
    project = _existing_project(project_root)
    selected_collector_command = (
        _collector_command_for_setup(collector_command)
        if prepare_collector
        else collector_command or _WHEEL_COLLECTOR_COMMAND
    )
    if (
        prepare_collector
        and collector_privilege_mode == "paranoid3_helper"
        and selected_collector_command != _NATIVE_COLLECTOR_COMMAND
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "setup",
            "paranoid3_helper requires the architecture-specific native Collector package",
            recoverable=True,
            suggested_actions=(
                "Install the matching perflens and perflens-collector DEBs, then rerun init.",
            ),
        )
    admin_command = selected_collector_command.with_name("perflens-admin")
    output, previous_artifact = _setup_output_state(
        project,
        output_directory,
        update_existing=update_existing,
    )
    if previous_artifact is not None and not prepare_collector:
        collector_privilege_mode = previous_artifact.collector_privilege_mode
    previous_claude_configuration = _previous_claude_configuration(
        project,
        previous_artifact,
    )
    _validate_disabled_clients_detached(
        project,
        previous_artifact,
        codex_enabled=codex_enabled,
        claude_enabled=claude_enabled,
        previous_claude_configuration=previous_claude_configuration,
    )
    skill_path, skill_status = _skill_preflight(
        project,
        install_skill=install_skill,
        client="codex",
        update_existing=update_existing,
        expected_fingerprint=(
            previous_artifact.skill_fingerprint if previous_artifact is not None else None
        ),
        recorded_path=(previous_artifact.skill_path if previous_artifact is not None else None),
    )
    claude_skill_path, claude_skill_status = _skill_preflight(
        project,
        install_skill=install_claude_skill,
        client="claude-code",
        update_existing=update_existing,
        expected_fingerprint=(
            previous_artifact.claude_skill_fingerprint if previous_artifact is not None else None
        ),
        recorded_path=(
            previous_artifact.claude_skill_path if previous_artifact is not None else None
        ),
    )
    collector_spool_root = (
        _HELPER_SPOOL_ROOT
        if collector_privilege_mode == "paranoid3_helper"
        else _COLLECTOR_SPOOL_ROOT
    )
    configuration = render_codex_config(
        project,
        allow_process_execution=allow_process_execution,
        automatic_collection=automatic_collection,
        allow_project_execution=automatic_collection,
        allow_pid_attach=allow_pid_attach,
        automatic_modes=automatic_modes,
        automatic_max_duration_seconds=automatic_max_duration_seconds,
        automatic_max_frequency_hz=automatic_max_frequency_hz,
        automatic_max_output_bytes=automatic_max_output_bytes,
        automatic_plan_ttl_seconds=automatic_plan_ttl_seconds,
        collector_spool_root=collector_spool_root,
        mcp_command=mcp_command,
    )
    codex_plan: CodexConfigInstallPlan | None = (
        plan_codex_project_config(project, configuration) if install_codex_config else None
    )
    claude_configuration = render_claude_config(
        project,
        allow_process_execution=allow_process_execution,
        automatic_collection=automatic_collection,
        allow_project_execution=automatic_collection,
        allow_pid_attach=allow_pid_attach,
        automatic_modes=automatic_modes,
        automatic_max_duration_seconds=automatic_max_duration_seconds,
        automatic_max_frequency_hz=automatic_max_frequency_hz,
        automatic_max_output_bytes=automatic_max_output_bytes,
        automatic_plan_ttl_seconds=automatic_plan_ttl_seconds,
        collector_spool_root=collector_spool_root,
        mcp_command=mcp_command,
    )
    claude_plan: ClaudeConfigInstallPlan | None = (
        plan_claude_project_config(
            project,
            claude_configuration,
            managed_configuration=previous_claude_configuration,
        )
        if install_claude_config
        else None
    )
    capabilities = inspect_collection_capabilities(perf_path)
    collection_status, blocked_modes = _collection_status(capabilities)
    selected_uid = os.geteuid() if collector_uid is None else collector_uid
    next_steps = _next_steps(
        project,
        output,
        prepare_collector=prepare_collector,
        automatic_collection=automatic_collection,
        collection_status=collection_status,
        admin_command=admin_command,
        codex_plan=codex_plan,
        claude_plan=claude_plan,
        codex_selected=codex_enabled,
        claude_selected=claude_enabled,
    )

    backup = _setup_backup_path(output) if previous_artifact is not None else None
    created = False
    installed_skill = False
    installed_claude_skill = False
    applied_codex_config = False
    applied_claude_config = False
    moved_collector_assets = False
    try:
        if backup is not None:
            output.rename(backup)
        output.mkdir()
        created = True
        preserved_collector_assets = (
            backup / "collector-assets"
            if backup is not None
            and not prepare_collector
            and (backup / "collector-assets").is_dir()
            else None
        )
        mcp_config_path = output / "codex-mcp.toml"
        capability_path = output / "collection-capabilities.json"
        chinese_guide_path = output / "下一步.zh-CN.md"
        english_guide_path = output / "NEXT_STEPS.md"
        write_text_atomic(configuration, mcp_config_path, max_output_bytes=_MAX_GUIDE_BYTES)
        write_json_new_atomic(
            capabilities,
            capability_path,
            max_output_bytes=_MAX_SETUP_JSON_BYTES,
        )
        write_text_atomic(
            _chinese_guide(
                project,
                output,
                capabilities,
                prepare_collector,
                automatic_collection,
                admin_command,
                selected_collector_command,
                codex_plan,
                claude_plan,
                codex_enabled,
                claude_enabled,
                collector_privilege_mode,
            ),
            chinese_guide_path,
            max_output_bytes=_MAX_GUIDE_BYTES,
        )
        write_text_atomic(
            _english_guide(
                project,
                output,
                capabilities,
                prepare_collector,
                automatic_collection,
                admin_command,
                selected_collector_command,
                codex_plan,
                claude_plan,
                codex_enabled,
                claude_enabled,
                collector_privilege_mode,
            ),
            english_guide_path,
            max_output_bytes=_MAX_GUIDE_BYTES,
        )
        claude_mcp_config_path = output / "claude-mcp.json"
        write_text_atomic(
            claude_configuration,
            claude_mcp_config_path,
            max_output_bytes=_MAX_GUIDE_BYTES,
        )

        collector_assets_path: Path | None = None
        if prepare_collector:
            collector_assets_path = install_collector_assets(
                output / "collector-assets",
                allowed_uids=(selected_uid,),
                collector_command=selected_collector_command,
                perf_path=perf_path,
                privilege_mode=collector_privilege_mode,
            )
        elif preserved_collector_assets is not None:
            collector_assets_path = output / "collector-assets"
            preserved_collector_assets.rename(collector_assets_path)
            moved_collector_assets = True

        if skill_status == "installed":
            skill_path = install_project_skill(project, client="codex")
            installed_skill = True
        elif skill_status == "updated":
            assert skill_path is not None

        if claude_skill_status == "installed":
            claude_skill_path = install_project_skill(project, client="claude-code")
            installed_claude_skill = True
        elif claude_skill_status == "updated":
            assert claude_skill_path is not None

        skill_fingerprint = _owned_skill_fingerprint(skill_path, status=skill_status)
        claude_skill_fingerprint = _owned_skill_fingerprint(
            claude_skill_path,
            status=claude_skill_status,
        )

        generated = [
            mcp_config_path,
            capability_path,
            chinese_guide_path,
            english_guide_path,
            claude_mcp_config_path,
        ]
        if codex_plan is not None and codex_plan.status != "existing":
            generated.append(codex_plan.path)
        if claude_plan is not None and claude_plan.status != "existing":
            generated.append(claude_plan.path)
        if collector_assets_path is not None:
            generated.extend(sorted(collector_assets_path.iterdir()))
        setup_path = output / "setup.json"
        generated.append(setup_path)
        artifact = SetupArtifact(
            perflens_version=__version__,
            project_root=str(project),
            output_directory=str(output),
            skill_status=skill_status,
            skill_path=str(skill_path) if skill_path is not None else None,
            skill_fingerprint=skill_fingerprint,
            mcp_config_path=str(mcp_config_path),
            codex_project_config_path=(str(codex_plan.path) if codex_plan is not None else None),
            codex_project_config_status=(
                codex_plan.status if codex_plan is not None else "skipped"
            ),
            claude_skill_status=claude_skill_status,
            claude_skill_path=(str(claude_skill_path) if claude_skill_path is not None else None),
            claude_skill_fingerprint=claude_skill_fingerprint,
            claude_mcp_config_path=str(claude_mcp_config_path),
            claude_project_config_path=(str(claude_plan.path) if claude_plan is not None else None),
            claude_project_config_status=(
                claude_plan.status if claude_plan is not None else "skipped"
            ),
            claude_project_config_managed=(
                claude_plan is not None
                and (
                    claude_plan.status in {"installed", "updated"}
                    or (
                        previous_artifact is not None
                        and previous_artifact.claude_project_config_managed
                    )
                )
            ),
            capability_report_path=str(capability_path),
            collector_assets_path=(
                str(collector_assets_path) if collector_assets_path is not None else None
            ),
            automatic_collection_enabled=automatic_collection,
            collector_privilege_mode=collector_privilege_mode,
            collection_status=collection_status,
            blocked_modes=blocked_modes,
            generated_files=tuple(str(path) for path in generated),
            next_steps=next_steps,
        )
        write_json_new_atomic(artifact, setup_path, max_output_bytes=_MAX_SETUP_JSON_BYTES)
        if codex_plan is not None:
            codex_plan.apply()
            applied_codex_config = codex_plan.status != "existing"
        if claude_plan is not None:
            claude_plan.apply()
            applied_claude_config = claude_plan.status != "existing"
        if skill_status == "updated":
            skill_path, _ = refresh_project_skill(
                project,
                client="codex",
                expected_fingerprint=_expected_skill_fingerprint(
                    previous_artifact,
                    client="codex",
                ),
                current_path=recorded_project_skill_path(
                    project,
                    client="codex",
                    recorded_path=(
                        previous_artifact.skill_path if previous_artifact is not None else None
                    ),
                ),
            )
        if claude_skill_status == "updated":
            claude_skill_path, _ = refresh_project_skill(
                project,
                client="claude-code",
                expected_fingerprint=_expected_skill_fingerprint(
                    previous_artifact,
                    client="claude-code",
                ),
                current_path=recorded_project_skill_path(
                    project,
                    client="claude-code",
                    recorded_path=(
                        previous_artifact.claude_skill_path
                        if previous_artifact is not None
                        else None
                    ),
                ),
            )
        if backup is not None:
            shutil.rmtree(backup)
        return artifact
    except BaseException:
        if applied_claude_config and claude_plan is not None:
            _rollback_config_plan(claude_plan)
        if applied_codex_config and codex_plan is not None:
            _rollback_config_plan(codex_plan)
        if moved_collector_assets and backup is not None and (output / "collector-assets").is_dir():
            (output / "collector-assets").rename(backup / "collector-assets")
        if created:
            shutil.rmtree(output, ignore_errors=True)
        if backup is not None and backup.exists() and not output.exists():
            backup.rename(output)
        if installed_skill and skill_path is not None:
            shutil.rmtree(skill_path, ignore_errors=True)
        if installed_claude_skill and claude_skill_path is not None:
            shutil.rmtree(claude_skill_path, ignore_errors=True)
        raise


def _existing_project(path: Path) -> Path:
    try:
        project = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "setup",
            "Project directory does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not project.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "setup",
            "Project path must be a directory",
            details={"path": str(project)},
        )
    return project


def _collector_command_for_setup(explicit: Path | None) -> Path:
    """Select a future Collector path without trusting PATH or writable launchers."""
    if explicit is not None:
        return explicit
    if _trusted_packaged_entrypoint(_NATIVE_COLLECTOR_COMMAND):
        return _NATIVE_COLLECTOR_COMMAND
    if _trusted_packaged_entrypoint(_NATIVE_MAIN_COMMAND):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "setup",
            "检测到系统安装的 PerfLens，但缺少 Collector 组件",
            recoverable=True,
            details={"missing_command": str(_NATIVE_COLLECTOR_COMMAND)},
            suggested_actions=(
                "安装同版本的 perflens-collector DEB/RPM 包后重新运行 setup。",
                "如果计划使用 wheel 布局，请显式传入 --collector-command。",
            ),
        )
    return _WHEEL_COLLECTOR_COMMAND


def _trusted_packaged_entrypoint(
    path: Path,
    *,
    native_parent: Path = Path("/usr/bin"),
    trusted_owner: int = 0,
) -> bool:
    """Accept only root-owned, non-writable native package entry points."""
    if path.parent != native_parent:
        return False
    try:
        entry_status = path.lstat()
        parent = path.parent.resolve(strict=True)
        parent_status = parent.stat()
        target = path.resolve(strict=True)
        target_status = target.stat()
        target_parent_status = target.parent.resolve(strict=True).stat()
    except OSError:
        return False
    if not stat.S_ISREG(target_status.st_mode) or target_status.st_mode & 0o111 == 0:
        return False
    protected = (parent_status, target_status, target_parent_status)
    if any(item.st_uid != trusted_owner or item.st_mode & 0o022 for item in protected):
        return False
    if entry_status.st_uid != trusted_owner:
        return False
    return stat.S_ISLNK(entry_status.st_mode) or entry_status.st_mode & 0o022 == 0


def _setup_output_state(
    project: Path,
    requested: Path | None,
    *,
    update_existing: bool,
) -> tuple[Path, SetupArtifact | None]:
    output = _output_path(project, requested)
    if not output.exists() and not output.is_symlink():
        return output, None
    if not update_existing:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Setup output directory already exists and will not be overwritten",
            recoverable=True,
            details={"path": str(output)},
            suggested_actions=("Rerun perflens init with --update after reviewing it.",),
        )
    if output.is_symlink() or not output.is_dir():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing setup path is unsafe and was preserved",
            details={"path": str(output)},
        )
    artifact_path = output / "setup.json"
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing setup directory has no trustworthy ownership record",
            details={"path": str(output)},
        )
    try:
        raw = artifact_path.read_bytes()
        if len(raw) > _MAX_SETUP_JSON_BYTES:
            raise ValueError("setup artifact exceeds its size limit")
        artifact = SetupArtifact.model_validate_json(raw)
        recorded_project = Path(artifact.project_root).resolve(strict=True)
        recorded_output = Path(artifact.output_directory).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing setup ownership record is invalid and was preserved",
            details={"path": str(artifact_path)},
        ) from exc
    if recorded_project != project or recorded_output != output:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing setup ownership does not match the selected project",
            details={"path": str(output), "project": str(project)},
        )
    _validate_setup_update_contents(output)
    return output, artifact


def _validate_setup_update_contents(output: Path) -> None:
    managed_names = {
        "NEXT_STEPS.md",
        "claude-mcp.json",
        "codex-mcp.toml",
        "collection-capabilities.json",
        "collector-assets",
        "setup.json",
        "下一步.zh-CN.md",
    }
    try:
        entries = tuple(output.iterdir())
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing setup directory cannot be inspected safely",
            details={"path": str(output)},
        ) from exc
    unknown = tuple(sorted(path.name for path in entries if path.name not in managed_names))
    if unknown:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing setup directory contains user files and was preserved",
            recoverable=True,
            details={"path": str(output), "unknown_entries": unknown},
            suggested_actions=(
                "Move user files outside perflens-setup before rerunning init --update.",
            ),
        )
    assets = output / "collector-assets"
    if assets.is_symlink() or (assets.exists() and not assets.is_dir()):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing Collector staging assets are unsafe and were preserved",
            details={"path": str(assets)},
        )


def _output_path(project: Path, requested: Path | None) -> Path:
    candidate = requested or Path("perflens-setup")
    if not candidate.is_absolute():
        candidate = project / candidate
    try:
        output = candidate.expanduser().resolve(strict=False)
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Setup output path cannot be resolved safely",
            details={"path": str(candidate)},
        ) from exc
    if not output.is_relative_to(project) or not parent.is_relative_to(project):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Setup output directory must remain inside the selected project",
            details={"path": str(output), "project": str(project)},
        )
    return output


def _previous_claude_configuration(
    project: Path,
    artifact: SetupArtifact | None,
) -> str | None:
    if artifact is None or not artifact.claude_project_config_managed:
        return None
    setup = Path(artifact.output_directory)
    path = setup / "claude-mcp.json"
    if not setup.is_relative_to(project) or path.is_symlink() or not path.is_file():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Recorded Claude MCP ownership file is missing or unsafe",
            details={"path": str(path)},
        )
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SETUP_JSON_BYTES:
            raise ValueError("Claude MCP ownership file exceeds its size limit")
        return raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Recorded Claude MCP ownership file is invalid",
            details={"path": str(path)},
        ) from exc


def _validate_disabled_clients_detached(
    project: Path,
    artifact: SetupArtifact | None,
    *,
    codex_enabled: bool,
    claude_enabled: bool,
    previous_claude_configuration: str | None,
) -> None:
    if artifact is None:
        return
    still_active: list[str] = []
    if not codex_enabled and artifact.codex_project_config_status != "skipped":
        try:
            codex_plan = plan_codex_project_config_removal(project)
        except PerfLensError:
            codex_plan = True
        if codex_plan is not None:
            still_active.append("codex")
    if (
        not codex_enabled
        and artifact.skill_status != "skipped"
        and any(
            path.exists() or path.is_symlink()
            for path in project_skill_candidates(project, client="codex")
        )
        and "codex" not in still_active
    ):
        still_active.append("codex")
    if not claude_enabled and artifact.claude_project_config_status != "skipped":
        try:
            claude_plan = plan_claude_project_config_removal(
                project,
                managed_configuration=previous_claude_configuration,
            )
        except PerfLensError:
            claude_plan = True
        if claude_plan is not None:
            still_active.append("claude-code")
    if (
        not claude_enabled
        and artifact.claude_skill_status != "skipped"
        and any(
            path.exists() or path.is_symlink()
            for path in project_skill_candidates(project, client="claude-code")
        )
        and "claude-code" not in still_active
    ):
        still_active.append("claude-code")
    if still_active:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "setup",
            "Disabled clients are still attached and were preserved",
            recoverable=True,
            details={"clients": still_active},
            suggested_actions=(
                "Run perflens detach --client CLIENT first, then rerun init --update.",
            ),
        )


def _setup_backup_path(output: Path) -> Path:
    backup = output.with_name(f".{output.name}.perflens-backup")
    if backup.exists() or backup.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Setup update backup path already exists",
            details={"path": str(backup)},
        )
    return backup


def _expected_skill_fingerprint(
    artifact: SetupArtifact | None,
    *,
    client: SkillClient,
) -> str:
    recorded = None
    if artifact is not None:
        recorded = (
            artifact.skill_fingerprint if client == "codex" else artifact.claude_skill_fingerprint
        )
    return recorded or bundled_skill_fingerprint()


def _owned_skill_fingerprint(
    path: Path | None,
    *,
    status: Literal["installed", "updated", "existing", "skipped"],
) -> str | None:
    if path is None or status == "skipped":
        return None
    bundled = bundled_skill_fingerprint()
    if status in {"installed", "updated"}:
        return bundled
    current = project_skill_fingerprint(path)
    if current == bundled:
        return bundled
    return None


def _rollback_config_plan(
    plan: CodexConfigInstallPlan | ClaudeConfigInstallPlan,
) -> None:
    if plan.status == "existing":
        return
    try:
        current = plan.path.read_text(encoding="utf-8") if plan.path.exists() else None
        if current != plan.content:
            return
        if plan.expected_content is None:
            plan.path.unlink()
        else:
            write_text_atomic(
                plan.expected_content,
                plan.path,
                max_output_bytes=_MAX_SETUP_JSON_BYTES,
            )
    except (OSError, PerfLensError):
        return


def _skill_preflight(
    project: Path,
    *,
    install_skill: bool,
    client: SkillClient,
    update_existing: bool,
    expected_fingerprint: str | None,
    recorded_path: str | None,
) -> tuple[
    Path | None,
    Literal["installed", "updated", "existing", "skipped"],
]:
    target = project_skill_path(project, client=client)
    if not install_skill:
        return None, "skipped"
    current_target = recorded_project_skill_path(
        project,
        client=client,
        recorded_path=recorded_path,
    )
    if not current_target.exists() and not current_target.is_symlink():
        return target, "installed"
    try:
        resolved = current_target.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing Skill path cannot be resolved safely",
            details={"path": str(current_target)},
        ) from exc
    if (
        current_target.is_symlink()
        or not resolved.is_relative_to(project)
        or not resolved.is_dir()
        or not (resolved / "SKILL.md").is_file()
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing PerfLens Skill path is incomplete or unsafe",
            details={"path": str(current_target)},
        )
    if update_existing:
        current = project_skill_fingerprint(resolved)
        expected = expected_fingerprint or bundled_skill_fingerprint()
        if current != expected:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "setup",
                "Existing PerfLens Skill was modified and was preserved",
                recoverable=True,
                details={"path": str(resolved)},
            )
        if current_target != target or current != bundled_skill_fingerprint():
            return target, "updated"
    return current_target, "existing"


def _collection_status(
    capabilities: CollectionCapabilityArtifact,
) -> tuple[Literal["available", "conditional", "blocked"], tuple[str, ...]]:
    blocked = tuple(mode.mode for mode in capabilities.modes if mode.status == "blocked")
    if len(blocked) == len(capabilities.modes):
        return "blocked", blocked
    if blocked or any(mode.status == "conditional" for mode in capabilities.modes):
        return "conditional", blocked
    return "available", ()


def _next_steps(
    project: Path,
    output: Path,
    *,
    prepare_collector: bool,
    automatic_collection: bool,
    collection_status: str,
    admin_command: Path,
    codex_plan: CodexConfigInstallPlan | None,
    claude_plan: ClaudeConfigInstallPlan | None,
    codex_selected: bool,
    claude_selected: bool,
) -> tuple[str, ...]:
    steps = [
        f"Review {output / '下一步.zh-CN.md'}.",
        f"Ask the Skill to analyze a profile inside {project}.",
    ]
    if codex_selected and codex_plan is None:
        steps.insert(
            1,
            f"Merge {output / 'codex-mcp.toml'} into the user's Codex config, then restart Codex.",
        )
    elif codex_plan is not None:
        steps.insert(1, f"Restart Codex; project MCP config is at {codex_plan.path}.")
    if claude_selected and claude_plan is None:
        steps.append(f"Merge {output / 'claude-mcp.json'} into the project .mcp.json.")
    elif claude_plan is not None:
        steps.append(
            "Approve the project MCP server in Claude Code; configuration is at "
            f"{claude_plan.path}."
        )
    if prepare_collector:
        steps.append(
            "Have an administrator review collector-assets/collector.toml, then run "
            f"{admin_command} deploy explicitly; setup never sudoed."
        )
    else:
        steps.append(
            "Rerun setup with --prepare-collector only when live PID collection is needed."
        )
    if automatic_collection:
        steps.append(
            "After Collector deployment, use the Skill to run and profile an exact project "
            "executable."
        )
    if collection_status != "available":
        steps.append("Review collection-capabilities.json before claiming live collection works.")
    return tuple(steps)


def _chinese_guide(
    project: Path,
    output: Path,
    capabilities: CollectionCapabilityArtifact,
    prepare_collector: bool,
    automatic_collection: bool = False,
    admin_command: Path = Path("/opt/perflens/bin/perflens-admin"),
    collector_command: Path = _WHEEL_COLLECTOR_COMMAND,
    codex_plan: CodexConfigInstallPlan | None = None,
    claude_plan: ClaudeConfigInstallPlan | None = None,
    codex_selected: bool = True,
    claude_selected: bool = False,
    collector_privilege_mode: Literal["cap_perfmon", "paranoid3_helper"] = "cap_perfmon",
) -> str:
    layout_note = _chinese_layout_note(admin_command, collector_command)
    policy_path = output / "collector-assets" / "collector.toml"
    status_command = _status_command(project, output)
    dry_run_command = shlex.join(
        (str(admin_command), "deploy", "--config", str(policy_path), "--dry-run")
    )
    deploy_arguments = ["sudo", str(admin_command), "deploy", "--config", str(policy_path)]
    if collector_privilege_mode == "paranoid3_helper":
        deploy_arguments.append("--acknowledge-privileged-helper-risk")
    deploy_command = shlex.join(deploy_arguments)
    privilege_note = (
        "当前选择 `paranoid3_helper`：保持 `perf_event_paranoid=3`，Python Broker 无权限，"
        "仅 Rust Helper 以 root 身份和 CAP_PERFMON/CAP_SYS_ADMIN/CAP_SYS_PTRACE 边界执行"
        "固定 PID 采集。"
        "该模式风险更高，正式部署必须带确认参数。"
        if collector_privilege_mode == "paranoid3_helper"
        else "当前选择默认 `cap_perfmon`：Collector 不以 root 运行；Debian "
        "`perf_event_paranoid=3` 下通常需管理员按威胁模型调整到 2。"
    )
    collector_section = (
        f"""
## 需要自动采集时

已生成 `{output / "collector-assets"}`。
这些只是待管理员检查的模板；PerfLens 没有执行 sudo、修改 sysctl 或启动服务。
先检查 `{output / "collector-assets" / "collector.toml"}`，再由管理员执行：

```bash
{dry_run_command}
{deploy_command}
```

{layout_note}

{privilege_note}

部署命令默认输出中文摘要：预检会明确说明“尚未修改系统”，正式部署会明确说明健康
握手是否通过，并给出重新登录和普通用户验收步骤。自动化程序需要完整版本化结果时
给命令加 `--json`。

部署器只接受配置数据，不会修改 sysctl；安装后仍要以普通用户运行
`perflens accept-collector --authorize-host-acceptance`。
"""
        if prepare_collector
        else """
## 需要自动采集时

本次没有生成 Collector 资产。确认确实需要实时 PID 采集后，使用新的输出目录重新运行：

```bash
perflens setup --project <项目> --prepare-collector --automatic-collection
```

普通 Profile 分析不需要 Collector 或 root。
"""
    )
    project_section = (
        f"""
## 6. 直接优化当前项目

MCP 配置已包含自动采集和普通用户项目执行能力。Collector 部署并验收后，可以说：

```text
使用 $perflens 优化当前项目的运行性能。
允许运行 `{project}` 内已经确认的可执行文件，并对本次启动的进程
采集最多 10 秒；不要附加其他已有进程。
```

Skill 会先确认工作负载；PerfLens 再以当前普通用户启动它，内部取得本次进程的
PID 并交给 Collector。用户不需要查找或输入 PID。
"""
        if automatic_collection
        else """
## 6. 直接优化当前项目

本次 MCP 配置没有开启项目自动运行。需要该能力时，请使用一个新的输出目录重新运行
`perflens setup --automatic-collection`，并先完成 Collector 部署。
"""
    )
    codex_section = (
        f"""项目级配置已安全{_codex_status_chinese(codex_plan.status)}到
`{codex_plan.path}`。PerfLens 只管理带有明确 PerfLens 托管标记的 MCP 配置块；
已有其他 Codex 设置会保留。现在重启 Codex，再执行 `codex mcp list` 检查 `perflens`。

同时保留了 `{output / "codex-mcp.toml"}` 作为可检查、可迁移的独立配置片段。
"""
        if codex_plan is not None
        else (
            f"""本次使用了 `--skip-codex-config`，没有修改项目的 Codex 配置。打开
`{output / "codex-mcp.toml"}`，复制其中完整的 `[mcp_servers.perflens]` 配置块到
项目 `.codex/config.toml` 或用户配置；不要覆盖已有设置。保存后重启 Codex，再执行
`codex mcp list` 检查 `perflens`。
"""
            if codex_selected
            else "当前项目没有启用 Codex 集成，因此 Codex 不会发现 PerfLens。\n"
        )
    )
    claude_section = (
        f"""## 3. Claude Code (已启用)

项目级 MCP 配置已安全{_codex_status_chinese(claude_plan.status)}到
`{claude_plan.path}`，项目 Skill 位于 `.claude/skills/{SKILL_NAME}`。
首次创建顶层 `.claude/skills` 后重新启动 Claude Code，检查并批准项目
`.mcp.json` 中的 `perflens` 服务，然后可以说：

```text
使用 /{SKILL_NAME} 分析并优化当前项目的运行性能。
```

Claude Code 会在首次使用项目级 MCP 时单独请求信任；PerfLens 不会代替用户批准。
独立配置副本保存在 `{output / "claude-mcp.json"}`。
"""
        if claude_plan is not None
        else (
            f"""## 3. Claude Code (需手动接入)

本次没有修改 `.mcp.json`。请检查 `{output / "claude-mcp.json"}` 后手动合并，
项目 Skill 位于 `.claude/skills/{SKILL_NAME}`。
"""
            if claude_selected
            else f"""## 3. Claude Code (未启用)

当前项目没有安装 Claude Code Skill，也没有写入 `.mcp.json`，所以 Claude Code
不会发现 PerfLens。需要时在一个尚未初始化的项目运行
`perflens init --client claude-code`。可检查的配置模板保存在
`{output / "claude-mcp.json"}`。
"""
        )
    )
    codex_skill_section = (
        f"""## 2. Codex Skill

PerfLens Skill 位于项目的 `.agents/skills/{SKILL_NAME}`。可以对 Codex 说：

```text
使用 $perflens 分析这个项目的性能 Profile，区分直接证据、候选原因和缺失证据。
```
"""
        if codex_selected
        else """## 2. Codex Skill (未启用)

当前项目没有安装 Codex Skill，也没有写入 `.codex/config.toml`。
"""
    )
    return f"""# PerfLens 安装后的下一步

项目：`{project}`

## 1. MCP 配置

{codex_section}

{codex_skill_section}

{claude_section}
## 4. 当前采集检查

权限报告：`{output / "collection-capabilities.json"}`

综合状态：`{_collection_status_chinese(capabilities)}`。这只是权限诊断，不是成功采样证明。
{collector_section}
## 5. 一条命令检查当前状态

以后不需要重新记住部署排错命令，直接运行本次引导对应的只读检查：

```bash
{status_command}
```

如果运行 setup 时使用了自定义输出目录，必须保留这里的 `--setup-directory`，否则可能
检查到另一次旧引导。该命令不会运行 perf、修改系统或写入 Collector spool。

{project_section}
## 7. 采集时长

实时采集不是固定 10 秒。自动计划默认 10 秒，用户可以在请求中调整，
但 MCP 和 Collector 都会执行各自的时长上限；当前默认上限是 30 秒。
`accept-collector` 使用内置测试负载完成部署验收，不需要输入 PID；默认 1 秒且最多 5 秒。

## 8. 获取帮助

```bash
perflens --help
perflens doctor
perflens init --help
perflens setup --help
```
"""


def _collection_status_chinese(capabilities: CollectionCapabilityArtifact) -> str:
    status = _collection_status(capabilities)[0]
    return {
        "available": "可用",
        "conditional": "部分受限",
        "blocked": "当前不可用",
    }[status]


def _codex_status_chinese(status: str) -> str:
    return {"installed": "安装", "updated": "更新", "existing": "确认已存在"}[status]


def _status_command(project: Path, output: Path) -> str:
    return shlex.join(
        (
            "perflens",
            "status",
            "--project",
            str(project),
            "--setup-directory",
            str(output),
        )
    )


def _chinese_layout_note(admin_command: Path, collector_command: Path) -> str:
    if collector_command == _NATIVE_COLLECTOR_COMMAND:
        return (
            "已安全识别系统包布局；管理员入口使用 "
            f"`{admin_command}`，Collector 入口使用 `{collector_command}`。"
        )
    return (
        "当前按 wheel 独立环境布局生成；执行前应先把同版本 wheel 安装到 "
        f"`{collector_command.parent}`。如果实际路径不同，请重新运行 setup 并传入 "
        "`--collector-command`，不要手改 systemd unit。"
    )


def _english_guide(
    project: Path,
    output: Path,
    capabilities: CollectionCapabilityArtifact,
    prepare_collector: bool,
    automatic_collection: bool = False,
    admin_command: Path = Path("/opt/perflens/bin/perflens-admin"),
    collector_command: Path = _WHEEL_COLLECTOR_COMMAND,
    codex_plan: CodexConfigInstallPlan | None = None,
    claude_plan: ClaudeConfigInstallPlan | None = None,
    codex_selected: bool = True,
    claude_selected: bool = False,
    collector_privilege_mode: Literal["cap_perfmon", "paranoid3_helper"] = "cap_perfmon",
) -> str:
    status_command = _status_command(project, output)
    layout = (
        "A trusted native package layout was detected."
        if collector_command == _NATIVE_COLLECTOR_COMMAND
        else "This bundle targets the isolated wheel layout under /opt/perflens."
    )
    collector = (
        "Administrator-reviewed Collector assets were generated. Validate the TOML with "
        f"`{admin_command} deploy --config <toml> --dry-run`, then have an "
        "administrator run the same command with sudo and without `--dry-run`. Then run "
        "`perflens accept-collector --authorize-host-acceptance` as the ordinary user. "
        "Deployment is Chinese-first; add `--json` for the complete versioned artifact. "
        f"{layout}"
        if prepare_collector
        else "No Collector assets were generated; existing-profile analysis needs no privilege."
    )
    codex = (
        f"Project MCP configuration was safely {codex_plan.status} at `{codex_plan.path}`; "
        "restart Codex and run `codex mcp list`. The standalone codex-mcp.toml remains "
        "available for review and migration."
        if codex_plan is not None
        else (
            "No project configuration was changed. Merge codex-mcp.toml manually, restart "
            "Codex, and run `codex mcp list`."
            if codex_selected
            else "Codex integration is not activated for this project."
        )
    )
    claude = (
        f"Claude Code project MCP configuration is {claude_plan.status} at "
        f"`{claude_plan.path}` and its Skill is under `.claude/skills/{SKILL_NAME}`. "
        "Restart Claude Code when the top-level skills directory is new, then approve the "
        "project MCP server when prompted."
        if claude_plan is not None
        else (
            "Claude Code Skill was installed but .mcp.json was not changed; merge "
            "claude-mcp.json manually."
            if claude_selected
            else "Claude Code was not activated for this project. Run "
            "`perflens init --client claude-code` in a new project to opt in."
        )
    )
    return f"""# PerfLens next steps

Project: `{project}`

1. {codex}
2. {claude}
3. Use the selected project Skill for evidence-first analysis.
4. Review `{output / "collection-capabilities.json"}`; the aggregate status is
   `{_collection_status(capabilities)[0]}` and is not proof of successful sampling.
5. {collector}
6. Project workload execution is {"enabled" if automatic_collection else "disabled"} in the
   generated MCP configuration. It always runs as the ordinary MCP user and still requires
   per-call authorization.
7. Recheck this exact onboarding bundle with `{status_command}`. Keep
   `--setup-directory` when a custom output directory was used; the command is read-only.

Run `perflens --help`, `perflens doctor`, `perflens init --help`, or
`perflens setup --help` for command help.
"""
