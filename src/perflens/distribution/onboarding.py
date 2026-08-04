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
from perflens.distribution.codex import render_codex_config
from perflens.distribution.collector import install_collector_assets
from perflens.distribution.skill import SKILL_NAME, install_project_skill
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_GUIDE_BYTES = 256 << 10
_MAX_SETUP_JSON_BYTES = 1 << 20
_NATIVE_MAIN_COMMAND = Path("/usr/bin/perflens")
_NATIVE_COLLECTOR_COMMAND = Path("/usr/bin/perflens-collector")
_WHEEL_COLLECTOR_COMMAND = Path("/opt/perflens/bin/perflens-collector")


def run_project_setup(
    project_root: Path,
    *,
    output_directory: Path | None = None,
    install_skill: bool = True,
    allow_process_execution: bool = False,
    mcp_command: Path | None = None,
    prepare_collector: bool = False,
    automatic_collection: bool = False,
    collector_uid: int | None = None,
    collector_command: Path | None = None,
    perf_path: Path = Path("/usr/bin/perf"),
) -> SetupArtifact:
    """Create a bounded onboarding bundle inside one selected project."""
    project = _existing_project(project_root)
    selected_collector_command = (
        _collector_command_for_setup(collector_command)
        if prepare_collector
        else collector_command or _WHEEL_COLLECTOR_COMMAND
    )
    admin_command = selected_collector_command.with_name("perflens-admin")
    output = _new_output_directory(project, output_directory)
    skill_path, skill_status = _skill_preflight(project, install_skill=install_skill)
    configuration = render_codex_config(
        project,
        allow_process_execution=allow_process_execution,
        automatic_collection=automatic_collection,
        allow_project_execution=automatic_collection,
        mcp_command=mcp_command,
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
    )

    created = False
    installed_skill = False
    try:
        output.mkdir()
        created = True
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
            ),
            english_guide_path,
            max_output_bytes=_MAX_GUIDE_BYTES,
        )

        collector_assets_path: Path | None = None
        if prepare_collector:
            collector_assets_path = install_collector_assets(
                output / "collector-assets",
                allowed_uids=(selected_uid,),
                collector_command=selected_collector_command,
                perf_path=perf_path,
            )

        if skill_status == "installed":
            skill_path = install_project_skill(project)
            installed_skill = True

        generated = [
            mcp_config_path,
            capability_path,
            chinese_guide_path,
            english_guide_path,
        ]
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
            mcp_config_path=str(mcp_config_path),
            capability_report_path=str(capability_path),
            collector_assets_path=(
                str(collector_assets_path) if collector_assets_path is not None else None
            ),
            automatic_collection_enabled=automatic_collection,
            collection_status=collection_status,
            blocked_modes=blocked_modes,
            generated_files=tuple(str(path) for path in generated),
            next_steps=next_steps,
        )
        write_json_new_atomic(artifact, setup_path, max_output_bytes=_MAX_SETUP_JSON_BYTES)
        return artifact
    except BaseException:
        if created:
            shutil.rmtree(output, ignore_errors=True)
        if installed_skill and skill_path is not None:
            shutil.rmtree(skill_path, ignore_errors=True)
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


def _new_output_directory(project: Path, requested: Path | None) -> Path:
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
    if output.exists() or output.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Setup output directory already exists and will not be overwritten",
            recoverable=True,
            details={"path": str(output)},
        )
    return output


def _skill_preflight(
    project: Path, *, install_skill: bool
) -> tuple[Path | None, Literal["installed", "existing", "skipped"]]:
    target = project / ".agents" / "skills" / SKILL_NAME
    if not install_skill:
        return None, "skipped"
    if not target.exists() and not target.is_symlink():
        return target, "installed"
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing Skill path cannot be resolved safely",
            details={"path": str(target)},
        ) from exc
    if (
        target.is_symlink()
        or not resolved.is_relative_to(project)
        or not resolved.is_dir()
        or not (resolved / "SKILL.md").is_file()
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "setup",
            "Existing PerfLens Skill path is incomplete or unsafe",
            details={"path": str(target)},
        )
    return resolved, "existing"


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
) -> tuple[str, ...]:
    steps = [
        f"Review {output / '下一步.zh-CN.md'}.",
        f"Merge {output / 'codex-mcp.toml'} into the user's Codex config, then restart Codex.",
        f"Ask the Skill to analyze a profile inside {project}.",
    ]
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
) -> str:
    layout_note = _chinese_layout_note(admin_command, collector_command)
    policy_path = output / "collector-assets" / "collector.toml"
    dry_run_command = shlex.join(
        (str(admin_command), "deploy", "--config", str(policy_path), "--dry-run")
    )
    deploy_command = shlex.join(
        ("sudo", str(admin_command), "deploy", "--config", str(policy_path))
    )
    collector_section = (
        f"""
## 需要自动采集时

已生成 `{output / 'collector-assets'}`。
这些只是待管理员检查的模板；PerfLens 没有执行 sudo、修改 sysctl 或启动服务。
先检查 `{output / 'collector-assets' / 'collector.toml'}`，再由管理员执行：

```bash
{dry_run_command}
{deploy_command}
```

{layout_note}

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
## 4. 直接优化当前项目

MCP 配置已包含自动采集和普通用户项目执行能力。Collector 部署并验收后，可以说：

```text
使用 $perflens-performance-analysis 优化当前项目的运行性能。
允许运行 `{project}` 内已经确认的可执行文件，并对本次启动的进程
采集最多 10 秒；不要附加其他已有进程。
```

Skill 会先确认工作负载；PerfLens 再以当前普通用户启动它，内部取得本次进程的
PID 并交给 Collector。用户不需要查找或输入 PID。
"""
        if automatic_collection
        else """
## 4. 直接优化当前项目

本次 MCP 配置没有开启项目自动运行。需要该能力时，请使用一个新的输出目录重新运行
`perflens setup --automatic-collection`，并先完成 Collector 部署。
"""
    )
    return f"""# PerfLens 安装后的下一步

项目：`{project}`

## 1. MCP 配置

打开 `{output / 'codex-mcp.toml'}`，复制其中完整的
`[mcp_servers.perflens]` 配置块。Linux 上的用户配置通常是
`~/.codex/config.toml`；如果项目已经受信任，也可以放入项目的
`.codex/config.toml`。不要直接覆盖已有配置，保存后重启 Codex，
再执行 `codex mcp list` 检查 `perflens`。

## 2. Skill

PerfLens Skill 位于项目的 `.agents/skills/{SKILL_NAME}`。可以对 Codex 说：

```text
使用 $perflens-performance-analysis 分析这个项目的性能 Profile，区分直接证据、候选原因和缺失证据。
```

## 3. 当前采集检查

权限报告：`{output / 'collection-capabilities.json'}`

综合状态：`{_collection_status_chinese(capabilities)}`。这只是权限诊断，不是成功采样证明。
{collector_section}
{project_section}
## 5. 采集时长

实时采集不是固定 10 秒。自动计划默认 10 秒，用户可以在请求中调整，
但 MCP 和 Collector 都会执行各自的时长上限；当前默认上限是 30 秒。
`accept-collector` 使用内置测试负载完成部署验收，不需要输入 PID；默认 1 秒且最多 5 秒。

## 6. 获取帮助

```bash
perflens --help
perflens doctor
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
) -> str:
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
    return f"""# PerfLens next steps

Project: `{project}`

1. Merge `{output / 'codex-mcp.toml'}` into the user's Codex
   configuration without overwriting existing settings, then restart Codex.
2. Use the project Skill at `.agents/skills/{SKILL_NAME}` for evidence-first analysis.
3. Review `{output / 'collection-capabilities.json'}`; the aggregate status is
   `{_collection_status(capabilities)[0]}` and is not proof of successful sampling.
4. {collector}
5. Project workload execution is {'enabled' if automatic_collection else 'disabled'} in the
   generated MCP configuration. It always runs as the ordinary MCP user and still requires
   per-call authorization.

Run `perflens --help`, `perflens doctor`, or `perflens setup --help` for command help.
"""
