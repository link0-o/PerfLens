"""PerfLens command-line interface."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import typer
from pydantic import TypeAdapter, ValidationError

from perflens import __version__
from perflens.application.analyze import analyze_folded, analyze_perf_data, analyze_perf_script
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.compare import (
    compare_analysis_files,
    compare_benchmark_files,
    normalize_benchmark,
)
from perflens.application.diagnose import classify_analysis, load_analysis, report_analysis
from perflens.application.symbols import get_source_context, inspect_elf, resolve_source
from perflens.application.trace_evidence import validate_trace_evidence_invariants
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.application.verify_trace import (
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
from perflens.artifacts.filesystem import (
    write_json_atomic,
    write_json_new_atomic,
    write_text_atomic,
)
from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_STAT_EVENTS,
    HARDWARE_STAT_EVENTS,
    PID_ATTACH_AUTHORIZATION,
    CollectionRequest,
    CollectionTarget,
    collect_profile,
)
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionCapabilityArtifact,
    CollectorAcceptanceArtifact,
    ProjectDetachmentArtifact,
    RuntimeStatusArtifact,
)
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceEvidenceArtifact,
)
from perflens.distribution.acceptance import accept_collector
from perflens.distribution.claude import render_claude_config
from perflens.distribution.codex import render_codex_config
from perflens.distribution.collector import install_collector_assets
from perflens.distribution.detach import detach_project_integration
from perflens.distribution.onboarding import run_project_setup
from perflens.distribution.skill import install_project_skill
from perflens.distribution.status import inspect_runtime_status
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.error_presentation import (
    ERROR_EXIT_CODES,
    configure_json_errors,
    error_json,
    json_errors_enabled,
    render_error_chinese,
)
from perflens.reporting.diff import render_benchmark_comparison, render_profile_comparison
from perflens.security.paths import (
    validate_input_file,
    validate_new_output_file,
    validate_output_file,
)

type TraceAnalysisArtifact = (
    SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact
)
_TRACE_ANALYSIS_ADAPTER: TypeAdapter[TraceAnalysisArtifact] = TypeAdapter(
    SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact
)

app = typer.Typer(
    name="perflens",
    help="基于证据的 Linux 性能分析工具。",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)


@app.callback(invoke_without_command=True)
def root(
    version: Annotated[
        bool,
        typer.Option("--version", help="显示 PerfLens 版本并退出。", is_eager=True),
    ] = False,
    json_errors: Annotated[
        bool,
        typer.Option(
            "--json-errors",
            help="为自动化程序输出完整、带版本的 JSON 错误。",
            envvar="PERFLENS_JSON_ERRORS",
        ),
    ] = False,
) -> None:
    """运行确定性的 PerfLens 分析命令。"""
    configure_json_errors(json_errors)
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("install-skill")
def install_skill_command(
    project_root: Annotated[
        Path,
        typer.Option(
            "--project",
            file_okay=False,
            help="用于安装 .agents/skills 的现有项目根目录。",
        ),
    ] = Path("."),
    client: Annotated[
        Literal["codex", "claude-code"],
        typer.Option("--client", help="安装 Skill 的项目客户端。"),
    ] = "codex",
) -> None:
    """把内置的性能分析 Skill 安装到项目中。"""
    try:
        target = install_project_skill(project_root, client=client)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(target))


@app.command("codex-config")
def codex_config_command(
    workspace: Annotated[
        Path,
        typer.Option("--workspace", file_okay=False, help="允许访问的工作区根目录。"),
    ] = Path("."),
    artifact_root: Annotated[
        Path | None,
        typer.Option("--artifact-root", file_okay=False, help="MCP 产物保存目录。"),
    ] = None,
    allow_process_execution: Annotated[
        bool,
        typer.Option(
            "--allow-process-execution",
            help="允许有界的 perf.data 转换和源码符号化。",
        ),
    ] = False,
    mcp_command: Annotated[
        Path | None,
        typer.Option("--mcp-command", dir_okay=False, help="可信 perflens-mcp 入口路径。"),
    ] = None,
) -> None:
    """输出项目级 Codex MCP TOML 配置片段。"""
    try:
        configuration = render_codex_config(
            workspace,
            artifact_root=artifact_root,
            allow_process_execution=allow_process_execution,
            mcp_command=mcp_command,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(configuration, nl=False)


@app.command("claude-config")
def claude_config_command(
    workspace: Annotated[
        Path,
        typer.Option("--workspace", file_okay=False, help="允许访问的工作区根目录。"),
    ] = Path("."),
    artifact_root: Annotated[
        Path | None,
        typer.Option("--artifact-root", file_okay=False, help="MCP 产物保存目录。"),
    ] = None,
    allow_process_execution: Annotated[
        bool,
        typer.Option(
            "--allow-process-execution",
            help="允许有界的 perf.data 转换和源码符号化。",
        ),
    ] = False,
    mcp_command: Annotated[
        Path | None,
        typer.Option("--mcp-command", dir_okay=False, help="可信 perflens-mcp 入口路径。"),
    ] = None,
) -> None:
    """输出项目级 Claude Code MCP JSON 配置。"""
    try:
        configuration = render_claude_config(
            workspace,
            artifact_root=artifact_root,
            allow_process_execution=allow_process_execution,
            mcp_command=mcp_command,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(configuration, nl=False)


@app.command("doctor")
def doctor_command(
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="可选的新 JSON 输出路径。"),
    ] = None,
    perf_path: Annotated[
        Path | None,
        typer.Option("--perf-path", dir_okay=False, help="明确指定系统 perf 程序。"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整、带版本的能力 JSON。"),
    ] = False,
) -> None:
    """显示只读的中文采集权限摘要。"""
    try:
        artifact = inspect_collection_capabilities(perf_path)
        if output_path is not None:
            safe_output = validate_new_output_file(output_path)
            write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)
            typer.echo(str(safe_output))
            return
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(
            json.dumps(
                artifact.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return
    _render_doctor_chinese(artifact)


@app.command("status")
def status_command(
    project_root: Annotated[
        Path,
        typer.Option("--project", file_okay=False, help="需要检查的项目根目录。"),
    ] = Path("."),
    setup_directory: Annotated[
        Path,
        typer.Option(
            "--setup-directory",
            file_okay=False,
            help="项目中的 setup 引导目录。",
        ),
    ] = Path("perflens-setup"),
    collector_socket: Annotated[
        Path,
        typer.Option("--collector-socket", dir_okay=False, help="Collector Unix Socket 路径。"),
    ] = Path("/run/perflens/collector.sock"),
    perf_path: Annotated[
        Path | None,
        typer.Option("--perf-path", dir_okay=False, help="明确指定系统 perf 程序。"),
    ] = None,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="可选的新 JSON 输出路径。"),
    ] = None,
) -> None:
    """只读检查项目与 Collector 是否就绪, 并输出中文摘要。"""
    try:
        artifact = inspect_runtime_status(
            project_root,
            setup_directory=setup_directory,
            collector_socket=collector_socket,
            perf_path=perf_path,
        )
        if output_path is not None:
            safe_output = validate_new_output_file(output_path)
            write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)
            typer.echo(str(safe_output))
            return
    except PerfLensError as exc:
        _fail(exc)
    _render_status_chinese(artifact)


@app.command("init")
def init_command(
    project_root: Annotated[
        Path,
        typer.Argument(
            file_okay=False,
            help="要按需启用 PerfLens 的项目, 默认是当前目录。",
        ),
    ] = Path("."),
    setup_directory: Annotated[
        Path,
        typer.Option(
            "--setup-directory",
            file_okay=False,
            help="项目内的托管引导目录, 默认是 perflens-setup。",
        ),
    ] = Path("perflens-setup"),
    client: Annotated[
        Literal["all", "codex", "claude-code"],
        typer.Option(
            "--client",
            help="要在当前项目激活的 AI 客户端, 默认同时支持两者。",
        ),
    ] = "all",
    automatic_collection: Annotated[
        bool,
        typer.Option(
            "--automatic-collection/--read-only",
            help="启用有界项目运行和自动采集, --read-only 只分析已有证据。",
        ),
    ] = True,
    automatic_modes: Annotated[
        list[str] | None,
        typer.Option(
            "--automatic-mode",
            help="允许的自动采集模式; 可重复传入, 默认 stat 和 record。",
        ),
    ] = None,
    automatic_max_duration_seconds: Annotated[
        float,
        typer.Option(
            "--automatic-max-duration-seconds",
            min=0.001,
            max=86_400,
            help="MCP 自动采集单次最长秒数。",
        ),
    ] = 30.0,
    automatic_max_frequency_hz: Annotated[
        int,
        typer.Option(
            "--automatic-max-frequency-hz",
            min=1,
            max=10_000,
            help="MCP record/off-CPU 最大采样频率 Hz。",
        ),
    ] = 99,
    automatic_max_output_bytes: Annotated[
        int,
        typer.Option(
            "--automatic-max-output-bytes",
            min=1,
            max=1 << 40,
            help="MCP 单次自动采集最大输出字节数。",
        ),
    ] = DEFAULT_MAX_OUTPUT_BYTES,
    automatic_plan_ttl_seconds: Annotated[
        int,
        typer.Option(
            "--automatic-plan-ttl-seconds",
            min=1,
            max=3600,
            help="一次性自动采集计划的有效秒数。",
        ),
    ] = 120,
    allow_existing_pid_attach: Annotated[
        bool,
        typer.Option(
            "--allow-existing-pid-attach",
            help="额外允许自动计划附加用户明确授权的已有 PID; 默认关闭。",
        ),
    ] = False,
    prepare_collector: Annotated[
        bool,
        typer.Option(
            "--prepare-collector",
            help="同时生成供管理员审查的 Collector 部署资产, 不会执行 sudo。",
        ),
    ] = False,
    collector_privilege_mode: Annotated[
        Literal["cap_perfmon", "paranoid3_helper"] | None,
        typer.Option(
            "--collector-privilege-mode",
            help=(
                "显式覆盖 Collector 权限模式; 默认安全识别主机已部署模式, "
                "未部署时使用 cap_perfmon。"
            ),
        ),
    ] = None,
    mcp_command: Annotated[
        Path | None,
        typer.Option("--mcp-command", dir_okay=False, help="可信 perflens-mcp 入口路径。"),
    ] = None,
    perf_path: Annotated[
        Path,
        typer.Option("--perf-path", dir_okay=False, help="系统 perf 程序的绝对路径。"),
    ] = Path("/usr/bin/perf"),
    update_existing: Annotated[
        bool,
        typer.Option(
            "--update",
            help="安全更新当前项目已有的 PerfLens 托管配置和未修改 Skill。",
        ),
    ] = False,
) -> None:
    """只在当前项目激活 PerfLens Skill 和 MCP, 未 init 的项目不可见。"""
    codex_selected = client in {"all", "codex"}
    claude_selected = client in {"all", "claude-code"}
    try:
        artifact = run_project_setup(
            project_root,
            output_directory=setup_directory,
            install_skill=codex_selected,
            install_codex_config=codex_selected,
            install_claude_skill=claude_selected,
            install_claude_config=claude_selected,
            codex_enabled=codex_selected,
            claude_enabled=claude_selected,
            allow_process_execution=automatic_collection,
            mcp_command=mcp_command,
            prepare_collector=prepare_collector,
            automatic_collection=automatic_collection,
            allow_pid_attach=allow_existing_pid_attach,
            automatic_modes=tuple(automatic_modes or ("stat", "record")),
            automatic_max_duration_seconds=automatic_max_duration_seconds,
            automatic_max_frequency_hz=automatic_max_frequency_hz,
            automatic_max_output_bytes=automatic_max_output_bytes,
            automatic_plan_ttl_seconds=automatic_plan_ttl_seconds,
            perf_path=perf_path,
            collector_privilege_mode=collector_privilege_mode,
            update_existing=update_existing,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo("PerfLens 已按项目激活, 其他未运行 init 的项目不会发现这些集成。")
    if update_existing:
        typer.echo("更新模式: 已重建托管引导; 客户端配置与 Skill 的用户修改不会被覆盖。")
    typer.echo(f"项目: {artifact.project_root}")
    if codex_selected:
        typer.echo(f"Codex Skill: {artifact.skill_path}")
        typer.echo(f"Codex MCP: {artifact.codex_project_config_path}")
    if claude_selected:
        typer.echo(f"Claude Code Skill: {artifact.claude_skill_path}")
        typer.echo(f"Claude Code MCP: {artifact.claude_project_config_path}")
    typer.echo(f"Collector 权限模式: {artifact.collector_privilege_mode}")
    typer.echo(f"Collector 功能配置: {artifact.collector_feature_profile}")
    typer.echo(f"自动采集: {'已启用 (仍需每次工作负载授权)' if automatic_collection else '未启用'}")
    typer.echo(f"中文下一步: {Path(artifact.output_directory) / '下一步.zh-CN.md'}")


@app.command("setup")
def setup_command(
    project_root: Annotated[
        Path,
        typer.Option(
            "--project",
            file_okay=False,
            help="用于安装 Skill 和引导文件的现有项目。",
        ),
    ] = Path("."),
    output_directory: Annotated[
        Path | None,
        typer.Option(
            "--output-directory",
            file_okay=False,
            help="项目内的新引导目录; 默认是 perflens-setup。",
        ),
    ] = None,
    update_existing: Annotated[
        bool,
        typer.Option(
            "--update",
            help="验证所有权后更新现有引导目录和未修改的托管接入。",
        ),
    ] = False,
    install_skill: Annotated[
        bool,
        typer.Option(
            "--install-skill/--skip-skill",
            help="尚未安装时安装内置 Skill。",
        ),
    ] = True,
    install_codex_config: Annotated[
        bool,
        typer.Option(
            "--install-codex-config/--skip-codex-config",
            help=("把生成的 MCP 表安全接入项目 .codex/config.toml。"),
        ),
    ] = True,
    install_claude_code: Annotated[
        bool,
        typer.Option(
            "--claude-code/--skip-claude-code",
            help="把 Skill 和 MCP 配置按项目接入 Claude Code。",
        ),
    ] = False,
    allow_process_execution: Annotated[
        bool,
        typer.Option(
            "--allow-process-execution",
            help="在 MCP 配置中开放有界 perf.data 转换和符号化。",
        ),
    ] = False,
    mcp_command: Annotated[
        Path | None,
        typer.Option("--mcp-command", dir_okay=False, help="可信 perflens-mcp 入口路径。"),
    ] = None,
    prepare_collector: Annotated[
        bool,
        typer.Option(
            "--prepare-collector",
            help="生成供管理员审查的 Collector 资产; 不会安装或提权。",
        ),
    ] = False,
    collector_privilege_mode: Annotated[
        Literal["cap_perfmon", "paranoid3_helper"] | None,
        typer.Option(
            "--collector-privilege-mode",
            help=(
                "显式覆盖 Collector 权限模式; 默认安全识别主机已部署模式, "
                "未部署时使用 cap_perfmon。"
            ),
        ),
    ] = None,
    automatic_collection: Annotated[
        bool,
        typer.Option(
            "--automatic-collection",
            help="为已授权的普通用户项目运行和采集生成 MCP 策略。",
        ),
    ] = False,
    automatic_modes: Annotated[
        list[str] | None,
        typer.Option(
            "--automatic-mode",
            help="允许的自动采集模式; 可重复传入, 默认 stat 和 record。",
        ),
    ] = None,
    automatic_max_duration_seconds: Annotated[
        float,
        typer.Option(
            "--automatic-max-duration-seconds",
            min=0.001,
            max=86_400,
            help="MCP 自动采集单次最长秒数。",
        ),
    ] = 30.0,
    automatic_max_frequency_hz: Annotated[
        int,
        typer.Option(
            "--automatic-max-frequency-hz",
            min=1,
            max=10_000,
            help="MCP record/off-CPU 最大采样频率 Hz。",
        ),
    ] = 99,
    automatic_max_output_bytes: Annotated[
        int,
        typer.Option(
            "--automatic-max-output-bytes",
            min=1,
            max=1 << 40,
            help="MCP 单次自动采集最大输出字节数。",
        ),
    ] = DEFAULT_MAX_OUTPUT_BYTES,
    automatic_plan_ttl_seconds: Annotated[
        int,
        typer.Option(
            "--automatic-plan-ttl-seconds",
            min=1,
            max=3600,
            help="一次性自动采集计划的有效秒数。",
        ),
    ] = 120,
    allow_existing_pid_attach: Annotated[
        bool,
        typer.Option(
            "--allow-existing-pid-attach",
            help="额外允许自动计划附加用户明确授权的已有 PID; 默认关闭。",
        ),
    ] = False,
    collector_uid: Annotated[
        int | None,
        typer.Option(
            "--collector-uid",
            min=0,
            help="写入 Collector 策略的普通用户 UID; 默认是当前 UID。",
        ),
    ] = None,
    collector_command: Annotated[
        Path | None,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help=(
                "未来使用的 Collector 绝对路径。优先识别可信 /usr/bin 包入口; "
                "否则生成 /opt/perflens wheel 部署布局。"
            ),
        ),
    ] = None,
    perf_path: Annotated[
        Path,
        typer.Option("--perf-path", dir_okay=False, help="系统 perf 程序的绝对路径。"),
    ] = Path("/usr/bin/perf"),
) -> None:
    """为一个项目生成安全、中文优先的安装引导。"""
    try:
        artifact = run_project_setup(
            project_root,
            output_directory=output_directory,
            install_skill=install_skill,
            install_codex_config=install_codex_config,
            install_claude_skill=install_claude_code,
            install_claude_config=install_claude_code,
            codex_enabled=True,
            claude_enabled=install_claude_code,
            allow_process_execution=allow_process_execution,
            mcp_command=mcp_command,
            prepare_collector=prepare_collector,
            automatic_collection=automatic_collection,
            allow_pid_attach=allow_existing_pid_attach,
            automatic_modes=tuple(automatic_modes or ("stat", "record")),
            automatic_max_duration_seconds=automatic_max_duration_seconds,
            automatic_max_frequency_hz=automatic_max_frequency_hz,
            automatic_max_output_bytes=automatic_max_output_bytes,
            automatic_plan_ttl_seconds=automatic_plan_ttl_seconds,
            collector_uid=collector_uid,
            collector_command=collector_command,
            perf_path=perf_path,
            collector_privilege_mode=collector_privilege_mode,
            update_existing=update_existing,
        )
    except PerfLensError as exc:
        _fail(exc)
    skill_label = {
        "installed": "已安装",
        "updated": "已安全更新",
        "existing": "已存在/未覆盖",
        "skipped": "已跳过",
    }[artifact.skill_status]
    collection_label = {
        "available": "可用",
        "conditional": "部分受限",
        "blocked": "当前不可用",
    }[artifact.collection_status]
    typer.echo("PerfLens 引导文件已经生成。")
    typer.echo(f"项目: {artifact.project_root}")
    typer.echo(f"Skill: {skill_label}")
    codex_label = {
        "installed": "已安装",
        "updated": "已更新 (保留其他设置)",
        "existing": "已存在且内容一致",
        "skipped": "已跳过 (需手动合并片段)",
    }[artifact.codex_project_config_status]
    typer.echo(f"Codex 项目配置: {codex_label}")
    if artifact.codex_project_config_path is not None:
        typer.echo(f"Codex 配置路径: {artifact.codex_project_config_path}")
    claude_skill_label = {
        "installed": "已安装",
        "updated": "已安全更新",
        "existing": "已存在/未覆盖",
        "skipped": "未启用",
    }[artifact.claude_skill_status]
    claude_config_label = {
        "installed": "已安装",
        "updated": "已更新 (保留其他 MCP 服务)",
        "existing": "已存在且内容一致",
        "skipped": "未启用",
    }[artifact.claude_project_config_status]
    typer.echo(f"Claude Code Skill: {claude_skill_label}")
    typer.echo(f"Claude Code 项目配置: {claude_config_label}")
    if artifact.claude_project_config_path is not None:
        typer.echo(f"Claude Code 配置路径: {artifact.claude_project_config_path}")
    typer.echo(f"采集状态: {collection_label}")
    typer.echo(f"Collector 权限模式: {artifact.collector_privilege_mode}")
    typer.echo(f"项目自动运行: {'已启用' if artifact.automatic_collection_enabled else '未启用'}")
    typer.echo(f"请继续阅读: {Path(artifact.output_directory) / '下一步.zh-CN.md'}")
    typer.echo(
        "检查当前状态: "
        + shlex.join(
            (
                "perflens",
                "status",
                "--project",
                artifact.project_root,
                "--setup-directory",
                artifact.output_directory,
            )
        )
    )


@app.command("detach")
def detach_command(
    project_root: Annotated[
        Path,
        typer.Option(
            "--project",
            file_okay=False,
            help="需要移除 PerfLens 托管 Codex MCP 配置块的项目。",
        ),
    ] = Path("."),
    client: Annotated[
        Literal["all", "codex", "claude-code"],
        typer.Option(
            "--client",
            help="解除接入的客户端, 默认同时处理 Codex 和 Claude Code。",
        ),
    ] = "all",
    keep_skills: Annotated[
        bool,
        typer.Option(
            "--keep-skills",
            help="只移除 MCP 配置, 保留项目 Skill; 默认移除未修改的托管 Skill。",
        ),
    ] = False,
    setup_directory: Annotated[
        Path,
        typer.Option(
            "--setup-directory",
            file_okay=False,
            help="用于验证配置和 Skill 所有权的项目引导目录。",
        ),
    ] = Path("perflens-setup"),
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只检查将移除的托管块, 不修改文件。"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整、带版本的解除接入结果。"),
    ] = False,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="可选的新 JSON 证据路径。"),
    ] = None,
) -> None:
    """解除项目 MCP 接入, 同时保留 Skill、引导文件和分析结果。"""
    try:
        safe_output = validate_new_output_file(output_path) if output_path is not None else None
        artifact = detach_project_integration(
            project_root,
            client=client,
            remove_skills=not keep_skills,
            setup_directory=setup_directory,
            dry_run=dry_run,
        )
        if safe_output is not None:
            write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(artifact.model_dump_json(indent=2))
        return
    _render_detachment_chinese(artifact, output_path=safe_output)


@app.command("stage-collector-assets")
def stage_collector_assets_command(
    output_directory: Annotated[
        Path,
        typer.Option(
            "--output-directory",
            file_okay=False,
            help="用于保存可检查服务模板的新目录。",
        ),
    ],
    allowed_uid: Annotated[
        int,
        typer.Option(
            "--allowed-uid",
            min=0,
            help="此 Collector 实例唯一允许的普通用户 UID。",
        ),
    ] = 1000,
    collector_command: Annotated[
        Path,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="写入 systemd unit 的 perflens-collector 绝对路径。",
        ),
    ] = Path("/usr/bin/perflens-collector"),
    perf_path: Annotated[
        Path,
        typer.Option(
            "--perf-path",
            dir_okay=False,
            help="写入 Collector 策略的 perf 绝对路径。",
        ),
    ] = Path("/usr/bin/perf"),
    privilege_mode: Annotated[
        Literal["cap_perfmon", "paranoid3_helper"],
        typer.Option(
            "--privilege-mode",
            help="写入策略的权限模式; paranoid3_helper 需要管理员显式风险确认。",
        ),
    ] = "cap_perfmon",
) -> None:
    """生成 Collector 策略和 systemd 模板, 不安装也不调用 sudo。"""
    try:
        target = install_collector_assets(
            output_directory,
            allowed_uids=(allowed_uid,),
            collector_command=collector_command,
            perf_path=perf_path,
            privilege_mode=privilege_mode,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(target))


@app.command("verify-collector")
def verify_collector_command(
    socket_path: Annotated[
        Path,
        typer.Option("--socket", dir_okay=False, help="现有 Collector Unix Socket。"),
    ],
    pid: Annotated[int, typer.Option("--pid", min=1, help="用于验收且归当前用户所有的实时 PID。")],
    duration_seconds: Annotated[
        float,
        typer.Option(
            "--duration-seconds",
            min=0.1,
            max=5.0,
            help="短时 perf stat 验收时长; 最多 5 秒。",
        ),
    ] = 1.0,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="可选的新 JSON 元数据路径。"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整、带版本的采集 JSON。"),
    ] = False,
    perf_path: Annotated[
        Path | None,
        typer.Option(
            "--perf-path",
            dir_okay=False,
            help="可选本机 perf 路径; 只用于生成能力快照。",
        ),
    ] = None,
    authorize_target: Annotated[
        bool,
        typer.Option("--authorize-target", help="确认已接受有界观测影响。"),
    ] = False,
    authorization: Annotated[
        str,
        typer.Option("--authorization", help="目标采集的完整显式授权短语。"),
    ] = "",
    authorize_pid_attach: Annotated[
        bool,
        typer.Option("--authorize-pid-attach", help="单独确认允许附加到 --pid。"),
    ] = False,
    pid_authorization: Annotated[
        str,
        typer.Option("--pid-authorization", help="PID 附加的完整显式授权短语。"),
    ] = "",
    event_source: Annotated[
        Literal["auto", "hardware_required", "software_only"],
        typer.Option(
            "--event-source",
            help="事件来源策略: auto 自动降级; hardware_required 必须硬件; software_only 仅软件。",
        ),
    ] = "auto",
) -> None:
    """通过已安装 Collector 执行一次有界真实 perf stat 验收。"""
    try:
        if not authorize_target or authorization != ACTIVE_COLLECTION_AUTHORIZATION:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collector verification requires explicit target authorization",
                recoverable=True,
                suggested_actions=(
                    "Pass --authorize-target and the documented --authorization token.",
                ),
            )
        if not authorize_pid_attach or pid_authorization != PID_ATTACH_AUTHORIZATION:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collector verification requires explicit PID attachment authorization",
                recoverable=True,
                suggested_actions=(
                    "Pass --authorize-pid-attach and the documented --pid-authorization token.",
                ),
            )
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=pid,
                duration_seconds=duration_seconds,
                events=HARDWARE_STAT_EVENTS,
                event_source=event_source,
                max_output_bytes=8 << 20,
            ),
            policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat",),
                max_duration_seconds=5.0,
                max_output_bytes=8 << 20,
                plan_ttl_seconds=60,
            ),
            capabilities=inspect_collection_capabilities(perf_path),
        )
        if plan.policy_status != "allowed":
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collector verification plan was denied",
                recoverable=True,
                details={"warnings": list(plan.warnings)},
            )
        artifact = CollectorBrokerClient(
            socket_path,
            timeout_seconds=duration_seconds + 15,
        ).collect(plan)
        if output_path is not None:
            safe_output = validate_new_output_file(output_path)
            write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)
            typer.echo(str(safe_output))
            return
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(
            json.dumps(
                artifact.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return
    _render_collector_verification_chinese(artifact)


@app.command("accept-collector")
def accept_collector_command(
    socket_path: Annotated[
        Path,
        typer.Option("--socket", dir_okay=False, help="已安装 Collector 的 Unix Socket。"),
    ] = Path("/run/perflens/collector.sock"),
    duration_seconds: Annotated[
        float,
        typer.Option(
            "--duration-seconds",
            min=0.1,
            max=5.0,
            help="内置 CPU 测试负载的采集时长; 最多 5 秒。",
        ),
    ] = 1.0,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="可选的新验收 JSON 路径。"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整、带版本的验收 JSON。"),
    ] = False,
    perf_path: Annotated[
        Path | None,
        typer.Option(
            "--perf-path",
            dir_okay=False,
            help="可选本机 perf 路径; 只用于生成能力快照。",
        ),
    ] = None,
    authorize_host_acceptance: Annotated[
        bool,
        typer.Option(
            "--authorize-host-acceptance",
            help="授权采集 PerfLens 固定且归自身所有的测试负载。",
        ),
    ] = False,
) -> None:
    """无需选择 PID, 端到端验收已安装的 Collector。"""
    try:
        artifact = accept_collector(
            socket_path,
            duration_seconds=duration_seconds,
            authorized=authorize_host_acceptance,
            capabilities=inspect_collection_capabilities(perf_path),
        )
        if output_path is not None:
            safe_output = validate_new_output_file(output_path)
            write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)
            typer.echo(f"Collector 验收通过: 证据已写入 {safe_output}")
            return
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(
            json.dumps(
                artifact.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return
    _render_collector_acceptance_chinese(artifact)


@app.command("analyze-folded")
def analyze_folded_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=False, dir_okay=False, help="Folded 栈输入文件。"),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="带版本的 JSON 输出产物。"),
    ],
    max_input_bytes: Annotated[int, typer.Option(min=1, help="允许读取的最大输入字节数。")] = 1
    << 30,
    max_records: Annotated[
        int, typer.Option(min=1, help="允许解析的最大样本记录数。")
    ] = 10_000_000,
    max_line_chars: Annotated[int, typer.Option(min=16, help="单行允许的最大字符数。")] = 1 << 20,
    max_stack_depth: Annotated[int, typer.Option(min=1, help="单条调用栈允许的最大深度。")] = 4_096,
    max_unique_frames: Annotated[
        int, typer.Option(min=1, help="允许保留的最大唯一栈帧数。")
    ] = 2_000_000,
    max_unique_call_paths: Annotated[
        int, typer.Option(min=1, help="允许保留的最大唯一调用路径数。")
    ] = 1_000_000,
    max_warnings: Annotated[int, typer.Option(min=0, help="产物中最多保留的解析警告数。")] = 100,
    top_n: Annotated[int, typer.Option("--top-n", min=1, help="最多输出的热点数量。")] = 10_000,
    call_path_limit: Annotated[int, typer.Option(min=1, help="最多输出的调用路径数量。")] = 1_000,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 128
    << 20,
) -> None:
    """分析标准 FlameGraph folded 栈。"""
    limits = ResourceLimits(
        max_input_bytes=max_input_bytes,
        max_records=max_records,
        max_line_chars=max_line_chars,
        max_stack_depth=max_stack_depth,
        max_unique_frames=max_unique_frames,
        max_unique_call_paths=max_unique_call_paths,
        max_warnings=max_warnings,
        max_hotspots_output=top_n,
        max_call_paths_output=call_path_limit,
        max_output_bytes=max_output_bytes,
    )
    try:
        artifact = analyze_folded(input_path, limits=limits)
        safe_output = validate_output_file(
            output_path,
            input_path=Path(artifact.metadata.input_path),
        )
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("analyze-perf-script")
def analyze_perf_script_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=False, dir_okay=False, help="perf script 文本输入。"),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="带版本的 JSON 输出产物。"),
    ],
    max_input_bytes: Annotated[int, typer.Option(min=1, help="允许读取的最大输入字节数。")] = 1
    << 30,
    max_records: Annotated[
        int, typer.Option(min=1, help="允许解析的最大样本记录数。")
    ] = 10_000_000,
    max_line_chars: Annotated[int, typer.Option(min=16, help="单行允许的最大字符数。")] = 1 << 20,
    max_stack_depth: Annotated[int, typer.Option(min=1, help="单条调用栈允许的最大深度。")] = 4_096,
    max_unique_frames: Annotated[
        int, typer.Option(min=1, help="允许保留的最大唯一栈帧数。")
    ] = 2_000_000,
    max_unique_call_paths: Annotated[
        int, typer.Option(min=1, help="允许保留的最大唯一调用路径数。")
    ] = 1_000_000,
    max_warnings: Annotated[int, typer.Option(min=0, help="产物中最多保留的解析警告数。")] = 100,
    top_n: Annotated[int, typer.Option("--top-n", min=1, help="最多输出的热点数量。")] = 10_000,
    call_path_limit: Annotated[int, typer.Option(min=1, help="最多输出的调用路径数量。")] = 1_000,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 128
    << 20,
) -> None:
    """分析 PerfLens 约定字段格式的 perf script 文本。"""
    limits = ResourceLimits(
        max_input_bytes=max_input_bytes,
        max_records=max_records,
        max_line_chars=max_line_chars,
        max_stack_depth=max_stack_depth,
        max_unique_frames=max_unique_frames,
        max_unique_call_paths=max_unique_call_paths,
        max_warnings=max_warnings,
        max_hotspots_output=top_n,
        max_call_paths_output=call_path_limit,
        max_output_bytes=max_output_bytes,
    )
    try:
        artifact = analyze_perf_script(input_path, limits=limits)
        safe_output = validate_output_file(
            output_path,
            input_path=Path(artifact.metadata.input_path),
        )
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("analyze-perf-data")
def analyze_perf_data_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=False, dir_okay=False, help="perf.data 输入文件。"),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="带版本的 JSON 输出产物。"),
    ],
    perf_path: Annotated[
        Path | None,
        typer.Option("--perf-path", dir_okay=False, help="明确指定 perf 程序路径。"),
    ] = None,
    timeout_seconds: Annotated[float, typer.Option(min=0.1, help="perf 转换超时秒数。")] = 300.0,
    max_input_bytes: Annotated[int, typer.Option(min=1, help="允许读取的最大输入字节数。")] = 1
    << 30,
    max_records: Annotated[
        int, typer.Option(min=1, help="允许解析的最大样本记录数。")
    ] = 10_000_000,
    max_line_chars: Annotated[int, typer.Option(min=16, help="单行允许的最大字符数。")] = 1 << 20,
    max_stack_depth: Annotated[int, typer.Option(min=1, help="单条调用栈允许的最大深度。")] = 4_096,
    max_unique_frames: Annotated[
        int, typer.Option(min=1, help="允许保留的最大唯一栈帧数。")
    ] = 2_000_000,
    max_unique_call_paths: Annotated[
        int, typer.Option(min=1, help="允许保留的最大唯一调用路径数。")
    ] = 1_000_000,
    max_warnings: Annotated[int, typer.Option(min=0, help="产物中最多保留的解析警告数。")] = 100,
    top_n: Annotated[int, typer.Option("--top-n", min=1, help="最多输出的热点数量。")] = 10_000,
    call_path_limit: Annotated[int, typer.Option(min=1, help="最多输出的调用路径数量。")] = 1_000,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 128
    << 20,
) -> None:
    """通过系统 perf script 适配器分析 perf.data。"""
    limits = ResourceLimits(
        max_input_bytes=max_input_bytes,
        max_records=max_records,
        max_line_chars=max_line_chars,
        max_stack_depth=max_stack_depth,
        max_unique_frames=max_unique_frames,
        max_unique_call_paths=max_unique_call_paths,
        max_warnings=max_warnings,
        max_hotspots_output=top_n,
        max_call_paths_output=call_path_limit,
        max_output_bytes=max_output_bytes,
    )
    try:
        artifact = analyze_perf_data(
            input_path,
            limits=limits,
            perf_path=perf_path,
            timeout_seconds=timeout_seconds,
        )
        safe_output = validate_output_file(
            output_path,
            input_path=Path(artifact.metadata.input_path),
        )
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("verify-analysis")
def verify_analysis_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=False, dir_okay=False, help="Analysis JSON 输入。"),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="独立验证结果 JSON。"),
    ],
    no_source_check: Annotated[
        bool,
        typer.Option(
            "--no-source-check",
            help="只验证产物内部一致性; 不重新读取原始 Profile。",
        ),
    ] = False,
) -> None:
    """验证 Analysis 的指纹、来源清单、计数和权重守恒。"""
    try:
        analysis = load_analysis(input_path)
        verification = verify_analysis_artifact(
            analysis,
            verify_source=not no_source_check,
        )
        safe_output = validate_output_file(output_path, input_path=input_path)
        write_json_atomic(
            verification,
            safe_output,
            max_output_bytes=8 << 20,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("analyze-trace-evidence")
def analyze_trace_evidence_command(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input",
            exists=False,
            dir_okay=False,
            help="已规范化并完成哈希绑定的 TraceEvidence JSON。",
        ),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="确定性 Trace Analysis JSON。"),
    ],
    max_input_bytes: Annotated[
        int,
        typer.Option(min=1, help="TraceEvidence JSON 允许的最大字节数。"),
    ] = 128 << 20,
) -> None:
    """分析已脱敏的 sched、off-CPU 或 lock TraceEvidence。"""
    try:
        payload, safe_input = _read_bounded_json(
            input_path,
            max_input_bytes=max_input_bytes,
            artifact_label="TraceEvidence",
        )
        try:
            evidence = TraceEvidenceArtifact.model_validate_json(payload)
        except ValidationError as exc:
            raise _invalid_trace_json("TraceEvidence", exc) from exc
        validate_trace_evidence_invariants(evidence)
        analysis = build_trace_analysis(evidence)
        verification = verify_trace_analysis_artifact(analysis, evidence)
        require_usable_trace_analysis(verification)
        safe_output = validate_output_file(output_path, input_path=safe_input)
        write_json_atomic(
            analysis,
            safe_output,
            max_output_bytes=evidence.limits.max_output_bytes,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("verify-trace-analysis")
def verify_trace_analysis_command(
    analysis_path: Annotated[
        Path,
        typer.Option("--analysis", exists=False, dir_okay=False, help="Trace Analysis JSON。"),
    ],
    evidence_path: Annotated[
        Path,
        typer.Option("--evidence", exists=False, dir_okay=False, help="源 TraceEvidence JSON。"),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="独立验证结果 JSON。"),
    ],
    max_input_bytes: Annotated[
        int,
        typer.Option(min=1, help="单个输入 JSON 允许的最大字节数。"),
    ] = 128 << 20,
) -> None:
    """重放并验证 Trace Analysis. 公开 CLI 不读取私有原始 spool。"""
    try:
        evidence_payload, safe_evidence = _read_bounded_json(
            evidence_path,
            max_input_bytes=max_input_bytes,
            artifact_label="TraceEvidence",
        )
        analysis_payload, _ = _read_bounded_json(
            analysis_path,
            max_input_bytes=max_input_bytes,
            artifact_label="Trace Analysis",
        )
        try:
            evidence = TraceEvidenceArtifact.model_validate_json(evidence_payload)
            analysis = _TRACE_ANALYSIS_ADAPTER.validate_json(analysis_payload)
        except ValidationError as exc:
            raise _invalid_trace_json("Trace Analysis or TraceEvidence", exc) from exc
        validate_trace_evidence_invariants(evidence)
        verification = verify_trace_analysis_artifact(analysis, evidence)
        safe_output = validate_output_file(output_path, input_path=safe_evidence)
        safe_output = validate_output_file(safe_output, input_path=analysis_path)
        write_json_atomic(
            verification,
            safe_output,
            max_output_bytes=evidence.limits.max_output_bytes,
        )
        require_usable_trace_analysis(verification)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("inspect-elf")
def inspect_elf_command(
    input_path: Annotated[
        Path, typer.Option("--input", dir_okay=False, help="需要检查的 ELF 文件。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="带版本的 JSON 输出产物。")
    ],
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 8
    << 20,
) -> None:
    """检查 ELF 身份、Build ID 和调试信息能力。"""
    try:
        artifact = inspect_elf(input_path)
        safe_output = validate_output_file(output_path, input_path=Path(artifact.path))
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("resolve-source")
def resolve_source_command(
    binary_path: Annotated[
        Path, typer.Option("--binary", dir_okay=False, help="已验证的 ELF 二进制文件。")
    ],
    module_offset: Annotated[
        str, typer.Option("--module-offset", help="已验证的模块相对偏移, 例如 0x1234。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="带版本的 JSON 输出产物。")
    ],
    runtime_address: Annotated[
        str | None,
        typer.Option("--runtime-address", help="可选运行时地址, 仅作为证据记录。"),
    ] = None,
    addr2line_path: Annotated[
        Path | None,
        typer.Option("--addr2line-path", dir_okay=False, help="可信 addr2line 程序路径。"),
    ] = None,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 8
    << 20,
) -> None:
    """把已验证的模块相对偏移解析为源码栈帧。"""
    try:
        artifact = resolve_source(
            binary_path,
            _parse_address(module_offset, "module_offset"),
            runtime_address=(
                _parse_address(runtime_address, "runtime_address")
                if runtime_address is not None
                else None
            ),
            addr2line_path=addr2line_path,
        )
        safe_output = validate_output_file(output_path, input_path=Path(artifact.binary_path))
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("source-context")
def source_context_command(
    source_path: Annotated[
        Path, typer.Option("--file", dir_okay=False, help="需要读取上下文的源码文件。")
    ],
    line: Annotated[int, typer.Option(min=1, help="目标源码行号。")],
    workspace_root: Annotated[
        Path, typer.Option("--workspace", file_okay=False, help="允许访问的工作区根目录。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="带版本的 JSON 输出产物。")
    ],
    before: Annotated[int, typer.Option(min=0, max=200, help="目标行之前读取的行数。")] = 20,
    after: Annotated[int, typer.Option(min=0, max=200, help="目标行之后读取的行数。")] = 20,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 8
    << 20,
) -> None:
    """在允许的工作区内有界读取源码上下文。"""
    try:
        artifact = get_source_context(
            source_path,
            line,
            workspace_root=workspace_root,
            before=before,
            after=after,
        )
        safe_output = validate_output_file(output_path, input_path=Path(artifact.file))
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("classify")
def classify_command(
    analysis_path: Annotated[
        Path, typer.Option("--analysis", dir_okay=False, help="Profile 分析 JSON。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="诊断 JSON 输出路径。")
    ],
    max_input_bytes: Annotated[int, typer.Option(min=1, help="允许读取的最大输入字节数。")] = 128
    << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 128
    << 20,
) -> None:
    """生成只包含候选结论的证据与诊断产物。"""
    try:
        artifact = classify_analysis(analysis_path, max_input_bytes=max_input_bytes)
        safe_output = validate_output_file(output_path, input_path=analysis_path)
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("report")
def report_command(
    analysis_path: Annotated[
        Path, typer.Option("--analysis", dir_okay=False, help="Profile 分析 JSON。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="Markdown 报告输出路径。")
    ],
    problem_statement: Annotated[
        str, typer.Option("--problem", help="需要调查的性能问题描述。")
    ] = "Not supplied.",
    target_metric: Annotated[
        str, typer.Option("--metric", help="关注的性能指标名称。")
    ] = "Not supplied.",
    max_input_bytes: Annotated[int, typer.Option(min=1, help="允许读取的最大输入字节数。")] = 128
    << 20,
    max_output_bytes: Annotated[
        int, typer.Option(min=1, help="Markdown 产物允许的最大字节数。")
    ] = 128 << 20,
) -> None:
    """生成受证据约束的 Markdown 性能报告。"""
    try:
        report = report_analysis(
            analysis_path,
            problem_statement=problem_statement,
            target_metric=target_metric,
            max_input_bytes=max_input_bytes,
        )
        safe_output = validate_output_file(output_path, input_path=analysis_path)
        write_text_atomic(report, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("normalize-benchmark")
def normalize_benchmark_command(
    input_path: Annotated[
        Path, typer.Option("--input", dir_okay=False, help="第三方 Benchmark JSON。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="标准化 JSON 输出路径。")
    ],
    source_format: Annotated[
        Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"],
        typer.Option("--format", help="输入格式; auto 会自动识别。"),
    ] = "auto",
    benchmark_name: Annotated[
        str | None, typer.Option("--benchmark-name", help="多 Benchmark 文件中的目标名称。")
    ] = None,
    max_input_bytes: Annotated[int, typer.Option(min=1, help="允许读取的最大输入字节数。")] = 64
    << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="JSON 产物允许的最大字节数。")] = 64
    << 20,
) -> None:
    """标准化受支持的第三方 Benchmark JSON。"""
    try:
        artifact = normalize_benchmark(
            input_path,
            source_format=source_format,
            benchmark_name=benchmark_name,
            max_input_bytes=max_input_bytes,
        )
        safe_output = validate_output_file(output_path, input_path=input_path)
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("compare-profiles")
def compare_profiles_command(
    baseline_path: Annotated[
        Path, typer.Option("--baseline", dir_okay=False, help="优化前的分析 JSON。")
    ],
    candidate_path: Annotated[
        Path, typer.Option("--candidate", dir_okay=False, help="优化后的分析 JSON。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="比较 JSON 输出路径。")
    ],
    markdown_output: Annotated[
        Path | None,
        typer.Option("--markdown-output", dir_okay=False, help="可选 Markdown 比较报告。"),
    ] = None,
    minimum_delta_percent: Annotated[
        float, typer.Option(min=0, help="报告变化所需的最小百分点差值。")
    ] = 1.0,
    max_input_bytes: Annotated[
        int, typer.Option(min=1, help="每个输入允许读取的最大字节数。")
    ] = 128 << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="每个输出允许的最大字节数。")] = 128
    << 20,
) -> None:
    """比较两个 PerfLens Profile 分析产物。"""
    try:
        artifact = compare_analysis_files(
            baseline_path,
            candidate_path,
            minimum_delta_percent=minimum_delta_percent,
            max_input_bytes=max_input_bytes,
        )
        safe_output = validate_output_file(output_path, input_path=baseline_path)
        safe_output = validate_output_file(safe_output, input_path=candidate_path)
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
        if markdown_output is not None:
            safe_markdown = validate_output_file(markdown_output, input_path=baseline_path)
            safe_markdown = validate_output_file(safe_markdown, input_path=candidate_path)
            write_text_atomic(
                render_profile_comparison(artifact),
                safe_markdown,
                max_output_bytes=max_output_bytes,
            )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("compare-benchmarks")
def compare_benchmarks_command(
    baseline_path: Annotated[
        Path, typer.Option("--baseline", dir_okay=False, help="优化前 Benchmark JSON。")
    ],
    candidate_path: Annotated[
        Path, typer.Option("--candidate", dir_okay=False, help="优化后 Benchmark JSON。")
    ],
    output_path: Annotated[
        Path, typer.Option("--output", dir_okay=False, help="比较 JSON 输出路径。")
    ],
    markdown_output: Annotated[
        Path | None,
        typer.Option("--markdown-output", dir_okay=False, help="可选 Markdown 比较报告。"),
    ] = None,
    source_format: Annotated[
        Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"],
        typer.Option("--format", help="输入格式; auto 会自动识别。"),
    ] = "auto",
    benchmark_name: Annotated[
        str | None, typer.Option("--benchmark-name", help="多 Benchmark 文件中的目标名称。")
    ] = None,
    minimum_practical_impact_percent: Annotated[
        float, typer.Option(min=0, help="判定实际影响所需的最小百分比。")
    ] = 1.0,
    max_input_bytes: Annotated[int, typer.Option(min=1, help="每个输入允许读取的最大字节数。")] = 64
    << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1, help="每个输出允许的最大字节数。")] = 64
    << 20,
) -> None:
    """比较两个标准化或受支持的第三方 Benchmark 文件。"""
    try:
        artifact = compare_benchmark_files(
            baseline_path,
            candidate_path,
            source_format=source_format,
            benchmark_name=benchmark_name,
            minimum_practical_impact_percent=minimum_practical_impact_percent,
            max_input_bytes=max_input_bytes,
        )
        safe_output = validate_output_file(output_path, input_path=baseline_path)
        safe_output = validate_output_file(safe_output, input_path=candidate_path)
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
        if markdown_output is not None:
            safe_markdown = validate_output_file(markdown_output, input_path=baseline_path)
            safe_markdown = validate_output_file(safe_markdown, input_path=candidate_path)
            write_text_atomic(
                render_benchmark_comparison(artifact),
                safe_markdown,
                max_output_bytes=max_output_bytes,
            )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("collect-profile")
def collect_profile_command(
    data_output: Annotated[
        Path, typer.Option("--data-output", dir_okay=False, help="原始采集数据的新输出路径。")
    ],
    metadata_output: Annotated[
        Path,
        typer.Option("--metadata-output", dir_okay=False, help="采集元数据的新 JSON 路径。"),
    ],
    mode: Annotated[
        Literal["record", "stat", "sched", "lock", "off_cpu"],
        typer.Option("--mode", help="采集模式。"),
    ] = "record",
    executable: Annotated[
        Path | None,
        typer.Option("--executable", dir_okay=False, help="目标程序的绝对路径。"),
    ] = None,
    target_arguments: Annotated[
        list[str] | None,
        typer.Option("--target-arg", help="目标程序的一个参数; 多个参数可重复传入。"),
    ] = None,
    pid: Annotated[
        int | None, typer.Option("--pid", min=1, help="需要附加的现有进程 PID。")
    ] = None,
    duration_seconds: Annotated[
        float | None, typer.Option("--duration-seconds", min=0.01, help="采集时长 (秒)。")
    ] = None,
    perf_path: Annotated[
        Path | None, typer.Option("--perf-path", dir_okay=False, help="明确指定 perf 程序。")
    ] = None,
    frequency_hz: Annotated[
        int,
        typer.Option("--frequency-hz", min=1, max=10_000, help="record 采样频率 (Hz)。"),
    ] = 99,
    call_graph: Annotated[
        Literal["fp", "dwarf", "lbr"],
        typer.Option("--call-graph", help="record 调用栈采集方式。"),
    ] = "dwarf",
    events: Annotated[
        list[str] | None,
        typer.Option("--event", help="perf stat 事件; 重复传入可覆盖默认事件。"),
    ] = None,
    timeout_seconds: Annotated[
        float, typer.Option("--timeout-seconds", min=0.1, help="整个采集命令的超时秒数。")
    ] = 300.0,
    max_data_bytes: Annotated[
        int, typer.Option("--max-data-bytes", min=1, help="原始采集数据最大字节数。")
    ] = 1 << 30,
    max_metadata_bytes: Annotated[
        int, typer.Option("--max-metadata-bytes", min=1, help="元数据 JSON 最大字节数。")
    ] = 8 << 20,
    authorize_target: Annotated[
        bool,
        typer.Option("--authorize-target", help="确认已接受目标运行或观测影响。"),
    ] = False,
    authorization: Annotated[
        str, typer.Option("--authorization", help="目标采集的完整显式授权短语。")
    ] = "",
    authorize_pid_attach: Annotated[
        bool,
        typer.Option("--authorize-pid-attach", help="单独确认允许附加到 --pid。"),
    ] = False,
    pid_authorization: Annotated[
        str, typer.Option("--pid-authorization", help="PID 附加的完整显式授权短语。")
    ] = "",
) -> None:
    """每次明确授权后才执行有界 perf 采集。"""
    try:
        if not authorize_target:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Pass --authorize-target after reviewing target impact",
                recoverable=True,
                suggested_actions=(
                    f"Pass --authorization {ACTIVE_COLLECTION_AUTHORIZATION} explicitly.",
                ),
            )
        if pid is not None and not authorize_pid_attach:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "PID attachment additionally requires --authorize-pid-attach",
                recoverable=True,
                suggested_actions=(
                    f"Pass --pid-authorization {PID_ATTACH_AUTHORIZATION} explicitly.",
                ),
            )
        safe_data_output = validate_new_output_file(data_output)
        safe_metadata_output = validate_new_output_file(metadata_output)
        if safe_data_output == safe_metadata_output:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "output",
                "Data and metadata outputs must be different paths",
            )
        artifact = collect_profile(
            CollectionRequest(
                mode=mode,
                target=CollectionTarget(
                    executable=executable,
                    arguments=tuple(target_arguments or ()),
                    pid=pid,
                    duration_seconds=duration_seconds,
                ),
                output_path=safe_data_output,
                authorization=authorization,
                pid_authorization=pid_authorization if pid is not None else None,
                perf_path=perf_path,
                frequency_hz=frequency_hz,
                call_graph=call_graph,
                events=tuple(events) if events else DEFAULT_STAT_EVENTS,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_data_bytes,
            )
        )
        write_json_new_atomic(
            artifact,
            safe_metadata_output,
            max_output_bytes=max_metadata_bytes,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_metadata_output))


def _parse_address(value: str, field: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "cli",
            f"{field} must be a decimal or 0x-prefixed integer",
            details={"field": field},
        ) from exc
    if parsed < 0:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "cli",
            f"{field} must be non-negative",
            details={"field": field},
        )
    return parsed


def _render_doctor_chinese(artifact: CollectionCapabilityArtifact) -> None:
    status_labels = {"available": "可用", "conditional": "需要真实验收", "blocked": "受阻"}
    privilege_labels = {
        "none": "无需额外权限",
        "cap_perfmon": "需要受限 perf 采集权限",
        "cap_sys_admin_or_policy_change": "需要管理员审查内核策略或 Collector 权限",
    }
    reason_labels = {
        "The system perf executable is unavailable.": "系统中没有找到可执行的 perf。",
        (
            "perf_event_paranoid is greater than 2; this Debian-style policy blocks "
            "unprivileged perf_event_open before normal CAP_PERFMON scope checks."
        ): "perf_event_paranoid 大于 2, 普通用户直接采集会被内核策略阻止。",
        "The current credential has a perf monitoring privilege.": (
            "当前进程具备 perf 监控权限; 仍需真实短时验收。"
        ),
        "Own-process user-space collection depends on the selected events and kernel policy.": (
            "自有进程的用户态采集取决于事件类型和本机内核策略。"
        ),
        "Perf monitoring privilege and readable sched tracepoint metadata are present.": (
            "已有 perf 监控权限, 并且 sched tracepoint 元数据可读。"
        ),
        "Perf monitoring privilege is present, but tracefs metadata is not readable.": (
            "已有 perf 监控权限, 但 tracefs 元数据不可读。"
        ),
        "The tracepoint appears readable, but a real bounded probe is still required.": (
            "tracepoint 看起来可读, 但仍需有界真实采集验收。"
        ),
        "Tracepoint collection requires CAP_PERFMON or an equivalent host policy.": (
            "tracepoint 采集需要 CAP_PERFMON 或等效的主机策略。"
        ),
    }
    warning_labels = {
        "System perf executable was not found.": "未找到系统 perf 可执行文件。",
        "Configured perf executable cannot be resolved.": "指定的 perf 路径无法解析。",
        "Configured perf path is not an executable regular file.": (
            "指定的 perf 路径不是可执行普通文件。"
        ),
        "Unable to query the selected perf version.": "无法读取所选 perf 的版本。",
        "Unable to inspect effective process capabilities.": "无法检查当前进程 capability。",
        "Unable to inspect perf file capabilities.": "无法检查 perf 文件 capability。",
        "Unable to read /proc/sys/kernel/perf_event_paranoid.": (
            "无法读取内核 perf_event_paranoid。"
        ),
        "Unable to read /proc/sys/kernel/kptr_restrict.": "无法读取内核 kptr_restrict。",
        "Unable to read /proc/sys/kernel/yama/ptrace_scope.": ("无法读取内核 ptrace_scope。"),
    }
    recommendation_labels = {
        "Install a perf build matching the running Linux kernel.": (
            "安装与当前运行内核匹配的 perf。"
        ),
        "Have an administrator review perf_event_paranoid; do not weaken it automatically.": (
            "让管理员按主机威胁模型审查 perf_event_paranoid; 不要自动降低安全策略。"
        ),
        (
            "Prefer a dedicated collector service with a narrow policy over running the MCP "
            "server as root."
        ): "优先部署权限收窄的专用 Collector; 不要让 MCP 或 Agent 以 root 运行。",
        "Run a short authorized real probe before claiming a mode is operational.": (
            "宣称采集可用前, 必须执行一次明确授权的短时真实验收。"
        ),
    }
    statuses = {mode.status for mode in artifact.modes}
    overall = (
        "全部模式可进入真实验收"
        if statuses == {"available"}
        else "所有模式当前受阻"
        if statuses == {"blocked"}
        else "部分模式受限"
    )
    typer.echo("PerfLens 采集能力检查 (只读)")
    typer.echo(
        f"系统: {_terminal_text(artifact.platform)} {_terminal_text(artifact.kernel_release)}"
    )
    typer.echo(f"当前用户 UID: {artifact.effective_uid}")
    typer.echo(f"perf: {_terminal_text(artifact.perf_executable or '未找到')}")
    typer.echo(f"perf 版本: {_terminal_text(artifact.perf_version or '未知')}")
    typer.echo(
        "内核策略: "
        f"perf_event_paranoid={_optional_integer(artifact.perf_event_paranoid)}, "
        f"kptr_restrict={_optional_integer(artifact.kptr_restrict)}, "
        f"ptrace_scope={_optional_integer(artifact.ptrace_scope)}"
    )
    typer.echo(f"tracefs: {'可读' if artifact.tracefs_accessible else '不可读/未挂载'}")
    typer.echo(
        "当前进程 capability: "
        + (_terminal_text(", ".join(artifact.effective_capabilities)) or "无")
    )
    typer.echo(
        "perf 文件 capability: "
        + (_terminal_text(", ".join(artifact.perf_file_capabilities)) or "无")
    )
    typer.echo("硬件 PMU: 未主动探测 (只读检查不会运行 perf)")
    typer.echo("软件计数/采样: 未主动探测 (请运行 accept-collector 真实验收)")
    typer.echo(f"综合结论: {overall}")
    typer.echo("采集模式:")
    for mode in artifact.modes:
        typer.echo(
            f"- {mode.mode}: {status_labels[mode.status]}; "
            f"{privilege_labels[mode.required_privilege]}"
        )
        typer.echo(f"  说明: {_terminal_text(reason_labels.get(mode.reason, mode.reason))}")
    if artifact.warnings:
        typer.echo("检查提示:")
        for warning in artifact.warnings:
            typer.echo(f"- {_terminal_text(warning_labels.get(warning, warning))}")
    if artifact.recommendations:
        typer.echo("建议:")
        for recommendation in artifact.recommendations:
            typer.echo(
                f"- {_terminal_text(recommendation_labels.get(recommendation, recommendation))}"
            )
    typer.echo("结论边界:")
    typer.echo("- 本命令没有运行 perf、附加 PID、写入 spool 或修改主机配置。")
    typer.echo("- 可用/需要验收只代表前置条件; 真实采集必须另行短时验收。")
    typer.echo("下一步:")
    typer.echo("- 只分析已有 Profile 时可以直接继续, 不需要 root 或 Collector。")
    if "blocked" in statuses:
        typer.echo(
            "- 需要自动采集时运行 `perflens setup --prepare-collector "
            "--automatic-collection`, 再按生成的中文指南让管理员部署。"
        )
    else:
        typer.echo(
            "- Collector 已部署时运行 `perflens accept-collector --authorize-host-acceptance`。"
        )
    typer.echo("- 完整机器结果使用 `perflens doctor --json` 或 `--output <新文件.json>`。")


def _optional_integer(value: int | None) -> str:
    return "未知" if value is None else str(value)


def _terminal_text(value: str, *, max_characters: int = 512) -> str:
    visible = "".join(
        character if character.isprintable() and character != "\x1b" else "?" for character in value
    )
    if len(visible) <= max_characters:
        return visible
    return f"{visible[:max_characters]}..."


def _render_status_chinese(artifact: RuntimeStatusArtifact) -> None:
    setup_labels = {"missing": "未生成", "incomplete": "不完整/不安全", "ready": "就绪"}
    skill_labels = {"missing": "未安装", "incomplete": "不完整/不安全", "ready": "就绪"}
    mcp_labels = {
        "missing": "未接入",
        "incomplete": "无效或路径不安全",
        "ready": "已接入",
    }
    asset_labels = {
        "not_requested": "未请求",
        "missing": "缺失",
        "incomplete": "不完整/不安全",
        "ready": "就绪",
    }
    socket_labels = {
        "missing": "不存在",
        "invalid": "不是安全 Unix Socket",
        "inaccessible": "当前用户不可访问",
        "ready": "可访问",
    }
    group_labels = {"missing": "系统组不存在", "not_member": "当前会话未加入", "member": "已加入"}
    health_labels = {
        "not_checked": "未执行 (前置条件未满足)",
        "ready": "已通过身份认证",
        "unreachable": "无法完成通信",
        "rejected": "身份、权限或协议校验未通过",
    }
    host_labels = {"available": "可用", "conditional": "部分受限", "blocked": "当前受阻"}
    automatic_labels = {
        "not_configured": "未配置",
        "configuration_incomplete": "配置不完整",
        "collector_unavailable": "Collector 尚不可用",
        "access_denied": "当前会话无权访问 Collector",
        "ready_for_verification": "可进行真实短时验收 (尚未证明采集成功)",
    }
    issue_labels = {
        "setup_missing": "尚未生成项目引导文件。",
        "setup_unsafe": "引导目录是符号链接或不是目录。",
        "setup_artifact_missing": "缺少 setup.json。",
        "setup_artifact_invalid": "setup.json 无效或超过大小限制。",
        "setup_identity_mismatch": "setup.json 与当前项目或目录不匹配。",
        "skill_missing": "项目 Skill 尚未安装。",
        "skill_incomplete": "项目 Skill 不完整或路径不安全。",
        "mcp_project_config_missing": "所选客户端的项目配置尚未接入 PerfLens MCP。",
        "mcp_project_config_incomplete": (
            "项目 MCP 配置无效、入口程序失效、路径不安全; 或与本次引导不匹配。"
        ),
        "collector_assets_missing": "缺少 Collector 部署资产。",
        "collector_assets_incomplete": "Collector 部署资产不完整或路径不安全。",
        "collector_socket_missing": "Collector Socket 尚未创建。",
        "collector_socket_invalid": "Collector Socket 路径无效。",
        "collector_socket_inaccessible": "当前用户无法访问 Collector Socket。",
        "collector_group_missing": "perflens 系统组尚未创建。",
        "collector_group_not_member": "当前登录会话尚未加入 perflens 组。",
        "collector_service_user_missing": "专用 perflens 服务用户不存在; 无法验证 Collector 身份。",
        "collector_health_unreachable": "Collector Socket 存在; 但服务无法连接或没有响应。",
        "collector_health_rejected": "Collector 身份/权限/协议响应未通过安全校验。",
        "collector_feature_profile_mismatch": (
            "项目请求的功能配置与当前 Collector 功能配置不一致; 请更新项目配置。"
        ),
        "collector_trace_backend_unavailable": (
            "Collector 声明完整诊断, 但未开放全部 sched/off_cpu/lock 模式。"
        ),
        "host_collection_conditional": "本机普通用户 perf 权限仍需真实验收。",
        "host_collection_blocked": "本机普通用户 perf 权限诊断为受阻; Collector 权限需另行验收。",
    }
    typer.echo("PerfLens 状态检查 (只读)")
    typer.echo(f"项目: {artifact.project_root}")
    typer.echo(f"引导目录: {setup_labels[artifact.setup_status]}")
    typer.echo(f"Skill: {skill_labels[artifact.skill_status]}")
    typer.echo(f"项目 MCP 配置: {mcp_labels[artifact.mcp_config_status]}")
    typer.echo(f"Collector 资产: {asset_labels[artifact.collector_assets_status]}")
    typer.echo(f"Collector Socket: {socket_labels[artifact.collector_socket_status]}")
    typer.echo(f"perflens 用户组: {group_labels[artifact.collector_group_status]}")
    typer.echo(f"Collector 健康握手: {health_labels[artifact.collector_health_status]}")
    typer.echo(f"Collector 功能配置: {artifact.feature_profile}")
    if artifact.feature_profile == "full_diagnostics":
        typer.echo(f"Trace 后端状态: {artifact.trace_backend_status}")
    if artifact.collector_health_status == "ready":
        typer.echo(
            f"Collector 服务身份: PID {artifact.collector_service_pid}, "
            f"UID {artifact.collector_service_uid}"
        )
        typer.echo(f"Collector 策略版本: {artifact.collector_policy_version}")
        typer.echo("Collector 允许模式: " + (", ".join(artifact.collector_allowed_modes) or "无"))
        typer.echo(f"Collector 固定产物目录: {artifact.collector_spool_root}")
    typer.echo(f"本机 perf 权限: {host_labels[artifact.host_collection_status]}")
    typer.echo(f"自动采集: {automatic_labels[artifact.automatic_collection_status]}")
    issues = artifact.issues
    if issues:
        typer.echo("问题与提示:")
        for issue in issues:
            typer.echo(f"- {issue_labels.get(issue, issue)}")
    next_steps = _runtime_next_steps_chinese(artifact)
    if next_steps:
        typer.echo("下一步:")
        for step in next_steps:
            typer.echo(f"- {step}")


def _runtime_next_steps_chinese(artifact: RuntimeStatusArtifact) -> tuple[str, ...]:
    project = Path(artifact.project_root)
    setup = Path(artifact.setup_directory)
    status_command = shlex.join(
        (
            "perflens",
            "status",
            "--project",
            str(project),
            "--setup-directory",
            str(setup),
            "--collector-socket",
            artifact.collector_socket,
        )
    )
    setup_command = [
        "perflens",
        "setup",
        "--project",
        str(project),
        "--output-directory",
        _unused_setup_directory_name(project, artifact.status_id),
    ]

    steps: list[str] = []
    if artifact.setup_status == "missing":
        steps.append(f"只在当前项目激活 PerfLens: `perflens init {shlex.quote(str(project))}`")
    elif (
        artifact.setup_status != "ready"
        or artifact.skill_status != "ready"
        or artifact.mcp_config_status != "ready"
    ):
        if artifact.automatic_collection_requested:
            setup_command.extend(("--prepare-collector", "--automatic-collection"))
        steps.append(
            "用一个尚不存在的新目录重新生成完整引导 (不会覆盖旧文件): "
            f"`{shlex.join(setup_command)}`"
        )
    elif artifact.automatic_collection_status == "configuration_incomplete":
        setup_command.extend(("--prepare-collector", "--automatic-collection"))
        steps.append(f"重新生成完整自动采集资产: `{shlex.join(setup_command)}`")
    elif artifact.automatic_collection_status == "collector_unavailable":
        steps.append(f"打开 `{setup / '下一步.zh-CN.md'}`, 让管理员执行其中生成的部署/排错命令。")
    elif artifact.automatic_collection_status == "access_denied":
        steps.append("退出当前 Linux 登录会话并重新登录, 使 perflens 用户组生效。")
        steps.append(f"重新登录后再次检查: `{status_command}`")
    elif artifact.automatic_collection_status == "ready_for_verification":
        acceptance_command = shlex.join(
            (
                "perflens",
                "accept-collector",
                "--socket",
                artifact.collector_socket,
                "--authorize-host-acceptance",
            )
        )
        steps.append(f"执行一次 1 秒真实短时采集验收: `{acceptance_command}`")
    return tuple(steps)


def _render_detachment_chinese(
    artifact: ProjectDetachmentArtifact,
    *,
    output_path: Path | None,
) -> None:
    typer.echo("PerfLens 项目接入解除")
    typer.echo(f"项目: {artifact.project_root}")
    config_labels = {
        "not_found": "未找到 PerfLens 托管配置; 未修改文件",
        "planned": "预演通过; 尚未修改文件",
        "removed": "已只移除 PerfLens 托管配置块",
        "skipped": "未选择此客户端",
    }
    skill_labels = {
        "not_found": "未找到项目 Skill",
        "planned": "预演通过; 将移除未修改的托管 Skill",
        "removed": "已移除未修改的托管 Skill",
        "preserved": "按 --keep-skills 保留",
        "skipped": "未选择此客户端",
    }
    typer.echo(f"Codex MCP: {config_labels[artifact.codex_config_status]}")
    typer.echo(f"Codex Skill: {skill_labels[artifact.codex_skill_status]}")
    typer.echo(f"Claude Code MCP: {config_labels[artifact.claude_config_status]}")
    typer.echo(f"Claude Code Skill: {skill_labels[artifact.claude_skill_status]}")
    typer.echo("保留边界: 不删除引导目录、分析结果或系统 Collector 数据。")
    if artifact.removed_paths:
        typer.echo("已移除路径:")
        for path in artifact.removed_paths:
            typer.echo(f"- {path}")
    if artifact.preserved_paths:
        typer.echo("已保留的已知路径:")
        for path in artifact.preserved_paths:
            typer.echo(f"- {path}")
    if output_path is not None:
        typer.echo(f"版本化结果: {output_path}")
    typer.echo("下一步:")
    if "planned" in {
        artifact.codex_config_status,
        artifact.claude_config_status,
        artifact.codex_skill_status,
        artifact.claude_skill_status,
    }:
        selected_client = (
            "all"
            if set(artifact.selected_clients) == {"codex", "claude-code"}
            else artifact.selected_clients[0]
        )
        command_parts = [
            "perflens",
            "detach",
            "--project",
            artifact.project_root,
            "--client",
            selected_client,
        ]
        if not artifact.remove_skills:
            command_parts.append("--keep-skills")
        if artifact.setup_directory is not None:
            command_parts.extend(("--setup-directory", artifact.setup_directory))
        command = shlex.join(command_parts)
        typer.echo(f"- 确认后执行真实移除: `{command}`")
    elif "removed" in {
        artifact.codex_config_status,
        artifact.claude_config_status,
        artifact.codex_skill_status,
        artifact.claude_skill_status,
    }:
        typer.echo("- 重启已解除接入的 AI 客户端, 让项目停止发现 PerfLens。")
        typer.echo("- 确认其他项目也已 detach 后, 再卸载 wheel 或 DEB。")
    else:
        typer.echo("- 当前选择范围内没有可安全移除的 PerfLens 托管内容。")


def _unused_setup_directory_name(project: Path, status_id: str) -> str:
    for index in range(1, 101):
        name = "perflens-setup-new" if index == 1 else f"perflens-setup-new-{index}"
        candidate = project / name
        if not candidate.exists() and not candidate.is_symlink():
            return name
    return f"perflens-setup-{status_id.removeprefix('status-')}"


def _render_collector_acceptance_chinese(
    artifact: CollectorAcceptanceArtifact,
) -> None:
    typer.echo("PerfLens Collector 真实采集验收")
    typer.echo("状态: 通过")
    typer.echo("测试目标: PerfLens 内置普通用户 CPU 负载")
    typer.echo(f"验收 ID: {artifact.acceptance_id}")
    typer.echo(f"Collector Socket: {artifact.socket_path}")
    typer.echo(f"请求采集时长: {artifact.requested_duration_seconds:g} 秒")
    typer.echo(f"采集指标数量: {artifact.metric_count}")
    typer.echo(f"硬件 PMU: {_availability_chinese(artifact.hardware_pmu_status)}")
    if artifact.hardware_pmu_reason:
        typer.echo(f"硬件 PMU 说明: {_terminal_text(artifact.hardware_pmu_reason)}")
    if artifact.hardware_collection_id:
        typer.echo(f"硬件采集尝试 ID: {_terminal_text(artifact.hardware_collection_id)}")
    typer.echo(f"软件计数事件: {_availability_chinese(artifact.software_counting_status)}")
    typer.echo(f"软件 cpu-clock 采样: {_availability_chinese(artifact.software_sampling_status)}")
    typer.echo(f"证据文件: {artifact.output_path}")
    typer.echo(f"证据大小: {_human_bytes(artifact.output_bytes)}")
    typer.echo(f"证据 SHA-256: {artifact.output_sha256}")
    typer.echo(f"采集开始: {artifact.started_at}")
    typer.echo(f"采集结束: {artifact.finished_at}")
    if artifact.warnings:
        typer.echo("警告:")
        for warning in artifact.warnings:
            typer.echo(f"- {warning}")
    typer.echo("结论:")
    typer.echo("- 当前用户、Collector 策略和内核权限已完成软件计数与采样的真实短时采集。")
    if artifact.hardware_pmu_status == "unavailable":
        typer.echo("- 硬件 PMU 不可用时会自动降级; 仍可定位 CPU 热点和调度开销候选。")
        typer.echo("- 降级证据不能用于 IPC、硬件缓存未命中率或分支未命中率结论。")
    typer.echo("- 此结果只证明本机当前配置。任意项目或采集模式仍需分别验证。")
    typer.echo("下一步:")
    typer.echo("- 需要留档时重新运行并使用 --output <新文件.json>。")
    typer.echo("- 需要机器可读输出时使用 --json。")


def _render_collector_verification_chinese(artifact: CollectionArtifact) -> None:
    measured = sum(
        metric.status == "measured" and metric.value is not None for metric in artifact.metrics
    )
    typer.echo("PerfLens Collector 已有 PID 真实采集验证")
    typer.echo("状态: 采集完成")
    typer.echo(f"采集 ID: {_terminal_text(artifact.collection_id)}")
    typer.echo(f"目标 PID: {artifact.target_pid}")
    typer.echo(f"采集模式: {artifact.mode}")
    typer.echo(f"请求事件来源: {artifact.requested_event_source}")
    typer.echo(f"实际事件来源: {artifact.actual_event_source}")
    if artifact.record_event:
        typer.echo(f"实际采样事件: {_terminal_text(artifact.record_event)}")
    typer.echo(f"已自动降级: {'是' if artifact.fallback_used else '否'}")
    if artifact.fallback_reason:
        typer.echo(f"降级原因: {_terminal_text(artifact.fallback_reason)}")
    typer.echo(f"实际采集时长: {artifact.duration_seconds:g} 秒")
    typer.echo(f"指标: 实测 {measured} / 共 {len(artifact.metrics)}")
    typer.echo(f"证据文件: {_terminal_text(artifact.output_path)}")
    typer.echo(f"证据大小: {_human_bytes(artifact.output_bytes)}")
    typer.echo(f"证据 SHA-256: {artifact.output_sha256}")
    typer.echo(f"采集开始: {_terminal_text(artifact.started_at)}")
    typer.echo(f"采集结束: {_terminal_text(artifact.finished_at)}")
    if artifact.warnings:
        typer.echo("警告:")
        for warning in artifact.warnings:
            typer.echo(f"- {_terminal_text(warning)}")
    if artifact.evidence_limitations:
        typer.echo("证据限制:")
        for limitation in artifact.evidence_limitations:
            typer.echo(f"- {_terminal_text(limitation)}")
    if artifact.diagnostics:
        typer.echo("有界诊断:")
        for diagnostic in artifact.diagnostics:
            typer.echo(f"- {_terminal_text(diagnostic)}")
    typer.echo("结论边界:")
    typer.echo("- 这证明 Collector 对本次明确授权的已有 PID 完成了一次短时采集。")
    typer.echo("- 它不证明其他 PID、项目、事件或采集模式一定可用。")
    typer.echo("下一步:")
    typer.echo("- 需要完整机器结果时重新运行并添加 --json。")
    typer.echo("- 需要留档时重新运行并添加 --output <新文件.json>。")


def _human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    return f"{amount:.0f} {unit}" if amount.is_integer() else f"{amount:.1f} {unit}"


def _availability_chinese(status: str) -> str:
    return {
        "available": "可用",
        "unavailable": "不可用",
        "unknown": "未验证",
    }.get(status, status)


def _read_bounded_json(
    path: Path,
    *,
    max_input_bytes: int,
    artifact_label: str,
) -> tuple[bytes, Path]:
    safe_path = validate_input_file(path)
    try:
        size = safe_path.stat().st_size
        with safe_path.open("rb") as handle:
            payload = handle.read(max_input_bytes + 1)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "artifact",
            f"{artifact_label} cannot be read",
            details={"path": str(safe_path)},
        ) from exc
    if size > max_input_bytes or len(payload) > max_input_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "artifact",
            f"{artifact_label} exceeds max_input_bytes",
            details={
                "actual_bytes": max(size, len(payload)),
                "max_input_bytes": max_input_bytes,
            },
        )
    return payload, safe_path


def _invalid_trace_json(label: str, error: ValidationError) -> PerfLensError:
    return PerfLensError(
        ErrorCode.INVALID_INPUT,
        "artifact",
        f"Input is not a valid PerfLens {label} artifact",
        details={"validation_errors": error.error_count()},
    )


def _fail(error: PerfLensError) -> NoReturn:
    output = (
        error_json(error)
        if json_errors_enabled()
        else render_error_chinese(error, executable="perflens")
    )
    typer.echo(output, err=True)
    raise typer.Exit(ERROR_EXIT_CODES[error.code])


def main() -> None:
    try:
        app()
    except PerfLensError as exc:
        _fail(exc)
    except (OSError, ValueError) as exc:
        _fail(
            PerfLensError(
                ErrorCode.INVALID_INPUT,
                "cli",
                str(exc),
                details={},
            )
        )
    except Exception as exc:  # pragma: no cover - final transport safety boundary
        _fail(
            PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "cli",
                "Unexpected internal error",
                details={"exception_type": type(exc).__name__},
            )
        )


if __name__ == "__main__":
    main()
