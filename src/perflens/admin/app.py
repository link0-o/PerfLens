"""Human-invoked administrator CLI for optional Collector deployment."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Annotated, Literal, NoReturn, cast

import typer

from perflens import __version__
from perflens.admin.deploy import (
    deploy_collector,
    inspect_collector_spool,
    setup_collector,
    switch_collector_mode,
    undeploy_collector,
    update_collector_policy,
    upgrade_collector,
)
from perflens.admin.spool import (
    archive_collector_spool,
    prune_archived_collector_spool,
    verify_collector_spool_archive,
)
from perflens.contracts.artifacts import (
    CollectorDeploymentArtifact,
    CollectorModeSwitchArtifact,
    CollectorSetupArtifact,
    CollectorSpoolArchiveVerificationArtifact,
    CollectorSpoolStatusArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.error_presentation import (
    ERROR_EXIT_CODES,
    configure_json_errors,
    error_json,
    json_errors_enabled,
    render_error_chinese,
)

app = typer.Typer(
    name="perflens-admin",
    help="用于可选 PerfLens Collector 的显式管理员操作。",
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
            help="自动化程序输出完整的版本化 JSON 错误。",
            envvar="PERFLENS_JSON_ERRORS",
        ),
    ] = False,
) -> None:
    configure_json_errors(json_errors)
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("deploy")
def deploy_command(
    config: Annotated[
        Path,
        typer.Option("--config", dir_okay=False, help="已审查的 Collector TOML 策略。"),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只校验并显示部署计划; 不修改系统。"),
    ] = False,
    collector_command: Annotated[
        Path | None,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="可信的已安装 Collector 路径; 默认与 perflens-admin 位于同一目录。",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整的版本化 JSON 结果。"),
    ] = False,
    acknowledge_privileged_helper_risk: Annotated[
        bool,
        typer.Option(
            "--acknowledge-privileged-helper-risk",
            "--acknowledge-cap-sys-admin-risk",
            help=(
                "确认 paranoid=3 Rust Helper 的 root、CAP_SYS_ADMIN 与 "
                "CAP_SYS_PTRACE 风险。旧参数名仍兼容。"
            ),
        ),
    ] = False,
) -> None:
    """校验或部署 Collector; 默认输出中文摘要。"""
    try:
        result = deploy_collector(
            config,
            dry_run=dry_run,
            collector_command=collector_command,
            acknowledge_privileged_helper_risk=acknowledge_privileged_helper_risk,
        )
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    _render_deployment_chinese(result)


@app.command("setup")
def setup_command(
    mode: Annotated[
        Literal["analysis_only", "cap_perfmon", "paranoid3_helper"] | None,
        typer.Option(
            "--mode",
            help="非交互选择: analysis_only、cap_perfmon 或 paranoid3_helper。",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只生成并验证默认策略及命令计划。"),
    ] = False,
    allowed_uid: Annotated[
        int | None,
        typer.Option("--allowed-uid", min=1, help="获准采集的普通用户 UID。"),
    ] = None,
    collector_command: Annotated[
        Path | None,
        typer.Option("--collector-command", dir_okay=False, help="可信 Collector 入口。"),
    ] = None,
    perf_path: Annotated[
        Path,
        typer.Option("--perf-path", dir_okay=False, help="可信系统 perf 程序。"),
    ] = Path("/usr/bin/perf"),
    acknowledge_privileged_helper_risk: Annotated[
        bool,
        typer.Option(
            "--acknowledge-privileged-helper-risk",
            "--acknowledge-cap-sys-admin-risk",
            help="确认 paranoid=3 Helper 的 root 与 capability 风险。",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整的版本化 JSON 结果。"),
    ] = False,
) -> None:
    """首次选择并部署 Collector; 也可以明确选择仅分析。"""
    selected = mode
    interactive = selected is None
    if selected is None:
        typer.echo("请选择 PerfLens Collector 部署方式:")
        typer.echo("1. cap_perfmon (推荐, 权限更小)")
        typer.echo("2. paranoid3_helper (保留 paranoid=3, 风险更高)")
        typer.echo("3. 仅分析已有证据 (不部署 Collector)")
        choice = typer.prompt("请输入 1、2 或 3", default="1")
        choices = {"1": "cap_perfmon", "2": "paranoid3_helper", "3": "analysis_only"}
        if choice not in choices:
            _fail(PerfLensError(ErrorCode.INVALID_INPUT, "collector_setup", "未知的向导选项"))
        selected = cast(
            Literal["analysis_only", "cap_perfmon", "paranoid3_helper"],
            choices[choice],
        )
    if (
        interactive
        and selected == "paranoid3_helper"
        and not dry_run
        and not acknowledge_privileged_helper_risk
    ):
        acknowledged = typer.confirm(
            "该模式启用受限 root Rust Helper, 并使用 CAP_SYS_ADMIN/CAP_SYS_PTRACE; 确认继续?"
        )
        if not acknowledged:
            raise typer.Abort()
        acknowledge_privileged_helper_risk = True
    try:
        result = setup_collector(
            selected,
            dry_run=dry_run,
            collector_command=collector_command,
            perf_path=perf_path,
            allowed_uid=allowed_uid,
            acknowledge_privileged_helper_risk=acknowledge_privileged_helper_risk,
        )
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    _render_setup_chinese(result)


@app.command("switch-mode")
def switch_mode_command(
    target_mode: Annotated[
        Literal["cap_perfmon", "paranoid3_helper"],
        typer.Argument(help="要切换到的 Collector 权限模式。"),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只验证切换前置条件并显示事务计划。"),
    ] = False,
    acknowledge_privileged_helper_risk: Annotated[
        bool,
        typer.Option(
            "--acknowledge-privileged-helper-risk",
            "--acknowledge-cap-sys-admin-risk",
            help="确认切换到 paranoid3_helper 的 root 与 capability 风险。",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整的版本化 JSON 结果。"),
    ] = False,
) -> None:
    """事务化切换 Collector 模式; 失败时恢复旧策略和服务。"""
    try:
        result = switch_collector_mode(
            target_mode,
            dry_run=dry_run,
            acknowledge_privileged_helper_risk=acknowledge_privileged_helper_risk,
        )
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    _render_mode_switch_chinese(result)


@app.command("undeploy")
def undeploy_command(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只验证托管 unit, 不修改主机。"),
    ] = False,
) -> None:
    """停止并移除托管服务, 同时保留策略和采集产物。"""
    try:
        result = undeploy_collector(dry_run=dry_run)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("upgrade")
def upgrade_command(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只验证并比较托管 unit, 不修改系统。"),
    ] = False,
    collector_command: Annotated[
        Path | None,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="可信的新 Collector 路径; 默认与 perflens-admin 位于同一目录。",
        ),
    ] = None,
    acknowledge_privileged_helper_risk: Annotated[
        bool,
        typer.Option(
            "--acknowledge-privileged-helper-risk",
            "--acknowledge-cap-sys-admin-risk",
            help=(
                "确认升级将扩大 paranoid=3 Rust Helper 的 root capability 边界。旧参数名仍兼容。"
            ),
        ),
    ] = False,
) -> None:
    """安全升级并重启 Collector, 同时保留策略和采集产物。"""
    try:
        result = upgrade_collector(
            dry_run=dry_run,
            collector_command=collector_command,
            acknowledge_privileged_helper_risk=acknowledge_privileged_helper_risk,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("spool-status")
def spool_status_command(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            dir_okay=False,
            help="需要检查的已部署 Collector TOML 策略。",
        ),
    ] = Path("/etc/perflens/collector.toml"),
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整、带版本的 JSON 产物。"),
    ] = False,
) -> None:
    """只读显示 spool 使用量与剩余容量的中文摘要。"""
    try:
        result = inspect_collector_spool(config)
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    _render_spool_status_chinese(result)


@app.command("update-policy")
def update_policy_command(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            dir_okay=False,
            help="已经单独审查的候选 Collector TOML 策略。",
        ),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只验证并比较策略, 不修改系统。"),
    ] = False,
) -> None:
    """安全更新策略、重启并健康检查, 失败时自动恢复。"""
    try:
        result = update_collector_policy(config, dry_run=dry_run)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("archive-spool")
def archive_spool_command(
    output: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="新 ZIP 归档的绝对路径。"),
    ],
    config: Annotated[
        Path,
        typer.Option("--config", dir_okay=False, help="已部署的 Collector TOML 策略。"),
    ] = Path("/etc/perflens/collector.toml"),
    older_than_days: Annotated[
        int,
        typer.Option(
            "--older-than-days",
            min=0,
            max=36_500,
            help="只选择早于该天数的产物。",
        ),
    ] = 7,
    keep_latest: Annotated[
        int,
        typer.Option("--keep-latest", min=0, max=10_000, help="始终保留的最新产物数量。"),
    ] = 20,
    max_artifacts: Annotated[
        int,
        typer.Option("--max-artifacts", min=1, max=10_000, help="单次最多归档的产物数量。"),
    ] = 1000,
    max_total_bytes: Annotated[
        int,
        typer.Option("--max-total-bytes", min=1, max=1 << 40, help="单次归档的最大逻辑字节数。"),
    ] = 10 << 30,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只计算哈希并显示计划, 不创建归档。"),
    ] = False,
) -> None:
    """归档旧的托管 spool 证据, 不删除源文件。"""
    try:
        result = archive_collector_spool(
            output,
            config_path=config,
            older_than_days=older_than_days,
            keep_latest=keep_latest,
            max_artifacts=max_artifacts,
            max_total_bytes=max_total_bytes,
            dry_run=dry_run,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("prune-archived-spool")
def prune_archived_spool_command(
    archive: Annotated[
        Path,
        typer.Option("--archive", dir_okay=False, help="已经验证的归档 ZIP 路径。"),
    ],
    config: Annotated[
        Path,
        typer.Option("--config", dir_okay=False, help="已部署的 Collector TOML 策略。"),
    ] = Path("/etc/perflens/collector.toml"),
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只验证归档和源文件, 不执行删除。"),
    ] = False,
    authorization: Annotated[
        str | None,
        typer.Option(
            "--authorization",
            help="破坏性清理操作要求的完整授权短语。",
        ),
    ] = None,
) -> None:
    """只清理已经由归档 manifest 精确证明的源文件。"""
    try:
        result = prune_archived_collector_spool(
            archive,
            config_path=config,
            dry_run=dry_run,
            authorization=authorization,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("verify-spool-archive")
def verify_spool_archive_command(
    archive: Annotated[
        Path,
        typer.Option("--archive", dir_okay=False, help="由 root 管理的归档 ZIP 路径。"),
    ],
    config: Annotated[
        Path,
        typer.Option("--config", dir_okay=False, help="已部署的 Collector TOML 策略。"),
    ] = Path("/etc/perflens/collector.toml"),
    verify_sources: Annotated[
        bool,
        typer.Option(
            "--verify-sources",
            help="同时验证仍存在的所有源产物, 但不删除。",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出完整、带版本的 JSON 产物。"),
    ] = False,
) -> None:
    """验证归档结构和哈希, 不清理任何证据。"""
    try:
        result = verify_collector_spool_archive(
            archive,
            config_path=config,
            verify_sources=verify_sources,
        )
    except PerfLensError as exc:
        _fail(exc)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    _render_archive_verification_chinese(result)


def _render_setup_chinese(artifact: CollectorSetupArtifact) -> None:
    typer.echo("PerfLens Collector 首次设置")
    if artifact.status == "analysis_only":
        typer.echo("状态: 仅分析模式; 没有修改系统或启动 Collector")
    else:
        status = {
            "blocked": "目标模式当前不可用; 尚未修改系统",
            "dry_run": "预检通过; 尚未修改系统",
            "deployed": "部署完成",
        }[artifact.status]
        typer.echo(f"状态: {status}")
        typer.echo(f"选择的权限模式: {artifact.selected_mode}")
        typer.echo(f"系统策略位置: {artifact.config_path}")
        typer.echo(f"Collector 程序: {artifact.collector_command}")
        typer.echo("授权普通用户 UID: " + ", ".join(str(uid) for uid in artifact.allowed_uids))
    if artifact.planned_commands:
        typer.echo("固定系统命令计划:")
        for index, command in enumerate(artifact.planned_commands, start=1):
            typer.echo(f"{index}. {shlex.join(command)}")
    if artifact.warnings:
        typer.echo("安全边界与提示:")
        for warning in artifact.warnings:
            typer.echo(f"- {_chinese_admin_guidance(warning)}")
    if artifact.next_steps:
        typer.echo("下一步:")
        if artifact.status == "dry_run" and artifact.selected_mode is not None:
            command = ["sudo", "perflens-admin", "setup", "--mode", artifact.selected_mode]
            if artifact.selected_mode == "paranoid3_helper":
                command.append("--acknowledge-privileged-helper-risk")
            typer.echo(f"- 确认计划后正式执行: {shlex.join(command)}")
        for step in artifact.next_steps:
            typer.echo(f"- {_chinese_admin_guidance(step)}")


def _render_mode_switch_chinese(artifact: CollectorModeSwitchArtifact) -> None:
    labels = {
        "blocked": "预检发现目标模式不可用; 尚未修改系统",
        "dry_run": "预检通过; 尚未修改系统",
        "unchanged": "目标模式已经生效; 无需修改",
        "repaired": "已修复残留特权组件; cap_perfmon 健康检查通过",
        "switched": "切换完成; Collector 健康检查通过",
    }
    typer.echo("PerfLens Collector 模式切换")
    typer.echo(f"状态: {labels[artifact.status]}")
    typer.echo(f"当前模式: {artifact.current_mode}")
    typer.echo(f"目标模式: {artifact.target_mode}")
    typer.echo(f"系统策略位置: {artifact.config_path}")
    typer.echo("证据目录: 保留, 不迁移、不删除")
    if artifact.planned_commands:
        typer.echo("事务命令计划:")
        for index, command in enumerate(artifact.planned_commands, start=1):
            typer.echo(f"{index}. {shlex.join(command)}")
    if artifact.warnings:
        typer.echo("安全边界与提示:")
        for warning in artifact.warnings:
            typer.echo(f"- {_chinese_admin_guidance(warning)}")
    if artifact.next_steps:
        typer.echo("下一步:")
        if artifact.status == "dry_run":
            command = ["sudo", "perflens-admin", "switch-mode", artifact.target_mode]
            if artifact.target_mode == "paranoid3_helper":
                command.append("--acknowledge-privileged-helper-risk")
            typer.echo(f"- 确认计划后正式执行: {shlex.join(command)}")
        for step in artifact.next_steps:
            typer.echo(f"- {_chinese_admin_guidance(step)}")


def _chinese_admin_guidance(message: str) -> str:
    labels = {
        "No Collector service, capability, sysctl, or system file was changed.": (
            "没有修改 Collector 服务、capability、sysctl 或任何系统文件。"
        ),
        "Run perflens init inside each project that should analyze evidence.": (
            "在每个需要分析性能证据的项目中运行 perflens init。"
        ),
        "Host perf/kernel policy is not changed; a real collection can still be blocked.": (
            "PerfLens 未修改主机 perf/内核策略; 真实采集仍可能被内核阻止。"
        ),
        "Users added to the perflens group must start a new login session.": (
            "新加入 perflens 组的用户必须重新登录, 当前会话才会获得组权限。"
        ),
        "Start a new login session for every newly authorized user.": (
            "每个新授权用户都需要退出并重新登录。"
        ),
        "Run perflens accept-collector --authorize-host-acceptance as an ordinary user.": (
            "以普通用户运行 perflens accept-collector --authorize-host-acceptance。"
        ),
        "Enable automatic collection in the generated Codex MCP configuration.": (
            "按生成的 Codex MCP 配置启用自动采集。"
        ),
        "Host perf/kernel policy is not changed.": "PerfLens 未修改主机 perf/内核策略。",
        "Both Collector spool directories and all retained evidence are preserved.": (
            "两个 Collector 证据目录及其中已有证据都会保留。"
        ),
        "Run perflens init --update inside every previously initialized project.": (
            "在每个已初始化项目中运行 perflens init --update, 使 MCP 配置与主机模式同步。"
        ),
        "The previous Collector mode was restored successfully.": (
            "之前的 Collector 模式已成功恢复。"
        ),
        "A stale managed privileged Helper unit was found while cap_perfmon is selected; "
        "the repair will stop and remove it.": (
            "当前策略为 cap_perfmon, 但发现残留的托管特权 Helper; 修复会停止并移除它。"
        ),
        "The selected mode is already active, but its managed service template differs "
        "from the installed package.": ("目标模式已经生效, 但托管服务模板与当前安装包不一致。"),
        "Run sudo perflens-admin upgrade to update managed service templates without "
        "changing mode or policy.": (
            "运行 sudo perflens-admin upgrade 更新托管服务模板, 不改变模式或策略。"
        ),
        "Have an administrator review the host threat model and adjust the kernel policy "
        "separately before retrying.": ("请管理员先审查主机威胁模型并单独调整内核策略, 然后重试。"),
        "Choose paranoid3_helper with explicit risk acknowledgement, choose analysis_only, "
        "or have an administrator review the kernel policy separately.": (
            "请选择并明确确认 paranoid3_helper 风险、改用 analysis_only, "
            "或让管理员单独审查内核策略。"
        ),
    }
    if message.startswith("cap_perfmon is blocked by perf_event_paranoid="):
        value = message.partition("=")[2].partition(";")[0]
        return f"perf_event_paranoid={value} 会阻止 cap_perfmon; PerfLens 未修改 sysctl。"
    if message.startswith("The Rust Helper runs in a root service bounded to "):
        return (
            "Rust Helper 以 root 服务运行, 但 capability 被限制为 CAP_PERFMON、"
            "CAP_SYS_ADMIN 和 CAP_SYS_PTRACE; 这会扩大主机安全边界。"
        )
    return labels.get(message, message)


def _render_deployment_chinese(artifact: CollectorDeploymentArtifact) -> None:
    status_labels = {
        "dry_run": "预检通过; 尚未修改系统",
        "deployed": "部署完成; Collector 健康握手通过",
    }
    warning_labels = {
        "Host perf/kernel policy is not changed; a real collection can still be blocked.": (
            "PerfLens 未修改主机 perf/内核策略; 真实采集仍可能被内核阻止。"
        ),
        "Users added to the perflens group must start a new login session.": (
            "新加入 perflens 组的用户必须重新登录; 当前会话才会获得组权限。"
        ),
    }
    typer.echo("PerfLens Collector 部署")
    typer.echo(f"状态: {status_labels[artifact.status]}")
    typer.echo(f"检查的配置: {artifact.config_source}")
    typer.echo(f"系统策略位置: {artifact.config_path}")
    typer.echo(f"systemd 服务位置: {artifact.service_path}")
    typer.echo(f"Collector 程序: {artifact.collector_command}")
    typer.echo(f"权限模式: {artifact.privilege_mode}")
    typer.echo("授权普通用户 UID: " + ", ".join(str(uid) for uid in artifact.allowed_uids))
    command_label = (
        "计划执行的固定系统命令" if artifact.status == "dry_run" else "已执行的固定系统命令"
    )
    typer.echo(f"{command_label}:")
    if artifact.planned_commands:
        for index, command in enumerate(artifact.planned_commands, start=1):
            typer.echo(f"{index}. {shlex.join(command)}")
    else:
        typer.echo("- 无")
    if artifact.warnings:
        typer.echo("安全边界与提示:")
        for warning in artifact.warnings:
            typer.echo(f"- {warning_labels.get(warning, warning)}")
    typer.echo("下一步:")
    if artifact.status == "dry_run":
        trusted_admin = str(Path(artifact.collector_command).with_name("perflens-admin"))
        deploy_arguments = [
            "sudo",
            trusted_admin,
            "deploy",
            "--config",
            artifact.config_source,
            "--collector-command",
            artifact.collector_command,
        ]
        if artifact.privilege_mode == "paranoid3_helper":
            deploy_arguments.append("--acknowledge-privileged-helper-risk")
        deploy_command = shlex.join(deploy_arguments)
        typer.echo("- 确认以上路径、UID 和命令符合预期后; 再执行正式部署:")
        typer.echo(f"  {deploy_command}")
    else:
        typer.echo("- 如果刚被加入 perflens 组; 请退出当前登录会话后重新登录。")
        typer.echo("- 以授权的普通用户运行真实短时验收:")
        typer.echo("  perflens accept-collector --authorize-host-acceptance")
    typer.echo("- 自动化程序需要完整版本化结果时; 给本命令加 --json。")


def _render_spool_status_chinese(artifact: CollectorSpoolStatusArtifact) -> None:
    status_labels = {
        "ready": "正常",
        "warning": "接近边界",
        "exhausted": "容量已耗尽",
        "unsafe": "目录中存在不安全项目",
        "unavailable": "当前无法检查",
    }
    issue_labels = {
        "spool_unavailable": "spool 不存在、不可访问或不是安全目录。",
        "unexpected_non_regular_entry": "spool 中存在子目录、链接或其他非普通文件。",
        "spool_entry_changed_during_scan": "扫描期间有目录项发生变化。请停止写入后重试。",
        "spool_capacity_inspection_failed": "无法完整读取目录或文件系统容量。",
        "artifact_count_quota_exhausted": "产物文件数量已达到策略上限。",
        "spool_byte_quota_exhausted": "产物逻辑大小已达到策略上限。",
        "filesystem_free_space_reserve_exhausted": "文件系统空闲空间已触及保留边界。",
        "full_size_collection_cannot_be_reserved": "当前空间无法容纳策略允许的最大单次产物。",
        "spool_byte_quota_above_80_percent": "产物逻辑大小已使用至少 80%。",
        "artifact_count_quota_above_80_percent": "产物文件数量已使用至少 80%。",
    }
    advice_labels = {
        "ready": "长时间自动采集前继续运行本命令检查容量。",
        "warning": "先审查并归档旧证据。避免剩余容量耗尽。",
        "exhausted": "先审查并归档旧证据。只明确删除不再需要的文件。",
        "unsafe": "停止 Collector。在不跟随链接的前提下检查异常目录项。",
        "unavailable": "检查已部署策略、spool 路径、权限和文件系统状态。",
    }
    if artifact.spool_root == "/var/lib/perflens-helper" and artifact.status in {
        "warning",
        "exhausted",
    }:
        advice_labels[artifact.status] = (
            "停止新的采集; 由管理员使用 archive-spool 先归档和验证; 再明确清理 Helper 证据。"
        )
    typer.echo("PerfLens Collector 存储检查 (只读)")
    typer.echo(f"状态: {status_labels[artifact.status]}")
    typer.echo(f"目录: {artifact.spool_root}")
    typer.echo(f"产物文件: {artifact.observed_artifact_count} / {artifact.max_spool_artifacts}")
    typer.echo(
        "产物逻辑大小: "
        f"{_human_bytes(artifact.observed_logical_bytes)} / "
        f"{_human_bytes(artifact.max_spool_bytes)}"
    )
    typer.echo(f"文件系统可用空间: {_optional_human_bytes(artifact.filesystem_free_bytes)}")
    typer.echo(f"策略保留空间: {_human_bytes(artifact.min_free_bytes)}")
    typer.echo(
        f"当前单次最多可采集: {_optional_human_bytes(artifact.max_collectable_output_bytes)}"
    )
    typer.echo(f"目录扫描完整: {'是' if artifact.scan_complete else '否'}")
    if artifact.issues:
        typer.echo("问题与提示:")
        for issue in artifact.issues:
            typer.echo(f"- {issue_labels.get(issue, issue)}")
    typer.echo("建议:")
    typer.echo(f"- {advice_labels[artifact.status]}")


def _render_archive_verification_chinese(
    artifact: CollectorSpoolArchiveVerificationArtifact,
) -> None:
    typer.echo("PerfLens Collector 归档验证 (只读)")
    typer.echo("状态: 验证通过")
    typer.echo(f"归档: {artifact.archive_path}")
    typer.echo(f"归档 ID: {artifact.archive_id}")
    typer.echo(f"归档 SHA-256: {artifact.archive_sha256}")
    typer.echo(f"归档内证据: {artifact.artifact_count} 个")
    typer.echo(f"证据逻辑大小: {_human_bytes(artifact.total_logical_bytes)}")
    typer.echo(f"归档创建时间: {artifact.archive_created_at}")
    typer.echo(f"本次检查时间: {artifact.checked_at}")
    if artifact.source_artifacts_checked:
        typer.echo("源文件核对: 已完成")
        typer.echo(f"仍存在且完全匹配: {artifact.present_source_artifact_count}")
        typer.echo(f"已经不存在: {artifact.absent_source_artifact_count}")
    else:
        typer.echo("源文件核对: 未请求 (可加 --verify-sources)")
    typer.echo("结论:")
    typer.echo("- ZIP 结构、manifest、成员大小和逐文件 SHA-256 全部匹配。")
    typer.echo("- 本命令没有删除、覆盖或修改归档与 spool 证据。")
    if artifact.source_artifacts_checked and artifact.absent_source_artifact_count:
        typer.echo("- 原文件不存在不影响归档完整性。它们可能已经完成过安全清理。")


def _optional_human_bytes(value: int | None) -> str:
    return "未知" if value is None else _human_bytes(value)


def _human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    return f"{amount:.0f} {unit}" if amount.is_integer() else f"{amount:.1f} {unit}"


def _fail(error: PerfLensError) -> NoReturn:
    output = (
        error_json(error)
        if json_errors_enabled()
        else render_error_chinese(error, executable="perflens-admin")
    )
    typer.echo(output, err=True)
    raise typer.Exit(code=ERROR_EXIT_CODES[error.code])


def main() -> None:
    app()


if __name__ == "__main__":
    main()
