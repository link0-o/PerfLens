"""Human-invoked administrator CLI for optional Collector deployment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from perflens import __version__
from perflens.admin.deploy import (
    deploy_collector,
    inspect_collector_spool,
    undeploy_collector,
    update_collector_policy,
    upgrade_collector,
)
from perflens.contracts.artifacts import CollectorSpoolStatusArtifact, ErrorArtifact, ErrorBody
from perflens.domain.errors import ErrorCode, PerfLensError

app = typer.Typer(
    name="perflens-admin",
    help="Explicit administrator operations for the optional PerfLens Collector.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)


@app.callback(invoke_without_command=True)
def root(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the PerfLens version and exit.", is_eager=True),
    ] = False,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("deploy")
def deploy_command(
    config: Annotated[
        Path,
        typer.Option("--config", dir_okay=False, help="Reviewed Collector TOML policy."),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate and print the deployment plan without changes."),
    ] = False,
    collector_command: Annotated[
        Path | None,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="Trusted installed Collector path; defaults beside perflens-admin.",
        ),
    ] = None,
) -> None:
    """Install and start the fixed Collector service from one data-only config."""
    try:
        result = deploy_collector(
            config,
            dry_run=dry_run,
            collector_command=collector_command,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("undeploy")
def undeploy_command(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate the managed unit without changing the host."),
    ] = False,
) -> None:
    """Stop and remove the managed service while preserving policy and artifacts."""
    try:
        result = undeploy_collector(dry_run=dry_run)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


@app.command("upgrade")
def upgrade_command(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate and compare the managed unit without changes."),
    ] = False,
    collector_command: Annotated[
        Path | None,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="Trusted upgraded Collector path; defaults beside perflens-admin.",
        ),
    ] = None,
) -> None:
    """Safely upgrade and restart the Collector while preserving policy and artifacts."""
    try:
        result = upgrade_collector(
            dry_run=dry_run,
            collector_command=collector_command,
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
            help="Deployed Collector TOML policy to inspect.",
        ),
    ] = Path("/etc/perflens/collector.toml"),
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the complete versioned JSON artifact."),
    ] = False,
) -> None:
    """Read-only Chinese summary of spool usage and remaining capacity."""
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
            help="Separate reviewed candidate Collector TOML policy.",
        ),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate and compare policy without changes."),
    ] = False,
) -> None:
    """Safely update policy, restart, health-check, and roll back on failure."""
    try:
        result = update_collector_policy(config, dry_run=dry_run)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(result.model_dump_json(indent=2))


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
    typer.echo("PerfLens Collector 存储检查 (只读)")
    typer.echo(f"状态: {status_labels[artifact.status]}")
    typer.echo(f"目录: {artifact.spool_root}")
    typer.echo(
        "产物文件: "
        f"{artifact.observed_artifact_count} / {artifact.max_spool_artifacts}"
    )
    typer.echo(
        "产物逻辑大小: "
        f"{_human_bytes(artifact.observed_logical_bytes)} / "
        f"{_human_bytes(artifact.max_spool_bytes)}"
    )
    typer.echo(
        "文件系统可用空间: "
        f"{_optional_human_bytes(artifact.filesystem_free_bytes)}"
    )
    typer.echo(f"策略保留空间: {_human_bytes(artifact.min_free_bytes)}")
    typer.echo(
        "当前单次最多可采集: "
        f"{_optional_human_bytes(artifact.max_collectable_output_bytes)}"
    )
    typer.echo(f"目录扫描完整: {'是' if artifact.scan_complete else '否'}")
    if artifact.issues:
        typer.echo("问题与提示:")
        for issue in artifact.issues:
            typer.echo(f"- {issue_labels.get(issue, issue)}")
    typer.echo("建议:")
    typer.echo(f"- {advice_labels[artifact.status]}")


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
    exit_code = {
        ErrorCode.INVALID_INPUT: 2,
        ErrorCode.UNSUPPORTED_FORMAT: 3,
        ErrorCode.PROFILE_PARSE_FAILED: 3,
        ErrorCode.EXTERNAL_TOOL_FAILED: 6,
        ErrorCode.EXTERNAL_TOOL_TIMEOUT: 6,
        ErrorCode.RESOURCE_LIMIT_EXCEEDED: 4,
        ErrorCode.PATH_SAFETY_VIOLATION: 5,
        ErrorCode.OUTPUT_WRITE_FAILED: 5,
        ErrorCode.INTERNAL_ERROR: 70,
    }[error.code]
    material = f"{error.code}:{error.stage}:{error.message}"
    payload = ErrorArtifact(
        error=ErrorBody(
            error_id=f"err-{hashlib.sha256(material.encode()).hexdigest()[:16]}",
            code=error.code.value,
            stage=error.stage,
            message=error.message,
            recoverable=error.recoverable,
            retryable=error.retryable,
            details=error.details,
            suggested_actions=error.suggested_actions,
        )
    )
    typer.echo(json.dumps(payload.model_dump(mode="json"), ensure_ascii=False), err=True)
    raise typer.Exit(code=exit_code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
