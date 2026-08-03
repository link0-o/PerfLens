"""Human-invoked administrator CLI for optional Collector deployment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from perflens import __version__
from perflens.admin.deploy import deploy_collector
from perflens.contracts.artifacts import ErrorArtifact, ErrorBody
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
