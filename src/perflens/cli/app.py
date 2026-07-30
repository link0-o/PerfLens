"""PerfLens command-line interface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from perflens.application.analyze import analyze_folded, analyze_perf_data, analyze_perf_script
from perflens.application.diagnose import classify_analysis, report_analysis
from perflens.application.symbols import get_source_context, inspect_elf, resolve_source
from perflens.artifacts.filesystem import write_json_atomic, write_text_atomic
from perflens.contracts.artifacts import ErrorArtifact, ErrorBody
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.security.paths import validate_output_file

app = typer.Typer(
    name="perflens",
    help="Evidence-driven Linux performance analysis.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)


@app.callback()
def root() -> None:
    """Run deterministic PerfLens analysis commands."""


@app.command("analyze-folded")
def analyze_folded_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=False, dir_okay=False, help="Folded stack input."),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="Versioned JSON artifact."),
    ],
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 1 << 30,
    max_records: Annotated[int, typer.Option(min=1)] = 10_000_000,
    max_line_chars: Annotated[int, typer.Option(min=16)] = 1 << 20,
    max_stack_depth: Annotated[int, typer.Option(min=1)] = 4_096,
    max_unique_frames: Annotated[int, typer.Option(min=1)] = 2_000_000,
    max_unique_call_paths: Annotated[int, typer.Option(min=1)] = 1_000_000,
    max_warnings: Annotated[int, typer.Option(min=0)] = 100,
    top_n: Annotated[int, typer.Option("--top-n", min=1)] = 10_000,
    call_path_limit: Annotated[int, typer.Option(min=1)] = 1_000,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
) -> None:
    """Analyze standard FlameGraph folded stacks."""
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
        typer.Option("--input", exists=False, dir_okay=False, help="perf script text input."),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="Versioned JSON artifact."),
    ],
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 1 << 30,
    max_records: Annotated[int, typer.Option(min=1)] = 10_000_000,
    max_line_chars: Annotated[int, typer.Option(min=16)] = 1 << 20,
    max_stack_depth: Annotated[int, typer.Option(min=1)] = 4_096,
    max_unique_frames: Annotated[int, typer.Option(min=1)] = 2_000_000,
    max_unique_call_paths: Annotated[int, typer.Option(min=1)] = 1_000_000,
    max_warnings: Annotated[int, typer.Option(min=0)] = 100,
    top_n: Annotated[int, typer.Option("--top-n", min=1)] = 10_000,
    call_path_limit: Annotated[int, typer.Option(min=1)] = 1_000,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
) -> None:
    """Analyze text from the documented PerfLens perf script field set."""
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
        typer.Option("--input", exists=False, dir_okay=False, help="perf.data input."),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", dir_okay=False, help="Versioned JSON artifact."),
    ],
    perf_path: Annotated[
        Path | None,
        typer.Option("--perf-path", dir_okay=False, help="Explicit perf executable path."),
    ] = None,
    timeout_seconds: Annotated[float, typer.Option(min=0.1)] = 300.0,
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 1 << 30,
    max_records: Annotated[int, typer.Option(min=1)] = 10_000_000,
    max_line_chars: Annotated[int, typer.Option(min=16)] = 1 << 20,
    max_stack_depth: Annotated[int, typer.Option(min=1)] = 4_096,
    max_unique_frames: Annotated[int, typer.Option(min=1)] = 2_000_000,
    max_unique_call_paths: Annotated[int, typer.Option(min=1)] = 1_000_000,
    max_warnings: Annotated[int, typer.Option(min=0)] = 100,
    top_n: Annotated[int, typer.Option("--top-n", min=1)] = 10_000,
    call_path_limit: Annotated[int, typer.Option(min=1)] = 1_000,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
) -> None:
    """Analyze perf.data through the system perf script adapter."""
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


@app.command("inspect-elf")
def inspect_elf_command(
    input_path: Annotated[Path, typer.Option("--input", dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 8 << 20,
) -> None:
    """Inspect ELF identity, Build ID, and debug capabilities."""
    try:
        artifact = inspect_elf(input_path)
        safe_output = validate_output_file(output_path, input_path=Path(artifact.path))
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("resolve-source")
def resolve_source_command(
    binary_path: Annotated[Path, typer.Option("--binary", dir_okay=False)],
    module_offset: Annotated[str, typer.Option("--module-offset")],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    runtime_address: Annotated[str | None, typer.Option("--runtime-address")] = None,
    addr2line_path: Annotated[
        Path | None,
        typer.Option("--addr2line-path", dir_okay=False),
    ] = None,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 8 << 20,
) -> None:
    """Resolve a verified module-relative offset to source frames."""
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
    source_path: Annotated[Path, typer.Option("--file", dir_okay=False)],
    line: Annotated[int, typer.Option(min=1)],
    workspace_root: Annotated[Path, typer.Option("--workspace", file_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    before: Annotated[int, typer.Option(min=0, max=200)] = 20,
    after: Annotated[int, typer.Option(min=0, max=200)] = 20,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 8 << 20,
) -> None:
    """Read bounded source context inside an allowed workspace."""
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
    analysis_path: Annotated[Path, typer.Option("--analysis", dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
) -> None:
    """Build a candidate-only evidence and diagnosis bundle."""
    try:
        artifact = classify_analysis(analysis_path, max_input_bytes=max_input_bytes)
        safe_output = validate_output_file(output_path, input_path=analysis_path)
        write_json_atomic(artifact, safe_output, max_output_bytes=max_output_bytes)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(safe_output))


@app.command("report")
def report_command(
    analysis_path: Annotated[Path, typer.Option("--analysis", dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    problem_statement: Annotated[str, typer.Option("--problem")] = "Not supplied.",
    target_metric: Annotated[str, typer.Option("--metric")] = "Not supplied.",
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
) -> None:
    """Render an evidence-constrained Markdown performance report."""
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
    stable_material = f"{error.code}:{error.stage}:{error.message}"
    error_id = f"err-{hashlib.sha256(stable_material.encode()).hexdigest()[:16]}"
    artifact = ErrorArtifact(
        error=ErrorBody(
            error_id=error_id,
            code=error.code,
            stage=error.stage,
            message=error.message,
            recoverable=error.recoverable,
            retryable=error.retryable,
            details=error.details,
            suggested_actions=error.suggested_actions,
        )
    )
    typer.echo(
        json.dumps(artifact.model_dump(mode="json"), ensure_ascii=False, sort_keys=True),
        err=True,
    )
    raise typer.Exit(exit_code)


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
