"""PerfLens command-line interface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import typer

from perflens import __version__
from perflens.application.analyze import analyze_folded, analyze_perf_data, analyze_perf_script
from perflens.application.compare import (
    compare_analysis_files,
    compare_benchmark_files,
    normalize_benchmark,
)
from perflens.application.diagnose import classify_analysis, report_analysis
from perflens.application.symbols import get_source_context, inspect_elf, resolve_source
from perflens.artifacts.filesystem import (
    write_json_atomic,
    write_json_new_atomic,
    write_text_atomic,
)
from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    DEFAULT_STAT_EVENTS,
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
from perflens.contracts.artifacts import ErrorArtifact, ErrorBody
from perflens.distribution.codex import render_codex_config
from perflens.distribution.collector import install_collector_assets
from perflens.distribution.onboarding import run_project_setup
from perflens.distribution.skill import install_project_skill
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.reporting.diff import render_benchmark_comparison, render_profile_comparison
from perflens.security.paths import validate_new_output_file, validate_output_file

app = typer.Typer(
    name="perflens",
    help="Evidence-driven Linux performance analysis.",
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
    """Run deterministic PerfLens analysis commands."""
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
            help="Existing project root that will receive .agents/skills.",
        ),
    ] = Path("."),
) -> None:
    """Install the bundled Performance Analysis Skill into a project."""
    try:
        target = install_project_skill(project_root)
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(target))


@app.command("codex-config")
def codex_config_command(
    workspace: Annotated[
        Path,
        typer.Option("--workspace", file_okay=False, help="Allowed workspace root."),
    ] = Path("."),
    artifact_root: Annotated[
        Path | None,
        typer.Option("--artifact-root", file_okay=False),
    ] = None,
    allow_process_execution: Annotated[
        bool,
        typer.Option(
            "--allow-process-execution",
            help="Allow bounded perf.data conversion and source symbolization.",
        ),
    ] = False,
    mcp_command: Annotated[
        Path | None,
        typer.Option("--mcp-command", dir_okay=False),
    ] = None,
) -> None:
    """Print a project-scoped Codex MCP TOML configuration snippet."""
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


@app.command("doctor")
def doctor_command(
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="Optional new JSON output path."),
    ] = None,
    perf_path: Annotated[
        Path | None,
        typer.Option("--perf-path", dir_okay=False, help="Explicit system perf executable."),
    ] = None,
) -> None:
    """Inspect collection permissions without sampling or attaching to a process."""
    try:
        artifact = inspect_collection_capabilities(perf_path)
        if output_path is not None:
            safe_output = validate_new_output_file(output_path)
            write_json_new_atomic(artifact, safe_output, max_output_bytes=1 << 20)
            typer.echo(str(safe_output))
            return
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(
        json.dumps(artifact.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
    )


@app.command("setup")
def setup_command(
    project_root: Annotated[
        Path,
        typer.Option(
            "--project",
            file_okay=False,
            help="Existing project that will receive the Skill and onboarding files.",
        ),
    ] = Path("."),
    output_directory: Annotated[
        Path | None,
        typer.Option(
            "--output-directory",
            file_okay=False,
            help="New directory inside the project; defaults to perflens-setup.",
        ),
    ] = None,
    install_skill: Annotated[
        bool,
        typer.Option(
            "--install-skill/--skip-skill",
            help="Install the bundled Skill when it is not already present.",
        ),
    ] = True,
    allow_process_execution: Annotated[
        bool,
        typer.Option(
            "--allow-process-execution",
            help="Include bounded perf.data conversion and symbolization in the MCP snippet.",
        ),
    ] = False,
    mcp_command: Annotated[
        Path | None,
        typer.Option("--mcp-command", dir_okay=False),
    ] = None,
    prepare_collector: Annotated[
        bool,
        typer.Option(
            "--prepare-collector",
            help="Stage administrator-reviewed Collector assets; never install or elevate.",
        ),
    ] = False,
    automatic_collection: Annotated[
        bool,
        typer.Option(
            "--automatic-collection",
            help="Generate MCP policy for authorized unprivileged project launch and collection.",
        ),
    ] = False,
    collector_uid: Annotated[
        int | None,
        typer.Option(
            "--collector-uid",
            min=0,
            help="Ordinary UID to place in staged Collector policy; defaults to current UID.",
        ),
    ] = None,
    collector_command: Annotated[
        Path,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="Future absolute system Collector path used only in staged assets.",
        ),
    ] = Path("/opt/perflens/bin/perflens-collector"),
    perf_path: Annotated[
        Path,
        typer.Option("--perf-path", dir_okay=False),
    ] = Path("/usr/bin/perf"),
) -> None:
    """Generate a safe Chinese-first onboarding bundle for one project."""
    try:
        artifact = run_project_setup(
            project_root,
            output_directory=output_directory,
            install_skill=install_skill,
            allow_process_execution=allow_process_execution,
            mcp_command=mcp_command,
            prepare_collector=prepare_collector,
            automatic_collection=automatic_collection,
            collector_uid=collector_uid,
            collector_command=collector_command,
            perf_path=perf_path,
        )
    except PerfLensError as exc:
        _fail(exc)
    skill_label = {
        "installed": "已安装",
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
    typer.echo(f"采集状态: {collection_label}")
    typer.echo(
        f"项目自动运行: {'已启用' if artifact.automatic_collection_enabled else '未启用'}"
    )
    typer.echo(f"请继续阅读: {Path(artifact.output_directory) / '下一步.zh-CN.md'}")


@app.command("stage-collector-assets")
def stage_collector_assets_command(
    output_directory: Annotated[
        Path,
        typer.Option(
            "--output-directory",
            file_okay=False,
            help="New directory that will receive inspectable service templates.",
        ),
    ],
    allowed_uids: Annotated[
        list[int] | None,
        typer.Option(
            "--allowed-uid",
            min=0,
            help="Repeat for each ordinary UID permitted by the staged policy.",
        ),
    ] = None,
    collector_command: Annotated[
        Path,
        typer.Option(
            "--collector-command",
            dir_okay=False,
            help="Absolute perflens-collector path for the staged systemd unit.",
        ),
    ] = Path("/usr/bin/perflens-collector"),
    perf_path: Annotated[
        Path,
        typer.Option(
            "--perf-path",
            dir_okay=False,
            help="Absolute perf path for the staged Collector policy.",
        ),
    ] = Path("/usr/bin/perf"),
) -> None:
    """Stage Collector policy/systemd templates without installing or using sudo."""
    try:
        target = install_collector_assets(
            output_directory,
            allowed_uids=tuple(allowed_uids or (1000,)),
            collector_command=collector_command,
            perf_path=perf_path,
        )
    except PerfLensError as exc:
        _fail(exc)
    typer.echo(str(target))


@app.command("verify-collector")
def verify_collector_command(
    socket_path: Annotated[
        Path,
        typer.Option("--socket", dir_okay=False, help="Existing Collector Unix socket."),
    ],
    pid: Annotated[int, typer.Option("--pid", min=1, help="Owned live PID used for the probe.")],
    duration_seconds: Annotated[
        float,
        typer.Option(
            "--duration-seconds",
            min=0.1,
            max=5.0,
            help="Short perf-stat probe duration; capped at five seconds.",
        ),
    ] = 1.0,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", dir_okay=False, help="Optional new JSON metadata path."),
    ] = None,
    perf_path: Annotated[
        Path | None,
        typer.Option(
            "--perf-path",
            dir_okay=False,
            help="Optional local perf path used only for the capability snapshot.",
        ),
    ] = None,
    authorize_target: Annotated[
        bool,
        typer.Option("--authorize-target", help="Confirm the bounded observation impact."),
    ] = False,
    authorization: Annotated[str, typer.Option("--authorization")] = "",
    authorize_pid_attach: Annotated[
        bool,
        typer.Option("--authorize-pid-attach", help="Separately confirm attachment to --pid."),
    ] = False,
    pid_authorization: Annotated[str, typer.Option("--pid-authorization")] = "",
) -> None:
    """Run one bounded real perf-stat probe through an installed Collector."""
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
                events=DEFAULT_STAT_EVENTS,
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
    typer.echo(
        json.dumps(artifact.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
    )


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


@app.command("normalize-benchmark")
def normalize_benchmark_command(
    input_path: Annotated[Path, typer.Option("--input", dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    source_format: Annotated[
        Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"],
        typer.Option("--format"),
    ] = "auto",
    benchmark_name: Annotated[str | None, typer.Option("--benchmark-name")] = None,
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 64 << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 64 << 20,
) -> None:
    """Normalize supported third-party benchmark JSON."""
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
    baseline_path: Annotated[Path, typer.Option("--baseline", dir_okay=False)],
    candidate_path: Annotated[Path, typer.Option("--candidate", dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    markdown_output: Annotated[Path | None, typer.Option("--markdown-output")] = None,
    minimum_delta_percent: Annotated[float, typer.Option(min=0)] = 1.0,
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 128 << 20,
) -> None:
    """Compare two PerfLens profile analysis artifacts."""
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
    baseline_path: Annotated[Path, typer.Option("--baseline", dir_okay=False)],
    candidate_path: Annotated[Path, typer.Option("--candidate", dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    markdown_output: Annotated[Path | None, typer.Option("--markdown-output")] = None,
    source_format: Annotated[
        Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"],
        typer.Option("--format"),
    ] = "auto",
    benchmark_name: Annotated[str | None, typer.Option("--benchmark-name")] = None,
    minimum_practical_impact_percent: Annotated[float, typer.Option(min=0)] = 1.0,
    max_input_bytes: Annotated[int, typer.Option(min=1)] = 64 << 20,
    max_output_bytes: Annotated[int, typer.Option(min=1)] = 64 << 20,
) -> None:
    """Compare two normalized or supported third-party benchmark files."""
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
    data_output: Annotated[Path, typer.Option("--data-output", dir_okay=False)],
    metadata_output: Annotated[Path, typer.Option("--metadata-output", dir_okay=False)],
    mode: Annotated[
        Literal["record", "stat", "sched", "lock", "off_cpu"],
        typer.Option("--mode"),
    ] = "record",
    executable: Annotated[
        Path | None,
        typer.Option("--executable", dir_okay=False, help="Absolute target executable."),
    ] = None,
    target_arguments: Annotated[
        list[str] | None,
        typer.Option("--target-arg", help="Repeat for each target argument."),
    ] = None,
    pid: Annotated[int | None, typer.Option("--pid", min=1)] = None,
    duration_seconds: Annotated[float | None, typer.Option("--duration-seconds", min=0.01)] = None,
    perf_path: Annotated[Path | None, typer.Option("--perf-path", dir_okay=False)] = None,
    frequency_hz: Annotated[int, typer.Option("--frequency-hz", min=1, max=10_000)] = 99,
    call_graph: Annotated[Literal["fp", "dwarf", "lbr"], typer.Option("--call-graph")] = "dwarf",
    events: Annotated[
        list[str] | None,
        typer.Option("--event", help="Repeat to override default perf-stat events."),
    ] = None,
    timeout_seconds: Annotated[float, typer.Option("--timeout-seconds", min=0.1)] = 300.0,
    max_data_bytes: Annotated[int, typer.Option("--max-data-bytes", min=1)] = 1 << 30,
    max_metadata_bytes: Annotated[int, typer.Option("--max-metadata-bytes", min=1)] = 8 << 20,
    authorize_target: Annotated[
        bool,
        typer.Option("--authorize-target", help="Confirm target execution or observation impact."),
    ] = False,
    authorization: Annotated[str, typer.Option("--authorization")] = "",
    authorize_pid_attach: Annotated[
        bool,
        typer.Option("--authorize-pid-attach", help="Separately confirm attachment to --pid."),
    ] = False,
    pid_authorization: Annotated[str, typer.Option("--pid-authorization")] = "",
) -> None:
    """Collect bounded perf data only after explicit, per-invocation authorization."""
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
