"""Project-scoped GitHub Copilot CLI integration over the shared MCP JSON format."""

from __future__ import annotations

from pathlib import Path

from perflens.distribution.claude import (
    ClaudeConfigInstallPlan,
    ClaudeConfigRemovalPlan,
    plan_claude_project_config,
    plan_claude_project_config_removal,
    render_claude_config,
)

CopilotConfigInstallPlan = ClaudeConfigInstallPlan
CopilotConfigRemovalPlan = ClaudeConfigRemovalPlan


def render_copilot_config(
    workspace: Path,
    *,
    artifact_root: Path | None = None,
    allow_process_execution: bool = False,
    automatic_collection: bool = False,
    allow_project_execution: bool = False,
    allow_pid_attach: bool = False,
    collector_socket: Path = Path("/run/perflens/collector.sock"),
    collector_spool_root: Path = Path("/var/lib/perflens"),
    automatic_modes: tuple[str, ...] = ("stat", "record"),
    automatic_max_duration_seconds: float = 30.0,
    automatic_max_frequency_hz: int = 99,
    automatic_max_output_bytes: int = 256 << 20,
    automatic_plan_ttl_seconds: int = 120,
    allow_docker_targets: bool = False,
    allow_docker_optimization: bool = False,
    docker_project_config: Path | None = None,
    mcp_command: Path | None = None,
) -> str:
    """Return the project `.mcp.json` document understood by Copilot CLI."""
    return render_claude_config(
        workspace,
        artifact_root=artifact_root,
        allow_process_execution=allow_process_execution,
        automatic_collection=automatic_collection,
        allow_project_execution=allow_project_execution,
        allow_pid_attach=allow_pid_attach,
        collector_socket=collector_socket,
        collector_spool_root=collector_spool_root,
        automatic_modes=automatic_modes,
        automatic_max_duration_seconds=automatic_max_duration_seconds,
        automatic_max_frequency_hz=automatic_max_frequency_hz,
        automatic_max_output_bytes=automatic_max_output_bytes,
        automatic_plan_ttl_seconds=automatic_plan_ttl_seconds,
        allow_docker_targets=allow_docker_targets,
        allow_docker_optimization=allow_docker_optimization,
        docker_project_config=docker_project_config,
        mcp_command=mcp_command,
    )


def plan_copilot_project_config(
    workspace: Path,
    configuration: str,
    *,
    managed_configuration: str | None = None,
) -> CopilotConfigInstallPlan:
    """Safely merge PerfLens into Copilot CLI's project `.mcp.json`."""
    return plan_claude_project_config(
        workspace,
        configuration,
        managed_configuration=managed_configuration,
    )


def plan_copilot_project_config_removal(
    workspace: Path,
    *,
    managed_configuration: str | None,
) -> CopilotConfigRemovalPlan | None:
    """Remove only a recorded PerfLens Copilot CLI `.mcp.json` entry."""
    return plan_claude_project_config_removal(
        workspace,
        managed_configuration=managed_configuration,
    )
