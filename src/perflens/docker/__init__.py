"""Local Docker target-runtime adapters and deterministic identity checks."""

from perflens.docker.build_adapter import (
    DockerBuildExecutionResult,
    TypedDockerBuildAdapter,
    open_local_docker_build_adapter,
)
from perflens.docker.build_capability import project_docker_build_capability
from perflens.docker.build_context import (
    DockerBuildContextSnapshot,
    assert_docker_build_context_snapshot_current,
    build_docker_build_recipe,
    capture_docker_build_context,
    open_docker_build_context_snapshot,
)
from perflens.docker.builder_policy import (
    DockerAdministratorBuilderPolicy,
    assert_docker_administrator_builder_policy_current,
    load_docker_administrator_builder_policy,
)
from perflens.docker.capability import discover_docker_capability
from perflens.docker.cgroup import (
    CgroupV2ResourceReader,
    build_container_resource_context,
)
from perflens.docker.existing import discover_existing_container_processes
from perflens.docker.identity import resolve_existing_container_target
from perflens.docker.optimization_runtime import DockerOptimizationRuntime
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    DockerOptimizationSessionAuthority,
)
from perflens.docker.project_config import (
    DockerOptimizationProjectPolicy,
    DockerProjectPolicy,
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.docker.session import DockerSessionAuthority
from perflens.docker.workload import build_container_workload_spec

__all__ = [
    "EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION",
    "CgroupV2ResourceReader",
    "DockerAdministratorBuilderPolicy",
    "DockerBuildContextSnapshot",
    "DockerBuildExecutionResult",
    "DockerOptimizationProjectPolicy",
    "DockerOptimizationRuntime",
    "DockerOptimizationSessionAuthority",
    "DockerProjectPolicy",
    "DockerSessionAuthority",
    "TypedDockerBuildAdapter",
    "assert_docker_administrator_builder_policy_current",
    "assert_docker_build_context_snapshot_current",
    "build_container_resource_context",
    "build_container_workload_spec",
    "build_docker_build_recipe",
    "capture_docker_build_context",
    "discover_docker_capability",
    "discover_existing_container_processes",
    "load_docker_administrator_builder_policy",
    "load_docker_project_policy",
    "open_docker_build_context_snapshot",
    "open_local_docker_build_adapter",
    "project_docker_build_capability",
    "render_default_docker_project_policy",
    "resolve_existing_container_target",
]
