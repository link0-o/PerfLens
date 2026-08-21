"""Local Docker target-runtime adapters and deterministic identity checks."""

from perflens.docker.capability import discover_docker_capability
from perflens.docker.cgroup import (
    CgroupV2ResourceReader,
    build_container_resource_context,
)
from perflens.docker.existing import discover_existing_container_processes
from perflens.docker.identity import resolve_existing_container_target
from perflens.docker.session import DockerSessionAuthority
from perflens.docker.workload import build_container_workload_spec

__all__ = [
    "CgroupV2ResourceReader",
    "DockerSessionAuthority",
    "build_container_resource_context",
    "build_container_workload_spec",
    "discover_docker_capability",
    "discover_existing_container_processes",
    "resolve_existing_container_target",
]
