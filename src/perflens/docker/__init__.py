"""Local Docker target-runtime adapters and deterministic identity checks."""

from perflens.docker.capability import discover_docker_capability
from perflens.docker.identity import resolve_existing_container_target

__all__ = ["discover_docker_capability", "resolve_existing_container_target"]
