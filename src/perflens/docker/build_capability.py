"""Deterministic projection of Docker build-and-optimize capability evidence."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.contracts.docker_build import (
    DockerBuildCapabilityArtifact,
    DockerBuilderProjection,
    DockerBuildToolProjection,
    NetworkTier,
)
from perflens.docker.project_config import DockerProjectPolicy
from perflens.domain.errors import ErrorCode, PerfLensError

_NETWORK_ORDER: tuple[NetworkTier, ...] = (
    "local_only",
    "pinned_pull",
    "admin_builder_network",
)


def project_docker_build_capability(
    *,
    runtime: DockerRuntimeCapabilityArtifact,
    policy: DockerProjectPolicy,
    docker_tool: DockerBuildToolProjection | None,
    buildx_tool: DockerBuildToolProjection | None,
    builder: DockerBuilderProjection | None,
    available_network_tiers: tuple[NetworkTier, ...],
    base_image_present: bool,
    collector_available: bool,
    checked_at: datetime | None = None,
) -> DockerBuildCapabilityArtifact:
    """Combine independently inspected inputs without performing a build or pull."""
    _verify_runtime(runtime)
    if len(set(available_network_tiers)) != len(available_network_tiers):
        raise _capability_error("Docker build network tiers must be unique")
    try:
        tiers = tuple(sorted(available_network_tiers, key=_NETWORK_ORDER.index))
    except ValueError as exc:
        raise _capability_error(
            "Docker build capability contains an unsupported network tier"
        ) from exc

    limitations: list[str] = []
    optimization = policy.optimization
    if runtime.status != "available":
        limitations.append("The fixed local Docker runtime is not available.")
    if not optimization.enabled:
        limitations.append("Docker optimization is disabled in the project policy.")
    if not policy.managed.benchmark_output:
        limitations.append("The managed workload has no Benchmark output contract.")
    if docker_tool is None or buildx_tool is None or builder is None:
        limitations.append("Docker, Buildx, or the selected Builder identity is unavailable.")
    if optimization.network_tier not in tiers:
        limitations.append("The authorized network tier is unavailable.")
    if optimization.network_tier == "local_only" and not base_image_present:
        limitations.append("The exact base image digest is not available locally.")
    if not collector_available:
        limitations.append("The configured Collector is not available for optimization evidence.")
    status = (
        "available"
        if not limitations
        else ("partial" if runtime.status != "unavailable" else "unavailable")
    )
    timestamp = (checked_at or datetime.now(tz=UTC)).isoformat()
    runtime_sha256 = runtime.content_sha256
    identity = "\0".join(
        (
            "perflens-docker-build-capability-v1",
            timestamp,
            runtime_sha256,
            policy.sha256,
            docker_tool.binary_sha256 if docker_tool is not None else "",
            buildx_tool.binary_sha256 if buildx_tool is not None else "",
            builder.identity_sha256 if builder is not None else "",
            *tiers,
            *limitations,
        )
    )
    data = {
        "schema_version": "1.0",
        "perflens_version": __version__,
        "capability_id": (
            "docker-build-capability-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
        ),
        "checked_at": timestamp,
        "status": status,
        "runtime_capability_sha256": runtime_sha256,
        "project_policy_sha256": policy.sha256,
        "docker_tool": docker_tool,
        "buildx_tool": buildx_tool,
        "builder": builder,
        "available_network_tiers": tiers,
        "base_image_present": base_image_present,
        "benchmark_configured": bool(policy.managed.benchmark_output),
        "collector_available": collector_available,
        "build_supported": not limitations,
        "limitations": tuple(limitations),
        "next_steps": (
            ()
            if not limitations
            else ("Resolve every reported limitation and request a new read-only preview.",)
        ),
        "content_sha256": "0" * 64,
    }
    provisional = DockerBuildCapabilityArtifact.model_validate(data)
    return DockerBuildCapabilityArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _verify_runtime(runtime: DockerRuntimeCapabilityArtifact) -> None:
    if runtime.content_sha256 != contract_content_sha256(runtime, exclude={"content_sha256"}):
        raise _capability_error("Docker runtime capability content digest does not match")


def _capability_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_build_capability",
        message,
        recoverable=True,
    )
