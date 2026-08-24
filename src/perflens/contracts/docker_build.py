"""Versioned public contracts for bounded Docker build evidence.

These models deliberately expose hashes and bounded metadata only. Source names,
source bytes, authorization tokens, credentials, Docker endpoint paths, and
private archive paths remain inside the typed build adapter.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from perflens.contracts.artifacts import SCHEMA_VERSION, ContractModel

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
BuildCapabilityId = Annotated[str, Field(pattern=r"^docker-build-capability-[a-f0-9]{20}$")]
BuildRecipeId = Annotated[str, Field(pattern=r"^docker-build-recipe-[a-f0-9]{20}$")]
BuildContextId = Annotated[str, Field(pattern=r"^docker-build-context-[a-f0-9]{20}$")]
BuildArtifactId = Annotated[str, Field(pattern=r"^docker-build-[a-f0-9]{20}$")]
NetworkTier = Literal["local_only", "pinned_pull", "admin_builder_network"]


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


def _unique_sorted(values: tuple[str, ...], label: str) -> None:
    if len(set(values)) != len(values) or tuple(sorted(values)) != values:
        raise ValueError(f"{label} must be unique and sorted")


def _derived_id(prefix: str, domain: str, *values: str) -> str:
    material = "\0".join((domain, *values))
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:20]}"


def derive_docker_build_recipe_id(
    project_identity_sha256: str,
    policy_sha256: str,
    created_at: str,
) -> str:
    return _derived_id(
        "docker-build-recipe",
        "perflens-docker-build-recipe-v1",
        project_identity_sha256,
        policy_sha256,
        created_at,
    )


def derive_docker_build_context_id(
    recipe_content_sha256: str,
    archive_sha256: str,
    created_at: str,
) -> str:
    return _derived_id(
        "docker-build-context",
        "perflens-docker-build-context-v1",
        recipe_content_sha256,
        archive_sha256,
        created_at,
    )


def derive_docker_build_artifact_id(
    context_content_sha256: str,
    build_kind: str,
    candidate_round: int,
    final_image_digest: str,
    started_at: str,
) -> str:
    return _derived_id(
        "docker-build",
        "perflens-docker-build-artifact-v1",
        context_content_sha256,
        build_kind,
        str(candidate_round),
        final_image_digest,
        started_at,
    )


def docker_build_context_manifest_sha256(
    entries: tuple[DockerBuildContextEntry, ...],
) -> str:
    payload = [
        entry.model_dump(mode="json", exclude={"mutable"})
        for entry in sorted(entries, key=lambda item: item.path_sha256)
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


class DockerBuildToolProjection(ContractModel):
    tool: Literal["docker", "buildx", "buildkit"]
    version: str = Field(min_length=1, max_length=256)
    binary_sha256: Sha256


class DockerBuilderProjection(ContractModel):
    driver: Literal["docker", "docker-container"]
    identity_sha256: Sha256
    root_owned: bool
    builder_image_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    network_policy_sha256: Sha256 | None = None
    source_policy_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_builder(self) -> DockerBuilderProjection:
        advanced = (
            self.builder_image_digest,
            self.network_policy_sha256,
            self.source_policy_sha256,
        )
        if self.driver == "docker" and any(item is not None for item in advanced):
            raise ValueError("the local Docker driver cannot claim administrator Builder policy")
        if self.driver == "docker-container" and (
            not self.root_owned or any(item is None for item in advanced)
        ):
            raise ValueError("a networked docker-container Builder must be fully identity-pinned")
        return self


class DockerBuildCapabilityArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    capability_id: BuildCapabilityId
    checked_at: str
    status: Literal["available", "partial", "unavailable"]
    runtime_capability_sha256: Sha256
    project_policy_sha256: Sha256
    docker_tool: DockerBuildToolProjection | None = None
    buildx_tool: DockerBuildToolProjection | None = None
    builder: DockerBuilderProjection | None = None
    available_network_tiers: tuple[NetworkTier, ...] = ()
    base_image_present: bool
    benchmark_configured: bool
    collector_available: bool
    build_supported: bool
    limitations: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_capability(self) -> DockerBuildCapabilityArtifact:
        _timestamp(self.checked_at, "Docker build capability time")
        canonical = ("local_only", "pinned_pull", "admin_builder_network")
        if (
            len(set(self.available_network_tiers)) != len(self.available_network_tiers)
            or tuple(sorted(self.available_network_tiers, key=canonical.index))
            != self.available_network_tiers
        ):
            raise ValueError("Docker build network tiers must be unique and canonical")
        if self.status == "available":
            if (
                not self.build_supported
                or self.docker_tool is None
                or self.buildx_tool is None
                or self.builder is None
                or not self.available_network_tiers
                or self.limitations
            ):
                raise ValueError("available Docker build capability must be complete")
        elif not self.limitations:
            raise ValueError("non-available Docker build capability must explain its limits")
        if self.status != "available" and self.build_supported:
            raise ValueError("non-available Docker build capability cannot authorize builds")
        if self.build_supported and not self.benchmark_configured:
            raise ValueError("Docker optimization cannot be build-ready without a Benchmark")
        if "admin_builder_network" in self.available_network_tiers and (
            self.builder is None or self.builder.driver != "docker-container"
        ):
            raise ValueError(
                "administrator network tier requires a pinned docker-container Builder"
            )
        return self


class DockerOptimizationBudget(ContractModel):
    max_candidate_rounds: int = Field(ge=1, le=3)
    max_builds: int = Field(ge=2, le=4)
    max_workload_runs: int = Field(ge=1, le=10)
    max_recoverable_retries: int = Field(ge=0, le=1)
    max_build_seconds: int = Field(ge=1, le=900)
    max_total_build_seconds: int = Field(ge=1, le=3600)
    max_workload_active_seconds: int = Field(ge=1, le=1800)
    hard_expiry_seconds: int = Field(ge=1, le=7200)
    max_evidence_bytes: int = Field(ge=1, le=1 << 30)
    max_temporary_image_bytes: int = Field(ge=1, le=10 << 30)
    record_max_duration_seconds: int = Field(ge=1, le=30)
    record_frequency_hz: int = Field(ge=1, le=99)
    trace_max_duration_seconds: int = Field(ge=1, le=10)

    @model_validator(mode="after")
    def validate_budget(self) -> DockerOptimizationBudget:
        if self.max_builds < self.max_candidate_rounds + 1:
            raise ValueError("build budget cannot cover baseline plus candidate rounds")
        if self.max_total_build_seconds < self.max_build_seconds:
            raise ValueError("total build time cannot be below one build limit")
        if self.hard_expiry_seconds < max(
            self.max_total_build_seconds,
            self.max_workload_active_seconds,
        ):
            raise ValueError("hard expiry cannot be below bounded operation time")
        return self


class DockerBuildRecipeArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    recipe_id: BuildRecipeId
    created_at: str
    project_identity_sha256: Sha256
    project_policy_sha256: Sha256
    context_path_contract_sha256: tuple[Sha256, ...]
    mutable_path_contract_sha256: tuple[Sha256, ...]
    dockerfile_path_sha256: Sha256
    target: str | None = Field(default=None, max_length=128)
    platform: str = Field(pattern=r"^linux/[a-z0-9_]+(?:/[a-z0-9_.-]+)?$")
    build_arguments_sha256: Sha256
    base_image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    network_tier: NetworkTier
    builder_policy_id: str | None = Field(
        default=None,
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    workload_contract_sha256: Sha256
    benchmark_contract_sha256: Sha256
    resource_contract_sha256: Sha256
    mutable_dockerfile: bool
    mutable_dependency_lock: bool
    budget: DockerOptimizationBudget
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_recipe(self) -> DockerBuildRecipeArtifact:
        _timestamp(self.created_at, "Docker build Recipe creation time")
        _unique_sorted(self.context_path_contract_sha256, "context path contracts")
        _unique_sorted(self.mutable_path_contract_sha256, "mutable path contracts")
        if not self.context_path_contract_sha256 or not self.mutable_path_contract_sha256:
            raise ValueError("Docker build Recipe requires explicit context and mutable paths")
        if self.network_tier == "local_only" and self.builder_policy_id is not None:
            raise ValueError("local-only Recipe cannot bind an administrator Builder policy")
        if self.network_tier != "local_only" and self.builder_policy_id is None:
            raise ValueError("networked Recipe requires an administrator Builder policy")
        expected_id = derive_docker_build_recipe_id(
            self.project_identity_sha256,
            self.project_policy_sha256,
            self.created_at,
        )
        if self.recipe_id != expected_id:
            raise ValueError("Docker build Recipe ID does not match its project policy")
        return self


class DockerBuildContextEntry(ContractModel):
    path_sha256: Sha256
    entry_type: Literal["regular", "directory", "symlink"]
    mode: int = Field(ge=0, le=0o777)
    size: int = Field(ge=0)
    content_sha256: Sha256 | None = None
    symlink_target_sha256: Sha256 | None = None
    mutable: bool

    @model_validator(mode="after")
    def validate_entry(self) -> DockerBuildContextEntry:
        if self.entry_type == "regular":
            if self.content_sha256 is None or self.symlink_target_sha256 is not None:
                raise ValueError("regular context entries require only a content digest")
        elif self.entry_type == "symlink":
            if self.symlink_target_sha256 is None or self.content_sha256 is not None:
                raise ValueError("symlink entries require only a target digest")
        elif self.content_sha256 is not None or self.symlink_target_sha256 is not None:
            raise ValueError("directory entries cannot carry content or symlink digests")
        return self


class DockerBuildContextArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    context_id: BuildContextId
    created_at: str
    recipe_id: BuildRecipeId
    recipe_content_sha256: Sha256
    project_identity_sha256: Sha256
    entry_count: int = Field(ge=1, le=100_000)
    regular_file_count: int = Field(ge=1)
    mutable_entry_count: int = Field(ge=1)
    total_regular_bytes: int = Field(ge=0, le=2 << 30)
    entries: tuple[DockerBuildContextEntry, ...]
    immutable_manifest_sha256: Sha256
    mutable_manifest_sha256: Sha256
    archive_sha256: Sha256
    archive_bytes: int = Field(gt=0, le=3 << 30)
    quality_status: Literal["verified"] = "verified"
    limitations: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_context(self) -> DockerBuildContextArtifact:
        _timestamp(self.created_at, "Docker build Context creation time")
        if len(self.entries) != self.entry_count:
            raise ValueError("Docker build Context entry count does not match exported entries")
        path_hashes = tuple(entry.path_sha256 for entry in self.entries)
        _unique_sorted(path_hashes, "Docker build Context path digests")
        if sum(entry.entry_type == "regular" for entry in self.entries) != self.regular_file_count:
            raise ValueError("Docker build Context regular-file count is inconsistent")
        if (
            sum(entry.size for entry in self.entries if entry.entry_type == "regular")
            != self.total_regular_bytes
        ):
            raise ValueError("Docker build Context byte count is inconsistent")
        if sum(entry.mutable for entry in self.entries) != self.mutable_entry_count:
            raise ValueError("Docker build Context mutable count is inconsistent")
        immutable_entries = tuple(entry for entry in self.entries if not entry.mutable)
        mutable_entries = tuple(entry for entry in self.entries if entry.mutable)
        if self.immutable_manifest_sha256 != docker_build_context_manifest_sha256(
            immutable_entries
        ) or self.mutable_manifest_sha256 != docker_build_context_manifest_sha256(mutable_entries):
            raise ValueError("Docker build Context manifest digests do not match exported entries")
        if self.limitations:
            raise ValueError("verified Docker build Context cannot carry limitations")
        expected_id = derive_docker_build_context_id(
            self.recipe_content_sha256,
            self.archive_sha256,
            self.created_at,
        )
        if self.context_id != expected_id:
            raise ValueError("Docker build Context ID does not match Recipe and archive")
        return self


class DockerBuildArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    build_id: BuildArtifactId
    build_kind: Literal["baseline", "candidate"]
    candidate_round: int = Field(ge=0, le=3)
    started_at: str
    finished_at: str
    recipe_id: BuildRecipeId
    recipe_content_sha256: Sha256
    context_id: BuildContextId
    context_content_sha256: Sha256
    builder_identity_sha256: Sha256
    network_policy_sha256: Sha256
    final_image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    platform: str = Field(pattern=r"^linux/[a-z0-9_]+(?:/[a-z0-9_.-]+)?$")
    image_size_bytes: int = Field(gt=0, le=10 << 30)
    iid_file_sha256: Sha256
    metadata_file_sha256: Sha256
    provenance_sha256: Sha256
    immutable_manifest_sha256: Sha256
    treatment_manifest_sha256: Sha256
    status: Literal["verified"] = "verified"
    cleanup_eligible: bool
    limitations: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_build(self) -> DockerBuildArtifact:
        started = _timestamp(self.started_at, "Docker build start time")
        finished = _timestamp(self.finished_at, "Docker build finish time")
        if finished < started:
            raise ValueError("Docker build cannot finish before it starts")
        if (self.build_kind == "baseline") != (self.candidate_round == 0):
            raise ValueError(
                "baseline must be round zero and candidates must be rounds one to three"
            )
        if self.limitations:
            raise ValueError("verified Docker build cannot carry limitations")
        expected_id = derive_docker_build_artifact_id(
            self.context_content_sha256,
            self.build_kind,
            self.candidate_round,
            self.final_image_digest,
            self.started_at,
        )
        if self.build_id != expected_id:
            raise ValueError("Docker Build Artifact ID does not match its Context and round")
        return self
