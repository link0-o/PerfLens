"""Typed, identity-pinned Docker Buildx adapter for bounded optimization builds."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import tarfile
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerBuildCapabilityArtifact,
    DockerBuilderProjection,
    DockerBuildToolProjection,
    derive_docker_build_artifact_id,
)
from perflens.docker.adapter import (
    assert_docker_cli_current,
    assert_docker_endpoint_current,
    inspect_docker_cli,
    inspect_docker_endpoint,
    inspect_empty_docker_config_directory,
)
from perflens.docker.build_context import (
    DockerBuildContextSnapshot,
    assert_docker_build_context_snapshot_current,
    open_docker_build_context_snapshot,
)
from perflens.docker.builder_policy import (
    DockerAdministratorBuilderPolicy,
    assert_docker_administrator_builder_policy_current,
    base_image_reference_digest,
)
from perflens.docker.project_config import (
    DockerProjectPolicy,
    assert_docker_project_policy_current,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandResult, CommandRunner

_BUILDER_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_TEMPORARY_TAG = re.compile(r"^perflens-opt-[a-f0-9]{20}:(?:baseline-0|candidate-[1-3])$")
_MAX_JSON_BYTES = 8 << 20
_MAX_BUILD_OUTPUT_BYTES = 8 << 20
_MAX_DOCKERFILE_BYTES = 1 << 20
_LOCAL_NETWORK_POLICY_SHA256 = hashlib.sha256(
    b"perflens-docker-build-network-v1\0local-only-none"
).hexdigest()
_NO_REMOTE_SCHEMES = ("http://", "https://", "git://", "ssh://", "git@")
_SYSTEM_BUILDX_PLUGIN_DIRECTORIES = (
    Path("/usr/local/libexec/docker/cli-plugins"),
    Path("/usr/local/lib/docker/cli-plugins"),
    Path("/usr/libexec/docker/cli-plugins"),
    Path("/usr/lib/docker/cli-plugins"),
)


@dataclass(frozen=True, slots=True)
class DockerBuilderIdentity:
    name: str
    driver: Literal["docker", "docker-container"]
    identity_sha256: str
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class DockerBuildExecutionResult:
    artifact: DockerBuildArtifact
    temporary_tag: str


class TypedDockerBuildAdapter:
    """Expose fixed build recipes, never arbitrary Docker or Buildx arguments."""

    def __init__(
        self,
        *,
        docker_path: Path,
        buildx_path: Path,
        endpoint_path: Path,
        endpoint_kind: Literal["local_rootful", "local_rootless"],
        config_directory: Path,
        runtime_directory: Path | None = None,
        builder_name: str = "default",
        administrator_policy: DockerAdministratorBuilderPolicy | None = None,
        buildx_plugin_directories: tuple[Path, ...] = _SYSTEM_BUILDX_PLUGIN_DIRECTORIES,
        trusted_tool_owner_uids: tuple[int, ...] = (0,),
        trusted_policy_owner_uids: tuple[int, ...] = (0,),
        invoking_uid: int | None = None,
    ) -> None:
        if not _BUILDER_NAME.fullmatch(builder_name):
            raise _build_error("Docker Builder name is invalid")
        self._invoking_uid = os.geteuid() if invoking_uid is None else invoking_uid
        self._trusted_policy_owner_uids = trusted_policy_owner_uids
        self._docker = inspect_docker_cli(
            docker_path,
            trusted_owner_uids=trusted_tool_owner_uids,
        )
        self._buildx = inspect_docker_cli(
            buildx_path,
            trusted_owner_uids=trusted_tool_owner_uids,
        )
        self._buildx_plugin_directories = buildx_plugin_directories
        self._assert_buildx_resolution_current()
        self._endpoint = inspect_docker_endpoint(
            endpoint_path,
            kind=endpoint_kind,
            invoking_uid=self._invoking_uid,
        )
        self._trusted_empty_config = inspect_empty_docker_config_directory(
            config_directory,
            trusted_owner_uids=trusted_tool_owner_uids,
        )
        self._config = (
            _prepare_private_docker_config(runtime_directory, uid=self._invoking_uid)
            if runtime_directory is not None
            else self._trusted_empty_config
        )
        self._private_config_identity = (
            _directory_file_identity(self._config.lstat())
            if runtime_directory is not None
            else None
        )
        self._runner = CommandRunner({self._docker.path})
        self._administrator_policy = administrator_policy
        try:
            if administrator_policy is not None:
                assert_docker_administrator_builder_policy_current(
                    administrator_policy,
                    trusted_owner_uids=trusted_policy_owner_uids,
                )
                if administrator_policy.builder_name != builder_name:
                    raise _build_error("Docker Builder name differs from administrator policy")
            self._builder = self._inspect_builder_raw(builder_name)
            if administrator_policy is None and self._builder.driver != "docker":
                raise _build_error(
                    "Local-only Docker optimization requires the fixed Docker driver"
                )
            if administrator_policy is not None and (
                self._builder.driver != administrator_policy.driver
                or self._builder.identity_sha256 != administrator_policy.builder_identity_sha256
            ):
                raise _build_error("Docker Builder identity differs from administrator policy")
            self._docker_version = self._inspect_docker_version()
            self._buildx_version = self._inspect_buildx_version()
        except BaseException:
            self.close()
            raise

    @property
    def docker_tool_projection(self) -> DockerBuildToolProjection:
        return DockerBuildToolProjection(
            tool="docker",
            version=self._docker_version,
            binary_sha256=self._docker.sha256,
        )

    @property
    def buildx_tool_projection(self) -> DockerBuildToolProjection:
        return DockerBuildToolProjection(
            tool="buildx",
            version=self._buildx_version,
            binary_sha256=self._buildx.sha256,
        )

    @property
    def builder_projection(self) -> DockerBuilderProjection:
        policy = self._administrator_policy
        return DockerBuilderProjection(
            driver=self._builder.driver,
            identity_sha256=self._builder.identity_sha256,
            root_owned=policy is not None,
            builder_image_digest=(
                policy.builder_image_digest
                if policy is not None and policy.network_tier == "admin_builder_network"
                else None
            ),
            network_policy_sha256=(
                policy.network_policy_sha256
                if policy is not None and policy.network_tier == "admin_builder_network"
                else None
            ),
            source_policy_sha256=(
                policy.source_policy_sha256
                if policy is not None and policy.network_tier == "admin_builder_network"
                else None
            ),
        )

    @property
    def available_network_tiers(
        self,
    ) -> tuple[Literal["local_only", "pinned_pull", "admin_builder_network"], ...]:
        if self._administrator_policy is None:
            return ("local_only",)
        return (self._administrator_policy.network_tier,)

    def base_image_present(self, image_digest: str) -> bool:
        _validate_image_digest(image_digest)
        return self._inspect_image_optional(image_digest) is not None

    def build(
        self,
        *,
        capability: DockerBuildCapabilityArtifact,
        policy: DockerProjectPolicy,
        snapshot: DockerBuildContextSnapshot,
        private_directory: Path,
        session_identity_sha256: str,
        build_kind: Literal["baseline", "candidate"],
        candidate_round: int,
        started_at: datetime | None = None,
    ) -> DockerBuildExecutionResult:
        """Build one baseline/candidate from a verified private context snapshot."""
        self._validate_build_request(
            capability=capability,
            policy=policy,
            snapshot=snapshot,
            private_directory=private_directory,
            session_identity_sha256=session_identity_sha256,
            build_kind=build_kind,
            candidate_round=candidate_round,
        )
        assert_docker_project_policy_current(policy, allowed_roots=(policy.path.parent,))
        assert_docker_build_context_snapshot_current(snapshot)
        self._assert_environment_current()
        dockerfile = _read_and_validate_dockerfile(
            snapshot,
            dockerfile=policy.optimization.dockerfile,
            base_image_digest=policy.optimization.base_image_digest,
            administrator_policy=self._administrator_policy,
        )
        del dockerfile
        if policy.optimization.network_tier == "pinned_pull":
            self._pull_pinned_base(policy)
        elif policy.optimization.network_tier == "local_only" and not self.base_image_present(
            policy.optimization.base_image_digest
        ):
            raise _build_error("The exact local-only base image digest is unavailable")

        timestamp = started_at or datetime.now(tz=UTC)
        temporary_tag = _temporary_tag(
            session_identity_sha256,
            build_kind=build_kind,
            candidate_round=candidate_round,
        )
        if self._inspect_image_optional(temporary_tag) is not None:
            raise _build_error("Docker optimization temporary tag already exists")
        private_root = _safe_private_directory(private_directory, uid=self._invoking_uid)
        iid_path = _unused_private_path(private_root, suffix=".iid")
        metadata_path = _unused_private_path(private_root, suffix=".metadata.json")
        try:
            arguments = self._build_arguments(
                policy=policy,
                snapshot=snapshot,
                session_identity_sha256=session_identity_sha256,
                build_kind=build_kind,
                candidate_round=candidate_round,
                temporary_tag=temporary_tag,
                iid_path=iid_path,
                metadata_path=metadata_path,
            )
            with open_docker_build_context_snapshot(snapshot) as context_stream:
                output = io.BytesIO()
                result = self._run(
                    arguments,
                    output,
                    stdin=context_stream,
                    timeout_seconds=policy.optimization.max_build_seconds,
                    max_stdout_bytes=_MAX_BUILD_OUTPUT_BYTES,
                )
            finished_at = timestamp.timestamp() + result.duration_seconds
            finished = datetime.fromtimestamp(finished_at, tz=UTC)
            iid_bytes = _read_private_output(iid_path, private_root=private_root, maximum=256)
            metadata_bytes = _read_private_output(
                metadata_path,
                private_root=private_root,
                maximum=_MAX_JSON_BYTES,
            )
            iid = _parse_iid(iid_bytes)
            metadata = _parse_metadata(metadata_bytes)
            image = self._require_built_image(
                temporary_tag,
                iid=iid,
                metadata=metadata,
                policy=policy,
                session_identity_sha256=session_identity_sha256,
                recipe_content_sha256=snapshot.artifact.recipe_content_sha256,
                context_content_sha256=snapshot.artifact.content_sha256,
                build_kind=build_kind,
                candidate_round=candidate_round,
            )
            image_size = _bounded_image_size(image, policy.optimization.max_temporary_image_bytes)
            network_policy_sha256 = (
                self._administrator_policy.network_policy_sha256
                if self._administrator_policy is not None
                else _LOCAL_NETWORK_POLICY_SHA256
            )
            provenance_sha256 = _canonical_sha256(
                {
                    "provenance": metadata["buildx.build.provenance"],
                    "builder": self._builder.identity_sha256,
                    "network": network_policy_sha256,
                    "source": (
                        self._administrator_policy.source_policy_sha256
                        if self._administrator_policy is not None
                        else _LOCAL_NETWORK_POLICY_SHA256
                    ),
                }
            )
            data = {
                "schema_version": "1.0",
                "perflens_version": __version__,
                "build_id": derive_docker_build_artifact_id(
                    snapshot.artifact.content_sha256,
                    build_kind,
                    candidate_round,
                    iid,
                    timestamp.isoformat(),
                ),
                "build_kind": build_kind,
                "candidate_round": candidate_round,
                "started_at": timestamp.isoformat(),
                "finished_at": finished.isoformat(),
                "recipe_id": snapshot.artifact.recipe_id,
                "recipe_content_sha256": snapshot.artifact.recipe_content_sha256,
                "context_id": snapshot.artifact.context_id,
                "context_content_sha256": snapshot.artifact.content_sha256,
                "builder_identity_sha256": self._builder.identity_sha256,
                "network_policy_sha256": network_policy_sha256,
                "final_image_digest": iid,
                "platform": policy.optimization.platform,
                "image_size_bytes": image_size,
                "iid_file_sha256": hashlib.sha256(iid_bytes).hexdigest(),
                "metadata_file_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                "provenance_sha256": provenance_sha256,
                "immutable_manifest_sha256": snapshot.artifact.immutable_manifest_sha256,
                "treatment_manifest_sha256": snapshot.artifact.mutable_manifest_sha256,
                "status": "verified",
                "cleanup_eligible": True,
                "limitations": (),
                "content_sha256": "0" * 64,
            }
            provisional = DockerBuildArtifact.model_validate(data)
            artifact = DockerBuildArtifact.model_validate(
                {
                    **provisional.model_dump(mode="json"),
                    "content_sha256": contract_content_sha256(
                        provisional,
                        exclude={"content_sha256"},
                    ),
                }
            )
            self._assert_environment_current()
            return DockerBuildExecutionResult(artifact=artifact, temporary_tag=temporary_tag)
        except Exception:
            with suppress(PerfLensError):
                self._cleanup_verified_tag_if_present(
                    temporary_tag,
                    session_identity_sha256=session_identity_sha256,
                )
            raise
        finally:
            for output_path in (iid_path, metadata_path):
                with suppress(OSError):
                    output_path.unlink(missing_ok=True)

    def cleanup_build(
        self,
        result: DockerBuildExecutionResult,
        *,
        session_identity_sha256: str,
    ) -> Literal["removed", "retained", "missing"]:
        """Remove only a verified session tag; never prune or delete by loose identity."""
        if not result.artifact.cleanup_eligible:
            return "retained"
        return self._cleanup_verified_tag_if_present(
            result.temporary_tag,
            session_identity_sha256=session_identity_sha256,
            expected_digest=result.artifact.final_image_digest,
        )

    def close(self) -> None:
        """Remove only the private Buildx state created below the session directory."""
        identity = self._private_config_identity
        if identity is None or not shutil.rmtree.avoids_symlink_attacks:
            return
        try:
            if _directory_file_identity(self._config.lstat()) != identity:
                return
            shutil.rmtree(self._config)
        except OSError:
            return
        self._private_config_identity = None

    def _validate_build_request(
        self,
        *,
        capability: DockerBuildCapabilityArtifact,
        policy: DockerProjectPolicy,
        snapshot: DockerBuildContextSnapshot,
        private_directory: Path,
        session_identity_sha256: str,
        build_kind: str,
        candidate_round: int,
    ) -> None:
        if (
            capability.content_sha256
            != contract_content_sha256(
                capability,
                exclude={"content_sha256"},
            )
            or capability.status != "available"
            or not capability.build_supported
        ):
            raise _build_error("Docker build capability is not complete and content-bound")
        if capability.project_policy_sha256 != policy.sha256:
            raise _build_error("Docker build capability does not bind the current project policy")
        if (
            capability.docker_tool is None
            or capability.buildx_tool is None
            or capability.builder is None
            or capability.docker_tool.binary_sha256 != self._docker.sha256
            or capability.buildx_tool.binary_sha256 != self._buildx.sha256
            or capability.builder.identity_sha256 != self._builder.identity_sha256
        ):
            raise _build_error("Docker build tool or Builder identity changed after preview")
        if policy.optimization.network_tier not in capability.available_network_tiers:
            raise _build_error("Docker optimization network tier was not authorized")
        admin = self._administrator_policy
        if policy.optimization.network_tier == "local_only":
            if admin is not None and admin.policy_id == policy.optimization.builder_policy_id:
                raise _build_error("Local-only build cannot consume an administrator policy")
        elif (
            admin is None
            or admin.policy_id != policy.optimization.builder_policy_id
            or admin.network_tier != policy.optimization.network_tier
            or base_image_reference_digest(admin.base_image_reference)
            != policy.optimization.base_image_digest
        ):
            raise _build_error("Docker administrator Builder policy does not match the Recipe")
        if not _SHA256.fullmatch(session_identity_sha256):
            raise _build_error("Docker optimization session identity is invalid")
        if (build_kind == "baseline") != (candidate_round == 0) or not 0 <= candidate_round <= 3:
            raise _build_error("Docker build kind and candidate round are inconsistent")
        if snapshot.artifact.project_identity_sha256 == "0" * 64:
            raise _build_error("Docker build Context project identity is invalid")
        _safe_private_directory(private_directory, uid=self._invoking_uid)

    def _build_arguments(
        self,
        *,
        policy: DockerProjectPolicy,
        snapshot: DockerBuildContextSnapshot,
        session_identity_sha256: str,
        build_kind: Literal["baseline", "candidate"],
        candidate_round: int,
        temporary_tag: str,
        iid_path: Path,
        metadata_path: Path,
    ) -> tuple[str, ...]:
        optimization = policy.optimization
        network = "default" if optimization.network_tier == "admin_builder_network" else "none"
        arguments: list[str] = [
            "buildx",
            "build",
            "--builder",
            self._builder.name,
            "--file",
            optimization.dockerfile,
            "--platform",
            optimization.platform,
            "--network",
            network,
            "--pull=false",
            "--progress=plain",
            "--provenance=mode=max",
            "--sbom=false",
            "--load",
            "--iidfile",
            str(iid_path),
            "--metadata-file",
            str(metadata_path),
            "--tag",
            temporary_tag,
        ]
        labels = (
            f"io.perflens.optimization-session-sha256={session_identity_sha256}",
            f"io.perflens.build-recipe-sha256={snapshot.artifact.recipe_content_sha256}",
            f"io.perflens.build-context-sha256={snapshot.artifact.content_sha256}",
            f"io.perflens.build-kind={build_kind}",
            f"io.perflens.candidate-round={candidate_round}",
        )
        for label in labels:
            arguments.extend(("--label", label))
        if optimization.target is not None:
            arguments.extend(("--target", optimization.target))
        for name, value in optimization.build_args:
            arguments.extend(("--build-arg", f"{name}={value}"))
        arguments.append("-")
        return tuple(arguments)

    def _pull_pinned_base(self, policy: DockerProjectPolicy) -> None:
        administrator = self._administrator_policy
        if administrator is None or administrator.network_tier != "pinned_pull":
            raise _build_error("Pinned pull requires the authorized administrator policy")
        output = io.BytesIO()
        self._run(
            (
                "image",
                "pull",
                "--platform",
                policy.optimization.platform,
                administrator.base_image_reference,
            ),
            output,
            timeout_seconds=policy.optimization.max_build_seconds,
            max_stdout_bytes=_MAX_BUILD_OUTPUT_BYTES,
        )
        if self._inspect_image_optional(policy.optimization.base_image_digest) is None:
            raise _build_error("Pinned base image pull did not produce the authorized digest")

    def _require_built_image(
        self,
        temporary_tag: str,
        *,
        iid: str,
        metadata: dict[str, Any],
        policy: DockerProjectPolicy,
        session_identity_sha256: str,
        recipe_content_sha256: str,
        context_content_sha256: str,
        build_kind: str,
        candidate_round: int,
    ) -> dict[str, Any]:
        image = self._inspect_image_optional(temporary_tag)
        if image is None or image.get("Id") != iid:
            raise _build_error("Docker build output tag or image digest is unavailable")
        if metadata.get("containerimage.config.digest") != iid:
            raise _build_error("Docker Buildx metadata does not bind the final image digest")
        provenance = metadata.get("buildx.build.provenance")
        if not isinstance(provenance, dict):
            raise _build_error("Docker Buildx metadata omits bounded provenance")
        expected_platform = _platform_from_image(image)
        if expected_platform != policy.optimization.platform:
            raise _build_error("Docker final image platform differs from the Recipe")
        config = image.get("Config")
        labels = cast(dict[str, object], config).get("Labels") if isinstance(config, dict) else None
        expected_labels = {
            "io.perflens.optimization-session-sha256": session_identity_sha256,
            "io.perflens.build-recipe-sha256": recipe_content_sha256,
            "io.perflens.build-context-sha256": context_content_sha256,
            "io.perflens.build-kind": build_kind,
            "io.perflens.candidate-round": str(candidate_round),
        }
        typed_labels = cast(dict[str, object], labels) if isinstance(labels, dict) else None
        if typed_labels is None or any(
            typed_labels.get(key) != value for key, value in expected_labels.items()
        ):
            raise _build_error("Docker final image labels do not bind the authorized build")
        repo_tags = image.get("RepoTags")
        if not isinstance(repo_tags, list) or temporary_tag not in repo_tags:
            raise _build_error("Docker final image does not retain the private session tag")
        return image

    def _cleanup_verified_tag_if_present(
        self,
        temporary_tag: str,
        *,
        session_identity_sha256: str,
        expected_digest: str | None = None,
    ) -> Literal["removed", "retained", "missing"]:
        if not _TEMPORARY_TAG.fullmatch(temporary_tag) or not _SHA256.fullmatch(
            session_identity_sha256
        ):
            return "retained"
        image = self._inspect_image_optional(temporary_tag)
        if image is None:
            return "missing"
        config = image.get("Config")
        labels = cast(dict[str, object], config).get("Labels") if isinstance(config, dict) else None
        typed_labels = cast(dict[str, object], labels) if isinstance(labels, dict) else None
        if (
            typed_labels is None
            or typed_labels.get("io.perflens.optimization-session-sha256")
            != session_identity_sha256
            or (expected_digest is not None and image.get("Id") != expected_digest)
        ):
            return "retained"
        output = io.BytesIO()
        self._run(
            (
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                f"ancestor={temporary_tag}",
            ),
            output,
            timeout_seconds=15,
            max_stdout_bytes=16 << 10,
        )
        if output.getvalue().strip():
            return "retained"
        removed = io.BytesIO()
        self._run(
            ("image", "rm", temporary_tag),
            removed,
            timeout_seconds=30,
            max_stdout_bytes=64 << 10,
        )
        return "removed" if self._inspect_image_optional(temporary_tag) is None else "retained"

    def _inspect_image_optional(self, reference: str) -> dict[str, Any] | None:
        if not (_IMAGE_DIGEST.fullmatch(reference) or _TEMPORARY_TAG.fullmatch(reference)):
            raise _build_error("Docker image inspection reference is invalid")
        try:
            return self._run_json(
                ("image", "inspect", "--format", "{{json .}}", reference),
                timeout_seconds=15,
            )
        except PerfLensError as exc:
            stderr = str(exc.details.get("stderr", "")).lower()
            if (
                exc.code is ErrorCode.EXTERNAL_TOOL_FAILED
                and exc.details.get("exit_code") == 1
                and ("no such image" in stderr or "not found" in stderr)
            ):
                return None
            raise

    def _inspect_docker_version(self) -> str:
        data = self._run_json(("version", "--format", "{{json .Client}}"), check_builder=False)
        version = data.get("Version")
        if not isinstance(version, str) or not 1 <= len(version) <= 256:
            raise _build_error("Docker CLI version output is invalid")
        return version

    def _inspect_buildx_version(self) -> str:
        output = io.BytesIO()
        self._run(
            ("buildx", "version"),
            output,
            timeout_seconds=10,
            max_stdout_bytes=4096,
            check_builder=False,
        )
        try:
            value = output.getvalue().decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise _build_error("Docker Buildx version output is invalid") from exc
        if not 1 <= len(value) <= 256:
            raise _build_error("Docker Buildx version output is invalid")
        return value

    def _inspect_builder_raw(self, builder_name: str) -> DockerBuilderIdentity:
        output = io.BytesIO()
        self._run(
            ("buildx", "ls", "--format", "{{json .}}"),
            output,
            timeout_seconds=30,
            max_stdout_bytes=_MAX_JSON_BYTES,
            check_builder=False,
        )
        data = _select_builder_from_json_lines(output.getvalue(), builder_name)
        name = data.get("Name")
        driver = data.get("Driver")
        if name != builder_name or driver not in {"docker", "docker-container"}:
            raise _build_error("Docker Buildx returned a different Builder identity")
        raw_sha256 = _canonical_sha256(_stable_builder_entry(data))
        stable = {
            "Name": name,
            "Driver": driver,
            "Nodes": data.get("Nodes"),
        }
        return DockerBuilderIdentity(
            name=builder_name,
            driver=cast(Literal["docker", "docker-container"], driver),
            identity_sha256=_canonical_sha256(stable),
            raw_sha256=raw_sha256,
        )

    def _assert_environment_current(self) -> None:
        assert_docker_cli_current(self._docker)
        assert_docker_cli_current(self._buildx)
        self._assert_buildx_resolution_current()
        assert_docker_endpoint_current(self._endpoint, invoking_uid=self._invoking_uid)
        if self._administrator_policy is not None:
            assert_docker_administrator_builder_policy_current(
                self._administrator_policy,
                trusted_owner_uids=self._trusted_policy_owner_uids,
            )
        if self._inspect_builder_raw(self._builder.name) != self._builder:
            raise _build_error("Docker Builder identity changed after validation")

    def _assert_buildx_resolution_current(self) -> None:
        if not self._buildx_plugin_directories:
            raise _build_error("Docker Buildx plugin search policy is empty")
        selected: Path | None = None
        for directory in self._buildx_plugin_directories:
            if not directory.is_absolute() or directory.is_symlink():
                raise _build_error("Docker Buildx plugin search directory is unsafe")
            candidate = directory / "docker-buildx"
            if candidate.exists() or candidate.is_symlink():
                selected = inspect_docker_cli(
                    candidate,
                    trusted_owner_uids=self._buildx.trusted_owner_uids,
                ).path
                break
        if selected != self._buildx.path:
            raise _build_error("Pinned Docker Buildx is not the first resolved CLI plugin")

    def _run_json(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: int = 15,
        check_builder: bool = True,
    ) -> dict[str, Any]:
        output = io.BytesIO()
        self._run(
            arguments,
            output,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=_MAX_JSON_BYTES,
            check_builder=check_builder,
        )
        try:
            value = json.loads(output.getvalue())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _build_error("Docker Build Adapter returned malformed bounded JSON") from exc
        if not isinstance(value, dict):
            raise _build_error("Docker Build Adapter returned an unexpected JSON shape")
        return cast(dict[str, Any], value)

    def _run(
        self,
        arguments: tuple[str, ...],
        output: io.BytesIO,
        *,
        timeout_seconds: int,
        max_stdout_bytes: int,
        stdin: BinaryIO | None = None,
        check_builder: bool = True,
    ) -> CommandResult:
        assert_docker_cli_current(self._docker)
        assert_docker_cli_current(self._buildx)
        self._assert_buildx_resolution_current()
        assert_docker_endpoint_current(self._endpoint, invoking_uid=self._invoking_uid)
        self._assert_private_config_current()
        if self._administrator_policy is not None:
            assert_docker_administrator_builder_policy_current(
                self._administrator_policy,
                trusted_owner_uids=self._trusted_policy_owner_uids,
            )
        if check_builder and self._inspect_builder_raw(self._builder.name) != self._builder:
            raise _build_error("Docker Builder identity changed before operation")
        result = self._runner.run_to_file(
            (
                str(self._docker.path),
                "--config",
                str(self._config),
                "--host",
                f"unix://{self._endpoint.path}",
                *arguments,
            ),
            output,
            stdin=stdin,
            limits=CommandLimits(
                timeout_seconds=timeout_seconds,
                terminate_grace_seconds=1,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=1 << 20,
            ),
        )
        assert_docker_cli_current(self._docker)
        assert_docker_cli_current(self._buildx)
        self._assert_buildx_resolution_current()
        assert_docker_endpoint_current(self._endpoint, invoking_uid=self._invoking_uid)
        self._assert_private_config_current()
        if check_builder and self._inspect_builder_raw(self._builder.name) != self._builder:
            raise _build_error("Docker Builder identity changed after operation")
        return result

    def _assert_private_config_current(self) -> None:
        identity = self._private_config_identity
        if identity is None:
            return
        try:
            current = self._config.lstat()
        except OSError as exc:
            raise _build_error("Docker private Buildx configuration is unavailable") from exc
        if _directory_file_identity(current) != identity:
            raise _build_error("Docker private Buildx configuration identity changed")


def open_local_docker_build_adapter(
    *,
    administrator_policy: DockerAdministratorBuilderPolicy | None = None,
    docker_path: Path = Path("/usr/bin/docker"),
    config_directory: Path = Path("/usr/share/perflens/docker-empty-config"),
    runtime_directory: Path | None = None,
    rootful_socket: Path = Path("/run/docker.sock"),
    rootless_socket: Path | None = None,
    invoking_uid: int | None = None,
    trusted_tool_owner_uids: tuple[int, ...] = (0,),
    trusted_policy_owner_uids: tuple[int, ...] = (0,),
) -> TypedDockerBuildAdapter:
    """Open only the first fixed local endpoint and first system Buildx plugin."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    rootless = rootless_socket or Path(f"/run/user/{uid}/docker.sock")
    if rootless.exists() or rootless.is_socket():
        endpoint = rootless
        endpoint_kind: Literal["local_rootful", "local_rootless"] = "local_rootless"
    elif rootful_socket.exists() or rootful_socket.is_socket():
        endpoint = rootful_socket
        endpoint_kind = "local_rootful"
    else:
        raise _build_error("No fixed local Docker Unix socket is available")
    buildx_path = next(
        (
            directory / "docker-buildx"
            for directory in _SYSTEM_BUILDX_PLUGIN_DIRECTORIES
            if (directory / "docker-buildx").exists()
            or (directory / "docker-buildx").is_symlink()
        ),
        None,
    )
    if buildx_path is None:
        raise _build_error("No fixed system Docker Buildx plugin is available")
    return TypedDockerBuildAdapter(
        docker_path=docker_path,
        buildx_path=buildx_path,
        endpoint_path=endpoint,
        endpoint_kind=endpoint_kind,
        config_directory=config_directory,
        runtime_directory=runtime_directory,
        builder_name=(administrator_policy.builder_name if administrator_policy else "default"),
        administrator_policy=administrator_policy,
        trusted_tool_owner_uids=trusted_tool_owner_uids,
        trusted_policy_owner_uids=trusted_policy_owner_uids,
        invoking_uid=uid,
    )


def _read_and_validate_dockerfile(
    snapshot: DockerBuildContextSnapshot,
    *,
    dockerfile: str,
    base_image_digest: str,
    administrator_policy: DockerAdministratorBuilderPolicy | None,
) -> str:
    try:
        with (
            open_docker_build_context_snapshot(snapshot) as context_stream,
            tarfile.open(fileobj=context_stream, mode="r") as archive,
        ):
            members = [member for member in archive.getmembers() if member.name == dockerfile]
            if (
                len(members) != 1
                or not members[0].isreg()
                or members[0].size > _MAX_DOCKERFILE_BYTES
            ):
                raise _build_error("Authorized Dockerfile is absent, duplicated, or unsafe")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise _build_error("Authorized Dockerfile cannot be read from the Context")
            raw = stream.read(_MAX_DOCKERFILE_BYTES + 1)
    except (OSError, tarfile.TarError) as exc:
        raise _build_error("Docker build Context archive cannot be inspected") from exc
    try:
        content = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _build_error("Authorized Dockerfile must be UTF-8") from exc
    if not content or "\x00" in content or len(raw) > _MAX_DOCKERFILE_BYTES:
        raise _build_error("Authorized Dockerfile is empty or exceeds its fixed limit")
    instructions = _expand_onbuild_instructions(_dockerfile_instructions(content))
    aliases: set[str] = set()
    observed_base = False
    expected_reference = (
        administrator_policy.base_image_reference if administrator_policy is not None else None
    )
    for operation, argument in instructions:
        if operation == "FROM":
            tokens = _split_dockerfile_instruction(argument)
            while tokens and tokens[0].startswith("--"):
                if not tokens[0].startswith("--platform=") or "$" in tokens[0]:
                    raise _build_error("Dockerfile FROM uses an unsupported option")
                tokens.pop(0)
            if not tokens or "$" in tokens[0]:
                raise _build_error("Dockerfile FROM must use a fixed image reference")
            image = tokens[0]
            normalized_image = image.lower()
            if image != "scratch" and normalized_image not in aliases and not image.isdigit():
                if "@" not in image or image.rsplit("@", 1)[1] != base_image_digest:
                    raise _build_error(
                        "Every external Dockerfile base must use the authorized digest"
                    )
                if expected_reference is not None and image != expected_reference:
                    raise _build_error(
                        "Dockerfile base reference differs from administrator policy"
                    )
                observed_base = True
            if len(tokens) >= 3 and tokens[-2].upper() == "AS":
                alias = tokens[-1].lower()
                if not _BUILDER_NAME.fullmatch(alias) or alias in aliases:
                    raise _build_error("Dockerfile stage alias is invalid or duplicated")
                aliases.add(alias)
        elif operation == "ADD":
            tokens = _split_copy_or_add(argument)
            sources = [token for token in tokens if not token.startswith("--")][:-1]
            if not sources or any(
                source.lower().startswith(_NO_REMOTE_SCHEMES) for source in sources
            ):
                raise _build_error("Dockerfile remote or malformed ADD is forbidden")
        elif operation == "COPY":
            for token in _split_copy_or_add(argument):
                if token.startswith("--from="):
                    source = token.split("=", 1)[1].lower()
                    if source not in aliases and not source.isdigit():
                        raise _build_error(
                            "Dockerfile COPY cannot import an external build context"
                        )
        elif operation == "RUN":
            lowered = argument.lower().replace(" ", "")
            if (
                "--mount=type=secret" in lowered
                or "--mount=type=ssh" in lowered
                or "--network=host" in lowered
                or "--security=" in lowered
                or "--device=" in lowered
            ):
                raise _build_error(
                    "Dockerfile secret, SSH, host network, insecure, or device use is forbidden"
                )
            for match in re.finditer(r"--mount=([^\s]+)", argument, flags=re.IGNORECASE):
                for option in match.group(1).split(","):
                    if option.lower().startswith("from="):
                        source = option.split("=", 1)[1].lower()
                        if source not in aliases and not source.isdigit():
                            raise _build_error("Dockerfile RUN cannot mount an external context")
    if not observed_base:
        raise _build_error("Dockerfile does not use the authorized base image digest")
    return content


def _dockerfile_instructions(content: str) -> tuple[tuple[str, str], ...]:
    logical: list[str] = []
    pending = ""
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        directive = stripped.lower().replace(" ", "")
        if directive.startswith(("#syntax=", "#escape=")):
            raise _build_error("Custom Dockerfile frontend or escape syntax is forbidden")
        if not stripped or (stripped.startswith("#") and not pending):
            continue
        pending += (" " if pending else "") + stripped.rstrip("\\").rstrip()
        if stripped.endswith("\\"):
            continue
        logical.append(pending)
        pending = ""
    if pending:
        raise _build_error("Dockerfile has an unterminated continuation")
    instructions: list[tuple[str, str]] = []
    for line in logical:
        operation, separator, argument = line.partition(" ")
        if not separator or not operation.isalpha():
            raise _build_error("Dockerfile contains a malformed instruction")
        instructions.append((operation.upper(), argument.strip()))
    return tuple(instructions)


def _expand_onbuild_instructions(
    instructions: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    expanded: list[tuple[str, str]] = []
    for operation, argument in instructions:
        if operation != "ONBUILD":
            expanded.append((operation, argument))
            continue
        nested_operation, separator, nested_argument = argument.partition(" ")
        if not separator or not nested_operation.isalpha() or nested_operation.upper() == "ONBUILD":
            raise _build_error("Dockerfile ONBUILD instruction is malformed or nested")
        expanded.append((nested_operation.upper(), nested_argument.strip()))
    return tuple(expanded)


def _split_copy_or_add(value: str) -> list[str]:
    stripped = value.lstrip()
    if not stripped.startswith("["):
        return _split_dockerfile_instruction(value)
    try:
        decoded = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise _build_error("Dockerfile JSON instruction is malformed") from exc
    if not isinstance(decoded, list):
        raise _build_error("Dockerfile JSON instruction is malformed")
    raw_items = cast(list[object], decoded)
    if len(raw_items) < 2 or any(not isinstance(item, str) or not item for item in raw_items):
        raise _build_error("Dockerfile JSON instruction is malformed")
    return cast(list[str], raw_items)


def _split_dockerfile_instruction(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError as exc:
        raise _build_error("Dockerfile instruction cannot be tokenized safely") from exc


def _read_private_output(path: Path, *, private_root: Path, maximum: int) -> bytes:
    if not path.is_absolute() or path.is_symlink() or path.parent != private_root:
        raise _build_error("Docker Buildx output path escaped its private directory")
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum
        ):
            raise _build_error("Docker Buildx output identity, mode, or size is unsafe")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(descriptor)
            os.fchmod(descriptor, 0o400)
            raw = bytearray()
            while chunk := os.read(descriptor, min(1 << 16, maximum + 1 - len(raw))):
                raw.extend(chunk)
                if len(raw) > maximum:
                    raise _build_error("Docker Buildx output exceeds its fixed limit")
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or stat.S_IMODE(after.st_mode) != 0o400
                or _file_identity(path.lstat()) != _file_identity(after)
            ):
                raise _build_error("Docker Buildx output changed while it was read")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise _build_error("Docker Buildx output cannot be opened safely") from exc
    return bytes(raw)


def _parse_iid(raw: bytes) -> str:
    try:
        value = raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise _build_error("Docker Buildx IID output is invalid") from exc
    _validate_image_digest(value)
    return value


def _parse_metadata(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _build_error("Docker Buildx metadata is invalid") from exc
    if not isinstance(value, dict):
        raise _build_error("Docker Buildx metadata has an unexpected shape")
    return cast(dict[str, Any], value)


def _platform_from_image(image: dict[str, Any]) -> str:
    operating_system = image.get("Os")
    architecture = image.get("Architecture")
    variant = image.get("Variant")
    if not isinstance(operating_system, str) or not isinstance(architecture, str):
        raise _build_error("Docker final image omits its platform")
    suffix = f"/{variant}" if isinstance(variant, str) and variant else ""
    return f"{operating_system}/{architecture}{suffix}"


def _bounded_image_size(image: dict[str, Any], maximum: int) -> int:
    value = image.get("Size")
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise _resource_error("Docker final image exceeds the authorized image budget")
    return value


def _temporary_tag(
    session_identity_sha256: str,
    *,
    build_kind: Literal["baseline", "candidate"],
    candidate_round: int,
) -> str:
    suffix = "baseline-0" if build_kind == "baseline" else f"candidate-{candidate_round}"
    value = f"perflens-opt-{session_identity_sha256[:20]}:{suffix}"
    if not _TEMPORARY_TAG.fullmatch(value):
        raise _build_error("Docker optimization temporary tag is invalid")
    return value


def _unused_private_path(private_root: Path, *, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix="perflens-build-", suffix=suffix, dir=private_root)
    os.close(descriptor)
    path = Path(name)
    path.unlink()
    return path


def _safe_private_directory(path: Path, *, uid: int) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _build_error("Docker build private directory must be absolute and non-symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise _build_error("Docker build private directory is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _build_error("Docker build private directory owner or mode is unsafe")
    return resolved


def _prepare_private_docker_config(runtime_directory: Path, *, uid: int) -> Path:
    root = _safe_private_directory(runtime_directory, uid=uid)
    config = root / "docker-config"
    try:
        config.mkdir(mode=0o700)
        metadata = config.lstat()
    except OSError as exc:
        raise _build_error("Docker private Buildx configuration cannot be created") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or any(config.iterdir())
    ):
        raise _build_error("Docker private Buildx configuration is unsafe")
    return config


def _select_builder_from_json_lines(raw: bytes, builder_name: str) -> dict[str, Any]:
    if len(raw) > _MAX_JSON_BYTES:
        raise _resource_error("Docker Buildx Builder output exceeds its fixed limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _build_error("Docker Buildx Builder output is not valid UTF-8") from exc
    matching: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise _build_error("Docker Buildx Builder output is malformed") from exc
        if not isinstance(value, dict):
            raise _build_error("Docker Buildx Builder output has an unexpected shape")
        item = cast(dict[str, Any], value)
        if item.get("Name") != builder_name:
            continue
        digest = _canonical_sha256(_stable_builder_entry(item))
        matching.setdefault(digest, item)
    if len(matching) != 1:
        raise _build_error("Docker Buildx did not return one unambiguous Builder identity")
    return next(iter(matching.values()))


def _stable_builder_entry(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if key not in {"Current", "LastActivity"}
    }


def _directory_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise _build_error("Docker private Buildx configuration is not a directory")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _validate_image_digest(value: str) -> None:
    if not _IMAGE_DIGEST.fullmatch(value):
        raise _build_error("Docker image identity must be one sha256 digest")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _build_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_build_adapter",
        message,
        recoverable=True,
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "docker_build_adapter",
        message,
        recoverable=True,
    )
