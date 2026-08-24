"""Strict administrator policy for optional Docker optimization network tiers."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_POLICY_BYTES = 64 << 10
_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_BUILDER_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_IMAGE_REFERENCE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$"
)
_REGISTRY_PREFIX = re.compile(r"^[a-z0-9.-]+(?::[0-9]{1,5})?(?:/[a-z0-9][a-z0-9._/-]*)?$")
_EXPECTED_KEYS = {
    "schema_version",
    "policy_id",
    "network_tier",
    "builder_name",
    "driver",
    "builder_identity_sha256",
    "builder_image_digest",
    "network_policy_sha256",
    "source_policy_sha256",
    "allowed_registry_prefixes",
    "base_image_reference",
}


@dataclass(frozen=True, slots=True)
class DockerAdministratorBuilderPolicy:
    schema_version: Literal["1.0"]
    path: Path
    device: int
    inode: int
    owner_uid: int
    size: int
    modified_ns: int
    sha256: str
    policy_id: str
    network_tier: Literal["pinned_pull", "admin_builder_network"]
    builder_name: str
    driver: Literal["docker", "docker-container"]
    builder_identity_sha256: str
    builder_image_digest: str | None
    network_policy_sha256: str
    source_policy_sha256: str
    allowed_registry_prefixes: tuple[str, ...]
    base_image_reference: str


def load_docker_administrator_builder_policy(
    path: Path,
    *,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> DockerAdministratorBuilderPolicy:
    """Load one immutable, trusted policy without following a symbolic link."""
    if not path.is_absolute() or path.is_symlink() or not trusted_owner_uids:
        raise _policy_error("Docker Builder policy path or owner policy is unsafe")
    _validate_trusted_parents(path, trusted_owner_uids=trusted_owner_uids)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted_owner_uids
            or before.st_mode & 0o022
            or not 1 <= before.st_size <= _MAX_POLICY_BYTES
        ):
            raise _policy_error("Docker Builder policy owner, mode, links, or size are unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, min(1 << 15, _MAX_POLICY_BYTES + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > _MAX_POLICY_BYTES:
                raise _policy_error("Docker Builder policy exceeds its size limit")
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise _policy_error("Docker Builder policy changed while it was read")
    except OSError as exc:
        raise _policy_error("Docker Builder policy cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        parsed = cast(dict[str, object], tomllib.loads(bytes(raw).decode("utf-8")))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise _policy_error("Docker Builder policy must be valid UTF-8 TOML") from exc
    if set(parsed) != _EXPECTED_KEYS:
        raise _policy_error("Docker Builder policy has missing or unknown fields")
    values = parsed
    schema = values["schema_version"]
    policy_id = values["policy_id"]
    tier = values["network_tier"]
    builder_name = values["builder_name"]
    driver = values["driver"]
    builder_identity = values["builder_identity_sha256"]
    builder_image = values["builder_image_digest"]
    network_sha = values["network_policy_sha256"]
    source_sha = values["source_policy_sha256"]
    prefixes = values["allowed_registry_prefixes"]
    base_reference = values["base_image_reference"]
    if schema != "1.0" or not isinstance(policy_id, str) or not _POLICY_ID.fullmatch(policy_id):
        raise _policy_error("Docker Builder policy version or ID is invalid")
    if tier not in {"pinned_pull", "admin_builder_network"}:
        raise _policy_error("Docker Builder policy network tier is invalid")
    if (
        not isinstance(builder_name, str)
        or not _BUILDER_NAME.fullmatch(builder_name)
        or driver not in {"docker", "docker-container"}
        or not isinstance(builder_identity, str)
        or not _SHA256.fullmatch(builder_identity)
    ):
        raise _policy_error("Docker Builder identity is invalid")
    if not isinstance(network_sha, str) or not _SHA256.fullmatch(network_sha):
        raise _policy_error("Docker Builder network policy digest is invalid")
    if not isinstance(source_sha, str) or not _SHA256.fullmatch(source_sha):
        raise _policy_error("Docker Builder source policy digest is invalid")
    if not isinstance(prefixes, list):
        raise _policy_error("Docker Builder registry allowlist is invalid")
    raw_prefixes = cast(list[object], prefixes)
    if not 1 <= len(raw_prefixes) <= 64:
        raise _policy_error("Docker Builder registry allowlist is invalid")
    typed_prefixes = tuple(item for item in raw_prefixes if isinstance(item, str))
    if (
        len(typed_prefixes) != len(raw_prefixes)
        or len(set(typed_prefixes)) != len(typed_prefixes)
        or tuple(sorted(typed_prefixes)) != typed_prefixes
        or any(not _valid_registry_prefix(item) for item in typed_prefixes)
    ):
        raise _policy_error("Docker Builder registry allowlist must be unique and canonical")
    if not isinstance(base_reference, str) or not _valid_image_reference(base_reference):
        raise _policy_error("Docker Builder base image reference is invalid")
    if not any(_reference_is_within(base_reference, prefix) for prefix in typed_prefixes):
        raise _policy_error("Docker Builder base image is outside the registry allowlist")
    normalized_builder_image: str | None
    if tier == "admin_builder_network":
        if (
            driver != "docker-container"
            or not isinstance(builder_image, str)
            or not _IMAGE_DIGEST.fullmatch(builder_image)
        ):
            raise _policy_error(
                "Networked Docker Builder must pin a docker-container Builder image"
            )
        normalized_builder_image = builder_image
    else:
        if builder_image != "":
            raise _policy_error("Pinned-pull policy cannot configure a networked Builder image")
        normalized_builder_image = None
    return DockerAdministratorBuilderPolicy(
        schema_version="1.0",
        path=path,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        sha256=hashlib.sha256(raw).hexdigest(),
        policy_id=policy_id,
        network_tier=cast(Literal["pinned_pull", "admin_builder_network"], tier),
        builder_name=builder_name,
        driver=cast(Literal["docker", "docker-container"], driver),
        builder_identity_sha256=builder_identity,
        builder_image_digest=normalized_builder_image,
        network_policy_sha256=network_sha,
        source_policy_sha256=source_sha,
        allowed_registry_prefixes=typed_prefixes,
        base_image_reference=base_reference,
    )


def assert_docker_administrator_builder_policy_current(
    policy: DockerAdministratorBuilderPolicy,
    *,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> None:
    current = load_docker_administrator_builder_policy(
        policy.path,
        trusted_owner_uids=trusted_owner_uids,
    )
    if current != policy:
        raise _policy_error("Docker Builder policy changed after capability inspection")


def base_image_reference_digest(reference: str) -> str:
    if not _valid_image_reference(reference):
        raise _policy_error("Docker Builder base image reference is invalid")
    return reference.rsplit("@", 1)[1]


def _valid_image_reference(value: str) -> bool:
    return (
        len(value.encode("utf-8")) <= 1024
        and _IMAGE_REFERENCE.fullmatch(value) is not None
        and "//" not in value
        and "/../" not in f"/{value.split('@', 1)[0]}/"
    )


def _valid_registry_prefix(value: str) -> bool:
    return (
        len(value.encode("utf-8")) <= 512
        and _REGISTRY_PREFIX.fullmatch(value) is not None
        and "//" not in value
        and "/../" not in f"/{value}/"
    )


def _reference_is_within(reference: str, prefix: str) -> bool:
    name = reference.split("@", 1)[0]
    return name == prefix or name.startswith(prefix + "/")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_trusted_parents(path: Path, *, trusted_owner_uids: tuple[int, ...]) -> None:
    current = path.parent
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as exc:
            raise _policy_error("Docker Builder policy parent cannot be inspected") from exc
        trusted_sticky = bool(
            metadata.st_mode & stat.S_ISVTX and metadata.st_uid in trusted_owner_uids
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in trusted_owner_uids
            or (metadata.st_mode & 0o022 and not trusted_sticky)
        ):
            raise _policy_error("Docker Builder policy has an unsafe parent directory")
        if current == current.parent:
            return
        current = current.parent


def _policy_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_builder_policy",
        message,
        recoverable=True,
    )
