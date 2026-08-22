"""Strict, identity-pinned project policy for the local Docker target runtime."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, TypedDict, cast

from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_POLICY_BYTES = 256 << 10
_IMAGE_DIGEST = re.compile(r"^(?:|sha256:[a-f0-9]{64})$")
_CONTAINER_USER = re.compile(r"^(?:|[0-9]{1,10}(?::[0-9]{1,10})?)$")
_TOP_LEVEL_KEYS = {
    "schema_version",
    "target_runtime",
    "default_workflow",
    "default_authorization_mode",
    "allow_managed_temporary_containers",
    "max_workload_runs",
    "max_active_seconds",
    "hard_expiry_seconds",
    "max_evidence_bytes",
    "trace_max_duration_seconds",
    "managed",
}
_MANAGED_KEYS = {
    "image_digest",
    "entrypoint",
    "arguments",
    "working_directory",
    "container_user",
    "cpus",
    "memory_bytes",
    "pids",
    "treatment_paths",
    "benchmark_output",
    "benchmark_format",
    "benchmark_name",
}


@dataclass(frozen=True, slots=True)
class ManagedDockerProjectPolicy:
    image_digest: str
    entrypoint: str
    arguments: tuple[str, ...]
    working_directory: str
    container_user: str
    cpus: float
    memory_bytes: int
    pids: int
    treatment_paths: tuple[str, ...]
    benchmark_output: str
    benchmark_format: Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"]
    benchmark_name: str | None


@dataclass(frozen=True, slots=True)
class DockerProjectPolicy:
    path: Path
    device: int
    inode: int
    owner_uid: int
    size: int
    modified_ns: int
    sha256: str
    default_workflow: Literal["existing_container", "managed_temporary_container"]
    default_authorization_mode: Literal["per_run", "bounded_session"]
    allow_managed_temporary_containers: bool
    max_workload_runs: int
    max_active_seconds: int
    hard_expiry_seconds: int
    max_evidence_bytes: int
    trace_max_duration_seconds: int
    managed: ManagedDockerProjectPolicy


class _ValidatedPolicy(TypedDict):
    default_workflow: Literal["existing_container", "managed_temporary_container"]
    default_authorization_mode: Literal["per_run", "bounded_session"]
    allow_managed_temporary_containers: bool
    max_workload_runs: int
    max_active_seconds: int
    hard_expiry_seconds: int
    max_evidence_bytes: int
    trace_max_duration_seconds: int
    managed: ManagedDockerProjectPolicy


def render_default_docker_project_policy() -> str:
    """Return the bilingual, inactive-by-default managed-container policy."""
    return """# PerfLens v0.3.1 local Docker target policy.
# PerfLens v0.3.1 本地 Docker 目标策略。
# This file grants no target by itself. The Agent must still request per-run or bounded-session
# authorization, and every container/PID is independently rebound by the Broker and Helper.
# 本文件本身不授权任何目标; Agent 仍须请求单次或本轮对话授权,
# 且 Broker/Helper 会独立复核容器与 PID。

schema_version = "1.0"
target_runtime = "docker"
default_workflow = "existing_container"
default_authorization_mode = "per_run"
allow_managed_temporary_containers = false
max_workload_runs = 6
max_active_seconds = 1200
hard_expiry_seconds = 7200
max_evidence_bytes = 536870912
trace_max_duration_seconds = 10

# Existing containers are selected at task time by name/full ID; no target is permanently stored.
# 已有容器在任务开始时按名称/完整 ID 选择, 不在这里永久保存目标。

[managed]
# Managed temporary containers remain disabled until these fixed fields are reviewed and the
# top-level allow_managed_temporary_containers value is explicitly changed to true.
# 临时测试容器默认关闭; 审查下列固定字段后, 还必须显式把顶层开关改为 true。
image_digest = ""
entrypoint = ""
arguments = []
working_directory = "/workspace"
container_user = ""
cpus = 1.0
memory_bytes = 536870912
pids = 256
# Relative, user-reviewed project files whose content identifies the A/B treatment. Paths are
# never published; public artifacts retain only domain-separated contract hashes. Keep empty for
# analysis without a Verified Improvement claim.
# 用于标识 A/B 改动的项目内相对路径. 公开产物不保存路径, 仅保存合同哈希; 留空时仍可
# 分析, 但不能声称 Verified Improvement.
treatment_paths = []
# Optional JSON written by the fixed workload under /perflens-scratch. When configured, PerfLens
# reads it before cleanup and binds the normalized benchmark to this exact container run.
# 固定 workload 可在 /perflens-scratch 下写入此 JSON. 配置后 PerfLens 会在清理前读取,
# 并把规范化 benchmark 绑定到本次容器运行。
benchmark_output = ""
benchmark_format = "auto"
benchmark_name = ""
"""


def load_docker_project_policy(
    path: Path,
    *,
    allowed_roots: tuple[Path, ...],
    invoking_uid: int | None = None,
) -> DockerProjectPolicy:
    """Load one user-owned project policy from the same checked file descriptor."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    if not path.is_absolute() or path.is_symlink():
        raise _policy_error("Docker project policy must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=True)
        roots = tuple(root.expanduser().resolve(strict=True) for root in allowed_roots)
    except OSError as exc:
        raise _policy_error("Docker project policy path cannot be resolved safely") from exc
    if resolved != path or not any(resolved.is_relative_to(root) for root in roots):
        raise _policy_error("Docker project policy is outside the configured project roots")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(resolved, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != uid
            or before.st_mode & 0o022
            or not 1 <= before.st_size <= _MAX_POLICY_BYTES
        ):
            raise _policy_error("Docker project policy owner, mode, links, or size are unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, min(1 << 16, _MAX_POLICY_BYTES + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > _MAX_POLICY_BYTES:
                raise _policy_error("Docker project policy exceeds its size limit")
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise _policy_error("Docker project policy changed while it was read")
    except OSError as exc:
        raise _policy_error("Docker project policy cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        parsed = cast(dict[str, object], tomllib.loads(bytes(raw).decode("utf-8")))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise _policy_error("Docker project policy must be valid UTF-8 TOML") from exc
    values = _validate_policy_values(parsed)
    return DockerProjectPolicy(
        path=resolved,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        sha256=hashlib.sha256(raw).hexdigest(),
        **values,
    )


def assert_docker_project_policy_current(
    policy: DockerProjectPolicy,
    *,
    allowed_roots: tuple[Path, ...],
) -> None:
    current = load_docker_project_policy(
        policy.path,
        allowed_roots=allowed_roots,
        invoking_uid=policy.owner_uid,
    )
    if current != policy:
        raise _policy_error(
            "Docker project policy changed after MCP startup; restart the client to review it"
        )


def _validate_policy_values(parsed: dict[str, object]) -> _ValidatedPolicy:
    if set(parsed) != _TOP_LEVEL_KEYS:
        raise _policy_error("Docker project policy has missing or unknown top-level fields")
    if parsed["schema_version"] != "1.0" or parsed["target_runtime"] != "docker":
        raise _policy_error("Docker project policy version or runtime is unsupported")
    workflow = parsed["default_workflow"]
    authorization = parsed["default_authorization_mode"]
    if workflow not in {"existing_container", "managed_temporary_container"}:
        raise _policy_error("Docker default workflow is unsupported")
    if authorization not in {"per_run", "bounded_session"}:
        raise _policy_error("Docker authorization mode is unsupported")
    allow_managed = _boolean(parsed["allow_managed_temporary_containers"], "managed switch")
    max_runs = _integer(parsed["max_workload_runs"], "workload runs", 1, 6)
    max_active = _integer(parsed["max_active_seconds"], "active seconds", 1, 7200)
    hard_expiry = _integer(parsed["hard_expiry_seconds"], "hard expiry", 1, 28_800)
    max_evidence = _integer(parsed["max_evidence_bytes"], "evidence bytes", 1, 8 << 30)
    trace_duration = _integer(parsed["trace_max_duration_seconds"], "trace duration", 1, 10)
    if hard_expiry < max_active:
        raise _policy_error("Docker session hard expiry cannot be shorter than active time")
    if workflow == "managed_temporary_container" and not allow_managed:
        raise _policy_error("Docker default managed workflow is disabled by project policy")
    managed = parsed["managed"]
    if not isinstance(managed, dict):
        raise _policy_error("Docker managed policy must be a table")
    typed_managed = cast(dict[str, object], managed)
    if set(typed_managed) != _MANAGED_KEYS:
        raise _policy_error("Docker managed policy has missing or unknown fields")
    validated_managed = _validate_managed(typed_managed, enabled=allow_managed)
    return {
        "default_workflow": cast(
            Literal["existing_container", "managed_temporary_container"], workflow
        ),
        "default_authorization_mode": cast(Literal["per_run", "bounded_session"], authorization),
        "allow_managed_temporary_containers": allow_managed,
        "max_workload_runs": max_runs,
        "max_active_seconds": max_active,
        "hard_expiry_seconds": hard_expiry,
        "max_evidence_bytes": max_evidence,
        "trace_max_duration_seconds": trace_duration,
        "managed": validated_managed,
    }


def _validate_managed(
    values: dict[str, object],
    *,
    enabled: bool,
) -> ManagedDockerProjectPolicy:
    image = values["image_digest"]
    entrypoint = values["entrypoint"]
    user = values["container_user"]
    arguments_value = values["arguments"]
    if not isinstance(image, str) or not _IMAGE_DIGEST.fullmatch(image):
        raise _policy_error("Docker managed image must be empty or a fixed sha256 digest")
    if not isinstance(entrypoint, str) or not isinstance(user, str):
        raise _policy_error("Docker managed entrypoint and user must be strings")
    if not isinstance(arguments_value, list):
        raise _policy_error("Docker managed arguments must be a list")
    arguments = cast(list[object], arguments_value)
    if len(arguments) > 128 or any(
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or "\x00" in value
        for value in arguments
    ):
        raise _policy_error("Docker managed arguments are invalid or unbounded")
    working = values["working_directory"]
    if not isinstance(working, str):
        raise _policy_error("Docker managed working directory must be a string")
    _container_path(working, "working directory")
    if entrypoint:
        _container_path(entrypoint, "entrypoint")
    if not _CONTAINER_USER.fullmatch(user):
        raise _policy_error("Docker managed user must be an empty or numeric UID[:GID]")
    cpus = values["cpus"]
    if isinstance(cpus, bool) or not isinstance(cpus, int | float) or not 0 < cpus <= 1024:
        raise _policy_error("Docker managed CPU limit is invalid")
    _integer(values["memory_bytes"], "managed memory", 6 << 20, 1 << 50)
    _integer(values["pids"], "managed PIDs", 1, 1_000_000)
    treatment_paths_value = values["treatment_paths"]
    if not isinstance(treatment_paths_value, list):
        raise _policy_error("Docker managed treatment paths must be a list")
    raw_treatment_paths = cast(list[object], treatment_paths_value)
    if len(raw_treatment_paths) > 32 or any(
        not isinstance(value, str) for value in raw_treatment_paths
    ):
        raise _policy_error("Docker managed treatment paths are invalid or unbounded")
    treatment_paths = tuple(
        _project_relative_path(cast(str, value), "treatment path") for value in raw_treatment_paths
    )
    if len(set(treatment_paths)) != len(treatment_paths):
        raise _policy_error("Docker managed treatment paths must be unique")
    benchmark_output_value = values["benchmark_output"]
    benchmark_format_value = values["benchmark_format"]
    benchmark_name_value = values["benchmark_name"]
    if not isinstance(benchmark_output_value, str):
        raise _policy_error("Docker managed benchmark output must be a string")
    benchmark_output = (
        _project_relative_path(benchmark_output_value, "benchmark output")
        if benchmark_output_value
        else ""
    )
    if not isinstance(benchmark_format_value, str) or benchmark_format_value not in {
        "auto",
        "perflens",
        "pyperf",
        "google_benchmark",
        "hyperfine",
    }:
        raise _policy_error("Docker managed benchmark format is unsupported")
    if (
        not isinstance(benchmark_name_value, str)
        or len(benchmark_name_value.encode()) > 256
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in benchmark_name_value
        )
        or (benchmark_name_value and not benchmark_output)
    ):
        raise _policy_error("Docker managed benchmark name is invalid or has no output")
    if enabled and (not image or not entrypoint or not user):
        raise _policy_error("Enabled managed Docker workflow requires image, entrypoint, and user")
    return ManagedDockerProjectPolicy(
        image_digest=image,
        entrypoint=entrypoint,
        arguments=tuple(cast(str, value) for value in arguments),
        working_directory=working,
        container_user=user,
        cpus=float(cpus),
        memory_bytes=cast(int, values["memory_bytes"]),
        pids=cast(int, values["pids"]),
        treatment_paths=tuple(sorted(treatment_paths)),
        benchmark_output=benchmark_output,
        benchmark_format=cast(
            Literal["auto", "perflens", "pyperf", "google_benchmark", "hyperfine"],
            benchmark_format_value,
        ),
        benchmark_name=benchmark_name_value or None,
    )


def _container_path(value: str, label: str) -> None:
    path = PurePosixPath(value)
    if not value.startswith("/") or value == "/" or "\x00" in value or str(path) != value:
        raise _policy_error(f"Docker managed {label} must be a normalized absolute path")


def _project_relative_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
        or str(path) != value
        or value in {".", ".."}
        or ".." in path.parts
    ):
        raise _policy_error(f"Docker managed {label} must be a normalized project-relative path")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise _policy_error(f"Docker {label} must be a boolean")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise _policy_error(f"Docker {label} is outside its fixed bound")
    return value


def _policy_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_project_policy",
        message,
        recoverable=True,
    )
