"""Read-only local Docker capability discovery."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact, DockerToolIdentity
from perflens.docker.adapter import DockerCommandAdapter
from perflens.domain.errors import ErrorCode, PerfLensError

CapabilityStatus = Literal["available", "partial", "unavailable"]
EndpointKind = Literal["local_rootful", "local_rootless", "unsupported", "missing"]
DaemonMode = Literal["rootful", "rootless", "unknown"]
OperatingSystem = Literal["linux", "unknown"]
CgroupVersion = Literal["v2", "v1", "unknown"]


def open_local_docker_adapter(
    *,
    docker_path: Path = Path("/usr/bin/docker"),
    config_directory: Path = Path("/usr/share/perflens/docker-empty-config"),
    rootful_socket: Path = Path("/run/docker.sock"),
    rootless_socket: Path | None = None,
    invoking_uid: int | None = None,
    trusted_cli_owner_uids: tuple[int, ...] = (0,),
) -> DockerCommandAdapter:
    """Open only the fixed local rootless-or-rootful Docker endpoint."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    rootless = rootless_socket or Path(f"/run/user/{uid}/docker.sock")
    if rootless.exists() or rootless.is_socket():
        endpoint_path = rootless
        endpoint_kind: Literal["local_rootful", "local_rootless"] = "local_rootless"
    elif rootful_socket.exists() or rootful_socket.is_socket():
        endpoint_path = rootful_socket
        endpoint_kind = "local_rootful"
    else:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "docker_capability",
            "No fixed local Docker Unix socket was found",
            recoverable=True,
        )
    return DockerCommandAdapter(
        docker_path=docker_path,
        endpoint_path=endpoint_path,
        endpoint_kind=endpoint_kind,
        config_directory=config_directory,
        trusted_cli_owner_uids=trusted_cli_owner_uids,
        invoking_uid=uid,
    )


def discover_docker_capability(
    *,
    docker_path: Path = Path("/usr/bin/docker"),
    config_directory: Path = Path("/usr/share/perflens/docker-empty-config"),
    rootful_socket: Path = Path("/run/docker.sock"),
    rootless_socket: Path | None = None,
    invoking_uid: int | None = None,
    checked_at: datetime | None = None,
    trusted_cli_owner_uids: tuple[int, ...] = (0,),
) -> DockerRuntimeCapabilityArtifact:
    """Inspect a fixed local endpoint without starting Docker or a workload."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    timestamp = checked_at or datetime.now(tz=UTC)
    rootless = rootless_socket or Path(f"/run/user/{uid}/docker.sock")
    if rootless.exists() or rootless.is_socket():
        endpoint_path = rootless
        endpoint_kind = "local_rootless"
        daemon_mode = "rootless"
    elif rootful_socket.exists() or rootful_socket.is_socket():
        endpoint_path = rootful_socket
        endpoint_kind = "local_rootful"
        daemon_mode = "rootful"
    else:
        return _unavailable(
            checked_at=timestamp,
            endpoint_kind="missing",
            limitation="No fixed local Docker Unix socket was found.",
        )

    try:
        adapter = DockerCommandAdapter(
            docker_path=docker_path,
            endpoint_path=endpoint_path,
            endpoint_kind=endpoint_kind,
            config_directory=config_directory,
            trusted_cli_owner_uids=trusted_cli_owner_uids,
            invoking_uid=uid,
        )
        version = adapter.version_info()
        info = adapter.daemon_info()
        client_version, api_version = _parse_version(version)
        operating_system, cgroup_version = _parse_info(info)
    except (PerfLensError, ValueError) as exc:
        if isinstance(exc, PerfLensError):
            limitation = (
                f"Local Docker capability check failed: {exc.code.value}; {exc.message}."
            )
        else:
            limitation = "Local Docker capability check failed: INVALID_RESPONSE."
        return _unavailable(
            checked_at=timestamp,
            endpoint_kind=endpoint_kind,
            daemon_mode=daemon_mode,
            limitation=limitation,
        )

    if operating_system != "linux" or cgroup_version != "v2":
        limitations = (
            "Docker server is not a native Linux Engine."
            if operating_system != "linux"
            else "Docker server does not use cgroup v2."
        )
        return _build_capability(
            checked_at=timestamp,
            status="partial",
            endpoint_kind=endpoint_kind,
            daemon_mode=daemon_mode,
            docker_cli=DockerToolIdentity(
                path=str(adapter.cli_identity.path),
                version=client_version,
                binary_sha256=adapter.cli_identity.sha256,
            ),
            api_version=api_version,
            server_operating_system=operating_system,
            cgroup_version=cgroup_version,
            existing_container_discovery=False,
            managed_container_execution=False,
            limitations=(limitations,),
        )
    return _build_capability(
        checked_at=timestamp,
        status="available",
        endpoint_kind=endpoint_kind,
        daemon_mode=daemon_mode,
        docker_cli=DockerToolIdentity(
            path=str(adapter.cli_identity.path),
            version=client_version,
            binary_sha256=adapter.cli_identity.sha256,
        ),
        api_version=api_version,
        server_operating_system="linux",
        cgroup_version="v2",
        existing_container_discovery=True,
        managed_container_execution=True,
        limitations=(),
    )


def _parse_version(data: dict[str, Any]) -> tuple[str, str | None]:
    client = data.get("Client")
    server = data.get("Server")
    if not isinstance(client, dict) or not isinstance(server, dict):
        raise ValueError("Docker version response omits Client or Server")
    client_fields = cast(dict[str, object], client)
    server_fields = cast(dict[str, object], server)
    version = client_fields.get("Version")
    api_version = server_fields.get("ApiVersion") or client_fields.get("ApiVersion")
    if not isinstance(version, str) or not version or len(version) > 256:
        raise ValueError("Docker client version is missing or invalid")
    if api_version is not None and (not isinstance(api_version, str) or len(api_version) > 64):
        raise ValueError("Docker API version is invalid")
    return version, api_version


def _parse_info(data: dict[str, Any]) -> tuple[OperatingSystem, CgroupVersion]:
    operating_system = data.get("OSType")
    cgroup_version = data.get("CgroupVersion")
    normalized_os = "linux" if operating_system == "linux" else "unknown"
    if cgroup_version == "2":
        normalized_cgroup: CgroupVersion = "v2"
    elif cgroup_version == "1":
        normalized_cgroup = "v1"
    else:
        normalized_cgroup = "unknown"
    return normalized_os, normalized_cgroup


def _unavailable(
    *,
    checked_at: datetime,
    endpoint_kind: EndpointKind,
    limitation: str,
    daemon_mode: DaemonMode = "unknown",
) -> DockerRuntimeCapabilityArtifact:
    return _build_capability(
        checked_at=checked_at,
        status="unavailable",
        endpoint_kind=endpoint_kind,
        daemon_mode=daemon_mode,
        docker_cli=None,
        api_version=None,
        server_operating_system="unknown",
        cgroup_version="unknown",
        existing_container_discovery=False,
        managed_container_execution=False,
        limitations=(limitation,),
    )


def _build_capability(
    *,
    checked_at: datetime,
    status: CapabilityStatus,
    endpoint_kind: EndpointKind,
    daemon_mode: DaemonMode,
    docker_cli: DockerToolIdentity | None,
    api_version: str | None,
    server_operating_system: OperatingSystem,
    cgroup_version: CgroupVersion,
    existing_container_discovery: bool,
    managed_container_execution: bool,
    limitations: tuple[str, ...],
) -> DockerRuntimeCapabilityArtifact:
    timestamp = checked_at.isoformat()
    identity = "\0".join((timestamp, status, endpoint_kind, daemon_mode, *limitations))
    data = {
        "schema_version": "1.0",
        "perflens_version": __version__,
        "capability_id": f"docker-capability-{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
        "checked_at": timestamp,
        "status": status,
        "endpoint_kind": endpoint_kind,
        "daemon_mode": daemon_mode,
        "docker_cli": docker_cli,
        "api_version": api_version,
        "server_operating_system": server_operating_system,
        "cgroup_version": cgroup_version,
        "existing_container_discovery": existing_container_discovery,
        "managed_container_execution": managed_container_execution,
        "limitations": limitations,
        "next_steps": (
            ()
            if status == "available"
            else ("Install or start a supported local Linux Docker Engine with cgroup v2.",)
        ),
        "content_sha256": "0" * 64,
    }
    provisional = DockerRuntimeCapabilityArtifact.model_validate(data)
    return DockerRuntimeCapabilityArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )
