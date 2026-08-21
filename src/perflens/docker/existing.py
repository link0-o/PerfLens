"""Bounded process discovery for an already-running local Docker container."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    ContainerProcessCandidate,
    ContainerProcessInventoryArtifact,
)
from perflens.docker.adapter import DockerCommandAdapter
from perflens.docker.identity import (
    KernelProcessIdentity,
    LinuxContainerIdentityReader,
    PrivateContainerInstance,
    assert_container_membership,
    container_identity_sha256,
    parse_container_instance,
    parse_container_top,
)
from perflens.domain.errors import ErrorCode, PerfLensError


@dataclass(frozen=True, slots=True)
class ExistingContainerDiscovery:
    instance: PrivateContainerInstance
    inventory: ContainerProcessInventoryArtifact
    stable_identities: tuple[KernelProcessIdentity, ...]

    def identity_for_host_pid(self, host_pid: int) -> KernelProcessIdentity:
        matches = tuple(item for item in self.stable_identities if item.host_pid == host_pid)
        if len(matches) != 1:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_discovery",
                "Selected Docker process is not a stable discovered candidate",
                recoverable=True,
            )
        return matches[0]


def discover_existing_container_processes(
    adapter: DockerCommandAdapter,
    container_reference: str,
    *,
    reader: LinuxContainerIdentityReader | None = None,
    observation_duration_ms: int = 100,
    waiter: Callable[[float], None] = time.sleep,
    created_at: datetime | None = None,
) -> ExistingContainerDiscovery:
    """Observe bounded CPU deltas without exposing argv or target-external metadata."""
    if not 1 <= observation_duration_ms <= 10_000:
        raise _discovery_error("Docker process observation duration is outside its fixed bound")
    identity_reader = reader or LinuxContainerIdentityReader()
    instance = parse_container_instance(adapter.inspect_container(container_reference))
    initial_hints = parse_container_top(adapter.top_container(container_reference))
    hint_by_pid = {item.host_pid: item for item in initial_hints}
    if instance.init_host_pid not in hint_by_pid:
        raise _discovery_error("Docker init PID is absent from the process inventory")
    init_identity = identity_reader.inspect_process(instance.init_host_pid)
    initial_identities: dict[int, KernelProcessIdentity] = {}
    initial_ticks: dict[int, int] = {}
    limitations: list[str] = []
    for hint in initial_hints:
        try:
            identity = (
                init_identity
                if hint.host_pid == instance.init_host_pid
                else identity_reader.inspect_process(hint.host_pid)
            )
            assert_container_membership(instance, init_identity, identity, hint)
            initial_ticks[hint.host_pid] = identity_reader.inspect_cpu_time_ticks(identity)
            initial_identities[hint.host_pid] = identity
        except PerfLensError:
            limitations.append("A Docker process candidate failed initial Linux identity binding.")
    waiter(observation_duration_ms / 1000.0)
    current_instance = parse_container_instance(adapter.inspect_container(container_reference))
    if current_instance != instance:
        raise _discovery_error("Docker container changed during process observation")
    current_hints = parse_container_top(adapter.top_container(container_reference))
    current_by_pid = {item.host_pid: item for item in current_hints}
    if instance.init_host_pid not in current_by_pid:
        raise _discovery_error("Docker init PID changed during process observation")
    current_init = identity_reader.inspect_process(instance.init_host_pid)
    if current_init != init_identity:
        raise _discovery_error("Docker init process identity changed during observation")
    retained: list[tuple[KernelProcessIdentity, int]] = []
    for host_pid, identity in initial_identities.items():
        hint = current_by_pid.get(host_pid)
        if hint is None or hint != hint_by_pid[host_pid]:
            limitations.append("A Docker process candidate changed during CPU observation.")
            continue
        try:
            current_identity = identity_reader.inspect_process(host_pid)
            assert_container_membership(instance, current_init, current_identity, hint)
            if current_identity != identity:
                raise _discovery_error("Docker process identity changed during CPU observation")
            final_ticks = identity_reader.inspect_cpu_time_ticks(current_identity)
            delta = final_ticks - initial_ticks[host_pid]
            if delta < 0:
                raise _discovery_error("Docker process CPU counter decreased during observation")
            retained.append((current_identity, delta))
        except PerfLensError:
            limitations.append("A Docker process candidate failed final Linux identity binding.")
    if len(current_hints) != len(initial_hints):
        limitations.append("Container process membership changed during CPU observation.")
    retained.sort(key=lambda item: (-item[1], item[0].host_pid))
    recommendation, recommended_pid = _recommend_process(retained)
    candidates = tuple(
        ContainerProcessCandidate(
            container_pid=identity.container_pid,
            host_pid=identity.host_pid,
            executable_name=identity.executable_name,
            cpu_delta_ticks=delta,
            recommendation=(
                "dominant" if recommended_pid == identity.host_pid else "candidate"
            ),
        )
        for identity, delta in retained
    )
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _discovery_error("Docker process inventory timestamp must include a timezone")
    container_identity = container_identity_sha256(adapter, instance)
    identity = hashlib.sha256(
        "\0".join(
            (
                container_identity,
                timestamp.isoformat(),
                str(observation_duration_ms),
                *(
                    f"{item.host_pid}:{item.container_pid}:{item.cpu_delta_ticks}"
                    for item in candidates
                ),
            )
        ).encode()
    ).hexdigest()
    limitation_tuple = tuple(sorted(set(limitations)))
    provisional = ContainerProcessInventoryArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        inventory_id=f"container-inventory-{identity[:20]}",
        created_at=timestamp.isoformat(),
        container_identity_sha256=container_identity,
        observation_duration_ms=observation_duration_ms,
        candidates=candidates,
        candidate_count=len(candidates),
        candidates_truncated=False,
        automatic_recommendation=recommendation,
        recommended_host_pid=recommended_pid,
        limitations=limitation_tuple,
        content_sha256="0" * 64,
    )
    artifact = ContainerProcessInventoryArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )
    return ExistingContainerDiscovery(
        instance=instance,
        inventory=artifact,
        stable_identities=tuple(item[0] for item in retained),
    )


def _recommend_process(
    retained: list[tuple[KernelProcessIdentity, int]],
) -> tuple[Literal["unique", "dominant", "ambiguous", "none"], int | None]:
    if not retained:
        return "none", None
    if len(retained) == 1:
        return "unique", retained[0][0].host_pid
    highest = retained[0][1]
    second = retained[1][1]
    total = sum(delta for _, delta in retained)
    if highest > 0 and highest >= max(1, second * 2) and highest * 10 >= total * 7:
        return "dominant", retained[0][0].host_pid
    return "ambiguous", None


def _discovery_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_discovery",
        message,
        recoverable=True,
    )
