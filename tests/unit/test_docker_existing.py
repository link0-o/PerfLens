from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.docker.adapter import (
    DockerCliIdentity,
    DockerCommandAdapter,
    DockerEndpointSnapshot,
)
from perflens.docker.existing import discover_existing_container_processes
from perflens.docker.identity import LinuxContainerIdentityReader
from perflens.domain.errors import ErrorCode, PerfLensError

_CONTAINER_ID = "a" * 64
_REPLACEMENT_ID = "d" * 64
_IMAGE_DIGEST = "sha256:" + "b" * 64


@dataclass(slots=True)
class _SequencedAdapter:
    inspect_results: list[dict[str, Any]]
    top_results: list[str]
    inspect_calls: int = 0
    top_calls: int = 0

    @property
    def cli_identity(self) -> DockerCliIdentity:
        return DockerCliIdentity(
            path=Path("/usr/bin/docker"),
            sha256="c" * 64,
            device=1,
            inode=2,
            size=1024,
            trusted_owner_uids=(0,),
        )

    @property
    def endpoint_identity(self) -> DockerEndpointSnapshot:
        return DockerEndpointSnapshot(
            path=Path("/run/docker.sock"),
            kind="local_rootless",
            device=3,
            inode=4,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o600,
        )

    def inspect_container(self, reference: str) -> dict[str, Any]:
        assert reference == "service"
        index = min(self.inspect_calls, len(self.inspect_results) - 1)
        self.inspect_calls += 1
        return self.inspect_results[index]

    def top_container(self, reference: str) -> str:
        assert reference == "service"
        index = min(self.top_calls, len(self.top_results) - 1)
        self.top_calls += 1
        return self.top_results[index]


def _inspect(*, container_id: str = _CONTAINER_ID) -> dict[str, Any]:
    return {
        "Id": container_id,
        "Image": _IMAGE_DIGEST,
        "State": {"Running": True, "Pid": 1001},
        "Config": {
            "Cmd": ["--token=must-not-leak"],
            "Env": ["SECRET=must-not-leak"],
        },
        "Mounts": [{"Source": "/private/host/path"}],
    }


def _stat_text(
    pid: int,
    start_time: int,
    *,
    user_ticks: int,
    system_ticks: int,
    name: str,
) -> str:
    fields = ["S", *("0" for _ in range(39))]
    fields[11] = str(user_ticks)
    fields[12] = str(system_ticks)
    fields[19] = str(start_time)
    return f"{pid} ({name}) {' '.join(fields)}\n"


def _write_process(
    proc_root: Path,
    *,
    host_pid: int,
    container_pid: int,
    start_time: int,
    executable_name: str,
    user_ticks: int = 0,
    system_ticks: int = 0,
) -> None:
    process = proc_root / str(host_pid)
    process.mkdir()
    _write_stat(
        proc_root,
        host_pid=host_pid,
        start_time=start_time,
        executable_name=executable_name,
        user_ticks=user_ticks,
        system_ticks=system_ticks,
    )
    uid = os.geteuid()
    (process / "status").write_text(
        f"Name:\t{executable_name}\n"
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"NSpid:\t{host_pid}\t{container_pid}\n",
        encoding="ascii",
    )
    (process / "comm").write_text(f"{executable_name}\n", encoding="ascii")
    (process / "cgroup").write_text(
        "0::/docker/test-container\n",
        encoding="ascii",
    )
    namespaces = process / "ns"
    namespaces.mkdir()
    for index, namespace in enumerate(("pid", "user", "mnt", "cgroup"), start=1):
        (namespaces / namespace).symlink_to(f"{namespace}:[{100 + index}]")


def _write_stat(
    proc_root: Path,
    *,
    host_pid: int,
    start_time: int,
    executable_name: str,
    user_ticks: int,
    system_ticks: int,
) -> None:
    (proc_root / str(host_pid) / "stat").write_text(
        _stat_text(
            host_pid,
            start_time,
            user_ticks=user_ticks,
            system_ticks=system_ticks,
            name=executable_name,
        ),
        encoding="ascii",
    )


def _identity_reader(tmp_path: Path) -> tuple[LinuxContainerIdentityReader, Path]:
    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    proc_root.mkdir()
    (cgroup_root / "docker" / "test-container").mkdir(parents=True)
    return (
        LinuxContainerIdentityReader(proc_root=proc_root, cgroup_root=cgroup_root),
        proc_root,
    )


def _adapter(
    *,
    initial_top: str,
    final_top: str | None = None,
    final_container_id: str = _CONTAINER_ID,
) -> DockerCommandAdapter:
    adapter = _SequencedAdapter(
        inspect_results=[_inspect(), _inspect(container_id=final_container_id)],
        top_results=[initial_top, final_top or initial_top],
    )
    return cast(DockerCommandAdapter, adapter)


def test_existing_discovery_recommends_dominant_process_without_private_data(
    tmp_path: Path,
) -> None:
    reader, proc_root = _identity_reader(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
        user_ticks=10,
    )
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9002,
        executable_name="worker",
        user_ticks=20,
    )

    def advance(_: float) -> None:
        _write_stat(
            proc_root,
            host_pid=1001,
            start_time=9001,
            executable_name="init",
            user_ticks=15,
            system_ticks=0,
        )
        _write_stat(
            proc_root,
            host_pid=1002,
            start_time=9002,
            executable_name="worker",
            user_ticks=120,
            system_ticks=0,
        )

    discovery = discover_existing_container_processes(
        _adapter(initial_top="PID PPID COMM\n1001 0 init\n1002 1001 worker\n"),
        "service",
        reader=reader,
        waiter=advance,
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    inventory = discovery.inventory
    assert inventory.automatic_recommendation == "dominant"
    assert inventory.recommended_host_pid == 1002
    assert tuple(item.cpu_delta_ticks for item in inventory.candidates) == (100, 5)
    assert discovery.identity_for_host_pid(1002).container_pid == 12
    assert inventory.content_sha256 == contract_content_sha256(
        inventory,
        exclude={"content_sha256"},
    )
    serialized = inventory.model_dump_json()
    for private in (
        _CONTAINER_ID,
        _IMAGE_DIGEST,
        "must-not-leak",
        "/private/host/path",
        "/run/docker.sock",
        "/docker/test-container",
    ):
        assert private not in serialized


@pytest.mark.parametrize(
    ("rows", "deltas", "expected", "recommended_pid"),
    [
        ("1001 0 init\n", (7,), "unique", 1001),
        ("1001 0 init\n1002 1001 worker\n", (10, 10), "ambiguous", None),
    ],
)
def test_existing_discovery_handles_unique_and_ambiguous_candidates(
    tmp_path: Path,
    rows: str,
    deltas: tuple[int, ...],
    expected: str,
    recommended_pid: int | None,
) -> None:
    reader, proc_root = _identity_reader(tmp_path)
    pids = (1001, 1002)[: len(deltas)]
    for index, host_pid in enumerate(pids):
        _write_process(
            proc_root,
            host_pid=host_pid,
            container_pid=1 if host_pid == 1001 else 12,
            start_time=9001 + index,
            executable_name="init" if host_pid == 1001 else "worker",
        )

    def advance(_: float) -> None:
        for index, (host_pid, delta) in enumerate(zip(pids, deltas, strict=True)):
            _write_stat(
                proc_root,
                host_pid=host_pid,
                start_time=9001 + index,
                executable_name="init" if host_pid == 1001 else "worker",
                user_ticks=delta,
                system_ticks=0,
            )

    discovery = discover_existing_container_processes(
        _adapter(initial_top=f"PID PPID COMM\n{rows}"),
        "service",
        reader=reader,
        waiter=advance,
    )
    assert discovery.inventory.automatic_recommendation == expected
    assert discovery.inventory.recommended_host_pid == recommended_pid


def test_existing_discovery_omits_changed_candidate_and_reports_partial_inventory(
    tmp_path: Path,
) -> None:
    reader, proc_root = _identity_reader(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9002,
        executable_name="worker",
    )

    def replace_worker(_: float) -> None:
        _write_stat(
            proc_root,
            host_pid=1002,
            start_time=9999,
            executable_name="worker",
            user_ticks=50,
            system_ticks=0,
        )

    discovery = discover_existing_container_processes(
        _adapter(initial_top="PID PPID COMM\n1001 0 init\n1002 1001 worker\n"),
        "service",
        reader=reader,
        waiter=replace_worker,
    )
    assert tuple(item.host_pid for item in discovery.inventory.candidates) == (1001,)
    assert discovery.inventory.limitations
    with pytest.raises(PerfLensError):
        discovery.identity_for_host_pid(1002)


def test_existing_discovery_rejects_container_replacement(tmp_path: Path) -> None:
    reader, proc_root = _identity_reader(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    with pytest.raises(PerfLensError) as captured:
        discover_existing_container_processes(
            _adapter(
                initial_top="PID PPID COMM\n1001 0 init\n",
                final_container_id=_REPLACEMENT_ID,
            ),
            "service",
            reader=reader,
            waiter=lambda _: None,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "container changed" in captured.value.message
    assert _CONTAINER_ID not in captured.value.message
    assert _REPLACEMENT_ID not in captured.value.message


def test_existing_discovery_rejects_decreasing_cpu_counter_as_candidate(
    tmp_path: Path,
) -> None:
    reader, proc_root = _identity_reader(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
        user_ticks=100,
    )

    def decrease(_: float) -> None:
        _write_stat(
            proc_root,
            host_pid=1001,
            start_time=9001,
            executable_name="init",
            user_ticks=99,
            system_ticks=0,
        )

    discovery = discover_existing_container_processes(
        _adapter(initial_top="PID PPID COMM\n1001 0 init\n"),
        "service",
        reader=reader,
        waiter=decrease,
    )
    assert discovery.inventory.candidate_count == 0
    assert discovery.inventory.automatic_recommendation == "none"
    assert discovery.inventory.limitations


@pytest.mark.parametrize("duration_ms", [0, 10_001])
def test_existing_discovery_rejects_unbounded_observation_duration(
    tmp_path: Path,
    duration_ms: int,
) -> None:
    reader, _ = _identity_reader(tmp_path)
    with pytest.raises(PerfLensError):
        discover_existing_container_processes(
            _adapter(initial_top="PID PPID COMM\n1001 0 init\n"),
            "service",
            reader=reader,
            observation_duration_ms=duration_ms,
            waiter=lambda _: None,
        )
