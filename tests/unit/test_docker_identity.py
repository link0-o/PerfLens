from __future__ import annotations

import errno
import os
import subprocess
import sys
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
from perflens.docker.identity import (
    LinuxContainerIdentityReader,
    NamespaceIdentity,
    assert_container_target_current,
    bind_container_collection_target,
    build_managed_container_target_artifact,
    parse_container_instance,
    parse_container_top,
    resolve_existing_container_target,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_CONTAINER_ID = "a" * 64
_IMAGE_DIGEST = "sha256:" + "b" * 64


@dataclass(slots=True)
class _FakeAdapter:
    inspect_data: dict[str, Any]
    top_text: str
    endpoint_kind: str = "local_rootless"

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
            kind=cast(Any, self.endpoint_kind),
            device=3,
            inode=4,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o600,
        )

    def inspect_container(self, _reference: str) -> dict[str, Any]:
        return self.inspect_data

    def top_container(self, _reference: str) -> str:
        return self.top_text


class _ReplacingAdapter(_FakeAdapter):
    inspect_calls: int = 0

    def inspect_container(self, reference: str) -> dict[str, Any]:
        self.inspect_calls += 1
        data = super().inspect_container(reference)
        if self.inspect_calls == 1:
            return data
        return {**data, "Id": "d" * 64}


def _inspect(*, init_pid: int = 1001, running: bool = True) -> dict[str, Any]:
    return {
        "Id": _CONTAINER_ID,
        "Image": _IMAGE_DIGEST,
        "State": {"Running": running, "Pid": init_pid},
        "Config": {"Env": ["SECRET=must-not-leak"]},
        "Mounts": [{"Source": "/private/host/path"}],
    }


def _stat_text(pid: int, start_time: int, *, name: str = "worker") -> str:
    fields = ["S", "0", "0", "0", "0", "0", "0", "0", "0", "0"]
    fields.extend("0" for _ in range(40))
    fields[19] = str(start_time)
    return f"{pid} ({name}) {' '.join(fields)}\n"


def _write_process(
    proc_root: Path,
    *,
    host_pid: int,
    container_pid: int,
    start_time: int,
    executable_name: str,
    cgroup_path: str = "/docker/test-container",
    namespace_offset: int = 0,
) -> None:
    process = proc_root / str(host_pid)
    process.mkdir()
    (process / "stat").write_text(
        _stat_text(host_pid, start_time, name=executable_name),
        encoding="ascii",
    )
    uid = os.geteuid()
    (process / "status").write_text(
        f"Name:\t{executable_name}\n"
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"NSpid:\t{host_pid}\t{container_pid}\n",
        encoding="ascii",
    )
    (process / "comm").write_text(f"{executable_name}\n", encoding="ascii")
    (process / "cgroup").write_text(f"0::{cgroup_path}\n", encoding="ascii")
    namespaces = process / "ns"
    namespaces.mkdir()
    for index, name in enumerate(("pid", "user", "mnt", "cgroup"), start=1):
        (namespaces / name).symlink_to(f"{name}:[{100 + index + namespace_offset}]")


def _identity_filesystem(tmp_path: Path) -> tuple[LinuxContainerIdentityReader, Path, Path]:
    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    proc_root.mkdir()
    (cgroup_root / "docker" / "test-container").mkdir(parents=True)
    return (
        LinuxContainerIdentityReader(proc_root=proc_root, cgroup_root=cgroup_root),
        proc_root,
        cgroup_root,
    )


def _adapter(*, endpoint_kind: str = "local_rootless") -> DockerCommandAdapter:
    fake = _FakeAdapter(
        inspect_data=_inspect(),
        top_text="PID PPID COMMAND\n1001 0 init\n1002 1001 worker\n",
        endpoint_kind=endpoint_kind,
    )
    return cast(DockerCommandAdapter, fake)


def test_parse_container_instance_requires_full_running_identity() -> None:
    instance = parse_container_instance(_inspect())
    assert instance.container_id == _CONTAINER_ID
    assert instance.image_digest == _IMAGE_DIGEST
    assert instance.init_host_pid == 1001

    stopped = _inspect(running=False)
    with pytest.raises(PerfLensError) as captured:
        parse_container_instance(stopped)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    malformed = _inspect()
    malformed["Id"] = "short"
    with pytest.raises(PerfLensError):
        parse_container_instance(malformed)

    boolean_pid = _inspect()
    boolean_pid["State"]["Pid"] = True
    with pytest.raises(PerfLensError):
        parse_container_instance(boolean_pid)


def test_parse_container_top_is_bounded_and_never_accepts_argv_columns() -> None:
    parsed = parse_container_top("PID PPID COMMAND\n1001 0 python worker\n1002 1001 helper\n")
    assert tuple(item.host_pid for item in parsed) == (1001, 1002)
    assert parsed[0].executable_name == "python worker"

    for malformed in (
        "PID COMMAND\n1 worker\n",
        "PID PPID COMMAND\n1 0 worker\n1 0 duplicate\n",
        "PID PPID COMMAND\n1 x worker\n",
        "PID PPID COMMAND\n1 0 bad\x00name\n",
        "PID PPID COMMAND\n1 0 bad/name\n",
    ):
        with pytest.raises(PerfLensError):
            parse_container_top(malformed)


def test_reader_binds_pid_uid_start_time_namespace_and_cgroup(tmp_path: Path) -> None:
    reader, proc_root, cgroup_root = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    identity = reader.inspect_process(1002)
    assert identity.host_uid == os.geteuid()
    assert identity.host_start_time_ticks == 9876
    assert identity.container_pid == 12
    assert identity.namespace.pid == 101
    assert identity.cgroup_inode == (cgroup_root / "docker/test-container").stat().st_ino
    assert identity.cgroup_relative_path == "/docker/test-container"


def test_reader_uses_real_nsfs_inodes_from_a_pinned_proc_descriptor() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        identity = LinuxContainerIdentityReader().inspect_process(process.pid)
        assert identity.namespace.pid == os.stat(
            f"/proc/{process.pid}/ns/pid",
            follow_symlinks=True,
        ).st_ino
        assert identity.namespace.user == os.stat(
            f"/proc/{process.pid}/ns/user",
            follow_symlinks=True,
        ).st_ino
        assert identity.namespace.mount == os.stat(
            f"/proc/{process.pid}/ns/mnt",
            follow_symlinks=True,
        ).st_ino
        assert identity.namespace.cgroup == os.stat(
            f"/proc/{process.pid}/ns/cgroup",
            follow_symlinks=True,
        ).st_ino
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_reader_identifies_the_unavailable_namespace(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    (proc_root / "1002/ns/mnt").unlink()
    with pytest.raises(PerfLensError, match="mnt namespace") as captured:
        reader.inspect_process(1002)
    assert captured.value.recoverable is True


def test_reader_uses_authenticated_gate_namespace_only_when_procfs_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    original_open = os.open
    original_readlink = os.readlink

    def deny_namespace_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "ns/mnt" and dir_fd is not None:
            raise PermissionError(errno.EPERM, "namespace read denied")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def deny_namespace_readlink(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> str:
        if path == "ns/mnt" and dir_fd is not None:
            raise PermissionError(errno.EACCES, "namespace link denied")
        return original_readlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", deny_namespace_open)
    monkeypatch.setattr(os, "readlink", deny_namespace_readlink)
    attestation = NamespaceIdentity(pid=101, user=102, mount=103, cgroup=104)
    identity = reader.inspect_process(
        1002,
        namespace_attestation=attestation,
    )
    assert identity.namespace == attestation


def test_reader_does_not_mask_missing_namespace_with_gate_attestation(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    (proc_root / "1002/ns/mnt").unlink()
    with pytest.raises(PerfLensError, match="mnt namespace"):
        reader.inspect_process(
            1002,
            namespace_attestation=NamespaceIdentity(
                pid=101,
                user=102,
                mount=103,
                cgroup=104,
            ),
        )


def test_reader_rejects_gate_namespace_that_disagrees_with_readable_procfs(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    with pytest.raises(PerfLensError, match="differs from the Gate attestation"):
        reader.inspect_process(
            1002,
            namespace_attestation=NamespaceIdentity(
                pid=999,
                user=102,
                mount=103,
                cgroup=104,
            ),
        )


def test_reader_rejects_invalid_or_malformed_gate_namespace_attestation(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    with pytest.raises(PerfLensError, match="attestation is invalid"):
        reader.inspect_process(
            1002,
            namespace_attestation=NamespaceIdentity(
                pid=0,
                user=102,
                mount=103,
                cgroup=104,
            ),
        )

    namespace = proc_root / "1002/ns/pid"
    namespace.unlink()
    namespace.symlink_to("pid:[0]")
    with pytest.raises(PerfLensError, match="namespace identity is malformed"):
        reader.inspect_process(
            1002,
            namespace_attestation=NamespaceIdentity(
                pid=101,
                user=102,
                mount=103,
                cgroup=104,
            ),
        )


def test_reader_rejects_malformed_namespace_magic_link(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9876,
        executable_name="worker",
    )
    namespace = proc_root / "1002/ns/pid"
    namespace.unlink()
    namespace.symlink_to("pid:[0]")
    with pytest.raises(PerfLensError, match="namespace identity is malformed"):
        reader.inspect_process(1002)


def test_resolver_emits_privacy_safe_content_bound_target(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
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
    resolved = resolve_existing_container_target(
        _adapter(),
        "service",
        container_pid=12,
        reader=reader,
        invoking_uid=os.geteuid(),
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    artifact = resolved.artifact
    assert artifact.host_pid == 1002
    assert artifact.container_pid == 12
    assert artifact.uid_mapping == "rootless_same_uid"
    assert artifact.content_sha256 == contract_content_sha256(
        artifact,
        exclude={"content_sha256"},
    )
    serialized = artifact.model_dump_json()
    assert _CONTAINER_ID not in serialized
    assert "/docker/test-container" not in serialized
    assert "/run/docker.sock" not in serialized
    assert "SECRET" not in serialized
    assert "/private/host/path" not in serialized

    with pytest.raises(PerfLensError) as conflicting:
        resolve_existing_container_target(
            _adapter(),
            "service",
            host_pid=1002,
            container_pid=12,
            reader=reader,
        )
    assert conflicting.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_collection_binding_revalidates_every_linux_identity_field(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
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
    target = resolve_existing_container_target(
        _adapter(),
        "service",
        host_pid=1002,
        reader=reader,
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    ).artifact

    binding = bind_container_collection_target(target, reader=reader)
    assert binding.host_pid == 1002
    assert binding.container_pid == 12
    assert binding.namespace.pid_namespace_inode == 101
    assert binding.target_content_sha256 == target.content_sha256
    assert_container_target_current(binding, reader=reader)

    (proc_root / "1002/stat").write_text(
        _stat_text(1002, 9003),
        encoding="ascii",
    )
    with pytest.raises(PerfLensError, match="identity changed"):
        assert_container_target_current(binding, reader=reader)


def test_collection_binding_rejects_tampered_public_target(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    target = resolve_existing_container_target(
        _adapter(),
        "service",
        host_pid=1001,
        reader=reader,
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    ).artifact
    tampered = target.model_copy(update={"executable_name": "different"})
    with pytest.raises(PerfLensError, match="content digest"):
        bind_container_collection_target(tampered, reader=reader)


def test_managed_target_uses_separate_fixed_recipe_without_private_identity(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="perflens-gate",
    )
    adapter = _adapter()
    instance = parse_container_instance(_inspect())
    target = reader.inspect_process(1001)
    artifact = build_managed_container_target_artifact(
        adapter=adapter,
        instance=instance,
        target=target,
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    assert artifact.target_kind == "managed_temporary_container"
    assert artifact.adapter_recipe_id == "local-docker-managed-v1"
    assert artifact.content_sha256 == contract_content_sha256(
        artifact,
        exclude={"content_sha256"},
    )
    serialized = artifact.model_dump_json()
    assert _CONTAINER_ID not in serialized
    assert "/docker/test-container" not in serialized


def test_managed_target_allows_only_the_post_gate_executable_transition(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="perflens-gate",
    )
    artifact = build_managed_container_target_artifact(
        adapter=_adapter(),
        instance=parse_container_instance(_inspect()),
        target=reader.inspect_process(1001),
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    binding = bind_container_collection_target(artifact, reader=reader)

    (proc_root / "1001/comm").write_text("workload\n", encoding="ascii")
    with pytest.raises(PerfLensError, match="identity changed"):
        assert_container_target_current(binding, reader=reader)
    assert_container_target_current(
        binding,
        reader=reader,
        allow_managed_exec_transition=True,
    )

    (proc_root / "1001/stat").write_text(
        _stat_text(1001, 9002, name="workload"),
        encoding="ascii",
    )
    with pytest.raises(PerfLensError, match="identity changed"):
        assert_container_target_current(
            binding,
            reader=reader,
            allow_managed_exec_transition=True,
        )


def test_existing_target_never_accepts_an_executable_transition(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    artifact = resolve_existing_container_target(
        _adapter(),
        "service",
        host_pid=1001,
        reader=reader,
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    ).artifact
    binding = bind_container_collection_target(artifact, reader=reader)
    (proc_root / "1001/comm").write_text("replacement\n", encoding="ascii")

    with pytest.raises(PerfLensError, match="identity changed"):
        assert_container_target_current(
            binding,
            reader=reader,
            allow_managed_exec_transition=True,
        )


def test_managed_target_rejects_non_init_process_and_naive_timestamp(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="perflens-gate",
    )
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=2,
        start_time=9002,
        executable_name="child",
    )
    adapter = _adapter()
    instance = parse_container_instance(_inspect())
    with pytest.raises(PerfLensError):
        build_managed_container_target_artifact(
            adapter=adapter,
            instance=instance,
            target=reader.inspect_process(1002),
        )
    with pytest.raises(PerfLensError):
        build_managed_container_target_artifact(
            adapter=adapter,
            instance=instance,
            target=reader.inspect_process(1001),
            created_at=datetime(2026, 8, 21),
        )


def test_resolver_requires_explicit_selection_for_multiple_processes(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    with pytest.raises(PerfLensError) as captured:
        resolve_existing_container_target(_adapter(), "service", reader=reader)
    assert "explicit target" in captured.value.message


def test_resolver_rejects_process_outside_container_namespace(tmp_path: Path) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
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
        namespace_offset=50,
    )
    with pytest.raises(PerfLensError) as captured:
        resolve_existing_container_target(
            _adapter(),
            "service",
            host_pid=1002,
            reader=reader,
        )
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "outside" in captured.value.message


def test_resolver_rejects_container_name_replacement_during_verification(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    replacing = _ReplacingAdapter(
        inspect_data=_inspect(),
        top_text="PID PPID COMMAND\n1001 0 init\n",
    )
    with pytest.raises(PerfLensError) as captured:
        resolve_existing_container_target(
            cast(DockerCommandAdapter, replacing),
            "service",
            host_pid=1001,
            reader=reader,
        )
    assert captured.value.recoverable
    assert "changed" in captured.value.message


def test_resolver_rejects_rootless_uid_mismatch_and_gates_rootful_cross_uid(
    tmp_path: Path,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1001,
        container_pid=1,
        start_time=9001,
        executable_name="init",
    )
    mismatched_uid = os.geteuid() + 1
    with pytest.raises(PerfLensError) as captured:
        resolve_existing_container_target(
            _adapter(),
            "service",
            host_pid=1001,
            reader=reader,
            invoking_uid=mismatched_uid,
        )
    assert "Rootless" in captured.value.message

    with pytest.raises(PerfLensError) as captured:
        resolve_existing_container_target(
            _adapter(endpoint_kind="local_rootful"),
            "service",
            host_pid=1001,
            reader=reader,
            invoking_uid=mismatched_uid,
        )
    assert "administrator policy" in captured.value.message

    authorized = resolve_existing_container_target(
        _adapter(endpoint_kind="local_rootful"),
        "service",
        host_pid=1001,
        reader=reader,
        invoking_uid=mismatched_uid,
        allow_rootful_cross_uid=True,
    )
    assert authorized.artifact.uid_mapping == "rootful_cross_uid"
    assert authorized.artifact.rootful_risk_authorized


@pytest.mark.parametrize(
    ("file_name", "replacement"),
    (
        ("status", "Uid:\t0\t1\t0\t1\nNSpid:\t1002\t12\n"),
        ("cgroup", "1:name=systemd:/legacy\n"),
        ("stat", "malformed\n"),
        ("comm", "bad/name\n"),
    ),
)
def test_reader_rejects_malformed_proc_identity(
    tmp_path: Path,
    file_name: str,
    replacement: str,
) -> None:
    reader, proc_root, _ = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9002,
        executable_name="worker",
    )
    (proc_root / "1002" / file_name).write_text(replacement, encoding="ascii")
    with pytest.raises(PerfLensError) as captured:
        reader.inspect_process(1002)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_reader_rejects_proc_identity_symlink_and_cgroup_symlink(tmp_path: Path) -> None:
    reader, proc_root, cgroup_root = _identity_filesystem(tmp_path)
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9002,
        executable_name="worker",
    )
    stat_path = proc_root / "1002/stat"
    stat_path.unlink()
    stat_path.symlink_to("status")
    with pytest.raises(PerfLensError):
        reader.inspect_process(1002)

    proc_root.joinpath("1002").rename(proc_root / "old")
    _write_process(
        proc_root,
        host_pid=1002,
        container_pid=12,
        start_time=9002,
        executable_name="worker",
    )
    cgroup = cgroup_root / "docker/test-container"
    cgroup.rmdir()
    cgroup.symlink_to(cgroup_root)
    with pytest.raises(PerfLensError):
        reader.inspect_process(1002)
