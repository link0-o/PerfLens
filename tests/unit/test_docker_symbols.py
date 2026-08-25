from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

import pytest
from mcp.client import Client

from perflens.application.analyze import analyze_perf_data
from perflens.application.evidence import (
    build_collection_evidence_provenance,
    compute_analysis_content_sha256,
    contract_content_sha256,
)
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.classification.engine import build_diagnosis_bundle
from perflens.collection.planning import AutomaticCollectionPolicy
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CollectionArtifact,
    ContainerCollectionCgroupBinding,
    ContainerCollectionNamespaceBinding,
    ContainerCollectionTargetBinding,
)
from perflens.contracts.docker import (
    ContainerModuleEvidence,
    ContainerModuleSnapshotArtifact,
    ContainerModuleSnapshotLimits,
)
from perflens.docker import symbols as docker_symbols
from perflens.docker.identity import (
    KernelProcessIdentity,
    LinuxContainerIdentityReader,
    NamespaceIdentity,
)
from perflens.docker.project_config import render_default_docker_project_policy
from perflens.docker.symbols import (
    BuildIdListResult,
    PerfBuildIdListAdapter,
    RecordedModule,
    build_container_symbol_context,
    capture_container_module_snapshot,
    materialize_container_workspace_symfs,
    pin_container_process_root,
    project_container_analysis,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.symbols.elf import ElfInspector


def _tool(name: str) -> str:
    discovered = shutil.which(name)
    assert discovered is not None
    return str(Path(discovered).resolve())


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


class _Reader:
    def __init__(self, identity: KernelProcessIdentity, *, unavailable: bool = False) -> None:
        self.identity = identity
        self.unavailable = unavailable

    def inspect_process(self, _host_pid: int) -> KernelProcessIdentity:
        if self.unavailable:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_identity",
                "target unavailable",
            )
        return self.identity


def _identity() -> KernelProcessIdentity:
    return KernelProcessIdentity(
        host_pid=1234,
        host_uid=os.geteuid(),
        host_start_time_ticks=5678,
        container_pid=12,
        nspid=(1234, 12),
        executable_name="app",
        namespace=NamespaceIdentity(pid=101, user=102, mount=103, cgroup=104),
        cgroup_relative_path="/docker/test",
        cgroup_inode=105,
    )


def _binding(identity: KernelProcessIdentity) -> ContainerCollectionTargetBinding:
    container_identity = "5" * 64
    image_identity = "6" * 64
    cgroup_identity = _sha256_text(
        "cgroup-v2",
        container_identity,
        identity.cgroup_relative_path,
        str(identity.cgroup_inode),
    )
    fingerprint = _sha256_text(
        container_identity,
        image_identity,
        str(identity.host_pid),
        str(identity.host_uid),
        str(identity.host_start_time_ticks),
        str(identity.container_pid),
        str(identity.namespace.pid),
        str(identity.namespace.user),
        str(identity.namespace.mount),
        str(identity.namespace.cgroup),
        str(identity.cgroup_inode),
        cgroup_identity,
    )
    return ContainerCollectionTargetBinding(
        target_id="container-target-" + "4" * 20,
        target_kind="existing_container",
        target_content_sha256="a" * 64,
        container_identity_sha256=container_identity,
        image_identity_sha256=image_identity,
        identity_fingerprint=fingerprint,
        container_pid=identity.container_pid,
        host_pid=identity.host_pid,
        host_uid=identity.host_uid,
        host_start_time_ticks=identity.host_start_time_ticks,
        executable_name=identity.executable_name,
        namespace=ContainerCollectionNamespaceBinding(
            pid_namespace_inode=identity.namespace.pid,
            user_namespace_inode=identity.namespace.user,
            mount_namespace_inode=identity.namespace.mount,
            cgroup_namespace_inode=identity.namespace.cgroup,
        ),
        cgroup=ContainerCollectionCgroupBinding(
            inode=identity.cgroup_inode,
            identity_sha256=cgroup_identity,
        ),
        uid_mapping="rootless_same_uid",
        adapter_recipe_id="local-docker-read-v1",
        adapter_sha256="8" * 64,
    )


def _collection(profile: Path, binding: ContainerCollectionTargetBinding) -> CollectionArtifact:
    payload = profile.read_bytes()
    return CollectionArtifact(
        collection_id="collection-" + "1" * 16,
        mode="record",
        target_type="pid",
        target_argument_count=0,
        target_pid=binding.host_pid,
        target_runtime="docker",
        container_target=binding,
        output_path=str(profile),
        output_sha256=hashlib.sha256(payload).hexdigest(),
        output_bytes=len(payload),
        output_format="perf_data",
        output_owner_uid=os.geteuid(),
        perf_executable="/usr/bin/perf",
        started_at="2026-08-22T00:00:00+00:00",
        finished_at="2026-08-22T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=99,
        call_graph="dwarf",
        record_event="cpu-clock",
        requested_event_source="software_only",
        actual_event_source="software",
        evidence_limitations=(
            "instructions-per-cycle unavailable",
            "hardware cache-miss evidence unavailable",
            "hardware branch-miss evidence unavailable",
        ),
        authorization="explicit",
    )


def _compile_module(path: Path, source: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603 - fixed test compiler
        (_tool("gcc"), "-g", "-O0", "-o", str(path), str(source)),
        check=True,
        capture_output=True,
    )
    build_id = ElfInspector().inspect(path).build_id
    assert build_id is not None
    return build_id


def _fake_perf(path: Path) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version docker-symbol-test')\n"
        "elif args and args[0] == 'script':\n"
        "    print('app 1234/1234 [000] 1.0: 11 cpu-clock: ')\n"
        "    print('        400010 work (/opt/app) /workspace/src/main.c:7')\n"
        "    print('diagnostic /run/secrets/container-token', file=sys.stderr)\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_perf_with_dsos(path: Path, dsos: tuple[str, str]) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"dsos = {dsos!r}\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version docker-symbol-order-test')\n"
        "elif args and args[0] == 'script':\n"
        "    for index, dso in enumerate(dsos, start=1):\n"
        "        print(f'app 1234/1234 [000] {index}.0: 11 cpu-clock: ')\n"
        "        print(f'        4000{index:02x} work ({dso}) /workspace/src/main.c:7')\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_empty_perf(path: Path) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version docker-empty-test')\n"
        "elif args and args[0] == 'script':\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_symfs_perf(
    path: Path,
    build_id: str,
    *,
    source_path: str = "/workspace/src/main.c",
) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        "import pathlib\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version docker-symfs-test')\n"
        "elif args[:2] == ['buildid-list', '--with-hits']:\n"
        f"    print('{build_id} /workspace/build/app')\n"
        "elif args and args[0] == 'script':\n"
        "    assert '--symfs' in args, args\n"
        "    symfs = pathlib.Path(args[args.index('--symfs') + 1])\n"
        "    assert (symfs / 'workspace/build/app').is_file(), args\n"
        "    print('app 1234/1234 [000] 1.0: 11 cpu-clock: ')\n"
        f"    print('        400010 work (/workspace/build/app) {source_path}:7')\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_buildid_perf(path: Path, build_id: str) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['buildid-list', '--with-hits']:\n"
        f"    print('{build_id} /opt/app')\n"
        "    print('malformed private diagnostic')\n"
        f"    print('{build_id} [kernel.kallsyms]')\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _module_result(build_id: str, path: str = "/opt/app") -> BuildIdListResult:
    return BuildIdListResult(
        records=(RecordedModule(build_id=build_id, container_path=path),),
        observed_record_count=1,
        records_truncated=False,
        diagnostic_count=0,
        adapter_sha256="b" * 64,
    )


def _with_analysis_content(
    analysis: AnalysisArtifact,
    **updates: object,
) -> AnalysisArtifact:
    provisional = analysis.model_copy(update={**updates, "content_sha256": "0" * 64})
    return provisional.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(provisional)}
    )


def _verified_symbol_inputs(
    fixture_root: Path,
    tmp_path: Path,
) -> tuple[
    CollectionArtifact,
    ContainerModuleSnapshotArtifact,
    AnalysisArtifact,
    Path,
]:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
    )
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "main.c").write_text("\n" * 8, encoding="utf-8")
    analysis = analyze_perf_data(
        profile,
        perf_path=_fake_perf(tmp_path / "perf"),
        collection=build_collection_evidence_provenance(collection),
    )
    return collection, snapshot, analysis, workspace


def test_container_module_snapshot_and_source_mapping_are_identity_bound(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))

    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert snapshot.status == "verified"
    assert snapshot.modules[0].status == "verified"
    assert snapshot.modules[0].observed_build_id == build_id
    serialized = snapshot.model_dump_json()
    assert "/opt/app" not in serialized
    assert str(proc_root) not in serialized

    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "main.c").write_text("\n" * 8, encoding="utf-8")
    analysis = analyze_perf_data(
        profile,
        perf_path=_fake_perf(tmp_path / "perf"),
        collection=build_collection_evidence_provenance(collection),
    )
    context = build_container_symbol_context(
        analysis,
        snapshot,
        workspace_root=workspace,
        created_at=datetime(2026, 8, 22, 0, 0, 2, tzinfo=UTC),
    )

    assert context.quality_status == "verified"
    assert context.source_mappings[0].workspace_relative_path == "src/main.c"
    assert context.source_analysis_content_sha256 == analysis.content_sha256
    assert "/workspace/src/main.c" not in context.model_dump_json()

    projected, projected_context = project_container_analysis(analysis, context)
    serialized_analysis = projected.model_dump_json()
    assert "/opt/app" not in serialized_analysis
    assert "/workspace/src/main.c" not in serialized_analysis
    assert "/run/secrets/container-token" not in serialized_analysis
    assert "src/main.c:7" in serialized_analysis
    assert "redacted-diagnostic-sha256:" in serialized_analysis
    assert "redacted-preview-sha256:" in serialized_analysis
    assert projected.metadata.input_path == "@PRIVATE_COLLECTION@"
    assert projected.metadata.conversion.converter_path == "@PRIVATE_CONVERTER@"
    assert projected.metadata.conversion.argv[0] == "@PRIVATE_CONVERTER@"
    assert projected_context.source_analysis_id == projected.analysis_id
    assert projected_context.source_analysis_content_sha256 == projected.content_sha256


def test_public_projection_recanonicalizes_redacted_hotspots_and_call_paths(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    binding = _binding(identity)
    candidates = tuple(f"/private/module-{index}" for index in range(16))
    dsos = next(
        (left, right)
        for left in candidates
        for right in candidates
        if left < right
        and docker_symbols._private_path_digest(  # pyright: ignore[reportPrivateUsage]
            binding.container_identity_sha256,
            left,
            domain="module",
        )
        > docker_symbols._private_path_digest(  # pyright: ignore[reportPrivateUsage]
            binding.container_identity_sha256,
            right,
            domain="module",
        )
    )
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, binding)
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
    )
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "main.c").write_text("\n" * 8, encoding="utf-8")
    analysis = analyze_perf_data(
        profile,
        perf_path=_fake_perf_with_dsos(tmp_path / "perf", dsos),
        collection=build_collection_evidence_provenance(collection),
    )
    assert tuple(path.frames[0].dso for path in analysis.call_paths) == dsos
    context = build_container_symbol_context(
        analysis,
        snapshot,
        workspace_root=workspace,
    )

    projected, _projected_context = project_container_analysis(analysis, context)

    assert tuple(path.path_id for path in projected.call_paths) == ("P-001", "P-002")
    assert list(projected.call_paths) == sorted(
        projected.call_paths,
        key=lambda item: (
            -item.weight,
            tuple((frame.symbol, frame.dso) for frame in item.frames),
        ),
    )
    assert tuple(hotspot.hotspot_id for hotspot in projected.hotspots) == ("H-001", "H-002")
    assert list(projected.hotspots) == sorted(
        projected.hotspots,
        key=lambda item: (
            -item.self_weight,
            -item.inclusive_weight,
            item.symbol,
            item.dso,
        ),
    )
    verify_analysis_artifact(projected, verify_source=False)


def test_pinned_container_root_survives_short_lived_proc_entry(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    binding = _binding(identity)
    proc_root = tmp_path / "proc"
    process_directory = proc_root / str(identity.host_pid)
    module = process_directory / "root" / "workspace" / "build" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, binding)

    pinned = pin_container_process_root(
        binding,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
    )
    # Model procfs retiring /proc/<pid> after a short workload exits. The open
    # descriptor remains bound to the same container root and exact module bytes.
    process_directory.rename(tmp_path / "retired-process")
    try:
        snapshot = capture_container_module_snapshot(
            collection,
            proc_root=proc_root,
            reader=cast(LinuxContainerIdentityReader, _Reader(identity, unavailable=True)),
            build_id_reader=lambda _path: _module_result(
                build_id,
                "/workspace/build/app",
            ),
            pinned_process_root=pinned,
        )
    finally:
        pinned.close()

    assert snapshot.status == "verified"
    assert snapshot.referenced_module_count == 1
    assert snapshot.modules[0].status == "verified"
    assert snapshot.modules[0].observed_build_id == build_id
    assert snapshot.process_root_identity_sha256 is not None


def test_pinned_container_workspace_survives_nested_mount_retirement(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    binding = _binding(identity)
    proc_root = tmp_path / "proc"
    process_root = proc_root / str(identity.host_pid) / "root"
    workspace = process_root / "workspace"
    module = workspace / "build" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    pinned = pin_container_process_root(
        binding,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
    )
    # Model Docker detaching the read-only /workspace bind mount after the
    # container exits.  A replacement at the same path must not be trusted;
    # the descriptor pinned while the Gate was live remains the only source.
    workspace.rename(tmp_path / "retired-workspace")
    replacement = process_root / "workspace" / "build" / "app"
    replacement_source = tmp_path / "replacement.c"
    replacement_source.write_text("int main(void) { return 7; }\n", encoding="utf-8")
    replacement_build_id = _compile_module(
        replacement,
        replacement_source,
    )
    assert replacement_build_id != build_id
    try:
        evidence, charged_bytes = pinned.inspect_module(
            RecordedModule(build_id, "/workspace/build/app"),
            container_identity_sha256=binding.container_identity_sha256,
            remaining_bytes=64 << 20,
            max_module_bytes=64 << 20,
        )
    finally:
        pinned.close()

    assert evidence.status == "verified"
    assert evidence.observed_build_id == build_id
    assert charged_bytes > 0


def test_pinned_container_root_rejects_a_different_collection_binding(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    binding = _binding(identity)
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, binding).model_copy(
        update={"container_target": binding.model_copy(update={"target_content_sha256": "f" * 64})}
    )
    pinned = pin_container_process_root(
        binding,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
    )
    try:
        with pytest.raises(PerfLensError) as raised:
            capture_container_module_snapshot(
                collection,
                proc_root=proc_root,
                build_id_reader=lambda _path: _module_result(build_id),
                pinned_process_root=pinned,
            )
    finally:
        pinned.close()

    assert raised.value.code == ErrorCode.PATH_SAFETY_VIOLATION
    assert "does not match the Collection target" in raised.value.message


def test_verified_workspace_module_is_materialized_in_private_symfs(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    workspace = tmp_path / "workspace"
    workspace_module = workspace / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    captured_module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    captured_module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, captured_module)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    module_result = _module_result(build_id, "/workspace/build/app")
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: module_result,
    )

    with materialize_container_workspace_symfs(
        collection,
        snapshot,
        workspace_root=workspace,
        build_id_reader=lambda _path: module_result,
    ) as symfs:
        assert symfs is not None
        assert symfs.module_count == 1
        copied = symfs.root / "workspace" / "build" / "app"
        assert copied.read_bytes() == workspace_module.read_bytes()
        assert stat.S_IMODE(copied.stat().st_mode) == 0o400
        assert str(symfs.root) not in symfs.identity_sha256
        private_root = symfs.root

    assert not private_root.exists()


def test_workspace_module_mismatch_degrades_without_guessing_symbols(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    workspace = tmp_path / "workspace"
    workspace_module = workspace / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    captured_module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    captured_module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, captured_module)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    module_result = _module_result(build_id, "/workspace/build/app")
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: module_result,
    )
    workspace_module.write_bytes(b"replaced after collection")

    with materialize_container_workspace_symfs(
        collection,
        snapshot,
        workspace_root=workspace,
        build_id_reader=lambda _path: module_result,
    ) as symfs:
        assert symfs is None


def test_workspace_module_copy_without_write_progress_degrades_safely(
    fixture_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    workspace = tmp_path / "workspace"
    workspace_module = workspace / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    captured_module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    captured_module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, captured_module)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    module_result = _module_result(build_id, "/workspace/build/app")
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: module_result,
    )

    def no_write_progress(_descriptor: int, _buffer: object) -> int:
        return 0

    monkeypatch.setattr(docker_symbols.os, "write", no_write_progress)

    with materialize_container_workspace_symfs(
        collection,
        snapshot,
        workspace_root=workspace,
        build_id_reader=lambda _path: module_result,
    ) as symfs:
        assert symfs is None


def test_materialized_symfs_rejects_analysis_time_mutation(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    workspace = tmp_path / "workspace"
    workspace_module = workspace / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    captured_module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    captured_module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, captured_module)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    module_result = _module_result(build_id, "/workspace/build/app")
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: module_result,
    )

    with (
        pytest.raises(PerfLensError, match="symfs module identity changed"),
        materialize_container_workspace_symfs(
            collection,
            snapshot,
            workspace_root=workspace,
            build_id_reader=lambda _path: module_result,
        ) as symfs,
    ):
        assert symfs is not None
        copied = symfs.root / "workspace" / "build" / "app"
        copied.chmod(0o600)


def test_workspace_symfs_rejects_mismatched_binding_and_unsafe_inventory(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    workspace = tmp_path / "workspace"
    workspace_module = workspace / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    captured_module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    captured_module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, captured_module)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    module_result = _module_result(build_id, "/workspace/build/app")
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: module_result,
    )

    provisional = snapshot.model_copy(
        update={"source_output_sha256": "f" * 64, "content_sha256": "0" * 64}
    )
    wrong_snapshot = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    with (
        pytest.raises(PerfLensError, match="same Docker Collection"),
        materialize_container_workspace_symfs(
            collection,
            wrong_snapshot,
            workspace_root=workspace,
            build_id_reader=lambda _path: module_result,
        ),
    ):
        pass

    conflicting = BuildIdListResult(
        records=(
            RecordedModule(build_id, "/workspace/build/app"),
            RecordedModule("f" * 40, "/workspace/build/app"),
        ),
        observed_record_count=2,
        records_truncated=False,
        diagnostic_count=0,
        adapter_sha256="b" * 64,
    )
    with materialize_container_workspace_symfs(
        collection,
        snapshot,
        workspace_root=workspace,
        build_id_reader=lambda _path: conflicting,
    ) as symfs:
        assert symfs is None

    workspace_alias = tmp_path / "workspace-alias"
    workspace_alias.symlink_to(workspace, target_is_directory=True)
    with materialize_container_workspace_symfs(
        collection,
        snapshot,
        workspace_root=workspace_alias,
        build_id_reader=lambda _path: module_result,
    ) as symfs:
        assert symfs is None


def test_materialized_symfs_rejects_added_files(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    workspace = tmp_path / "workspace"
    workspace_module = workspace / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    captured_module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    captured_module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, captured_module)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    module_result = _module_result(build_id, "/workspace/build/app")
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: module_result,
    )

    with (
        pytest.raises(PerfLensError, match="file set changed"),
        materialize_container_workspace_symfs(
            collection,
            snapshot,
            workspace_root=workspace,
            build_id_reader=lambda _path: module_result,
        ) as symfs,
    ):
        assert symfs is not None
        (symfs.root / "workspace" / "unexpected").write_bytes(b"not verified")


def test_perf_buildid_adapter_uses_fixed_recipe_and_bounds_private_records(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    build_id = "a" * 40

    result = PerfBuildIdListAdapter(
        _fake_buildid_perf(tmp_path / "perf-buildid", build_id),
    ).inspect(profile)

    assert result.records == (RecordedModule(build_id, "/opt/app"),)
    assert result.observed_record_count == 1
    assert result.diagnostic_count == 2
    assert not result.records_truncated


@pytest.mark.parametrize("failure", ["symlink", "mismatch", "limit", "target_exit"])
def test_container_module_failures_are_partial_without_path_disclosure(
    fixture_root: Path,
    tmp_path: Path,
    failure: str,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    if failure == "symlink":
        outside = tmp_path / "secret-module"
        module.replace(outside)
        module.symlink_to(outside)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    recorded_build_id = "c" * len(build_id) if failure == "mismatch" else build_id
    limits = ContainerModuleSnapshotLimits(
        max_modules=64,
        max_module_bytes=1 if failure == "limit" else 64 << 20,
        max_total_module_bytes=256 << 20,
        max_build_id_output_bytes=1 << 20,
    )

    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(
            LinuxContainerIdentityReader,
            _Reader(identity, unavailable=failure == "target_exit"),
        ),
        build_id_reader=lambda _path: _module_result(recorded_build_id),
        limits=limits,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert snapshot.status == "partial"
    assert snapshot.limitations
    if snapshot.modules:
        assert snapshot.modules[0].status != "verified"
    serialized = snapshot.model_dump_json()
    assert "/opt/app" not in serialized
    assert "secret-module" not in serialized


def test_container_module_path_replacement_is_rejected(
    fixture_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    replacement = tmp_path / "replacement-module"
    shutil.copy2(module, replacement)
    stale = tmp_path / "stale-module"
    original_hash = docker_symbols._sha256_handle  # pyright: ignore[reportPrivateUsage]
    replaced = False

    def replace_after_hash(handle: BinaryIO, *, max_bytes: int) -> tuple[str, int]:
        nonlocal replaced
        result = original_hash(handle, max_bytes=max_bytes)
        if not replaced and max_bytes > len(b"PERFILE2"):
            module.replace(stale)
            replacement.replace(module)
            replaced = True
        return result

    monkeypatch.setattr(docker_symbols, "_sha256_handle", replace_after_hash)
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")

    snapshot = capture_container_module_snapshot(
        _collection(profile, _binding(identity)),
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
    )

    assert replaced
    assert snapshot.status == "partial"
    assert snapshot.modules[0].status == "unavailable"
    assert "/opt/app" not in snapshot.model_dump_json()


def test_container_process_root_replacement_discards_captured_modules(
    fixture_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    process_root = proc_root / str(identity.host_pid) / "root"
    module = process_root / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    stale_root = process_root.with_name("root-before-replacement")
    original_build_id = docker_symbols._build_id_from_handle  # pyright: ignore[reportPrivateUsage]
    replaced = False

    def replace_root_after_build_id(handle: BinaryIO) -> str | None:
        nonlocal replaced
        result = original_build_id(handle)
        if not replaced:
            process_root.rename(stale_root)
            process_root.mkdir()
            replaced = True
        return result

    monkeypatch.setattr(
        docker_symbols,
        "_build_id_from_handle",
        replace_root_after_build_id,
    )
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")

    snapshot = capture_container_module_snapshot(
        _collection(profile, _binding(identity)),
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
    )

    assert replaced
    assert snapshot.status == "partial"
    assert snapshot.modules == ()
    assert snapshot.process_root_identity_sha256 is None
    serialized = snapshot.model_dump_json()
    assert "/opt/app" not in serialized
    assert "root-before-replacement" not in serialized


def test_container_source_escape_is_rejected_without_exposing_private_path(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    analysis = analyze_perf_data(
        profile,
        perf_path=_fake_perf(tmp_path / "perf"),
        collection=build_collection_evidence_provenance(collection),
    )
    escaped_hotspot = analysis.hotspots[0].model_copy(
        update={"source_locations": ("/run/secrets/token:7",)}
    )
    provisional = analysis.model_copy(
        update={"hotspots": (escaped_hotspot,), "content_sha256": "0" * 64}
    )
    escaped_analysis = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )

    context = build_container_symbol_context(
        escaped_analysis,
        snapshot,
        workspace_root=workspace,
    )

    assert context.quality_status == "partial"
    assert context.source_mappings[0].status == "unmapped"
    assert "/run/secrets/token" not in context.model_dump_json()


def test_container_module_contract_rejects_tampered_content(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    snapshot = capture_container_module_snapshot(
        _collection(profile, _binding(identity)),
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
    )
    tampered = json.loads(snapshot.model_dump_json())
    tampered["modules"][0]["content_sha256"] = "f" * 64

    parsed = type(snapshot).model_validate(tampered)
    assert parsed.content_sha256 != contract_content_sha256(
        parsed,
        exclude={"content_sha256"},
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    analysis = analyze_perf_data(
        profile,
        perf_path=_fake_perf(tmp_path / "perf"),
        collection=build_collection_evidence_provenance(_collection(profile, _binding(identity))),
    )
    with pytest.raises(PerfLensError) as snapshot_error:
        build_container_symbol_context(
            analysis,
            parsed,
            workspace_root=workspace,
        )
    assert snapshot_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    with pytest.raises(ValueError, match="cannot claim file evidence"):
        ContainerModuleEvidence(
            container_path_sha256="1" * 64,
            recorded_build_id="a" * 40,
            observed_build_id="a" * 40,
            status="unavailable",
        )

    partial_without_reason = snapshot.model_dump(mode="json")
    partial_without_reason["status"] = "partial"
    partial_without_reason["process_root_identity_sha256"] = None
    partial_without_reason["limitations"] = []
    partial_without_reason["content_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="requires a limitation"):
        ContainerModuleSnapshotArtifact.model_validate(partial_without_reason)


def test_projection_and_diagnosis_reject_tampered_symbol_context(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    context = build_container_symbol_context(
        analysis,
        snapshot,
        workspace_root=workspace,
    )
    projected_analysis, projected_context = project_container_analysis(analysis, context)
    tampered = projected_context.model_copy(update={"limitations": ("tampered after publication",)})

    with pytest.raises(PerfLensError) as projection_error:
        project_container_analysis(projected_analysis, tampered)
    assert projection_error.value.code is ErrorCode.PROFILE_PARSE_FAILED
    with pytest.raises(ValueError, match="content digest"):
        build_diagnosis_bundle(projected_analysis, container_symbols=tampered)


def test_symbol_artifacts_and_diagnosis_are_verified_from_one_snapshot(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    build_id = _compile_module(module, fixture_root / "symbols" / "sample.c")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(build_id),
    )
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "main.c").write_text("\n" * 8, encoding="utf-8")
    analysis = analyze_perf_data(
        profile,
        perf_path=_fake_perf(tmp_path / "perf"),
        collection=build_collection_evidence_provenance(collection),
    )
    context = build_container_symbol_context(
        analysis,
        snapshot,
        workspace_root=workspace,
    )
    with pytest.raises(PerfLensError) as private_diagnosis_error:
        build_diagnosis_bundle(analysis, container_symbols=context)
    assert private_diagnosis_error.value.code is ErrorCode.PROFILE_PARSE_FAILED
    projected_analysis, projected_context = project_container_analysis(analysis, context)
    diagnosis = build_diagnosis_bundle(
        projected_analysis,
        container_symbols=projected_context,
    )
    artifact_root = tmp_path / "artifacts"
    store = ArtifactStore(
        artifact_root,
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    store.save(collection, collection.collection_id, "collection")
    store.save(snapshot, snapshot.module_snapshot_id, "container-module-snapshot")
    store.save(projected_analysis, projected_analysis.analysis_id, "analysis")
    store.save(
        projected_context,
        projected_context.symbol_context_id,
        "container-symbol-context",
    )
    store.save(
        diagnosis,
        f"diagnosis-{projected_analysis.analysis_id}",
        "diagnosis",
    )

    assert store.load_container_module_snapshot(snapshot.module_snapshot_id) == snapshot
    assert (
        store.load_container_symbol_context(projected_context.symbol_context_id)
        == projected_context
    )
    module_page, module_next, _module_size = store.read_page(
        snapshot.module_snapshot_id,
        "container-module-snapshot",
        offset=0,
        limit=65_536,
    )
    context_page, context_next, _context_size = store.read_page(
        projected_context.symbol_context_id,
        "container-symbol-context",
        offset=0,
        limit=65_536,
    )
    assert snapshot.module_snapshot_id in module_page
    assert projected_context.symbol_context_id in context_page
    assert module_next is None
    assert context_next is None
    assert store.load_diagnosis(projected_analysis.analysis_id) == diagnosis
    assert diagnosis.container_symbol_context_content_sha256 == projected_context.content_sha256

    collection_path = artifact_root / f"{collection.collection_id}.collection.json"
    original_collection = collection_path.read_text(encoding="utf-8")
    wrong_mode = json.loads(original_collection)
    wrong_mode["mode"] = "sched"
    collection_path.write_text(json.dumps(wrong_mode), encoding="utf-8")
    with pytest.raises(PerfLensError) as mode_error:
        store.load_container_module_snapshot(snapshot.module_snapshot_id)
    assert mode_error.value.code is ErrorCode.PROFILE_PARSE_FAILED
    collection_path.write_text(original_collection, encoding="utf-8")

    context_path = artifact_root / (
        f"{projected_context.symbol_context_id}.container-symbol-context.json"
    )
    tampered = json.loads(context_path.read_text(encoding="utf-8"))
    tampered["quality_status"] = "partial"
    tampered["limitations"] = ["tampered"]
    context_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(PerfLensError) as captured:
        store.load_container_symbol_context(projected_context.symbol_context_id)
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_store_rejects_unprojected_docker_analysis_and_page(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, _snapshot, analysis, _workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    artifact_root = tmp_path / "private-analysis-artifacts"
    store = ArtifactStore(
        artifact_root,
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    store.save(analysis, analysis.analysis_id, "analysis")

    with pytest.raises(PerfLensError) as load_error:
        store.load_analysis(analysis.analysis_id)
    assert load_error.value.code is ErrorCode.PROFILE_PARSE_FAILED
    with pytest.raises(PerfLensError) as page_error:
        store.read_page(
            analysis.analysis_id,
            "analysis",
            offset=0,
            limit=1024,
        )
    assert page_error.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_mcp_docker_analysis_publishes_verified_symbol_context(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    project = tmp_path / "project"
    workspace_source = project / "src" / "main.c"
    workspace_source.parent.mkdir(parents=True)
    workspace_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    policy = project / "perflens-setup" / "container-workload.toml"
    policy.parent.mkdir()
    policy.write_text(render_default_docker_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    workspace_module = project / "build" / "app"
    build_id = _compile_module(
        workspace_module,
        fixture_root / "symbols" / "sample.c",
    )
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "workspace" / "build" / "app"
    module.parent.mkdir(parents=True)
    shutil.copyfile(workspace_module, module)
    profile = project / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result(
            build_id,
            "/workspace/build/app",
        ),
    )
    artifact_root = project / "artifacts"
    artifact_root.mkdir()
    store = ArtifactStore(artifact_root, PathPolicy((tmp_path,)), allow_writes=True)
    store.save(collection, collection.collection_id, "collection")
    store.save(snapshot, snapshot.module_snapshot_id, "container-module-snapshot")
    server = create_server(
        ServerConfig(
            allowed_roots=(tmp_path,),
            artifact_root=artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            docker_project_config=policy,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(enabled=True),
            perf_path=_fake_symfs_perf(
                tmp_path / "perf",
                build_id,
                source_path=str(workspace_source),
            ),
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            analyzed_result = await client.call_tool(
                "analyze_collection",
                {"collection_id": collection.collection_id},
            )
            assert not analyzed_result.is_error
            analyzed = cast(dict[str, object], analyzed_result.structured_content)
            summary = cast(dict[str, object], analyzed["summary"])
            assert summary["container_symbol_quality"] == "verified"
            assert summary["container_mapped_source_count"] == 1
            analysis_id = cast(str, analyzed["artifact_id"])
            context = store.load_container_symbol_context_for_analysis(analysis_id)
            assert context is not None
            assert context.source_mappings[0].workspace_relative_path == "src/main.c"
            serialized_analysis = store.load_analysis(analysis_id).model_dump_json()
            assert "/workspace/build/app" not in serialized_analysis
            assert "/workspace/src/main.c" not in serialized_analysis
            assert str(project) not in serialized_analysis
            assert "/run/secrets/container-token" not in serialized_analysis
            assert "src/main.c:7" in serialized_analysis
            saved_analysis = store.load_analysis(analysis_id)
            assert any(
                item.startswith("verified_container_symfs_sha256:")
                for item in saved_analysis.metadata.conversion.compatibility_fallbacks
            )
            assert all(
                "perflens-container-symfs-" not in item
                for item in saved_analysis.metadata.conversion.argv
            )

            diagnosis_result = await client.call_tool(
                "build_diagnosis_bundle",
                {"analysis_id": analysis_id},
            )
            assert not diagnosis_result.is_error
            diagnosis = store.load_diagnosis(analysis_id)
            assert diagnosis is not None
            assert diagnosis.container_symbol_context_id == context.symbol_context_id
            assert diagnosis.container_symbol_context_content_sha256 == context.content_sha256
            assert all(
                "not independently verified" not in limitation
                for limitation in diagnosis.limitations
            )

    asyncio.run(exercise())


def test_mcp_docker_analysis_publishes_empty_record_as_partial(
    tmp_path: Path,
) -> None:
    identity = _identity()
    project = tmp_path / "project"
    project.mkdir()
    policy = project / "perflens-setup" / "container-workload.toml"
    policy.parent.mkdir()
    policy.write_text(render_default_docker_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    profile = project / "profile.data"
    profile.write_bytes(b"PERFILE2-empty-record")
    collection = _collection(profile, _binding(identity))
    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=tmp_path / "missing-proc",
        reader=cast(LinuxContainerIdentityReader, _Reader(identity, unavailable=True)),
        build_id_reader=lambda _path: BuildIdListResult(
            records=(),
            observed_record_count=0,
            records_truncated=False,
            diagnostic_count=0,
            adapter_sha256="b" * 64,
        ),
    )
    assert snapshot.status == "partial"
    artifact_root = project / "artifacts"
    artifact_root.mkdir()
    store = ArtifactStore(artifact_root, PathPolicy((tmp_path,)), allow_writes=True)
    store.save(collection, collection.collection_id, "collection")
    store.save(snapshot, snapshot.module_snapshot_id, "container-module-snapshot")
    server = create_server(
        ServerConfig(
            allowed_roots=(tmp_path,),
            artifact_root=artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            docker_project_config=policy,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(enabled=True),
            perf_path=_fake_empty_perf(tmp_path / "perf-empty"),
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            analyzed_result = await client.call_tool(
                "analyze_collection",
                {"collection_id": collection.collection_id},
            )
            assert not analyzed_result.is_error
            analyzed = cast(dict[str, object], analyzed_result.structured_content)
            summary = cast(dict[str, object], analyzed["summary"])
            assert summary["status"] == "partial"
            assert summary["quality_status"] == "partial"
            assert summary["sample_count"] == 0
            assert summary["hotspot_count"] == 0
            assert summary["container_symbol_quality"] == "partial"
            analysis_id = cast(str, analyzed["artifact_id"])
            analysis = store.load_analysis(analysis_id)
            assert analysis.metadata.event == "unknown"
            assert analysis.metadata.weight_source == "sample_count_fallback"
            assert analysis.evidence_quality.allowed_conclusions == ()
            assert "The profile contains no usable weighted samples." in (
                analysis.evidence_quality.limitations
            )
            context = store.load_container_symbol_context_for_analysis(analysis_id)
            assert context is not None
            assert context.quality_status == "partial"

            tampered_quality = analysis.evidence_quality.model_copy(update={"event": "cpu-clock"})
            tampered_metadata = analysis.metadata.model_copy(update={"event": "cpu-clock"})
            tampered = _with_analysis_content(
                analysis,
                evidence_quality=tampered_quality,
                metadata=tampered_metadata,
            )
            with pytest.raises(PerfLensError) as event_error:
                verify_analysis_artifact(tampered, verify_source=False)
            assert event_error.value.details["failure"] == (
                "empty profile claims an observed source Collection event"
            )

    asyncio.run(exercise())


def test_perf_buildid_adapter_rejects_invalid_tool_and_limits(tmp_path: Path) -> None:
    missing = tmp_path / "missing-perf"
    with pytest.raises(PerfLensError) as missing_error:
        PerfBuildIdListAdapter(missing)
    assert missing_error.value.code is ErrorCode.INVALID_INPUT

    executable = _fake_buildid_perf(tmp_path / "perf", "a" * 40)
    with pytest.raises(PerfLensError) as limits_error:
        PerfBuildIdListAdapter(executable, timeout_seconds=0)
    assert limits_error.value.code is ErrorCode.INVALID_INPUT


def test_perf_buildid_adapter_rejects_non_utf8_and_tool_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    invalid = tmp_path / "perf-invalid"
    invalid.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.buffer.write(b'\\xff')\n",
        encoding="utf-8",
    )
    invalid.chmod(invalid.stat().st_mode | stat.S_IXUSR)
    with pytest.raises(PerfLensError) as utf8_error:
        PerfBuildIdListAdapter(invalid).inspect(profile)
    assert utf8_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    executable = _fake_buildid_perf(tmp_path / "perf-changing", "b" * 40)
    original_sha256_path = docker_symbols._sha256_path  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def changing_identity(path: Path) -> tuple[str, int]:
        nonlocal calls
        calls += 1
        digest, size = original_sha256_path(path)
        return (("f" * 64) if calls > 1 else digest), size

    monkeypatch.setattr(docker_symbols, "_sha256_path", changing_identity)
    with pytest.raises(PerfLensError) as replacement_error:
        PerfBuildIdListAdapter(executable).inspect(profile)
    assert replacement_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_perf_buildid_adapter_bounds_lines_and_discards_unsafe_paths(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    executable = tmp_path / "perf-many-lines"
    executable.write_text(
        f"#!{sys.executable}\n"
        "print()\n"
        "print('x' * 9000)\n"
        "for index in range(4097):\n"
        "    print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa /opt/m' + str(index))\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)

    result = PerfBuildIdListAdapter(executable).inspect(profile)

    assert result.records_truncated
    assert result.diagnostic_count == 2
    assert 0 < result.observed_record_count < 4097
    assert all(item.container_path.startswith("/opt/m") for item in result.records)


def test_snapshot_reports_inventory_truncation_without_fabricating_count(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    root = proc_root / str(identity.host_pid) / "root"
    app_id = _compile_module(root / "opt" / "app", fixture_root / "symbols" / "sample.c")
    other_id = _compile_module(
        root / "opt" / "other",
        fixture_root / "symbols" / "sample.c",
    )
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    result = BuildIdListResult(
        records=(
            RecordedModule(app_id, "/opt/app"),
            RecordedModule("c" * len(app_id), "/opt/app"),
            RecordedModule(other_id, "/opt/other"),
        ),
        observed_record_count=3,
        records_truncated=True,
        diagnostic_count=1,
        adapter_sha256="b" * 64,
    )

    snapshot = capture_container_module_snapshot(
        _collection(profile, _binding(identity)),
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: result,
    )

    assert snapshot.status == "partial"
    assert snapshot.referenced_module_count == 2
    assert len(snapshot.modules) == 2
    assert snapshot.modules_truncated
    assert any("conflicting" in item for item in snapshot.limitations)
    assert any("truncated" in item for item in snapshot.limitations)


@pytest.mark.parametrize("module_kind", ["non_elf", "directory"])
def test_snapshot_does_not_guess_non_elf_or_non_regular_modules(
    tmp_path: Path,
    module_kind: str,
) -> None:
    identity = _identity()
    proc_root = tmp_path / "proc"
    module = proc_root / str(identity.host_pid) / "root" / "opt" / "app"
    module.parent.mkdir(parents=True)
    if module_kind == "directory":
        module.mkdir()
    else:
        module.write_bytes(b"not-an-elf")
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")

    snapshot = capture_container_module_snapshot(
        _collection(profile, _binding(identity)),
        proc_root=proc_root,
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result("a" * 40),
    )

    assert snapshot.status == "partial"
    assert snapshot.modules[0].status == "unavailable"
    assert snapshot.modules[0].observed_build_id is None


def test_snapshot_rejects_wrong_collection_naive_time_and_missing_procfs(
    tmp_path: Path,
) -> None:
    identity = _identity()
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    host_collection = collection.model_copy(
        update={"target_runtime": "host", "container_target": None}
    )
    with pytest.raises(PerfLensError) as target_error:
        capture_container_module_snapshot(host_collection)
    assert target_error.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(PerfLensError) as time_error:
        capture_container_module_snapshot(
            collection,
            created_at=datetime(2026, 8, 22),
        )
    assert time_error.value.code is ErrorCode.INVALID_INPUT

    snapshot = capture_container_module_snapshot(
        collection,
        proc_root=tmp_path / "missing-proc",
        reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
        build_id_reader=lambda _path: _module_result("a" * 40),
    )
    assert snapshot.status == "partial"
    assert snapshot.process_root_identity_sha256 is None


def test_snapshot_rejects_replaced_raw_profile_before_module_inspection(
    tmp_path: Path,
) -> None:
    identity = _identity()
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    profile.write_bytes(b"REPLACED")
    inspected = False

    def inspect(_path: Path) -> BuildIdListResult:
        nonlocal inspected
        inspected = True
        return _module_result("a" * 40)

    with pytest.raises(PerfLensError) as error:
        capture_container_module_snapshot(
            collection,
            proc_root=tmp_path / "proc",
            reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
            build_id_reader=inspect,
        )

    assert error.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert not inspected


def test_snapshot_rejects_profile_path_replacement_during_module_inspection(
    tmp_path: Path,
) -> None:
    identity = _identity()
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))
    inspected_private_snapshot = False

    def inspect(snapshot_path: Path) -> BuildIdListResult:
        nonlocal inspected_private_snapshot
        inspected_private_snapshot = snapshot_path != profile
        assert snapshot_path.read_bytes() == b"PERFILE2"
        replacement = tmp_path / "replacement.data"
        replacement.write_bytes(b"PERFILE2")
        replacement.replace(profile)
        return _module_result("a" * 40)

    with pytest.raises(PerfLensError) as error:
        capture_container_module_snapshot(
            collection,
            proc_root=tmp_path / "proc",
            reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
            build_id_reader=inspect,
        )

    assert inspected_private_snapshot
    assert error.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_snapshot_rejects_private_profile_mutation_during_module_inspection(
    tmp_path: Path,
) -> None:
    identity = _identity()
    profile = tmp_path / "profile.data"
    profile.write_bytes(b"PERFILE2")
    collection = _collection(profile, _binding(identity))

    def inspect(snapshot_path: Path) -> BuildIdListResult:
        snapshot_path.write_bytes(b"CHANGED!")
        return _module_result("a" * 40)

    with pytest.raises(PerfLensError) as error:
        capture_container_module_snapshot(
            collection,
            proc_root=tmp_path / "proc",
            reader=cast(LinuxContainerIdentityReader, _Reader(identity)),
            build_id_reader=inspect,
        )

    assert error.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_public_projection_rejects_malformed_redaction_payloads(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    context = build_container_symbol_context(
        analysis,
        snapshot,
        workspace_root=workspace,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    projected, _projected_context = project_container_analysis(analysis, context)
    malformed_conversion = projected.metadata.conversion.model_copy(
        update={"diagnostics": ("redacted-diagnostic-sha256:/run/secrets/token",)}
    )
    malformed_metadata = projected.metadata.model_copy(update={"conversion": malformed_conversion})

    with pytest.raises(PerfLensError) as diagnostic_error:
        docker_symbols.assert_public_container_analysis(
            projected.model_copy(update={"metadata": malformed_metadata})
        )
    assert diagnostic_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    malformed_warning = projected.warnings[0].model_copy(
        update={"preview": "redacted-preview-sha256:not-a-digest"}
    )
    with pytest.raises(PerfLensError) as preview_error:
        docker_symbols.assert_public_container_analysis(
            projected.model_copy(update={"warnings": (malformed_warning,)})
        )
    assert preview_error.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_symbol_context_rejects_mismatch_and_unsafe_workspace(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    mismatched = snapshot.model_copy(update={"source_collection_id": "collection-" + "2" * 16})
    with pytest.raises(PerfLensError) as mismatch_error:
        build_container_symbol_context(analysis, mismatched, workspace_root=workspace)
    assert mismatch_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    wrong_target_digest = snapshot.model_copy(update={"container_target_content_sha256": "e" * 64})
    with pytest.raises(PerfLensError) as target_digest_error:
        build_container_symbol_context(
            analysis,
            wrong_target_digest,
            workspace_root=workspace,
        )
    assert target_digest_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    with pytest.raises(PerfLensError) as missing_error:
        build_container_symbol_context(
            analysis,
            snapshot,
            workspace_root=tmp_path / "missing-workspace",
        )
    assert missing_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    not_directory = tmp_path / "workspace-file"
    not_directory.write_text("not a directory", encoding="utf-8")
    with pytest.raises(PerfLensError) as directory_error:
        build_container_symbol_context(
            analysis,
            snapshot,
            workspace_root=not_directory,
        )
    assert directory_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as time_error:
        build_container_symbol_context(
            analysis,
            snapshot,
            workspace_root=workspace,
            created_at=datetime(2026, 8, 22),
        )
    assert time_error.value.code is ErrorCode.INVALID_INPUT


def test_python_source_without_line_is_mapped_and_raw_variant_is_redacted(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    source = workspace / "src" / "workload.py"
    source.write_text("def work():\n    pass\n", encoding="utf-8")
    hotspot = analysis.hotspots[0].model_copy(
        update={
            "symbol": "py::work",
            "symbol_variants": (
                "py::work:/workspace/src/workload.py",
                "opaque /run/secrets/container-token:1",
                r"opaque C:\container\secret.py",
            ),
            "symbol_variant_count": 3,
            "normalization_merged": True,
            "source_locations": (),
        }
    )
    call_path = analysis.call_paths[0].model_copy(
        update={
            "frames": tuple(
                frame.model_copy(
                    update={
                        "symbol": "py::work",
                        "symbol_variant_count": 3,
                        "normalization_merged": True,
                    }
                )
                for frame in analysis.call_paths[0].frames
            )
        }
    )
    python_quality = analysis.evidence_quality.model_copy(
        update={
            "normalization_merge_count": 1,
            "forbidden_conclusions": tuple(
                dict.fromkeys(
                    (
                        *analysis.evidence_quality.forbidden_conclusions,
                        "unique_machine_code_identity_from_normalized_symbol",
                    )
                )
            ),
        }
    )
    python_analysis = _with_analysis_content(
        analysis,
        hotspots=(hotspot,),
        call_paths=(call_path,),
        evidence_quality=python_quality,
    )
    context = build_container_symbol_context(
        python_analysis,
        snapshot,
        workspace_root=workspace,
    )

    assert context.source_mappings[0].line is None
    assert context.source_location_count == 1
    assert context.source_mappings[0].workspace_relative_path == "src/workload.py"
    projected, _projected_context = project_container_analysis(python_analysis, context)
    serialized = projected.model_dump_json()
    assert "/workspace/src/workload.py" not in serialized
    assert "/run/secrets/container-token" not in serialized
    assert r"C:\container\secret.py" not in serialized
    assert "py::work:src/workload.py" in serialized
    assert "redacted-symbol-variant-sha256:" in serialized
    assert all(
        "container-token" not in item and "secret.py" not in item
        for item in projected.hotspots[0].symbol_variants
    )


def test_source_mapping_preserves_upstream_truncation_and_rejects_symlink_escape(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.c").write_text("secret", encoding="utf-8")
    (workspace / "link").symlink_to(outside, target_is_directory=True)
    hotspot = analysis.hotspots[0].model_copy(
        update={
            "source_locations": ("/workspace/link/secret.c:1",),
            "source_locations_truncated": True,
        }
    )
    evidence_quality = analysis.evidence_quality.model_copy(
        update={
            "source_locations_truncated_hotspot_count": 1,
            "forbidden_conclusions": tuple(
                dict.fromkeys(
                    (
                        *analysis.evidence_quality.forbidden_conclusions,
                        "complete_source_location_distribution",
                    )
                )
            ),
        }
    )
    escaped_analysis = _with_analysis_content(
        analysis,
        hotspots=(hotspot,),
        evidence_quality=evidence_quality,
    )

    context = build_container_symbol_context(
        escaped_analysis,
        snapshot,
        workspace_root=workspace,
    )

    assert context.quality_status == "partial"
    assert context.source_mappings_truncated
    assert context.source_location_count == len(context.source_mappings) == 1
    assert context.source_mappings[0].status == "rejected"
    assert str(outside) not in context.model_dump_json()


def test_projection_rejects_wrong_context_and_digests_unmapped_source(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    hotspot = analysis.hotspots[0].model_copy(
        update={"source_locations": ("/run/secrets/token:7", "not-a-source")}
    )
    private_analysis = _with_analysis_content(analysis, hotspots=(hotspot,))
    context = build_container_symbol_context(
        private_analysis,
        snapshot,
        workspace_root=workspace,
    )
    wrong_context = context.model_copy(update={"source_analysis_content_sha256": "f" * 64})
    with pytest.raises(PerfLensError) as mismatch_error:
        project_container_analysis(private_analysis, wrong_context)
    assert mismatch_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    wrong_collection = context.model_copy(update={"source_collection_id": "collection-" + "9" * 16})
    with pytest.raises(PerfLensError) as collection_error:
        project_container_analysis(private_analysis, wrong_collection)
    assert collection_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    projected, _projected_context = project_container_analysis(private_analysis, context)
    serialized = projected.model_dump_json()
    assert "/run/secrets/token" not in serialized
    assert "not-a-source" not in serialized
    assert "container-source-sha256:" in serialized


def test_missing_authorized_workspace_yields_private_partial_projection(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, _workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )

    context = build_container_symbol_context(
        analysis,
        snapshot,
        workspace_root=None,
    )
    projected, _projected_context = project_container_analysis(analysis, context)

    assert context.quality_status == "partial"
    assert context.source_mappings[0].status == "unavailable"
    assert context.source_mappings[0].workspace_relative_path is None
    serialized = projected.model_dump_json()
    assert "/workspace/src/main.c" not in serialized
    assert "container-source-sha256:" in serialized


def test_projection_redacts_path_bearing_symbols_and_relationships(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    _collection_artifact, snapshot, analysis, workspace = _verified_symbol_inputs(
        fixture_root,
        tmp_path,
    )
    private_symbol = "work /run/secrets/private-symbol"
    hotspot = analysis.hotspots[0].model_copy(
        update={
            "symbol": private_symbol,
            "symbol_variants": (private_symbol,),
            "top_callers": (private_symbol,),
            "top_callees": (private_symbol,),
        }
    )
    call_path = analysis.call_paths[0].model_copy(
        update={
            "frames": tuple(
                frame.model_copy(update={"symbol": private_symbol})
                for frame in analysis.call_paths[0].frames
            )
        }
    )
    private_analysis = _with_analysis_content(
        analysis,
        hotspots=(hotspot,),
        call_paths=(call_path,),
    )
    context = build_container_symbol_context(
        private_analysis,
        snapshot,
        workspace_root=workspace,
    )

    projected, _projected_context = project_container_analysis(private_analysis, context)

    assert private_symbol not in projected.model_dump_json()
    assert projected.hotspots[0].symbol.startswith("container-symbol-sha256:")
    assert projected.hotspots[0].symbol == projected.call_paths[0].frames[0].symbol
    assert projected.hotspots[0].top_callers == (projected.hotspots[0].symbol,)
    assert projected.hotspots[0].top_callees == (projected.hotspots[0].symbol,)


def test_hashing_and_perf_discovery_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(PerfLensError) as growth_error:
        docker_symbols._sha256_handle(  # pyright: ignore[reportPrivateUsage]
            io.BytesIO(b"too large"),
            max_bytes=1,
        )
    assert growth_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    def missing_tool(_name: str) -> None:
        return None

    monkeypatch.setattr(docker_symbols.shutil, "which", missing_tool)
    with pytest.raises(PerfLensError) as discovery_error:
        PerfBuildIdListAdapter()
    assert discovery_error.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
