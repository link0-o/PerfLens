# pyright: reportPrivateUsage=false
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from mcp.client import Client

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockRunArtifact,
    derive_runtime_lock_run_finalization_id,
)
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp import server as server_module
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.native_launcher import (
    NativeLaunchCapability,
    NativeLaunchRequest,
    NativeLaunchResult,
    NativePthreadLauncher,
    NativePthreadTargetIdentity,
)
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)

_FIXTURE = Path(__file__).parents[1] / "fixtures/runtime_locks/native-pthread-exact.ndjson"
type _Behavior = Literal[
    "success",
    "short_tid",
    "identity_mismatch",
    "malformed",
    "timeout",
    "outside_stream",
]


def _structured(result: object) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    return cast(dict[str, Any], structured)


class _FakeNativeLauncher:
    def __init__(
        self,
        project_root: Path,
        private_root: Path,
        *,
        behavior: _Behavior = "success",
    ) -> None:
        self.project_root = project_root
        self.private_root = private_root
        self.behavior = behavior
        self.launch_count = 0
        self.requests: list[NativeLaunchRequest] = []

    def inspect_target(self, executable: Path) -> NativePthreadTargetIdentity:
        payload = executable.read_bytes()
        metadata = executable.stat(follow_symlinks=False)
        digest = hashlib.sha256(payload).hexdigest()
        identity = hashlib.sha256(
            "\0".join(
                (
                    "test-native-target-v1",
                    executable.relative_to(self.project_root).as_posix(),
                    digest,
                    str(metadata.st_dev),
                    str(metadata.st_ino),
                )
            ).encode()
        ).hexdigest()
        return NativePthreadTargetIdentity(
            path=executable,
            project_relative_path=executable.relative_to(self.project_root).as_posix(),
            identity_sha256=identity,
            binary_sha256=digest,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            mode=metadata.st_mode & 0o7777,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
            interpreter="/lib64/ld-linux-x86-64.so.2",
            runtime_glibc_version="2.41",
            required_glibc_versions=("2.2.5",),
            visible_lock_surfaces=("condition", "mutex", "rwlock_read"),
        )

    def capability(self, executable: Path) -> NativeLaunchCapability:
        target = self.inspect_target(executable)
        return _native_capability(target_identity_sha256=target.identity_sha256)

    def launch(
        self,
        executable: Path,
        request: NativeLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> NativeLaunchResult:
        target = self.inspect_target(executable)
        assert target.identity_sha256 == expected_target_identity_sha256
        self.launch_count += 1
        self.requests.append(request)
        target_pid = 4242
        worker_tid = 4243
        start_ticks = 77
        raw = _native_stream(
            target_pid=target_pid,
            worker_tid=worker_tid,
            target_uid=os.geteuid(),
            target_start_ticks=(78 if self.behavior == "identity_mismatch" else start_ticks),
            semantics=request.semantics,
            threshold_ns=request.threshold_ns,
            max_events=request.max_events,
        )
        if self.behavior == "malformed":
            raw = b'{"schema_version":"1.0","record_type":"probe_header"}\nnot-json\n'
        name = f"native-pthread-{self.launch_count:020x}.ndjson"
        stream_root = self.project_root if self.behavior == "outside_stream" else self.private_root
        stream_path = stream_root / name
        stream_path.write_bytes(raw)
        stream_path.chmod(0o600)
        started = datetime.now(tz=UTC)
        finished = started + timedelta(milliseconds=200)
        return NativeLaunchResult(
            stream_path=stream_path,
            stream_sha256=hashlib.sha256(raw).hexdigest(),
            stream_size=len(raw),
            target_identity_sha256=target.identity_sha256,
            target_pid=target_pid,
            target_uid=os.geteuid(),
            target_start_ticks=start_ticks,
            observed_tids=(
                (target_pid,) if self.behavior == "short_tid" else (target_pid, worker_tid)
            ),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=0.2,
            accounted_active_seconds=1,
            exit_code=(-15 if self.behavior == "timeout" else 0),
            termination_reason=("duration_limit" if self.behavior == "timeout" else "exited"),
            footer_observed=True,
            declared_event_count=10,
            lost_event_count=0,
            truncated=False,
        )


def _native_capability(*, target_identity_sha256: str | None = None) -> NativeLaunchCapability:
    return NativeLaunchCapability(
        target_scope="host_launched_workload",
        launch_backend="host_launcher",
        availability="available",
        target_identity_sha256=target_identity_sha256,
        target_label="workload",
        probe_sha256="2" * 64,
        runtime_glibc_version="2.41",
        supported_semantics=("exact", "thresholded"),
        supported_lock_surfaces=("condition", "mutex", "rwlock_read", "rwlock_write"),
        limitations=("Test capability accepts only one reviewed workload.",),
    )


def _native_stream(
    *,
    target_pid: int,
    worker_tid: int,
    target_uid: int,
    target_start_ticks: int,
    semantics: Literal["exact", "thresholded"],
    threshold_ns: int | None,
    max_events: int,
) -> bytes:
    records = [json.loads(line) for line in _FIXTURE.read_text(encoding="utf-8").splitlines()]
    header = records[0]
    header.update(
        {
            "pid": target_pid,
            "uid": target_uid,
            "target_start_time_ticks": target_start_ticks,
            "observed_target_tids": [target_pid, worker_tid],
            "semantics": semantics,
            "duration_threshold_ns": threshold_ns,
            "max_events": max_events,
            "fast_path_visibility": "complete" if semantics == "exact" else "partial",
        }
    )
    for record in records[1:]:
        if record["record_type"] != "probe_event":
            continue
        record["pid"] = target_pid
        record["tid"] = worker_tid
        if semantics == "thresholded":
            record["timestamp_ns"] *= 1000
            if record["duration_ns"] is not None:
                record["duration_ns"] *= 1000
            if record["hold_duration_ns"] is not None:
                record["hold_duration_ns"] *= 1000
    return b"".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for record in records
    )


def _server(
    tmp_path: Path,
    *,
    behavior: _Behavior = "success",
    docker_enabled: bool = False,
) -> tuple[object, Path, Path, list[_FakeNativeLauncher]]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    workload = project / "workload"
    workload.write_bytes(b"reviewed native workload\n")
    workload.chmod(0o755)
    setup = project / "perflens-setup"
    setup.mkdir()
    policy_path = setup / "runtime-locks.toml"
    policy_path.write_text(
        render_default_runtime_lock_project_policy(docker_enabled=docker_enabled),
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    artifacts = project / "artifacts"
    artifacts.mkdir()
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(project,))
    project_identity = inspect_managed_project_root(project).identity_sha256
    capability = inspect_runtime_lock_capability(
        policy,
        project_identity_sha256=project_identity,
        native_pthread_capability=_native_capability(),
    )
    launchers: list[_FakeNativeLauncher] = []

    def launcher_factory(project_root: Path, private_root: Path) -> NativePthreadLauncher:
        launcher = _FakeNativeLauncher(project_root, private_root, behavior=behavior)
        launchers.append(launcher)
        return cast(NativePthreadLauncher, launcher)

    server = create_server(
        ServerConfig(
            allowed_roots=(project,),
            artifact_root=artifacts,
            allow_writes=True,
            allow_process_execution=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy_path,
            runtime_lock_capability_factory=lambda: capability,
            runtime_lock_native_launcher_factory=launcher_factory,
        )
    )
    return server, project, artifacts, launchers


@pytest.mark.parametrize(
    "target_scope",
    ("managed_temporary_container", "docker_optimization"),
)
def test_native_docker_preview_is_rejected_before_authorization(
    tmp_path: Path,
    target_scope: str,
) -> None:
    server, _project, artifacts, launchers = _server(tmp_path, docker_enabled=True)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            rejected = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": target_scope,
                    "allowed_adapters": ["native_pthread"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert rejected.is_error
            assert "parent Docker Preview" in str(rejected.content)
            assert not list(artifacts.glob("*.runtime-lock-preview.json"))

            controlled_import = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "controlled_import",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert not controlled_import.is_error, controlled_import.content
            assert _structured(controlled_import)["target_scope"] == "controlled_import"

    asyncio.run(exercise())
    assert launchers == []


async def _authorize_host_session(
    client: Client,
    *,
    semantics: tuple[str, ...] = ("exact",),
) -> tuple[dict[str, Any], dict[str, Any]]:
    previewed = await client.call_tool(
        "preview_runtime_lock_session",
        {
            "target_scope": "host_launched_workload",
            "allowed_adapters": ["native_pthread"],
            "allowed_semantics": list(semantics),
            "executable": "workload",
            "arguments": ["--reviewed", "42"],
        },
    )
    assert not previewed.is_error, previewed.content
    preview = _structured(previewed)
    authorized = await client.call_tool(
        "authorize_runtime_lock_session",
        {
            "preview_id": preview["preview_id"],
            "preview_content_sha256": preview["content_sha256"],
            "authorization_summary_sha256": preview["authorization_summary_sha256"],
            "authorization": "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION",
        },
    )
    assert not authorized.is_error, authorized.content
    return preview, _structured(authorized)


def test_native_host_preview_collects_converts_verifies_and_cleans_private_stream(
    tmp_path: Path,
) -> None:
    server, project, artifacts, launchers = _server(tmp_path)
    run_id = ""
    execution_identity = ""
    finalization_id = ""
    finalization_content_sha256 = ""
    settled_session_artifact_id = ""

    async def exercise() -> None:
        nonlocal execution_identity, finalization_content_sha256, finalization_id
        nonlocal run_id, settled_session_artifact_id
        async with Client(cast(Any, server)) as client:
            preview, session = await _authorize_host_session(client)
            assert any("cooperatively" in item for item in preview["warnings"])
            assert any("not tamper-proof" in item for item in preview["warnings"])
            assert len(preview["adapter_execution_bindings"]) == 1
            execution_binding = preview["adapter_execution_bindings"][0]
            execution_identity = cast(str, execution_binding["execution_identity_sha256"])
            assert execution_binding["adapter_id"] == "native_pthread"
            assert execution_binding["runtime_version"] == "glibc-2.41"
            assert execution_binding["profile"] == "exact"
            assert execution_binding["runtime_payload_identity_sha256"] == "2" * 64
            assert preview["workload"] == {
                "adapter_id": "native_pthread",
                "workload_kind": "native_elf",
                "program": "workload",
                "program_sha256": hashlib.sha256(b"reviewed native workload\n").hexdigest(),
                "program_size": len(b"reviewed native workload\n"),
                "working_directory": ".",
                "arguments": ["--reviewed", "42"],
                "workload_identity_sha256": preview["workload"]["workload_identity_sha256"],
            }
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            reference = _structured(collected)
            run_id = cast(str, reference["artifact_id"])
            finalization_id = cast(str, reference["summary"]["runtime_lock_run_finalization_id"])
            finalization_content_sha256 = cast(
                str,
                reference["summary"]["runtime_lock_run_finalization_content_sha256"],
            )
            settled_session_artifact_id = cast(
                str, reference["summary"]["settled_session_artifact_id"]
            )
            assert reference["artifact_type"] == "runtime-lock-run"
            assert reference["summary"]["private_source_replay_status"] == "passed"
            assert reference["summary"]["event_count"] == 10
            assert reference["summary"]["target_pid"] == 4242
            assert reference["summary"]["session_state"] == "active"
            assert reference["summary"]["settled_session_revision"] == 2
            assert launchers[0].requests == [
                NativeLaunchRequest(
                    arguments=("--reviewed", "42"),
                    semantics="exact",
                    threshold_ns=None,
                    duration_seconds=3,
                    max_events=20,
                )
            ]
            private_root = launchers[0].private_root
            assert list(private_root.iterdir()) == []

            finalization_page = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": finalization_id,
                    "artifact_type": "runtime-lock-run-finalization",
                },
            )
            assert not finalization_page.is_error, finalization_page.content
            finalization_payload = json.loads(cast(str, _structured(finalization_page)["text"]))
            assert finalization_payload["content_sha256"] == finalization_content_sha256
            assert finalization_payload["run_id"] == run_id
            assert finalization_payload["final_session_artifact_id"] == (
                settled_session_artifact_id
            )
            assert finalization_payload["outcome"] == "completed"

            revoked = await client.call_tool(
                "revoke_runtime_lock_session",
                {"session_id": session["session_id"]},
            )
            assert not revoked.is_error, revoked.content
            terminal_session = _structured(revoked)
            assert terminal_session["state"] == "revoked"
            assert terminal_session["revision"] == 3
            assert terminal_session["settlement_finalization_id"] is None

            finalization_after_revoke = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": finalization_id,
                    "artifact_type": "runtime-lock-run-finalization",
                },
            )
            assert not finalization_after_revoke.is_error, finalization_after_revoke.content
            assert (
                json.loads(cast(str, _structured(finalization_after_revoke)["text"]))
                == finalization_payload
            )

    asyncio.run(exercise())
    assert len(list(artifacts.glob("*.runtime-lock-evidence.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-analysis.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-verification.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-run.json"))) == 1
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    loaded = store.load_runtime_lock_run(run_id)
    assert loaded.workload_identity_sha256
    assert loaded.adapter_execution_identity_sha256 == execution_identity
    assert loaded.quality_status == "partial"
    evidence = store.load_runtime_lock_evidence(loaded.runtime_lock_evidence_id)
    assert evidence.source.adapter_id == "native_pthread"
    assert evidence.source.adapter_execution_identity_sha256 == execution_identity
    verification = store.load_runtime_lock_verification(loaded.runtime_lock_verification_id)
    assert verification.verification_status == "verified"
    assert verification.source_replay_receipt is not None
    started = datetime.fromisoformat(loaded.started_at)
    finished = datetime.fromisoformat(loaded.finished_at)
    assert loaded.created_at == loaded.finished_at
    assert loaded.duration_seconds == math.ceil((finished - started).total_seconds()) == 1
    assert finalization_id == derive_runtime_lock_run_finalization_id(
        loaded.session_id,
        loaded.operation_identity_sha256,
    )
    finalization = store.load_runtime_lock_run_finalization(finalization_id)
    assert finalization.content_sha256 == finalization_content_sha256
    assert finalization.final_session_artifact_id == settled_session_artifact_id
    assert finalization.accounted_active_seconds == loaded.duration_seconds
    settled_session = store.load_runtime_lock_session(finalization.final_session_artifact_id)
    assert settled_session.active_seconds_used == loaded.duration_seconds
    assert settled_session.settlement_finalization_id == finalization.finalization_id
    assert any(
        warning.startswith("Native launch coverage is partial:") for warning in loaded.warnings
    )

    run_path = artifacts / f"{run_id}.runtime-lock-run.json"
    payload = json.loads(run_path.read_text(encoding="utf-8"))
    forged = RuntimeLockRunArtifact.model_validate(
        {**payload, "workload_identity_sha256": "f" * 64, "content_sha256": "0" * 64}
    )
    forged = forged.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                forged,
                exclude={"content_sha256"},
            )
        }
    )
    run_path.write_text(forged.model_dump_json(), encoding="utf-8")
    run_path.chmod(0o600)
    with pytest.raises(
        PerfLensError,
        match=r"identifier does not match|identity or verification chain",
    ):
        store.load_runtime_lock_run(run_id)


def test_native_thresholded_collection_uses_only_policy_threshold(tmp_path: Path) -> None:
    server, _project, _artifacts, launchers = _server(tmp_path)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_host_session(
                client,
                semantics=("thresholded",),
            )
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 30,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            assert launchers[0].requests[0].threshold_ns == 1000

    asyncio.run(exercise())


def test_native_persisted_run_rejects_promoted_quality_boundary_tampering(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _launchers = _server(tmp_path)
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_host_session(client)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            run_id = cast(str, _structured(collected)["artifact_id"])

    asyncio.run(exercise())
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    run = store.load_runtime_lock_run(run_id)
    analysis, _evidence, _verification = store.load_runtime_lock_analysis(
        run.runtime_lock_analysis_id
    )
    assert analysis.quality_status == "complete"
    assert run.quality_status == "partial"
    finalization_id = derive_runtime_lock_run_finalization_id(
        run.session_id,
        run.operation_identity_sha256,
    )
    finalization = store.load_runtime_lock_run_finalization(finalization_id)
    provisional = run.model_copy(
        update={
            "quality_status": "complete",
            "forbidden_conclusions": tuple(
                item
                for item in run.forbidden_conclusions
                if item != "unqualified_runtime_lock_conclusion"
            ),
            "content_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    run_path = artifacts / f"{run_id}.runtime-lock-run.json"
    run_path.write_text(forged.model_dump_json(), encoding="utf-8")
    run_path.chmod(0o600)
    provisional_marker = finalization.model_copy(
        update={"run_content_sha256": forged.content_sha256, "content_sha256": "0" * 64}
    )
    forged_marker = provisional_marker.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional_marker,
                exclude={"content_sha256"},
            )
        }
    )
    marker_path = artifacts / (f"{finalization_id}.runtime-lock-run-finalization.json")
    marker_path.write_text(forged_marker.model_dump_json(), encoding="utf-8")
    marker_path.chmod(0o600)

    with pytest.raises(PerfLensError, match="Agent-visible content"):
        store.load_runtime_lock_run(run_id)


def test_native_short_lived_tid_is_reported_partial_without_false_rejection(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _launchers = _server(tmp_path, behavior="short_tid")
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_host_session(client)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            run_id = cast(str, _structured(collected)["artifact_id"])

    asyncio.run(exercise())
    run = json.loads(next(artifacts.glob("*.runtime-lock-run.json")).read_text(encoding="utf-8"))
    assert run["quality_status"] == "partial"
    assert any("shorter-lived" in warning for warning in run["warnings"])
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    assert store.load_runtime_lock_run(run_id).quality_status == "partial"


def test_native_target_replacement_revokes_before_launch_and_replay_is_rejected(
    tmp_path: Path,
) -> None:
    server, project, artifacts, launchers = _server(tmp_path)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_host_session(client)
            (project / "workload").write_bytes(b"replaced after authorization\n")
            (project / "workload").chmod(0o755)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            assert "differs from the authorized Preview" in str(rejected.content)
            replay = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert replay.is_error
            assert "not bound to this connection" in str(replay.content)

    asyncio.run(exercise())
    assert launchers[0].launch_count == 0
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_native_identity_mismatch_and_timeout_fail_lease_and_clean_stream(
    tmp_path: Path,
) -> None:
    cases: tuple[tuple[_Behavior, str], ...] = (
        ("identity_mismatch", "identity changed"),
        ("timeout", "authorized duration"),
    )
    for behavior, expected in cases:
        case = tmp_path / behavior
        case.mkdir()
        server, _project, artifacts, launchers = _server(case, behavior=behavior)

        async def exercise(
            case_server: object = server,
            expected_text: str = expected,
        ) -> None:
            async with Client(cast(Any, case_server)) as client:
                _preview, session = await _authorize_host_session(client)
                rejected = await client.call_tool(
                    "collect_runtime_lock_evidence",
                    {
                        "session_id": session["session_id"],
                        "measurement_semantics": "exact",
                        "duration_seconds": 3,
                        "max_events": 20,
                    },
                )
                assert rejected.is_error
                assert expected_text in str(rejected.content)

        asyncio.run(exercise())
        assert not launchers[0].private_root.exists() or not list(
            launchers[0].private_root.iterdir()
        )
        assert not list(artifacts.glob("*.runtime-lock-run.json"))
        states = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in artifacts.glob("*.runtime-lock-session.json")
        ]
        assert any(item["state"] in {"failed", "exhausted"} for item in states)


def test_native_conversion_failure_retains_hash_bound_private_stream_until_shutdown(
    tmp_path: Path,
) -> None:
    server, _project, artifacts, launchers = _server(tmp_path, behavior="malformed")
    private_root: Path | None = None

    async def exercise() -> None:
        nonlocal private_root
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_host_session(client)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            assert "strict validation" in str(rejected.content)
            private_root = launchers[0].private_root
            retained = list(private_root.glob(".retained-native-pthread-*.ndjson"))
            assert len(retained) == 1
            retained_path = retained[0]
            retained_payload = retained_path.read_bytes()
            assert stat.S_IMODE(retained_path.stat().st_mode) == 0o600
            assert hashlib.sha256(retained_payload).hexdigest() in retained_path.name
            assert not list(private_root.glob("native-pthread-*.ndjson"))
            hidden = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": retained_path.name,
                    "artifact_type": "runtime-lock-evidence",
                },
            )
            assert hidden.is_error

    asyncio.run(exercise())
    assert private_root is not None
    assert not private_root.exists()
    assert not list(artifacts.glob("*.runtime-lock-evidence.json"))
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_native_private_retention_enforces_quota_rejects_unknown_entries_and_cleans(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)

    def pinned_stream(payload: bytes) -> server_module._PinnedRuntimeLockImport:
        path = root / f"native-pthread-{os.urandom(10).hex()}.ndjson"
        path.write_bytes(payload)
        path.chmod(0o600)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        return server_module._PinnedRuntimeLockImport(
            descriptor=descriptor,
            path=path,
            project_relative_path=path.name,
            source_sha256=hashlib.sha256(payload).hexdigest(),
            metadata=os.fstat(descriptor),
        )

    quota_pinned = pinned_stream(b"bounded diagnostic\n")
    try:
        with pytest.raises(PerfLensError) as quota_error:
            server_module._retain_native_runtime_lock_stream(
                quota_pinned,
                private_root=root,
                max_retained_bytes=quota_pinned.metadata.st_size - 1,
            )
        assert quota_error.value.code == ErrorCode.RESOURCE_LIMIT_EXCEEDED
        assert quota_pinned.path.exists()
    finally:
        os.close(quota_pinned.descriptor)
        quota_pinned.path.unlink()

    rejected_pinned = pinned_stream(b"identity diagnostic\n")
    unexpected = root / "unexpected-entry"
    unexpected.write_text("do not inspect or remove", encoding="utf-8")
    unexpected.chmod(0o600)
    try:
        with pytest.raises(PerfLensError, match="unexpected diagnostic entry"):
            server_module._retain_native_runtime_lock_stream(
                rejected_pinned,
                private_root=root,
                max_retained_bytes=1 << 20,
            )
        assert rejected_pinned.path.exists()
        assert unexpected.exists()
    finally:
        os.close(rejected_pinned.descriptor)
        rejected_pinned.path.unlink()
        unexpected.unlink()

    retained_pinned = pinned_stream(b"retained diagnostic\n")
    try:
        retained = server_module._retain_native_runtime_lock_stream(
            retained_pinned,
            private_root=root,
            max_retained_bytes=1 << 20,
        )
        assert retained.exists()
        assert not retained_pinned.path.exists()
    finally:
        os.close(retained_pinned.descriptor)
    server_module._cleanup_native_runtime_lock_retained_streams(root)
    assert list(root.iterdir()) == []


def test_native_preview_and_private_output_safety_reject_unsafe_inputs(
    tmp_path: Path,
) -> None:
    server, project, artifacts, launchers = _server(tmp_path, behavior="outside_stream")

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            for executable, arguments in (
                (str(project / "workload"), []),
                ("../workload", []),
                ("workload", ["token=secret"]),
                ("workload", ["--password", "secret"]),
                ("workload", ["--token", "secret"]),
                ("workload", ["--api_key", "secret"]),
            ):
                preview = await client.call_tool(
                    "preview_runtime_lock_session",
                    {
                        "target_scope": "host_launched_workload",
                        "allowed_adapters": ["native_pthread"],
                        "allowed_semantics": ["exact"],
                        "executable": executable,
                        "arguments": arguments,
                    },
                )
                assert preview.is_error
                if executable == str(project / "workload"):
                    assert (
                        "Runtime Lock workload executable must be one normalized "
                        "project-relative path"
                    ) in str(preview.content)
                    assert "Native pthread executable" not in str(preview.content)
            _preview, session = await _authorize_host_session(client)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            assert "outside its fixed private root" in str(rejected.content)

    asyncio.run(exercise())
    assert launchers[0].launch_count == 1
    # The server never deletes a path outside its private root, even when a
    # malicious test launcher claims it as evidence.
    assert (project / "native-pthread-00000000000000000001.ndjson").exists()
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_native_capability_is_import_only_when_process_execution_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    setup = project / "perflens-setup"
    setup.mkdir()
    policy = setup / "runtime-locks.toml"
    policy.write_text(render_default_runtime_lock_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    artifacts = project / "artifacts"
    artifacts.mkdir()

    def unexpected_discovery() -> None:
        raise AssertionError("disabled process execution must not inspect the package probe")

    monkeypatch.setattr(
        server_module,
        "discover_native_pthread_probe_policy",
        unexpected_discovery,
    )
    server = create_server(
        ServerConfig(
            allowed_roots=(project,),
            artifact_root=artifacts,
            allow_writes=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            inspected = await client.call_tool("inspect_runtime_lock_capability", {})
            assert not inspected.is_error, inspected.content
            adapters = {item["adapter_id"]: item for item in _structured(inspected)["adapters"]}
            native = adapters["native_pthread"]
            assert native["availability"] == "unavailable"
            assert "disabled by project MCP policy" in native["limitations"][0]

    asyncio.run(exercise())
