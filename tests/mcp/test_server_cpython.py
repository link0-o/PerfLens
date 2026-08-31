from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from mcp.client import Client

from perflens.contracts.runtime_lock_sessions import RuntimeLockSessionArtifact
from perflens.docker.workload import inspect_managed_project_root
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.cpython_adapter import (
    CpythonLaunchPolicy,
    build_cpython_adapter_bridge,
    inspect_cpython_installation,
)
from perflens.runtime_locks.cpython_launcher import (
    CpythonLaunchRequest,
    CpythonLaunchResult,
    CpythonTargetIdentity,
    CpythonThreadingLauncher,
)
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)
from perflens.runtime_locks.supervisor import RuntimeSupervisorClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (
    PROJECT_ROOT / "src/perflens/runtime_locks/cpython/cpython_threading_bootstrap.py"
)


def _structured(result: object) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    return cast(dict[str, Any], structured)


def _server(
    tmp_path: Path, supervisor: RuntimeSupervisorClient, *, malformed: bool = False
) -> tuple[object, Path, Path, list[object]]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    script = project / "workload.py"
    script.write_text(
        "import threading\nwith threading.Lock():\n    pass\n",
        encoding="utf-8",
    )
    script.chmod(0o600)
    setup = project / "perflens-setup"
    setup.mkdir()
    policy_path = setup / "runtime-locks.toml"
    policy_path.write_text(render_default_runtime_lock_project_policy(), encoding="utf-8")
    policy_path.chmod(0o600)
    artifacts = project / "artifacts"
    artifacts.mkdir()
    installed_bootstrap = project / "fixed-bootstrap.py"
    shutil.copyfile(BOOTSTRAP, installed_bootstrap)
    installed_bootstrap.chmod(0o644)
    interpreter = Path(sys.executable).resolve(strict=True)
    trusted = tuple(dict.fromkeys((0, os.geteuid(), interpreter.stat().st_uid)))
    installation = inspect_cpython_installation(
        interpreter_path=interpreter,
        bootstrap_path=installed_bootstrap,
        trusted_owner_uids=trusted,
    )
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(project,))
    bridge = build_cpython_adapter_bridge(
        policy,
        installation,
        created_at=datetime(2026, 8, 31, tzinfo=UTC).isoformat(),
    )
    assert bridge.launch_policy is not None
    inspection = inspect_runtime_lock_capability(
        policy,
        project_identity_sha256=inspect_managed_project_root(project).identity_sha256,
        cpython_bridge=bridge,
        created_at=datetime(2026, 8, 31, tzinfo=UTC),
    )
    launchers: list[object] = []

    def launcher_factory(
        project_root: Path, private_root: Path, launch_policy: CpythonLaunchPolicy
    ) -> CpythonThreadingLauncher:
        launcher: object = CpythonThreadingLauncher(
            project_root=project_root,
            private_output_root=private_root,
            policy=launch_policy,
            supervisor_client=supervisor,
        )
        if malformed:
            launcher = _MalformedCpythonLauncher(launcher)
        launchers.append(launcher)
        return cast(CpythonThreadingLauncher, launcher)

    server = create_server(
        ServerConfig(
            allowed_roots=(project,),
            artifact_root=artifacts,
            allow_writes=True,
            allow_process_execution=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy_path,
            runtime_lock_capability_factory=lambda: inspection,
            runtime_lock_cpython_bridge_factory=lambda: bridge,
            runtime_lock_cpython_launcher_factory=launcher_factory,
        )
    )
    return server, project, artifacts, launchers


class _MalformedCpythonLauncher:
    def __init__(self, delegate: CpythonThreadingLauncher) -> None:
        self.delegate = delegate

    def inspect_target(self, script: Path) -> CpythonTargetIdentity:
        return self.delegate.inspect_target(script)

    def launch(
        self,
        script: Path,
        request: CpythonLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> CpythonLaunchResult:
        result = self.delegate.launch(
            script,
            request,
            expected_target_identity_sha256=expected_target_identity_sha256,
        )
        payload = b'not-json\n'
        result.stream_path.write_bytes(payload)
        result.stream_path.chmod(0o600)
        return replace(
            result,
            stream_sha256=hashlib.sha256(payload).hexdigest(),
            stream_size=len(payload),
        )


def test_cpython_preview_authorize_collect_analyze_verify_and_cleanup(
    tmp_path: Path, runtime_supervisor_client: RuntimeSupervisorClient
) -> None:
    server, project, artifacts, launchers = _server(tmp_path, runtime_supervisor_client)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview_result = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["cpython_threading"],
                    "allowed_semantics": ["exact"],
                    "executable": "workload.py",
                    "arguments": [],
                },
            )
            assert not preview_result.is_error, preview_result.content
            preview = _structured(preview_result)
            assert preview["workload"]["workload_kind"] == "python_script"
            assert len(preview["adapter_execution_bindings"]) == 1
            authorization = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview[
                        "authorization_summary_sha256"
                    ],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
                    ),
                },
            )
            assert not authorization.is_error, authorization.content
            session = _structured(authorization)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 500,
                },
            )
            assert not collected.is_error, collected.content
            reference = _structured(collected)
            assert reference["artifact_type"] == "runtime-lock-run"
            assert reference["summary"]["adapter_id"] == "cpython_threading"
            assert reference["summary"]["private_source_replay_status"] == "passed"

    asyncio.run(exercise())
    assert len(launchers) == 1
    assert not list(artifacts.glob(".runtime-lock-cpython-*/*.ndjson"))
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    run_path = next(artifacts.glob("*.runtime-lock-run.json"))
    run_id = run_path.name.removesuffix(".runtime-lock-run.json")
    run = store.load_runtime_lock_run(run_id)
    assert run.adapter_id == "cpython_threading"
    assert run.correctness_status == "passed"
    assert run.quality_status == "partial"


def test_malformed_cpython_stream_is_retained_and_session_is_failed(
    tmp_path: Path, runtime_supervisor_client: RuntimeSupervisorClient
) -> None:
    server, _project, artifacts, _launchers = _server(
        tmp_path, runtime_supervisor_client, malformed=True
    )

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview_result = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["cpython_threading"],
                    "allowed_semantics": ["exact"],
                    "executable": "workload.py",
                    "arguments": [],
                },
            )
            assert not preview_result.is_error
            preview = _structured(preview_result)
            authorization = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview[
                        "authorization_summary_sha256"
                    ],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
                    ),
                },
            )
            session = _structured(authorization)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 500,
                },
            )
            assert collected.is_error
            assert "strict JSON" in str(collected.content)

    asyncio.run(exercise())
    retained = list(artifacts.glob(".runtime-lock-cpython-*/*.ndjson"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == b"not-json\n"
    sessions = [
        RuntimeLockSessionArtifact.model_validate_json(path.read_bytes())
        for path in artifacts.glob("*.runtime-lock-session.json")
    ]
    assert any(
        session.state == "failed" and session.invalidation_reason == "adapter_output_invalid"
        for session in sessions
    )
