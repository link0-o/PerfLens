# pyright: reportPrivateUsage=false
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp.client import Client
from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

from perflens.collection.planning import AutomaticCollectionPolicy
from perflens.contracts.artifacts import ArtifactReference
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp import server as server_module
from perflens.mcp.server import ServerConfig, create_server


@pytest.mark.parametrize(
    ("outcome", "start", "finish", "observed", "expected"),
    (
        ("success", 103.0, 104.25, 109.25, 2),
        ("post_exit_failure", 103.0, 104.25, 109.25, 2),
        ("pre_release_failure", None, None, 109.25, 0),
        ("running_failure", 103.0, None, 104.25, 2),
        ("timeout", 103.0, None, 140.0, 30),
        ("authorization_failure", None, None, 109.25, 0),
    ),
)
def test_parent_uses_measured_inner_duration_and_preserves_failed_attempt_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    start: float | None,
    finish: float | None,
    observed: float,
    expected: int,
) -> None:
    runtime, project, _ = make_optimization_runtime(tmp_path)
    server = create_server(
        ServerConfig(
            (tmp_path,),
            tmp_path / "artifacts",
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            docker_project_config=project / "container-workload.toml",
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True, allowed_modes=("stat", "record")
            ),
            docker_optimization_runtime_factory=lambda: runtime,
        )
    )
    tool = server._tool_manager.get_tool("collect_docker_optimization_workload")
    assert tool is not None
    cells = tool.fn.__closure__
    assert cells is not None
    closure = dict(zip(tool.fn.__code__.co_freevars, cells, strict=True))
    progress = cast(dict[str, int], closure["managed_active_seconds"].cell_contents)
    clock = [100.0]

    def authorize_internal(*_args: object, **_kwargs: object) -> SimpleNamespace:
        clock[0] += 3
        if outcome == "authorization_failure":
            raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "perf_control", "Synthetic failure")
        return SimpleNamespace(session_id="audit-inner")

    async def collect_inner(**_kwargs: object) -> ArtifactReference:
        # The real inner producer is covered by the managed Gate/broker test.
        # Model its measured receipt independently of the outer call's wall time.
        progress["audit-inner"] = server_module._managed_workload_active_seconds(
            workload_started_monotonic=start,
            workload_finished_monotonic=finish,
            workload_timeout_seconds=30,
            now_monotonic=observed,
        )
        clock[0] = observed + 5
        if outcome != "success":
            raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "perf_control", "Synthetic failure")
        return ArtifactReference(
            artifact_id="container-run-audit",
            artifact_type="container-run",
            uri="perflens://container-run/audit",
            summary={"evidence_bytes": 100},
        )

    closure["collect_managed_docker_workload"].cell_contents = collect_inner
    monkeypatch.setattr(
        server_module.ExistingDockerRuntime, "authorize_optimization_build", authorize_internal
    )
    def revoke(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(server_module.ExistingDockerRuntime, "revoke", revoke)

    async def exercise() -> None:
        async with Client(server) as client:
            preview_result = await client.call_tool(
                "preview_docker_optimization_session", {"allowed_modes": ["stat"]}
            )
            assert not preview_result.is_error
            preview = cast(dict[str, Any], preview_result.structured_content)
            authorization = await client.call_tool(
                "authorize_docker_optimization_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview["authorization_summary_sha256"],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                    ),
                },
            )
            assert not authorization.is_error
            session_id = cast(dict[str, Any], authorization.structured_content)["session_id"]
            built = await client.call_tool(
                "build_docker_optimization_candidate",
                {"session_id": session_id, "build_kind": "baseline", "candidate_round": 0},
            )
            assert not built.is_error
            request = {
                "session_id": session_id,
                "build_id": cast(dict[str, Any], built.structured_content)["artifact_id"],
                "mode": "stat",
                "duration_seconds": 1,
                "workload_timeout_seconds": 30,
                "max_output_bytes": 1 << 20,
            }
            monkeypatch.setattr(server_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
            result = await client.call_tool("collect_docker_optimization_workload", request)
            assert result.is_error == (outcome != "success"), result.content
            snapshot = runtime.snapshot(session_id)
            assert snapshot.workload_runs_used == 1
            assert snapshot.workload_active_seconds_used == expected
            assert snapshot.evidence_bytes_used == (100 if outcome == "success" else 0)
            assert not progress  # No unbounded state retained after success or failure.
            if outcome != "success":
                retry = await client.call_tool("collect_docker_optimization_workload", request)
                assert retry.is_error
                assert "stopped after a failed attempt" in str(retry.content)
                assert runtime.snapshot(session_id).workload_runs_used == 1

    asyncio.run(exercise())
