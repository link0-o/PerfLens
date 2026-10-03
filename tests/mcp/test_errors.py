# pyright: reportUnusedFunction=false
from __future__ import annotations

import asyncio
import json

import pytest
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from perflens.contracts.artifacts import ArtifactReference, ErrorArtifact
from perflens.domain.errors import ErrorCode, PerfLensError, stable_error_id
from perflens.mcp.errors import PerfLensMCPServer, domain_error_result


@pytest.mark.parametrize("code", tuple(ErrorCode))
def test_mcp_client_receives_versioned_domain_error_without_changing_success_schema(
    code: ErrorCode,
) -> None:
    server = PerfLensMCPServer("test")
    failure = PerfLensError(
        code,
        "perf_control",
        "Synthetic control failure",
        details={
            "docker_optimization_workload_attempt_charged": True,
            "docker_optimization_automatic_retry_allowed": False,
            "docker_optimization_workload_runs_used": 1,
        },
        suggested_actions=("Do not retry this Session.",),
    )

    @server.tool(structured_output=True)
    async def example(fail: bool) -> ArtifactReference:
        if fail:
            raise failure
        return ArtifactReference(
            artifact_id="test", artifact_type="test", uri="perflens://test", summary={}
        )

    async def exercise() -> None:
        async with Client(server) as client:
            tools = await server.list_tools()
            assert tools[0].output_schema == ArtifactReference.model_json_schema()
            failed = await client.call_tool("example", {"fail": True})
            assert failed.is_error
            parsed = ErrorArtifact.model_validate(failed.structured_content)
            assert parsed.error.error_id == stable_error_id(failure)
            assert parsed.error.code == code.value
            assert parsed.error.stage == failure.stage
            assert parsed.error.details == failure.details
            assert parsed.error.suggested_actions == failure.suggested_actions
            assert not parsed.error.recoverable
            assert not parsed.error.retryable
            block = failed.content[0]
            assert block.type == "text"
            assert json.loads(block.text) == failed.structured_content
            succeeded = await client.call_tool("example", {"fail": False})
            assert not succeeded.is_error
            assert (
                ArtifactReference.model_validate(succeeded.structured_content).artifact_id == "test"
            )

    asyncio.run(exercise())


def test_error_projection_bounds_text_and_omits_private_or_non_scalar_details() -> None:
    error = PerfLensError(
        ErrorCode.EXTERNAL_TOOL_FAILED,
        "stage" * 1000,
        "🚀" * 10000,
        details={
            "path": "/private/spool/secret",
            "environment": {"TOKEN": "secret"},
            "argv": ["program", "secret"],
            "stderr": "secret",
            "exit_code": float("nan"),
            "actual_bytes": 1 << 1000,
            "artifact_id": "/private/spool/secret",
            "limit": 65536,
            "duration_seconds": 1.25,
            "published": False,
            "run_id": None,
        },
        suggested_actions=("🚀" * 10000,) * 10,
    )
    result = domain_error_result(error)
    payload = ErrorArtifact.model_validate(result.structured_content)
    assert payload.error.details == {
        "limit": 65536,
        "duration_seconds": 1.25,
        "published": False,
        "run_id": None,
        "details_omitted": True,
        "presentation_truncated": True,
    }
    text = result.content[0]
    assert text.type == "text"
    assert "secret" not in text.text
    assert len(text.text.encode()) < 32768
    assert len(payload.error.message) == 1024
    assert len(payload.error.stage) == 128
    assert len(payload.error.suggested_actions) == 4


def test_sdk_failures_and_cancellation_are_not_reclassified_as_domain_errors() -> None:
    server = PerfLensMCPServer("test")

    @server.tool()
    async def cancelled() -> str:
        raise asyncio.CancelledError

    async def exercise() -> None:
        with pytest.raises(ToolError, match="Unknown tool"):
            await server.call_tool("missing", {})
        with pytest.raises(asyncio.CancelledError):
            await server.call_tool("cancelled", {})

    asyncio.run(exercise())
