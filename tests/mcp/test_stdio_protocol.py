from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters, stdio_client


def _stdio_parameters(tmp_path: Path) -> StdioServerParameters:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "perflens.mcp.server",
            "--allowed-root",
            str(tmp_path),
            "--artifact-root",
            str(artifact_root),
        ],
        cwd=str(Path(__file__).resolve().parents[2]),
    )


def test_stdio_allows_legacy_initialize_after_modern_protocol_probe(tmp_path: Path) -> None:
    """An auto-negotiating client can fall back without restarting the process."""

    async def exercise() -> None:
        async with Client(
            stdio_client(_stdio_parameters(tmp_path)),
            mode="auto",
            read_timeout_seconds=10,
        ) as client:
            assert client.protocol_version == "2025-11-25"
            assert client.server_info is not None
            assert client.server_info.name == "perflens"
            listed = await client.list_tools()
            tool_names = {tool.name for tool in listed.tools}
            assert "read_artifact_page" in tool_names
            assert "inspect_runtime_lock_capability" in tool_names

    asyncio.run(exercise())


def test_stdio_preserves_direct_modern_protocol_requests(tmp_path: Path) -> None:
    """The compatibility shim must not downgrade a direct modern client."""

    async def exercise() -> None:
        async with Client(
            stdio_client(_stdio_parameters(tmp_path)),
            mode="2026-07-28",
            read_timeout_seconds=10,
        ) as client:
            assert client.protocol_version == "2026-07-28"
            listed = await client.list_tools()
            tool_names = {tool.name for tool in listed.tools}
            assert "read_artifact_page" in tool_names
            assert "inspect_runtime_lock_capability" in tool_names

    asyncio.run(exercise())
