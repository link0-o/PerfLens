"""Bounded domain-error projection at the official MCP SDK transport boundary."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from contextvars import Context as ContextVarsContext
from typing import Any, Protocol, cast

from anyio.abc import ObjectReceiveStream
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp_types import CallToolResult, InputRequiredResult, JSONRPCRequest, TextContent

from perflens.contracts.artifacts import ErrorArtifact, ErrorBody
from perflens.domain.errors import PerfLensError, stable_error_id

# Do not forward arbitrary diagnostic dictionaries: they can contain private
# spool paths, commands, environment, stderr, or third-party exception objects.
_PUBLIC_DETAIL_FIELDS = (
    "adapter_id",
    "artifact_id",
    "artifact_type",
    "plan_id",
    "session_id",
    "run_id",
    "runtime_lock_analysis_id",
    "runtime_lock_verification_id",
    "docker_optimization_session_id",
    "docker_optimization_workload_attempt_charged",
    "docker_optimization_automatic_retry_allowed",
    "docker_optimization_workload_runs_used",
    "published",
    "exit_code",
    "offset",
    "limit",
    "actual_bytes",
    "max_output_bytes",
    "duration_seconds",
    "max_duration_seconds",
    "max_events",
    "event_count",
)
_PUBLIC_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_MODERN_PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
_MODERN_DISCOVERY_META_KEYS = frozenset(
    {
        _MODERN_PROTOCOL_VERSION_META_KEY,
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/clientInfo",
    }
)


class _SessionReadStream(Protocol):
    async def receive(self) -> SessionMessage | Exception: ...

    async def aclose(self) -> None: ...


class _ProtocolNegotiationReadStream(ObjectReceiveStream[SessionMessage | Exception]):
    """Let auto-negotiating clients fall back after a modern discovery probe."""

    def __init__(self, source: _SessionReadStream) -> None:
        self._source = source
        self._opening_request_seen = False

    @property
    def last_context(self) -> ContextVarsContext | None:
        """Preserve sender context when the wrapped transport provides one."""
        context = getattr(self._source, "last_context", None)
        return context if isinstance(context, ContextVarsContext) else None

    async def receive(self) -> SessionMessage | Exception:
        item = await self._source.receive()
        if self._opening_request_seen:
            return item
        if not isinstance(item, SessionMessage) or not isinstance(item.message, JSONRPCRequest):
            return item
        self._opening_request_seen = True
        request = item.message
        if request.method != "server/discover" or not request.params:
            return item
        raw_meta = request.params.get("_meta")
        if not isinstance(raw_meta, Mapping) or _MODERN_PROTOCOL_VERSION_META_KEY not in raw_meta:
            return item
        typed_meta = cast("Mapping[str, Any]", raw_meta)

        # The SDK chooses a connection's protocol era from this first request.
        # Treat discovery as an unsupported legacy probe so a client can send
        # ``initialize`` on the same process. Direct modern tool requests keep
        # their envelope and retain the SDK's modern-protocol behavior.
        params = dict(request.params)
        meta = {
            key: value
            for key, value in typed_meta.items()
            if key not in _MODERN_DISCOVERY_META_KEYS
        }
        if meta:
            params["_meta"] = meta
        else:
            params.pop("_meta", None)
        return SessionMessage(request.model_copy(update={"params": params}), item.metadata)

    async def aclose(self) -> None:
        await self._source.aclose()


def domain_error_result(error: PerfLensError) -> CallToolResult:
    """Return the same versioned error in JSON text and structured content.

    The text mirror supports clients that display only content. A tool error is
    never converted into success and never changes a success output schema.
    """
    details: dict[str, Any] = {}
    for name in _PUBLIC_DETAIL_FIELDS:
        if name not in error.details:
            continue
        value: object = error.details[name]
        if (
            value is None
            or isinstance(value, bool)
            or (isinstance(value, int) and abs(value) <= (1 << 63) - 1)
            or (isinstance(value, float) and math.isfinite(value) and abs(value) <= (1 << 63) - 1)
            or (isinstance(value, str) and _PUBLIC_TOKEN.fullmatch(value))
        ):
            details[name] = value
    if len(details) != len(error.details):
        details["details_omitted"] = True
    if (
        len(error.message) > 1024
        or len(error.stage) > 128
        or len(error.suggested_actions) > 4
        or any(len(action) > 256 for action in error.suggested_actions[:4])
    ):
        details["presentation_truncated"] = True
    artifact = ErrorArtifact(
        error=ErrorBody(
            error_id=stable_error_id(error),
            code=error.code.value,
            stage=error.stage[:128],
            message=error.message[:1024],
            recoverable=error.recoverable,
            retryable=error.retryable,
            details=details,
            suggested_actions=tuple(action[:256] for action in error.suggested_actions[:4]),
        )
    )
    payload = artifact.model_dump(mode="json")
    return CallToolResult(
        is_error=True,
        structured_content=payload,
        content=[TextContent(type="text", text=json.dumps(payload, sort_keys=True))],
    )


class PerfLensMCPServer(MCPServer[None]):
    """Preserve domain failures without replacing the SDK's tool/schema machinery."""

    async def run_stdio_async(self) -> None:
        """Serve stdio with deterministic modern-to-legacy negotiation fallback.

        MCP SDK 2 also auto-detects the 2026-07-28 handshake-free protocol from
        the first enveloped request. Some auto-negotiating clients send an
        enveloped ``server/discover`` probe and then a legacy ``initialize``
        request on the same process. Once auto-detection selects the modern
        protocol, the SDK must reject that fallback request and the client
        never discovers any PerfLens tools.

        An opening discovery probe is therefore presented to the SDK as a
        legacy method probe. The SDK returns method-not-found and then accepts
        the fallback handshake. Any other opening request is unchanged, so
        modern-only and legacy clients both retain their native protocol path.
        HTTP transports retain the SDK defaults.
        """
        lowlevel_server = self._lowlevel_server  # pyright: ignore[reportPrivateUsage]
        async with stdio_server() as (read_stream, write_stream):
            await lowlevel_server.run(
                _ProtocolNegotiationReadStream(read_stream),
                write_stream,
                lowlevel_server.create_initialization_options(),
            )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[None, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        try:
            return await super().call_tool(name, arguments, context)
        except PerfLensError as exc:
            return domain_error_result(exc)
        except ToolError as exc:
            # SDK tool execution wraps exceptions with an explicit cause. Only
            # project domain errors use this representation; protocol errors,
            # cancellation, and unrelated SDK failures retain their semantics.
            if isinstance(exc.__cause__, PerfLensError):
                return domain_error_result(exc.__cause__)
            raise
