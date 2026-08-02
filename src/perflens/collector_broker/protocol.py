"""Bounded JSON protocol shared by the collector broker and its client."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from perflens.contracts.artifacts import SCHEMA_VERSION, CollectionPlanArtifact, ContractModel

MAX_BROKER_MESSAGE_BYTES = 64 << 10


class BrokerCollectRequest(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    operation: Literal["collect_pid"] = "collect_pid"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")
    plan: CollectionPlanArtifact


class BrokerResponse(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    request_id: str
    ok: bool
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
