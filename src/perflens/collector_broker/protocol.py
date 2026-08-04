"""Bounded JSON protocol shared by the collector broker and its client."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, TypeAdapter, model_validator

from perflens.contracts.artifacts import SCHEMA_VERSION, CollectionPlanArtifact, ContractModel

MAX_BROKER_MESSAGE_BYTES = 64 << 10


class BrokerCollectRequest(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    operation: Literal["collect_pid"] = "collect_pid"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")
    plan: CollectionPlanArtifact


class BrokerHealthRequest(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    operation: Literal["health"] = "health"
    request_id: str = Field(pattern=r"^request-[a-f0-9]{16,64}$")


BrokerRequest = Annotated[
    BrokerCollectRequest | BrokerHealthRequest,
    Field(discriminator="operation"),
]
BROKER_REQUEST_ADAPTER: TypeAdapter[BrokerRequest] = TypeAdapter(BrokerRequest)


class BrokerError(ContractModel):
    code: str = Field(min_length=1, max_length=64)
    stage: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1024)
    recoverable: bool


class BrokerResponse(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    request_id: str = Field(pattern=r"^(unknown|request-[a-f0-9]{16,64})$")
    ok: bool
    result: dict[str, Any] | None = None
    error: BrokerError | None = None

    @model_validator(mode="after")
    def require_exactly_one_payload(self) -> BrokerResponse:
        if self.ok and (self.result is None or self.error is not None):
            raise ValueError("Successful broker responses require only a result")
        if not self.ok and (self.error is None or self.result is not None):
            raise ValueError("Failed broker responses require only an error")
        return self
