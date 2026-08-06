"""Private protocol for the optional Rust privileged Helper."""

from typing import TYPE_CHECKING

from perflens.privileged_helper.protocol import (
    HELPER_REQUEST_ADAPTER,
    HelperCollectPidRequest,
    HelperHealthRequest,
    HelperHealthResult,
    HelperRequest,
    parse_helper_request_frame,
)

if TYPE_CHECKING:
    from perflens.privileged_helper.client import HelperClient

__all__ = [
    "HELPER_REQUEST_ADAPTER",
    "HelperClient",
    "HelperCollectPidRequest",
    "HelperHealthRequest",
    "HelperHealthResult",
    "HelperRequest",
    "parse_helper_request_frame",
]


def __getattr__(name: str) -> object:
    if name == "HelperClient":
        from perflens.privileged_helper.client import HelperClient

        return HelperClient
    raise AttributeError(name)
