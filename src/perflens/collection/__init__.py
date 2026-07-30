"""Explicitly authorized active performance collection."""

from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    PID_ATTACH_AUTHORIZATION,
    CollectionRequest,
    CollectionTarget,
    collect_profile,
)

__all__ = [
    "ACTIVE_COLLECTION_AUTHORIZATION",
    "PID_ATTACH_AUTHORIZATION",
    "CollectionRequest",
    "CollectionTarget",
    "collect_profile",
]
