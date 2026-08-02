"""Explicitly authorized active performance collection."""

from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    PID_ATTACH_AUTHORIZATION,
    CollectionRequest,
    CollectionTarget,
    collect_profile,
)
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    assert_plan_current,
    create_collection_plan,
)

__all__ = [
    "ACTIVE_COLLECTION_AUTHORIZATION",
    "PID_ATTACH_AUTHORIZATION",
    "AutomaticCollectionPolicy",
    "CollectionPlanRequest",
    "CollectionRequest",
    "CollectionTarget",
    "assert_plan_current",
    "collect_profile",
    "create_collection_plan",
    "inspect_collection_capabilities",
]
