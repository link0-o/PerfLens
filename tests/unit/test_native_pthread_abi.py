from __future__ import annotations

from perflens.runtime_locks.native_pthread_abi import (
    NATIVE_PTHREAD_PROBE_EXPORTS,
    NATIVE_PTHREAD_PROBE_MARKER_EXPORTS,
    NATIVE_PTHREAD_WRAPPER_LOCK_KINDS,
    native_pthread_visible_lock_kinds,
)


def test_native_probe_export_and_capability_surfaces_are_exact() -> None:
    assert (
        NATIVE_PTHREAD_PROBE_MARKER_EXPORTS | frozenset(NATIVE_PTHREAD_WRAPPER_LOCK_KINDS)
    ) == NATIVE_PTHREAD_PROBE_EXPORTS
    assert "pthread_cond_signal" not in NATIVE_PTHREAD_PROBE_EXPORTS
    assert "pthread_cond_broadcast" not in NATIVE_PTHREAD_PROBE_EXPORTS
    assert NATIVE_PTHREAD_WRAPPER_LOCK_KINDS["pthread_rwlock_unlock"] == (
        "rwlock_read",
        "rwlock_write",
    )

    assert native_pthread_visible_lock_kinds(
        frozenset(
            {
                "pthread_cond_wait",
                "pthread_mutex_lock",
                "pthread_rwlock_clockrdlock",
                "pthread_rwlock_wrlock",
            }
        )
    ) == (
        "condition",
        "mutex",
        "recursive_mutex",
        "rwlock_read",
        "rwlock_write",
    )
    assert (
        native_pthread_visible_lock_kinds(
            frozenset({"pthread_mutex_unlock", "pthread_rwlock_unlock"})
        )
        == ()
    )
