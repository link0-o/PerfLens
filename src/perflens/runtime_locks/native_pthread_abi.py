"""Single reviewed ABI surface for the packaged Native pthread probe."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

NATIVE_PTHREAD_PROBE_ABI_VERSION: Final = 1
NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION: Final = "1.0"

NATIVE_PTHREAD_PROBE_MARKER_EXPORTS: Final = frozenset(
    {
        "perflens_pthread_probe_abi_version",
        "perflens_pthread_probe_protocol_version",
    }
)

# This is both the LD_PRELOAD interposition allowlist and the capability source
# map.  An unlock wrapper can serve more than one observed lock kind, whereas
# target capability discovery uses the acquisition/wait wrappers only.
NATIVE_PTHREAD_WRAPPER_LOCK_KINDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "pthread_cond_clockwait": ("condition",),
        "pthread_cond_timedwait": ("condition",),
        "pthread_cond_wait": ("condition",),
        "pthread_mutex_clocklock": ("mutex", "recursive_mutex"),
        "pthread_mutex_lock": ("mutex", "recursive_mutex"),
        "pthread_mutex_timedlock": ("mutex", "recursive_mutex"),
        "pthread_mutex_trylock": ("mutex", "recursive_mutex"),
        "pthread_mutex_unlock": ("mutex", "recursive_mutex"),
        "pthread_rwlock_clockrdlock": ("rwlock_read",),
        "pthread_rwlock_clockwrlock": ("rwlock_write",),
        "pthread_rwlock_rdlock": ("rwlock_read",),
        "pthread_rwlock_timedrdlock": ("rwlock_read",),
        "pthread_rwlock_timedwrlock": ("rwlock_write",),
        "pthread_rwlock_tryrdlock": ("rwlock_read",),
        "pthread_rwlock_trywrlock": ("rwlock_write",),
        "pthread_rwlock_unlock": ("rwlock_read", "rwlock_write"),
        "pthread_rwlock_wrlock": ("rwlock_write",),
    }
)

NATIVE_PTHREAD_PROBE_EXPORTS: Final = NATIVE_PTHREAD_PROBE_MARKER_EXPORTS | frozenset(
    NATIVE_PTHREAD_WRAPPER_LOCK_KINDS
)

# glibc 2.34+ folds libpthread/libdl into libc.  The amd64 TLS runtime remains
# a direct loader dependency in the reviewed GCC/Clang output.
NATIVE_PTHREAD_PROBE_NEEDED_LIBRARIES: Final = frozenset({"libc.so.6", "ld-linux-x86-64.so.2"})

_CAPABILITY_WRAPPERS: Final = frozenset(
    name for name in NATIVE_PTHREAD_WRAPPER_LOCK_KINDS if not name.endswith("_unlock")
)


def native_pthread_visible_lock_kinds(dynamic_symbols: frozenset[str]) -> tuple[str, ...]:
    """Return only kinds proven by an imported acquisition/wait wrapper."""

    return tuple(
        sorted(
            {
                lock_kind
                for symbol in dynamic_symbols & _CAPABILITY_WRAPPERS
                for lock_kind in NATIVE_PTHREAD_WRAPPER_LOCK_KINDS[symbol]
            }
        )
    )
