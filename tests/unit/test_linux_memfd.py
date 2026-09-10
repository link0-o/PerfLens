from __future__ import annotations

import fcntl

from perflens.runtime_locks.linux_memfd import (
    F_ADD_SEALS,
    F_GET_SEALS,
    F_SEAL_GROW,
    F_SEAL_SEAL,
    F_SEAL_SHRINK,
    F_SEAL_WRITE,
    IMMUTABLE_MEMFD_SEALS,
)


def test_linux_memfd_compatibility_constants_match_the_kernel_abi() -> None:
    assert F_ADD_SEALS == 1033
    assert F_GET_SEALS == 1034
    assert F_SEAL_SEAL == 0x0001
    assert F_SEAL_SHRINK == 0x0002
    assert F_SEAL_GROW == 0x0004
    assert F_SEAL_WRITE == 0x0008
    assert IMMUTABLE_MEMFD_SEALS == 0x000F

    for name, expected in (
        ("F_ADD_SEALS", F_ADD_SEALS),
        ("F_GET_SEALS", F_GET_SEALS),
        ("F_SEAL_SEAL", F_SEAL_SEAL),
        ("F_SEAL_SHRINK", F_SEAL_SHRINK),
        ("F_SEAL_GROW", F_SEAL_GROW),
        ("F_SEAL_WRITE", F_SEAL_WRITE),
    ):
        exposed = getattr(fcntl, name, None)
        assert exposed is None or exposed == expected
