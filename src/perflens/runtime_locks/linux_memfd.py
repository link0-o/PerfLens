"""Linux memfd sealing constants missing from some supported Python builds.

CPython only exposed these constants in Python 3.13. PerfLens supports Python
3.12 as well, while Linux has kept the fcntl ABI values stable since memfd
sealing was introduced. Keep the compatibility boundary in one module rather
than weakening or conditionally skipping the snapshot seals.
"""

from __future__ import annotations

import fcntl
from typing import Final


def _linux_fcntl_constant(name: str, fallback: int) -> int:
    value = getattr(fcntl, name, fallback)
    if isinstance(value, bool) or not isinstance(value, int) or value != fallback:
        raise RuntimeError(f"unexpected Linux fcntl ABI value for {name}")
    return value


F_ADD_SEALS: Final = _linux_fcntl_constant("F_ADD_SEALS", 1033)
F_GET_SEALS: Final = _linux_fcntl_constant("F_GET_SEALS", 1034)
F_SEAL_SEAL: Final = _linux_fcntl_constant("F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK: Final = _linux_fcntl_constant("F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW: Final = _linux_fcntl_constant("F_SEAL_GROW", 0x0004)
F_SEAL_WRITE: Final = _linux_fcntl_constant("F_SEAL_WRITE", 0x0008)

IMMUTABLE_MEMFD_SEALS: Final = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
