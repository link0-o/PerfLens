"""Conservative compiler suffix normalization.

Raw symbols remain available at the contract boundary. This helper intentionally
does not erase C++ template arguments or overload signatures.
"""

from __future__ import annotations

import re

_ADDRESS_OFFSET = re.compile(r"\+0x[0-9a-fA-F]+$")
_COMPILER_SUFFIX = re.compile(r"\.(?:isra|constprop|part)\.\d+$")
_RUST_HASH = re.compile(r"::h[0-9a-f]{16,17}$")


def normalize_symbol(raw_symbol: str) -> str:
    symbol = raw_symbol.strip()
    symbol = _ADDRESS_OFFSET.sub("", symbol)
    if symbol.endswith(" [clone]"):
        symbol = symbol.removesuffix(" [clone]")
    symbol = _COMPILER_SUFFIX.sub("", symbol)
    symbol = symbol.removesuffix(".cold")
    symbol = _RUST_HASH.sub("", symbol)
    return symbol
