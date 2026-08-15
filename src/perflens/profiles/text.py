"""Loss-visible helpers for bounded UTF-8 profile text streams."""

from __future__ import annotations

_SURROGATE_REPLACEMENTS = {codepoint: 0xFFFD for codepoint in range(0xDC80, 0xDD00)}


def sanitize_surrogateescaped_text(value: str) -> tuple[str, int, int]:
    """Return parse-safe text, exact source bytes, and invalid UTF-8 byte count.

    Streams are opened with ``errors="surrogateescape"`` so valid U+FFFD characters remain
    distinguishable from invalid source bytes. Each escaped byte is made visible as U+FFFD only
    after its original byte length and loss count have been recorded.
    """
    source_bytes = value.encode("utf-8", errors="surrogateescape")
    invalid_bytes = sum(0xDC80 <= ord(character) <= 0xDCFF for character in value)
    if invalid_bytes:
        value = value.translate(_SURROGATE_REPLACEMENTS)
    return value, len(source_bytes), invalid_bytes
