from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest
from tests.support.docker import write_self_contained_test_elf

from perflens.docker.elf import validate_self_contained_elf


def _validate(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        validate_self_contained_elf(descriptor, file_size=path.stat().st_size)
    finally:
        os.close(descriptor)


def test_self_contained_gate_elf_is_accepted(tmp_path: Path) -> None:
    _validate(write_self_contained_test_elf(tmp_path / "gate"))


def test_dynamic_gate_interpreter_is_rejected(tmp_path: Path) -> None:
    path = write_self_contained_test_elf(tmp_path / "gate")
    payload = bytearray(path.read_bytes())
    payload[64:68] = struct.pack("<I", 3)
    path.chmod(0o700)
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="static ELF"):
        _validate(path)


def test_out_of_bounds_load_segment_is_rejected(tmp_path: Path) -> None:
    path = write_self_contained_test_elf(tmp_path / "gate")
    payload = bytearray(path.read_bytes())
    payload[64 + 32 : 64 + 40] = struct.pack("<Q", len(payload) + 1)
    path.chmod(0o700)
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="outside the file"):
        _validate(path)


@pytest.mark.parametrize("payload", [b"", b"#!/bin/sh\n", b"\x7fELF"])
def test_malformed_gate_elf_is_rejected(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "gate"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        _validate(path)
