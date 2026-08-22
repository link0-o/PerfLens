"""Minimal ELF validation for the cross-image managed Container Gate."""

from __future__ import annotations

import os
import struct

_ELF_IDENT_SIZE = 16
_ELF_MAGIC = b"\x7fELF"
_ELF_CLASS_32 = 1
_ELF_CLASS_64 = 2
_ELF_DATA_LITTLE = 1
_ELF_DATA_BIG = 2
_ET_EXEC = 2
_ET_DYN = 3
_PT_LOAD = 1
_PT_INTERP = 3
_MAX_PROGRAM_HEADERS = 1024


def validate_self_contained_elf(descriptor: int, *, file_size: int) -> None:
    """Reject an ELF that needs an image-provided loader or shared libraries."""
    if descriptor < 0 or file_size < _ELF_IDENT_SIZE:
        raise ValueError("Container Gate is not a bounded ELF executable")
    ident = _pread_exact(descriptor, _ELF_IDENT_SIZE, 0)
    if ident[:4] != _ELF_MAGIC or ident[6] != 1:
        raise ValueError("Container Gate is not a supported ELF executable")
    byte_order = {_ELF_DATA_LITTLE: "<", _ELF_DATA_BIG: ">"}.get(ident[5])
    if byte_order is None:
        raise ValueError("Container Gate ELF byte order is unsupported")
    if ident[4] == _ELF_CLASS_64:
        header_format = f"{byte_order}16sHHIQQQIHHHHHH"
        program_format = f"{byte_order}IIQQQQQQ"
    elif ident[4] == _ELF_CLASS_32:
        header_format = f"{byte_order}16sHHIIIIIHHHHHH"
        program_format = f"{byte_order}IIIIIIII"
    else:
        raise ValueError("Container Gate ELF class is unsupported")

    header_size = struct.calcsize(header_format)
    header = struct.unpack(header_format, _pread_exact(descriptor, header_size, 0))
    if header[1] not in {_ET_EXEC, _ET_DYN} or header[2] == 0 or header[3] != 1:
        raise ValueError("Container Gate ELF executable header is invalid")
    program_offset = int(header[5])
    program_entry_size = int(header[9])
    program_count = int(header[10])
    minimum_entry_size = struct.calcsize(program_format)
    if (
        program_count < 1
        or program_count > _MAX_PROGRAM_HEADERS
        or program_entry_size < minimum_entry_size
        or program_offset < header_size
        or program_offset + program_entry_size * program_count > file_size
    ):
        raise ValueError("Container Gate ELF program headers are invalid")

    has_executable_load_segment = False
    for index in range(program_count):
        entry_offset = program_offset + index * program_entry_size
        entry = struct.unpack(
            program_format,
            _pread_exact(descriptor, minimum_entry_size, entry_offset),
        )
        segment_type = int(entry[0])
        if segment_type == _PT_INTERP:
            raise ValueError(
                "Container Gate must be a self-contained static ELF without an interpreter"
            )
        if segment_type == _PT_LOAD:
            if ident[4] == _ELF_CLASS_64:
                segment_flags = int(entry[1])
                segment_offset = int(entry[2])
                segment_file_size = int(entry[5])
            else:
                segment_offset = int(entry[1])
                segment_file_size = int(entry[4])
                segment_flags = int(entry[6])
            if (
                segment_offset > file_size
                or segment_file_size > file_size - segment_offset
            ):
                raise ValueError("Container Gate ELF load segment is outside the file")
            has_executable_load_segment = has_executable_load_segment or bool(
                segment_flags & 0x1
            )
    if not has_executable_load_segment:
        raise ValueError("Container Gate ELF has no executable load segment")


def _pread_exact(descriptor: int, size: int, offset: int) -> bytes:
    try:
        payload = os.pread(descriptor, size, offset)
    except OSError as exc:
        raise ValueError("Container Gate ELF cannot be read safely") from exc
    if len(payload) != size:
        raise ValueError("Container Gate ELF is truncated")
    return payload
