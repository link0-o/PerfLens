"""ELF metadata inspection backed by pyelftools."""

from __future__ import annotations

import binascii
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import ElfMetadata, ModuleIdentity
from perflens.security.paths import validate_input_file

ELF_METADATA_SCHEMA_VERSION = "1.0"
_CRC_CHUNK_BYTES = 64 << 10


@dataclass(frozen=True, slots=True)
class _DebugLink:
    name: str
    crc32: int


class ElfInspector:
    """Read identity and debug capabilities without implementing DWARF resolution."""

    def inspect(self, path: Path) -> ElfMetadata:
        safe_path = validate_input_file(path)
        try:
            with safe_path.open("rb") as handle:
                elf = ELFFile(cast(BinaryIO, handle))
                build_id = _build_id_from_elf(elf)
                debug_link = self._debug_link(elf)
                has_debug_info = elf.get_section_by_name(".debug_info") is not None
                is_stripped = elf.get_section_by_name(".symtab") is None
                elf_type = str(elf.header["e_type"])
                has_interpreter = any(
                    segment.header["p_type"] == "PT_INTERP" for segment in elf.iter_segments()
                )
                candidates = self._debug_candidates(safe_path, build_id, debug_link)
                return ElfMetadata(
                    schema_version=ELF_METADATA_SCHEMA_VERSION,
                    path=safe_path,
                    build_id=build_id,
                    architecture=str(elf.header["e_machine"]),
                    elf_type=elf_type,
                    is_pie=elf_type == "ET_DYN" and has_interpreter,
                    is_stripped=is_stripped,
                    has_debug_info=has_debug_info,
                    debug_link=debug_link.name if debug_link is not None else None,
                    debug_link_crc32=debug_link.crc32 if debug_link is not None else None,
                    debug_file_candidates=candidates,
                )
        except PerfLensError:
            raise
        except Exception as exc:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "elf",
                "Input is not a supported ELF file",
                details={"path": str(safe_path), "exception_type": type(exc).__name__},
            ) from exc

    def identity(self, path: Path) -> ModuleIdentity:
        metadata = self.inspect(path)
        return ModuleIdentity(
            build_id=metadata.build_id or f"path:{metadata.path}",
            dso_path=metadata.path,
            debug_file_candidates=metadata.debug_file_candidates,
            architecture=metadata.architecture,
            debug_link_name=metadata.debug_link,
            debug_link_crc32=metadata.debug_link_crc32,
        )

    @staticmethod
    def _debug_link(elf: ELFFile) -> _DebugLink | None:
        section = elf.get_section_by_name(".gnu_debuglink")
        if section is None:
            return None
        data = section.data()
        terminator = data.find(b"\0")
        if terminator <= 0:
            return None
        crc_offset = (terminator + 1 + 3) & ~3
        if crc_offset + 4 > len(data):
            return None
        try:
            name = data[:terminator].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
        if not name or name in {".", ".."} or Path(name).name != name or len(name) > 255:
            return None
        byte_order = "little" if elf.little_endian else "big"
        return _DebugLink(name, int.from_bytes(data[crc_offset : crc_offset + 4], byte_order))

    @staticmethod
    def _debug_candidates(
        path: Path, build_id: str | None, debug_link: _DebugLink | None
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []
        if debug_link is not None:
            for candidate in (
                path.parent / debug_link.name,
                path.parent / ".debug" / debug_link.name,
            ):
                resolved = _regular_file(candidate)
                if resolved is not None and _file_crc32(resolved) == debug_link.crc32:
                    candidates.append(resolved)
        if build_id is not None and len(build_id) > 2:
            resolved = _regular_file(
                Path("/usr/lib/debug/.build-id") / build_id[:2] / f"{build_id[2:]}.debug"
            )
            if resolved is not None and _elf_build_id(resolved) == build_id:
                candidates.append(resolved)
        return tuple(dict.fromkeys(candidates))


def select_verified_module_path(module: ModuleIdentity) -> Path:
    """Select only the original ELF or a debug file bound by Build ID/debuglink CRC."""
    original = module.dso_path.expanduser().resolve(strict=False)
    for candidate in (*module.debug_file_candidates, module.dso_path):
        resolved = _regular_file(candidate)
        if resolved is None:
            continue
        if resolved == original:
            if module.build_id == f"path:{original}" or _elf_build_id(resolved) == module.build_id:
                return resolved
            continue
        if _elf_build_id(resolved) == module.build_id:
            return resolved
        if (
            module.debug_link_name is not None
            and module.debug_link_crc32 is not None
            and _file_crc32(resolved) == module.debug_link_crc32
        ):
            return resolved
    raise PerfLensError(
        ErrorCode.INVALID_INPUT,
        "symbolization",
        "No identity-verified module or debug file candidate can be resolved",
        details={"dso_path": str(module.dso_path)},
    )


def _regular_file(path: Path) -> Path | None:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_file() else None


def _elf_build_id(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            return _build_id_from_elf(ELFFile(cast(BinaryIO, handle)))
    except Exception:
        return None


def _build_id_from_elf(elf: ELFFile) -> str | None:
    for section in elf.iter_sections():
        if not isinstance(section, NoteSection):
            continue
        for note in section.iter_notes():
            if note["n_type"] != "NT_GNU_BUILD_ID":
                continue
            descriptor = note["n_desc"]
            if isinstance(descriptor, bytes):
                return descriptor.hex()
            return str(descriptor).lower()
    return None


def read_elf_build_id(handle: BinaryIO) -> str | None:
    """Read a Build ID from an already identity-pinned file descriptor.

    Container callers use this entry point so resolving a path cannot introduce a
    second file-open race after the module has been confined beneath the target
    process root.
    """
    handle.seek(0)
    return _build_id_from_elf(ELFFile(handle))


def _file_crc32(path: Path) -> int | None:
    checksum = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(_CRC_CHUNK_BYTES):
                checksum = binascii.crc32(chunk, checksum)
    except OSError:
        return None
    return checksum & 0xFFFF_FFFF
