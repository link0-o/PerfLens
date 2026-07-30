"""ELF metadata inspection backed by pyelftools."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, cast

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import ElfMetadata, ModuleIdentity
from perflens.security.paths import validate_input_file

ELF_METADATA_SCHEMA_VERSION = "1.0"


class ElfInspector:
    """Read identity and debug capabilities without implementing DWARF resolution."""

    def inspect(self, path: Path) -> ElfMetadata:
        safe_path = validate_input_file(path)
        try:
            with safe_path.open("rb") as handle:
                elf = ELFFile(cast(BinaryIO, handle))
                build_id = self._build_id(elf)
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
                    debug_link=debug_link,
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
        )

    @staticmethod
    def _build_id(elf: ELFFile) -> str | None:
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

    @staticmethod
    def _debug_link(elf: ELFFile) -> str | None:
        section = elf.get_section_by_name(".gnu_debuglink")
        if section is None:
            return None
        raw = section.data().split(b"\0", maxsplit=1)[0]
        return raw.decode("utf-8", errors="replace") or None

    @staticmethod
    def _debug_candidates(
        path: Path, build_id: str | None, debug_link: str | None
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []
        if debug_link is not None:
            candidates.extend((path.parent / debug_link, path.parent / ".debug" / debug_link))
        if build_id is not None and len(build_id) > 2:
            candidates.append(
                Path("/usr/lib/debug/.build-id") / build_id[:2] / f"{build_id[2:]}.debug"
            )
        return tuple(candidate.resolve(strict=False) for candidate in candidates)
