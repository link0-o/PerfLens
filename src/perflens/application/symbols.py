"""Application services for ELF inspection and verified source resolution."""

from __future__ import annotations

from pathlib import Path

from perflens.contracts.artifacts import (
    ElfMetadataArtifact,
    ResolvedSourceFrame,
    SourceContextArtifact,
    SourceResolutionArtifact,
)
from perflens.domain.symbols import ModuleLocation
from perflens.symbols.addr2line import Addr2LineResolver
from perflens.symbols.elf import ElfInspector
from perflens.symbols.llvm import LlvmSymbolizerResolver, llvm_symbolizer_path
from perflens.symbols.source import PathMapping, SourceLocator


def inspect_elf(path: Path) -> ElfMetadataArtifact:
    metadata = ElfInspector().inspect(path)
    return ElfMetadataArtifact(
        path=str(metadata.path),
        build_id=metadata.build_id,
        architecture=metadata.architecture,
        elf_type=metadata.elf_type,
        is_pie=metadata.is_pie,
        is_stripped=metadata.is_stripped,
        has_debug_info=metadata.has_debug_info,
        debug_link=metadata.debug_link,
        debug_file_candidates=tuple(str(candidate) for candidate in metadata.debug_file_candidates),
    )


def resolve_source(
    binary_path: Path,
    module_offset: int,
    *,
    runtime_address: int | None = None,
    addr2line_path: Path | None = None,
) -> SourceResolutionArtifact:
    inspector = ElfInspector()
    metadata = inspector.inspect(binary_path)
    identity = inspector.identity(metadata.path)
    if addr2line_path is None and llvm_symbolizer_path() is not None:
        resolver = LlvmSymbolizerResolver()
    else:
        resolver = Addr2LineResolver(addr2line_path)
    try:
        frames = resolver.resolve(
            identity,
            ModuleLocation(
                module_offset=module_offset,
                runtime_ip=runtime_address,
                address_kind="module_offset",
            ),
        )
        resolver_version = resolver.resolver_version
    finally:
        resolver.close()
    warnings: tuple[str, ...] = ()
    if metadata.is_stripped and not any(
        candidate.is_file() for candidate in identity.debug_file_candidates
    ):
        warnings += ("Binary is stripped and no separate debug file was found.",)
    if not any(frame.file is not None and frame.line is not None for frame in frames):
        warnings += ("No source location was resolved for the verified module offset.",)
    return SourceResolutionArtifact(
        resolver_version=resolver_version,
        status="partial" if warnings else "complete",
        build_id=identity.build_id,
        binary_path=str(identity.dso_path),
        module_offset=f"0x{module_offset:x}",
        runtime_address=f"0x{runtime_address:x}" if runtime_address is not None else None,
        frames=tuple(
            ResolvedSourceFrame(
                symbol=frame.symbol,
                file=str(frame.file) if frame.file is not None else None,
                line=frame.line,
                column=frame.column,
                is_inline=frame.is_inline,
            )
            for frame in frames
        ),
        warnings=warnings,
    )


def get_source_context(
    source_path: Path,
    line: int,
    *,
    workspace_root: Path,
    before: int = 20,
    after: int = 20,
    mappings: tuple[PathMapping, ...] = (),
) -> SourceContextArtifact:
    context = SourceLocator(workspace_root, mappings).context(
        source_path,
        line,
        before=before,
        after=after,
    )
    return SourceContextArtifact(
        file=str(context.file),
        line=context.line,
        start_line=context.start_line,
        end_line=context.end_line,
        lines=context.lines,
    )
