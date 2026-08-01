from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from perflens.application.symbols import inspect_elf, resolve_source
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import ModuleLocation
from perflens.symbols.addr2line import Addr2LineResolver, parse_addr2line_group
from perflens.symbols.elf import ElfInspector


def _tool(name: str) -> str:
    path = shutil.which(name)
    assert path is not None
    return str(Path(path).resolve())


def _compile(source: Path, output: Path, *options: str) -> None:
    subprocess.run(  # noqa: S603 - fixed compiler resolved from PATH for test fixture
        (_tool("gcc"), "-g", "-O0", "-fno-inline", *options, "-o", str(output), str(source)),
        check=True,
        capture_output=True,
    )


def _symbol_address(binary: Path, symbol: str) -> int:
    result = subprocess.run(  # noqa: S603
        (_tool("nm"), "-n", str(binary)),
        check=True,
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) != 3:
            continue
        address, _kind, name = parts
        if name == symbol:
            return int(address, 16)
    raise AssertionError(f"symbol not found: {symbol}")


def test_inspects_pie_shared_library_build_id_and_debug_info(
    fixture_root: Path, tmp_path: Path
) -> None:
    source = fixture_root / "symbols" / "sample.c"
    executable = tmp_path / "sample"
    shared = tmp_path / "libsample.so"
    _compile(source, executable)
    _compile(source, shared, "-shared", "-fPIC")

    inspector = ElfInspector()
    executable_metadata = inspector.inspect(executable)
    shared_metadata = inspector.inspect(shared)

    assert executable_metadata.schema_version == "1.0"
    assert executable_metadata.build_id
    assert executable_metadata.has_debug_info
    assert executable_metadata.is_pie
    assert not executable_metadata.is_stripped
    assert shared_metadata.elf_type == "ET_DYN"
    assert not shared_metadata.is_pie
    artifact = inspect_elf(executable)
    assert artifact.build_id == executable_metadata.build_id


def test_long_lived_resolver_matches_source_golden_and_reuses_process(
    fixture_root: Path, tmp_path: Path
) -> None:
    source = fixture_root / "symbols" / "sample.c"
    executable = tmp_path / "sample"
    _compile(source, executable)
    address = _symbol_address(executable, "perflens_hot_function")
    identity = ElfInspector().identity(executable)

    with Addr2LineResolver(Path(_tool("addr2line"))) as resolver:
        first = resolver.resolve(
            identity,
            ModuleLocation(module_offset=address, address_kind="module_offset"),
        )
        second = resolver.resolve(
            identity,
            ModuleLocation(module_offset=address, address_kind="module_offset"),
        )
        assert resolver.process_count == 1
        assert first == second
        actual = {
            "symbol": first[0].symbol,
            "file": first[0].file.name if first[0].file is not None else None,
            "line": first[0].line,
            "is_inline": first[0].is_inline,
        }

    expected = json.loads(
        (fixture_root / "golden" / "symbol-resolution.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected

    application_result = resolve_source(
        executable,
        address,
        addr2line_path=Path(_tool("addr2line")),
    )
    assert application_result.status == "complete"
    assert application_result.frames[0].line == 3


def test_separate_debug_file_resolves_stripped_binary(fixture_root: Path, tmp_path: Path) -> None:
    source = fixture_root / "symbols" / "sample.c"
    executable = tmp_path / "sample"
    debug_file = tmp_path / "sample.debug"
    _compile(source, executable)
    address = _symbol_address(executable, "perflens_hot_function")
    subprocess.run(  # noqa: S603
        (_tool("objcopy"), "--only-keep-debug", str(executable), str(debug_file)),
        check=True,
    )
    subprocess.run(  # noqa: S603
        (_tool("strip"), "--strip-unneeded", str(executable)),
        check=True,
    )
    subprocess.run(  # noqa: S603
        (_tool("objcopy"), f"--add-gnu-debuglink={debug_file.name}", str(executable)),
        cwd=tmp_path,
        check=True,
    )

    inspector = ElfInspector()
    metadata = inspector.inspect(executable)
    assert metadata.is_stripped
    assert not metadata.has_debug_info
    assert metadata.debug_link == "sample.debug"
    with Addr2LineResolver(Path(_tool("addr2line"))) as resolver:
        resolved = resolver.resolve(
            inspector.identity(executable),
            ModuleLocation(module_offset=address, address_kind="module_offset"),
        )
    assert resolved[0].symbol == "perflens_hot_function"
    assert resolved[0].line == 3


def test_runtime_only_address_is_rejected_without_guessing(
    fixture_root: Path, tmp_path: Path
) -> None:
    executable = tmp_path / "sample"
    _compile(fixture_root / "symbols" / "sample.c", executable)
    identity = ElfInspector().identity(executable)
    with (
        Addr2LineResolver(Path(_tool("addr2line"))) as resolver,
        pytest.raises(PerfLensError) as captured,
    ):
        resolver.resolve(
            identity,
            ModuleLocation(
                module_offset=None,
                runtime_ip=0x7F0000001234,
                address_kind="runtime_only",
            ),
        )
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_inline_protocol_output_preserves_all_frames() -> None:
    frames = parse_addr2line_group(
        (
            b"inner(int)",
            b"/workspace/sample.cc:7",
            b"outer()",
            b"/workspace/sample.cc:12:3",
        )
    )
    assert [frame.symbol for frame in frames] == ["inner(int)", "outer()"]
    assert frames[0].is_inline
    assert frames[1].column == 3


def test_non_elf_is_rejected(tmp_path: Path) -> None:
    text = tmp_path / "not-elf"
    text.write_text("hello")
    with pytest.raises(PerfLensError) as captured:
        ElfInspector().inspect(text)
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_resolver_process_is_reaped_on_close(fixture_root: Path, tmp_path: Path) -> None:
    executable = tmp_path / "sample"
    _compile(fixture_root / "symbols" / "sample.c", executable)
    address = _symbol_address(executable, "perflens_hot_function")
    resolver = Addr2LineResolver(Path(_tool("addr2line")))
    resolver.resolve(
        ElfInspector().identity(executable),
        ModuleLocation(module_offset=address, address_kind="module_offset"),
    )
    (pid,) = resolver.process_pids
    resolver.close()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_addr2line_resolver_rejects_invalid_timeout() -> None:
    with pytest.raises(PerfLensError) as captured:
        Addr2LineResolver(Path(_tool("addr2line")), timeout_seconds=0)
    assert captured.value.code is ErrorCode.INVALID_INPUT
