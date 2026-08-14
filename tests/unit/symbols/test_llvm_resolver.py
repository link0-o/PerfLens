from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import ModuleIdentity, ModuleLocation
from perflens.symbols.llvm import LlvmSymbolizerResolver, parse_llvm_json_line


def test_parses_inline_llvm_json_frames() -> None:
    payload = json.dumps(
        {
            "Address": "0x10",
            "ModuleName": "app",
            "Symbol": [
                {"FunctionName": "inner", "FileName": "/src/a.cc", "Line": 7, "Column": 2},
                {"FunctionName": "outer", "FileName": "/src/a.cc", "Line": 12, "Column": 1},
            ],
        }
    ).encode()
    frames = parse_llvm_json_line(payload)
    assert [frame.symbol for frame in frames] == ["inner", "outer"]
    assert frames[0].is_inline
    assert not frames[1].is_inline


def test_long_lived_llvm_provider_batches_caches_and_reaps(tmp_path: Path) -> None:
    fake = tmp_path / "llvm-symbolizer"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "for value in sys.stdin:\n"
        "    address = int(value, 16)\n"
        "    print(json.dumps({'Address': value.strip(), 'ModuleName': 'module', "
        "'Symbol': [{'FunctionName': f'function_{address:x}', "
        "'FileName': '/src/sample.cc', 'Line': address, 'Column': 1}]}), flush=True)\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    module_path = tmp_path / "module"
    module_path.write_bytes(b"fixture")
    identity = ModuleIdentity(
        build_id=f"path:{module_path.resolve()}",
        dso_path=module_path,
        debug_file_candidates=(),
        architecture="test",
    )
    locations = (
        ModuleLocation(16, address_kind="module_offset"),
        ModuleLocation(32, address_kind="module_offset"),
    )
    resolver = LlvmSymbolizerResolver(fake)

    first = resolver.resolve_many(identity, locations)
    second = resolver.resolve_many(identity, locations)

    assert [frames[0].symbol for frames in first] == ["function_10", "function_20"]
    assert first == second
    assert resolver.process_count == 1
    (pid,) = resolver.process_pids
    resolver.close()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_llvm_provider_bounds_large_query_batches(tmp_path: Path) -> None:
    fake = tmp_path / "llvm-symbolizer"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "for value in sys.stdin:\n"
        "    address = int(value, 16)\n"
        "    print(json.dumps({'Symbol': [{'FunctionName': str(address), "
        "'FileName': '/src/sample.cc', 'Line': address + 1}]}), flush=True)\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    module_path = tmp_path / "module"
    module_path.write_bytes(b"fixture")
    identity = ModuleIdentity(
        build_id=f"path:{module_path.resolve()}",
        dso_path=module_path,
        debug_file_candidates=(),
        architecture="test",
    )
    locations = tuple(ModuleLocation(value, address_kind="module_offset") for value in range(600))

    with LlvmSymbolizerResolver(fake) as resolver:
        resolved = resolver.resolve_many(identity, locations)

    assert len(resolved) == len(locations)
    assert resolved[0][0].symbol == "0"
    assert resolved[-1][0].symbol == "599"


def test_llvm_provider_validates_executable_and_limits(tmp_path: Path) -> None:
    regular_file = tmp_path / "not-executable"
    regular_file.write_text("data")
    with pytest.raises(PerfLensError) as captured:
        LlvmSymbolizerResolver(regular_file)
    assert captured.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(PerfLensError) as captured:
        LlvmSymbolizerResolver(Path(sys.executable), max_cache_entries=0)
    assert captured.value.code is ErrorCode.INVALID_INPUT
