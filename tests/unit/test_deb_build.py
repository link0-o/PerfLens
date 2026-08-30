from __future__ import annotations

import runpy
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from perflens.runtime_locks.native_pthread_abi import NATIVE_PTHREAD_WRAPPER_LOCK_KINDS

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/build_deb.py"
_remove_nondeterministic_uv_metadata = cast(
    Callable[[Path], None],
    runpy.run_path(str(_SCRIPT))["_remove_nondeterministic_uv_metadata"],
)
_install_maintainer_script = cast(
    Callable[[Path, str, Path], None],
    runpy.run_path(str(_SCRIPT))["_install_maintainer_script"],
)
_validate_pthread_probe_library = cast(
    Callable[[Path], None],
    runpy.run_path(str(_SCRIPT))["_validate_pthread_probe_library"],
)
_MAIN_GLIBC_FLOOR = cast(str, runpy.run_path(str(_SCRIPT))["_MAIN_GLIBC_FLOOR"])


def _synthetic_probe_source(*, malformed_mutex_lock: str) -> str:
    wrappers: list[str] = []
    for name in NATIVE_PTHREAD_WRAPPER_LOCK_KINDS:
        if name == "pthread_mutex_lock":
            wrappers.append(malformed_mutex_lock)
        else:
            wrappers.append(f'__attribute__((visibility("default"))) void {name}(void) {{}}')
    return "\n".join(
        [
            '__attribute__((visibility("default"))) unsigned int '
            "perflens_pthread_probe_abi_version = 1;",
            '__attribute__((visibility("default"))) char '
            'perflens_pthread_probe_protocol_version[4] = "1.0";',
            *wrappers,
        ]
    )


def test_deb_builder_removes_variable_install_metadata_and_record_entries(
    tmp_path: Path,
) -> None:
    metadata = tmp_path / "example-1.0.dist-info"
    metadata.mkdir()
    cache = metadata / "uv_cache.json"
    cache.write_text('{"timestamp": 123}\n', encoding="utf-8")
    direct_url = metadata / "direct_url.json"
    direct_url.write_text('{"url": "file:///tmp/build-a/package.whl"}\n', encoding="utf-8")
    record = metadata / "RECORD"
    record.write_text(
        "example/__init__.py,sha256=abc,1\n"
        "example-1.0.dist-info/uv_cache.json,sha256=variable,19\n"
        "example-1.0.dist-info/direct_url.json,sha256=path,44\n"
        "example-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )

    _remove_nondeterministic_uv_metadata(tmp_path)

    assert not cache.exists()
    assert not direct_url.exists()
    assert record.read_text(encoding="utf-8") == (
        "example/__init__.py,sha256=abc,1\nexample-1.0.dist-info/RECORD,,\n"
    )


def test_deb_builder_rejects_ambiguous_uv_record_entries(tmp_path: Path) -> None:
    metadata = tmp_path / "example-1.0.dist-info"
    metadata.mkdir()
    (metadata / "uv_cache.json").write_text("{}", encoding="utf-8")
    duplicate = "example-1.0.dist-info/uv_cache.json,sha256=variable,2\n"
    (metadata / "RECORD").write_text(duplicate + duplicate, encoding="utf-8")

    with pytest.raises(RuntimeError, match="does not uniquely list"):
        _remove_nondeterministic_uv_metadata(tmp_path)


def test_main_deb_glibc_floor_matches_native_probe_matrix() -> None:
    assert _MAIN_GLIBC_FLOOR == "2.36"


def test_deb_builder_installs_only_known_executable_maintainer_scripts(
    tmp_path: Path,
) -> None:
    (tmp_path / "DEBIAN").mkdir()
    source = tmp_path / "source"
    source.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    _install_maintainer_script(tmp_path, "postinst", source)

    installed = tmp_path / "DEBIAN/postinst"
    assert installed.read_bytes() == source.read_bytes()
    assert installed.stat().st_mode & 0o777 == 0o755
    with pytest.raises(ValueError, match="unsupported"):
        _install_maintainer_script(tmp_path, "arbitrary", source)


def _compile_probe(
    tmp_path: Path,
    *,
    source: Path,
    name: str,
    compile_flags: tuple[str, ...] = (),
    link_flags: tuple[str, ...] = ("-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack",),
) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is required for the Native pthread DEB validation test")
    output = tmp_path / name
    subprocess.run(  # noqa: S603 - fixed compiler and test-owned source/output
        [
            compiler,
            "-std=c11",
            "-shared",
            "-fPIC",
            "-fvisibility=hidden",
            *compile_flags,
            str(source),
            *link_flags,
            "-ldl",
            "-pthread",
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return output


def test_deb_builder_accepts_only_hardened_native_pthread_probe(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    probe = _compile_probe(
        tmp_path,
        source=project_root / "native/pthread_probe/perflens_pthread_probe.c",
        name="libperflens-pthread-probe.so",
    )

    _validate_pthread_probe_library(probe)

    missing_markers_source = tmp_path / "missing-markers.c"
    missing_markers_source.write_text(
        "int unrelated_symbol(void) { return 0; }\n",
        encoding="utf-8",
    )
    missing_markers = _compile_probe(
        tmp_path,
        source=missing_markers_source,
        name="missing-markers.so",
    )
    with pytest.raises(ValueError, match="exports"):
        _validate_pthread_probe_library(missing_markers)

    data_wrapper_source = tmp_path / "data-wrapper.c"
    data_wrapper_source.write_text(
        _synthetic_probe_source(
            malformed_mutex_lock=(
                '__attribute__((visibility("default"))) int pthread_mutex_lock = 1;'
            )
        ),
        encoding="utf-8",
    )
    data_wrapper = _compile_probe(
        tmp_path,
        source=data_wrapper_source,
        name="data-wrapper.so",
    )
    with pytest.raises(ValueError, match="executable global functions"):
        _validate_pthread_probe_library(data_wrapper)

    nonexec_function_source = tmp_path / "nonexec-function.c"
    nonexec_function_source.write_text(
        _synthetic_probe_source(
            malformed_mutex_lock=(
                '__asm__(".section .data\\n.global pthread_mutex_lock\\n'
                ".type pthread_mutex_lock,@function\\npthread_mutex_lock:\\n.byte 0\\n"
                '.size pthread_mutex_lock,.-pthread_mutex_lock\\n.text");'
            )
        ),
        encoding="utf-8",
    )
    nonexec_function = _compile_probe(
        tmp_path,
        source=nonexec_function_source,
        name="nonexec-function.so",
    )
    with pytest.raises(ValueError, match="executable global functions"):
        _validate_pthread_probe_library(nonexec_function)

    executable_stack = _compile_probe(
        tmp_path,
        source=project_root / "native/pthread_probe/perflens_pthread_probe.c",
        name="executable-stack.so",
        link_flags=("-Wl,-z,defs,-z,relro,-z,now,-z,execstack",),
    )
    with pytest.raises(ValueError, match="executable stack"):
        _validate_pthread_probe_library(executable_stack)

    lazy_binding = _compile_probe(
        tmp_path,
        source=project_root / "native/pthread_probe/perflens_pthread_probe.c",
        name="lazy-binding.so",
        link_flags=("-Wl,-z,defs,-z,relro,-z,noexecstack",),
    )
    with pytest.raises(ValueError, match="immediate relocation"):
        _validate_pthread_probe_library(lazy_binding)

    wrong_markers = _compile_probe(
        tmp_path,
        source=project_root / "native/pthread_probe/perflens_pthread_probe.c",
        name="wrong-markers.so",
        compile_flags=(
            "-DPERFLENS_PTHREAD_PROBE_ABI_VERSION=2",
            '-DPERFLENS_PTHREAD_PROBE_PROTOCOL_VERSION="2.0"',
        ),
    )
    with pytest.raises(ValueError, match="ABI marker values"):
        _validate_pthread_probe_library(wrong_markers)

    extra_export_source = tmp_path / "extra-export.c"
    extra_export_source.write_text(
        f'#include "{project_root / "native/pthread_probe/perflens_pthread_probe.c"}"\n'
        '__attribute__((visibility("default"))) int unsafe_extra_export(void) { return 0; }\n',
        encoding="utf-8",
    )
    extra_export = _compile_probe(
        tmp_path,
        source=extra_export_source,
        name="extra-export.so",
    )
    with pytest.raises(ValueError, match="exports"):
        _validate_pthread_probe_library(extra_export)

    extra_dependency = _compile_probe(
        tmp_path,
        source=project_root / "native/pthread_probe/perflens_pthread_probe.c",
        name="extra-dependency.so",
        link_flags=(
            "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack",
            "-Wl,--no-as-needed",
            "-lm",
            "-Wl,--as-needed",
        ),
    )
    with pytest.raises(ValueError, match="dependencies"):
        _validate_pthread_probe_library(extra_dependency)


def test_deb_builder_rejects_non_elf_native_pthread_probe(tmp_path: Path) -> None:
    invalid = tmp_path / "libperflens-pthread-probe.so"
    invalid.write_bytes(b"not an ELF shared object")
    with pytest.raises(ValueError):
        _validate_pthread_probe_library(invalid)
