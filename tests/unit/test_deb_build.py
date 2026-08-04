from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/build_deb.py"
_remove_nondeterministic_uv_metadata = cast(
    Callable[[Path], None],
    runpy.run_path(str(_SCRIPT))["_remove_nondeterministic_uv_metadata"],
)


def test_deb_builder_removes_uv_timestamp_metadata_and_record_entry(tmp_path: Path) -> None:
    metadata = tmp_path / "example-1.0.dist-info"
    metadata.mkdir()
    cache = metadata / "uv_cache.json"
    cache.write_text('{"timestamp": 123}\n', encoding="utf-8")
    record = metadata / "RECORD"
    record.write_text(
        "example/__init__.py,sha256=abc,1\n"
        "example-1.0.dist-info/uv_cache.json,sha256=variable,19\n"
        "example-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )

    _remove_nondeterministic_uv_metadata(tmp_path)

    assert not cache.exists()
    assert record.read_text(encoding="utf-8") == (
        "example/__init__.py,sha256=abc,1\n"
        "example-1.0.dist-info/RECORD,,\n"
    )


def test_deb_builder_rejects_ambiguous_uv_record_entries(tmp_path: Path) -> None:
    metadata = tmp_path / "example-1.0.dist-info"
    metadata.mkdir()
    (metadata / "uv_cache.json").write_text("{}", encoding="utf-8")
    duplicate = "example-1.0.dist-info/uv_cache.json,sha256=variable,2\n"
    (metadata / "RECORD").write_text(duplicate + duplicate, encoding="utf-8")

    with pytest.raises(RuntimeError, match="does not uniquely list"):
        _remove_nondeterministic_uv_metadata(tmp_path)
