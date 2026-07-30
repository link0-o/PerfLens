from __future__ import annotations

from pathlib import Path

import pytest

from perflens.application.symbols import get_source_context
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.symbols.source import PathMapping, SourceLocator


def test_maps_container_path_and_returns_bounded_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    source_root = workspace / "src"
    source_root.mkdir(parents=True)
    source = source_root / "main.cc"
    source.write_text("one\ntwo\nthree\nfour\nfive\n")
    locator = SourceLocator(
        workspace,
        (PathMapping(Path("/container/src"), source_root),),
    )

    context = locator.context(Path("/container/src/main.cc"), 3, before=1, after=1)

    assert context.schema_version == "1.0"
    assert context.start_line == 2
    assert context.end_line == 4
    assert context.lines == ("two", "three", "four")
    artifact = get_source_context(
        Path("/container/src/main.cc"),
        3,
        workspace_root=workspace,
        before=1,
        after=1,
        mappings=(PathMapping(Path("/container/src"), source_root),),
    )
    assert artifact.lines == ("two", "three", "four")


def test_workspace_escape_and_symlink_escape_are_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "secret.cc"
    outside.write_text("secret\n")
    symlink = workspace / "link.cc"
    symlink.symlink_to(outside)
    locator = SourceLocator(workspace)

    for path in (outside, symlink):
        with pytest.raises(PerfLensError) as captured:
            locator.context(path, 1)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_source_context_range_is_bounded(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "main.c"
    source.write_text("line\n")
    locator = SourceLocator(workspace)
    with pytest.raises(PerfLensError, match="Invalid source context range"):
        locator.context(source, 1, before=300, after=300)
