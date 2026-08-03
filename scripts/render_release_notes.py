#!/usr/bin/env python3
"""Render beginner-friendly GitHub Release notes for one immutable tag."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from perflens import __version__

_MAX_TEMPLATE_BYTES = 256 << 10


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--template",
        type=Path,
        default=Path("docs/release-notes-template.zh-CN.md"),
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.tag != f"v{__version__}":
        parser.error(f"release tag must equal v{__version__}")
    try:
        template = arguments.template.resolve(strict=True)
        output_parent = arguments.output.expanduser().parent.resolve(strict=True)
    except OSError as exc:
        parser.error(f"release-note path cannot be resolved: {exc}")
    if not template.is_file():
        parser.error("--template must be a regular file")
    try:
        with template.open("rb") as handle:
            raw = handle.read(_MAX_TEMPLATE_BYTES + 1)
    except OSError as exc:
        parser.error(f"release-note template cannot be read: {exc}")
    if len(raw) > _MAX_TEMPLATE_BYTES:
        parser.error("release-note template exceeds its size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        parser.error(f"release-note template is not UTF-8: {exc}")
    if text.count("{version}") < 1 or text.count("{tag}") < 1:
        parser.error("release-note template requires {version} and {tag} placeholders")
    rendered = text.replace("{version}", __version__).replace("{tag}", arguments.tag)
    output = output_parent / arguments.output.name
    if output.exists() or output.is_symlink():
        parser.error("release-note output already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output)
    except OSError as exc:
        parser.error(f"release notes cannot be written: {exc}")
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
