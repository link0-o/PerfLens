#!/usr/bin/python3
"""Relocatable entry-point dispatcher for the native Debian package."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast


def main() -> None:
    runtime = Path(__file__).resolve().parent
    sys.path.insert(0, str(runtime))
    command = Path(sys.argv[0]).name
    entry_points = {
        "perflens": ("perflens.cli.app", "main"),
        "perflens-mcp": ("perflens.mcp.server", "main"),
        "perflens-collector": ("perflens.collector_broker.server", "main"),
        "perflens-admin": ("perflens.admin.app", "main"),
    }
    target = entry_points.get(command)
    if target is None:
        print(f"Unsupported PerfLens entry point: {command}", file=sys.stderr)
        raise SystemExit(64)
    module_name, function_name = target
    function = cast(
        Callable[[], None],
        getattr(importlib.import_module(module_name), function_name),
    )
    function()


if __name__ == "__main__":
    main()
