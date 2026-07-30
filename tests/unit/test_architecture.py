from __future__ import annotations

import ast
from pathlib import Path


def test_domain_layer_has_no_boundary_or_adapter_dependencies() -> None:
    project_root = Path(__file__).resolve().parents[2]
    domain_root = project_root / "src" / "perflens" / "domain"
    forbidden = (
        "pydantic",
        "typer",
        "perflens.application",
        "perflens.artifacts",
        "perflens.cli",
        "perflens.contracts",
        "perflens.profiles",
    )
    violations: list[str] = []

    for source_path in sorted(domain_root.glob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            modules: tuple[str, ...]
            if isinstance(node, ast.Import):
                modules = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                modules = (node.module,)
            else:
                continue
            for module in modules:
                if module.startswith(forbidden):
                    violations.append(f"{source_path.name}:{node.lineno}: {module}")

    assert violations == []
