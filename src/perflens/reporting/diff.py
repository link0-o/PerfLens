"""Markdown rendering for profile and benchmark comparisons."""

from __future__ import annotations

from importlib import resources

from jinja2 import Environment, StrictUndefined

from perflens.contracts.artifacts import BenchmarkComparison, ProfileComparison


def render_profile_comparison(comparison: ProfileComparison) -> str:
    return _render("profile-comparison.md.j2", comparison=comparison)


def render_benchmark_comparison(comparison: BenchmarkComparison) -> str:
    return _render("benchmark-comparison.md.j2", comparison=comparison)


def _render(template_name: str, **context: object) -> str:
    template_text = (
        resources.files("perflens.reporting.templates")
        .joinpath(template_name)
        .read_text(encoding="utf-8")
    )
    environment = Environment(
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - output is Markdown, not HTML
        keep_trailing_newline=True,
    )
    return environment.from_string(template_text).render(**context)
