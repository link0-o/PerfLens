"""Markdown report rendering through a packaged Jinja2 template."""

from __future__ import annotations

from importlib import resources

from jinja2 import Environment, StrictUndefined

from perflens.contracts.artifacts import AnalysisArtifact, DiagnosisBundle


def render_markdown_report(
    analysis: AnalysisArtifact,
    diagnosis: DiagnosisBundle,
    *,
    problem_statement: str = "Not supplied.",
    target_metric: str = "Not supplied.",
) -> str:
    template_text = (
        resources.files("perflens.reporting.templates")
        .joinpath("analysis.md.j2")
        .read_text(encoding="utf-8")
    )
    environment = Environment(
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - output is Markdown, not HTML
        keep_trailing_newline=True,
    )
    template = environment.from_string(template_text)
    unknown_self_weight = sum(
        hotspot.self_weight
        for hotspot in analysis.hotspots
        if hotspot.symbol in {"unknown", "[unknown]", "??"}
        or hotspot.dso in {"unknown", "[unknown]"}
    )
    unresolved_percent = (
        round(unknown_self_weight * 100 / analysis.metadata.total_weight, 3)
        if analysis.metadata.total_weight
        else 0.0
    )
    return template.render(
        analysis=analysis,
        diagnosis=diagnosis,
        problem_statement=problem_statement,
        target_metric=target_metric,
        unresolved_percent=unresolved_percent,
    )
