"""Keep the checked-in documentation usable in both supported languages."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCS_ROOT = PROJECT_ROOT / "docs"


def test_every_english_document_has_a_linked_simplified_chinese_counterpart() -> None:
    english_documents = sorted(
        path for path in DOCS_ROOT.glob("*.md") if not path.name.endswith(".zh-CN.md")
    )

    assert english_documents
    for english in english_documents:
        chinese = english.with_name(f"{english.stem}.zh-CN.md")
        assert chinese.is_file(), f"missing Simplified Chinese document for {english.name}"

        english_text = english.read_text(encoding="utf-8")
        chinese_text = chinese.read_text(encoding="utf-8")
        assert f"]({chinese.name})" in english_text
        assert f"]({english.name})" in chinese_text


def test_release_checksum_command_runs_from_the_manifest_directory() -> None:
    for name in ("releasing.md", "releasing.zh-CN.md"):
        text = (DOCS_ROOT / name).read_text(encoding="utf-8")
        assert "cd dist\n  sha256sum --check SHA256SUMS" in text
        assert "sha256sum --check dist/SHA256SUMS" not in text
