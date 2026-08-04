# Releasing PerfLens

[简体中文](releasing.zh-CN.md) | English

PerfLens releases are immutable Python distributions plus a standalone Skill
archive. A release contains:

- `perflens-<version>-py3-none-any.whl`
- `perflens-<version>.tar.gz`
- `perflens-performance-analysis-<version>.zip`
- `perflens_<version>-1_amd64.deb`
- `perflens-collector_<version>-1_all.deb`
- `sbom.cdx.json`
- `SHA256SUMS`

## Prepare

1. Work from a clean `main` branch with all CI checks passing.
2. Update both `pyproject.toml` and `src/perflens/_version.py` to the same
   version. Release preparation refuses a mismatch.
3. Move user-visible changes from `Unreleased` to the dated version section in
   `CHANGELOG.md`.
4. Confirm Python 3.12 and 3.13 remain supported.

## Validate locally

```bash
uv sync --all-groups --frozen
uv run ruff check .
uv run pyright
uv run pytest --cov=perflens --cov-fail-under=85
uv build --no-sources
uv run python scripts/build_deb.py \
  --output-directory dist \
  --python /usr/bin/python3 \
  --uv "$(command -v uv)"
uv run python tests/deb_package_smoke.py --directory dist

uv run --isolated --no-project \
  --with dist/perflens-0.1.1-py3-none-any.whl \
  tests/package_smoke.py
uv run --isolated --no-project \
  --with dist/perflens-0.1.1.tar.gz \
  tests/package_smoke.py

uv export --locked --no-dev --no-emit-project \
  --preview-features sbom-export \
  --format cyclonedx1.5 \
  --output-file dist/sbom.cdx.json
uv run python scripts/prepare_release.py --tag v0.1.1
uv run python scripts/render_release_notes.py \
  --tag v0.1.1 \
  --output /tmp/perflens-release-notes.md
sha256sum --check dist/SHA256SUMS
```

Use an empty `dist/` directory. The release-preparation script also rejects
stale or unexpected files, requires a CycloneDX JSON SBOM, and checksums only
the intended wheel, sdist, two DEBs, Skill zip, and SBOM. Official DEBs are
built on Debian 13 `amd64` with system Python 3.13; permissions and timestamps
are normalized before extracted-package command smoke tests.
`render_release_notes.py` renders beginner-oriented installation instructions
from the checked-in Chinese template. Use that file as the GitHub Release body
instead of showing generated commit notes alone.

## Publish a GitHub Release

Create and push an annotated version tag only after the release commit is on
`main`:

```bash
git tag -a v0.1.1 -m "PerfLens v0.1.1"
git push origin v0.1.1
```

`.github/workflows/release.yml` checks that the tag matches the package
version, reruns lint, types, tests, coverage, wheel, sdist, and DEB smoke tests,
then creates the GitHub Release. Build and verification jobs have read-only
repository permission and do not retain checkout credentials. They transfer a
single named release bundle to a separate publisher job; only that job receives
`contents: write`, does not check out or execute repository code, and runs only
the pinned artifact downloader plus `gh release create`. Do not reuse or move a
published version tag.

All external Actions are pinned to full commit SHAs. When upgrading one, review
the official release and source, replace the SHA and adjacent version comment
together, and run `tests/unit/test_workflow_security.py`. Never replace a pin
with a branch or movable major-version tag. Dependabot checks Action pins and
the uv lockfile weekly, but its pull requests still require the normal review
and full CI gates.

The published wheel and source distribution are each built twice with the
source commit timestamp supplied through `SOURCE_DATE_EPOCH`. The release stops
unless `scripts/verify_python_reproducibility.py` confirms byte-for-byte
identity. Treat a mismatch as a build-input or build-backend defect; do not skip
the comparison to publish.

## Optional PyPI publication

Configure a protected `pypi` GitHub environment and a PyPI Trusted Publisher
before enabling automated publication. Publish only the Python distributions,
not the Skill archive or SBOM:

```bash
uv publish \
  dist/perflens-0.1.1-py3-none-any.whl \
  dist/perflens-0.1.1.tar.gz
```

PyPI versions are immutable. If a release is wrong, fix it in a new version
instead of replacing uploaded files.
