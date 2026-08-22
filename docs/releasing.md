# Releasing PerfLens

[简体中文](releasing.zh-CN.md) | English

PerfLens releases are immutable Python distributions plus a standalone Skill
archive. A release contains:

- `perflens-<version>-py3-none-any.whl`
- `perflens-<version>.tar.gz`
- `perflens-skill-<version>.zip`
- `perflens_<version>-<Debian-revision>_amd64.deb`
- `perflens-collector_<version>-<Debian-revision>_<architecture>.deb`
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

The commands below use the planned next version as an example. Set
`perflens_release_version` to the exact version already written in both source
files before running them.

```bash
perflens_release_version=0.3.1
perflens_release_tag="v${perflens_release_version}"
uv sync --all-groups --frozen
uv run ruff check .
uv run pyright
uv run pytest --cov=perflens --cov-fail-under=85
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
cargo deny check
cargo build --release --locked \
  --package perflens-container-gate \
  --package perflens-privileged-helper \
  --package perflens-trace-helper
perflens_source_epoch="$(git log -1 --format=%ct)"
perflens_repro_dir="$(mktemp -d)"
SOURCE_DATE_EPOCH="$perflens_source_epoch" uv build --no-sources --out-dir dist
SOURCE_DATE_EPOCH="$perflens_source_epoch" uv build \
  --no-sources --out-dir "$perflens_repro_dir"
uv run python scripts/verify_python_reproducibility.py \
  --directory dist \
  --reproducible-directory "$perflens_repro_dir"
uv run python scripts/build_deb.py \
  --output-directory dist \
  --python /usr/bin/python3 \
  --uv "$(command -v uv)"
uv run python tests/deb_package_smoke.py --directory dist

uv run --isolated --no-project \
  --with "dist/perflens-${perflens_release_version}-py3-none-any.whl" \
  tests/package_smoke.py
uv run --isolated --no-project \
  --with "dist/perflens-${perflens_release_version}.tar.gz" \
  tests/package_smoke.py

uv export --locked --no-dev --no-emit-project \
  --preview-features sbom-export \
  --format cyclonedx1.5 \
  --output-file dist/sbom.cdx.json
uv run python scripts/prepare_release.py --tag "$perflens_release_tag"
uv run python scripts/render_release_notes.py \
  --tag "$perflens_release_tag" \
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
perflens_release_tag=v0.3.1
git tag -a "$perflens_release_tag" -m "PerfLens ${perflens_release_tag}"
git push origin "$perflens_release_tag"
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

An isolated attestation job then downloads only the verified bundle and uses a
pinned `actions/attest` to issue SLSA provenance for every downloadable asset.
It receives short-lived OIDC and attestation-write permissions, but has no
checkout, project-code execution, or Release-write permission. The separate
publisher runs only after attestation succeeds. After publication, spot-check
at least one asset:

```bash
perflens_release_version=0.3.1
gh attestation verify "./dist/perflens-${perflens_release_version}-py3-none-any.whl" \
  --repo link0-o/PerfLens \
  --signer-workflow link0-o/PerfLens/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

## Optional PyPI publication

Configure a protected `pypi` GitHub environment and a PyPI Trusted Publisher
before enabling automated publication. Publish only the Python distributions,
not the Skill archive or SBOM:

```bash
perflens_release_version=0.3.1
uv publish \
  "dist/perflens-${perflens_release_version}-py3-none-any.whl" \
  "dist/perflens-${perflens_release_version}.tar.gz"
```

PyPI versions are immutable. If a release is wrong, fix it in a new version
instead of replacing uploaded files.
