# PerfLens 发布流程

简体中文 | [English](releasing.md)

PerfLens 的正式发布版由不可变的 Python 安装包和独立 Skill 压缩包组成：

- `perflens-<版本>-py3-none-any.whl`
- `perflens-<版本>.tar.gz`
- `perflens-skill-<版本>.zip`
- `perflens_<版本>-<Debian修订号>_amd64.deb`
- `perflens-collector_<版本>-<Debian修订号>_<架构>.deb`
- `sbom.cdx.json`
- `SHA256SUMS`

## 发布前准备

1. 从干净的 `main` 分支开始，并确认所有 CI 检查通过。
2. 将 `pyproject.toml` 和 `src/perflens/_version.py` 修改为相同版本；发布准备脚本会拒绝版本不一致。
3. 把 `CHANGELOG.md` 中面向用户的改动从 `Unreleased` 移入带日期的版本章节。
4. 确认 Python 3.12 和 3.13 仍然受支持。

## 本地验证

```bash
uv sync --all-groups --frozen
uv run ruff check .
uv run pyright
uv run pytest --cov=perflens --cov-fail-under=85
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
  --with dist/perflens-0.2.0-py3-none-any.whl \
  tests/package_smoke.py
uv run --isolated --no-project \
  --with dist/perflens-0.2.0.tar.gz \
  tests/package_smoke.py

uv export --locked --no-dev --no-emit-project \
  --preview-features sbom-export \
  --format cyclonedx1.5 \
  --output-file dist/sbom.cdx.json
uv run python scripts/prepare_release.py --tag v0.2.0
uv run python scripts/render_release_notes.py \
  --tag v0.2.0 \
  --output /tmp/perflens-release-notes.md
sha256sum --check dist/SHA256SUMS
```

执行前应确保 `dist/` 为空。发布准备脚本也会拒绝旧文件或非预期文件，
要求 SBOM 是 CycloneDX JSON，并且只为预期的 wheel、sdist、两个 DEB、Skill
压缩包和 SBOM 生成校验和。DEB 正式构建环境是 Debian 13 `amd64` 的系统
Python 3.13；构建器会固定权限和时间戳，CI 会提取包并执行命令冒烟测试。
`render_release_notes.py` 会从受版本控制的中文模板生成面向普通用户的安装说明；
正式 Release 正文应使用这份文件，而不是只展示提交记录。

## 发布 GitHub Release

只有发布提交已经进入 `main` 后，才创建并推送带注释的版本标签：

```bash
git tag -a v0.2.0 -m "PerfLens v0.2.0"
git push origin v0.2.0
```

`.github/workflows/release.yml` 会检查标签和包版本是否一致，重新运行代码规范、类型、测试、覆盖率、wheel、sdist 和 DEB 冒烟测试，然后创建 GitHub Release。

构建与验证任务只有仓库只读权限，并且 checkout 不保留 Git 凭据。通过全部门禁后，它们
只把一个具名 Release Bundle 交给独立发布任务；只有该任务获得 `contents: write`，而且
不会 checkout 或执行仓库代码，只运行固定提交的产物下载 Action 和
`gh release create`。这样测试脚本、构建后端和项目依赖不会接触发布写权限。

所有外部 GitHub Action 都必须固定到完整提交 SHA。升级 Action 时应检查官方 Release
和源码，同时更新 SHA 与旁边的版本注释，并运行
`tests/unit/test_workflow_security.py`；禁止退回分支名或可移动的大版本标签。Dependabot
每周检查 Action 固定版本和 uv 锁文件，但它创建的 PR 仍需正常审查并通过全部 CI，不能
自动绕过门禁。

发布用 wheel 和源码包会以源码提交时间作为 `SOURCE_DATE_EPOCH` 独立构建两次，再由
`scripts/verify_python_reproducibility.py` 逐字节比较。只要任一包不同，Release 就会
停止。遇到差异应检查构建输入、时间戳和构建后端，不能删掉比较步骤强行发布。

随后，独立证明任务只下载已验证 Bundle，使用固定提交的 `actions/attest` 为每个正式
发行文件签发 SLSA Provenance；它拥有短时 OIDC 与 Attestation 写权限，但不 checkout、
不运行项目代码，也不拥有 Release 写权限。只有证明成功后，另一个隔离任务才创建
GitHub Release。发布完成后至少抽查一个资产：

```bash
gh attestation verify ./dist/perflens-0.2.0-py3-none-any.whl \
  --repo link0-o/PerfLens \
  --signer-workflow link0-o/PerfLens/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

已经发布的版本标签不要重复使用或移动。如果发现问题，应修复后发布新版本。

## 可选：发布到 PyPI

自动发布前，需要在 GitHub 配置受保护的 `pypi` Environment，并在 PyPI 配置 Trusted Publisher。只发布 Python wheel 和源码包，不要把 Skill 压缩包或 SBOM 上传到 PyPI：

```bash
uv publish \
  dist/perflens-0.2.0-py3-none-any.whl \
  dist/perflens-0.2.0.tar.gz
```

PyPI 版本不可覆盖。发布错误时应增加新版本，不应尝试替换已经上传的文件。
