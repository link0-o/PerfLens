# PerfLens 发布流程

简体中文 | [English](releasing.md)

PerfLens 的正式发布版由不可变的 Python 安装包和独立 Skill 压缩包组成：

- `perflens-<版本>-py3-none-any.whl`
- `perflens-<版本>.tar.gz`
- `perflens-performance-analysis-<版本>.zip`
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
uv build --no-sources

uv run --isolated --no-project \
  --with dist/perflens-0.1.0-py3-none-any.whl \
  tests/package_smoke.py
uv run --isolated --no-project \
  --with dist/perflens-0.1.0.tar.gz \
  tests/package_smoke.py

uv export --locked --no-dev --no-emit-project \
  --preview-features sbom-export \
  --format cyclonedx1.5 \
  --output-file dist/sbom.cdx.json
uv run python scripts/prepare_release.py --tag v0.1.0
sha256sum --check dist/SHA256SUMS
```

执行前应确保 `dist/` 为空，避免旧产物被错误写入校验和清单。

## 发布 GitHub Release

只有发布提交已经进入 `main` 后，才创建并推送带注释的版本标签：

```bash
git tag -a v0.1.0 -m "PerfLens v0.1.0"
git push origin v0.1.0
```

`.github/workflows/release.yml` 会检查标签和包版本是否一致，重新运行代码规范、类型、测试、覆盖率、wheel 和 sdist 冒烟测试，然后创建包含五类产物的 GitHub Release。

已经发布的版本标签不要重复使用或移动。如果发现问题，应修复后发布新版本。

## 可选：发布到 PyPI

自动发布前，需要在 GitHub 配置受保护的 `pypi` Environment，并在 PyPI 配置 Trusted Publisher。只发布 Python wheel 和源码包，不要把 Skill 压缩包或 SBOM 上传到 PyPI：

```bash
uv publish \
  dist/perflens-0.1.0-py3-none-any.whl \
  dist/perflens-0.1.0.tar.gz
```

PyPI 版本不可覆盖。发布错误时应增加新版本，不应尝试替换已经上传的文件。
