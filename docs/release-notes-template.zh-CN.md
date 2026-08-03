# PerfLens {version}

PerfLens 是面向 Linux 的确定性性能分析工具，包含 CLI、MCP Server、Performance Analysis Skill，以及可选的受限 Collector Broker。

## 第一次下载请看这里

普通用户下载：

```text
perflens-{version}-py3-none-any.whl
```

**`.whl` 不要解压。** 它不是双击运行的 ZIP，请在下载目录使用：

```bash
pipx install ./perflens-{version}-py3-none-any.whl
perflens setup \
  --project /绝对路径/你的项目 \
  --prepare-collector \
  --automatic-collection
```

也可以使用：

```bash
uv tool install ./perflens-{version}-py3-none-any.whl
```

安装后，终端会告诉你中文“下一步”文件的位置。完整说明：[安装与首次使用](https://github.com/link0-o/PerfLens/blob/{tag}/INSTALL.zh-CN.md)。

## 资源怎么选

- `perflens-{version}-py3-none-any.whl`：安装 CLI、MCP、Skill、Collector 和
  显式管理员部署入口；
- `perflens-{version}.tar.gz`：Python 源码发行包；
- `perflens-performance-analysis-{version}.zip`：只安装独立 Skill 时使用；
- `sbom.cdx.json`：CycloneDX 依赖清单；
- `SHA256SUMS`：四个正式发行产物的 SHA-256 校验。

## 自动采集

分析已有 Profile 不需要 root。实时自动采集需要管理员审核并部署独立 Collector；
Agent 和 MCP 始终保持普通用户权限。检查引导生成的 `collector.toml` 后，可以先执行
`/opt/perflens/bin/perflens-admin deploy --config <配置> --dry-run`，再由管理员执行一次
同样的命令（加 `sudo`、去掉 `--dry-run`）。之后用户可以直接说“优化当前项目的性能”，
确认具体程序和参数后由 PerfLens 自动取得新 PID。先运行 `perflens doctor`，再阅读
[产品部署指南](https://github.com/link0-o/PerfLens/blob/{tag}/docs/deployment.zh-CN.md)。

**Full Changelog**：https://github.com/link0-o/PerfLens/commits/{tag}
