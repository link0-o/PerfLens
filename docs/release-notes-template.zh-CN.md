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
perflens setup --project /绝对路径/你的项目
```

也可以使用：

```bash
uv tool install ./perflens-{version}-py3-none-any.whl
```

安装后，终端会告诉你中文“下一步”文件的位置。完整说明：[安装与首次使用](https://github.com/link0-o/PerfLens/blob/{tag}/INSTALL.zh-CN.md)。

## 资源怎么选

- `perflens-{version}-py3-none-any.whl`：普通用户安装 CLI、MCP 和 Collector 命令；
- `perflens-{version}.tar.gz`：Python 源码发行包；
- `perflens-performance-analysis-{version}.zip`：只安装独立 Skill 时使用；
- `sbom.cdx.json`：CycloneDX 依赖清单；
- `SHA256SUMS`：四个正式发行产物的 SHA-256 校验。

## 自动采集

分析已有 Profile 不需要 root。实时 PID 自动采集需要管理员审核并部署独立 Collector；Agent 和 MCP 始终保持普通用户权限。先运行 `perflens doctor`，再阅读[产品部署指南](https://github.com/link0-o/PerfLens/blob/{tag}/docs/deployment.zh-CN.md)。

**Full Changelog**：https://github.com/link0-o/PerfLens/commits/{tag}
