# PerfLens {version}

PerfLens 是面向 Linux 的确定性性能分析工具，包含 CLI、MCP Server、Performance Analysis Skill，以及可选的受限 Collector Broker。

## 第一次下载请看这里

Debian 13 `amd64` 用户优先下载：

```text
perflens_{version}-1_amd64.deb
```

```bash
sudo apt install ./perflens_{version}-1_amd64.deb
perflens setup --project /绝对路径/你的项目
```

其他 Linux 用户下载：

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
- `perflens_{version}-1_amd64.deb`：Debian 13 普通用户主安装包；
- `perflens-collector_{version}-1_all.deb`：可选 Collector 管理入口，必须与
  同版本主 DEB 一起安装；安装时不会自动启用服务；
- `perflens-{version}.tar.gz`：Python 源码发行包；
- `perflens-performance-analysis-{version}.zip`：只安装独立 Skill 时使用；
- `sbom.cdx.json`：CycloneDX 依赖清单；
- `SHA256SUMS`：六个正式发行产物的 SHA-256 校验。

## 自动采集

分析已有 Profile 不需要 root。实时自动采集需要管理员审核并部署独立 Collector；
Agent 和 MCP 始终保持普通用户权限。检查引导生成的 `collector.toml` 后，可以先执行
`perflens-admin deploy --config <配置> --dry-run`，再由管理员执行一次
同样的命令（加 `sudo`、去掉 `--dry-run`）。之后用户可以直接说“优化当前项目的性能”，
确认具体程序和参数后由 PerfLens 自动取得新 PID。用户重新登录后可先运行
`perflens accept-collector --authorize-host-acceptance`，用内置负载完成无需 PID 的
真实短时验收。先运行 `perflens doctor`，再阅读
[产品部署指南](https://github.com/link0-o/PerfLens/blob/{tag}/docs/deployment.zh-CN.md)。

Collector 还会在启动 perf 前检查 spool 总字节数、文件数和文件系统空闲余量；达到
管理员配置的边界时拒绝新采集，但不会自动删除旧证据。
部署后运行 `perflens-admin spool-status` 可用中文只读检查存储余量；需要版本化机器
可读证据时加 `--json`。
每套 Collector 只允许一个普通用户 UID，避免共享 `perflens` 组导致 Profile 跨用户泄露。

旧证据不会按时间自动删除。管理员可先用 `archive-spool --dry-run` 审查选择结果，再创建
带版本化 manifest 与逐文件 SHA-256 的 root 管理 ZIP。只有完成独立备份、运行
`prune-archived-spool --dry-run` 并逐项确认后，才输入
`I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE` 清理完全匹配的原文件；归档始终保留。

后续升级先安装新版本，再运行 `sudo perflens-admin upgrade --dry-run` 和
`sudo perflens-admin upgrade`。升级器保留管理员策略与历史证据，只替换可信托管 unit，
失败时尝试恢复；完成后用普通用户重新运行 `accept-collector` 验收。
部署和升级还会完成一次只读 Collector 健康协议往返，双方身份由内核 peer 凭据复核，
不会把遗留、无人监听或错误服务 UID 的 Socket 误判为成功。

需要调整模式、时长、事件或存储配额时，把当前 TOML 复制为权限 `0600` 的独立候选，
先运行 `perflens-admin update-policy --config <候选> --dry-run`，再由管理员加 `sudo`
应用。它自动重启、健康检查并在失败时恢复原策略，同时拒绝迁移授权 UID 或固定 spool。

**Full Changelog**：https://github.com/link0-o/PerfLens/commits/{tag}
