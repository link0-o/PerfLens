# PerfLens {version}

PerfLens 是面向 Linux 的确定性性能分析工具，包含 CLI、MCP Server、Performance Analysis Skill，以及可选的受限 Collector Broker。

## 第一次下载请看这里

Debian 13 `amd64` 用户优先下载：

```text
perflens_{version}-{debian_revision}_amd64.deb
```

```bash
sudo apt install ./perflens_{version}-{debian_revision}_amd64.deb
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

需要分析本地 Docker 容器中一个明确进程的项目，进入项目后运行
`perflens init --docker`，审查生成的 `container-workload.toml`，再在 Agent 对话中确认
单次或有界会话授权。PerfLens 不安装/启动 Docker、不加入 Docker 组；v0.3.1 固定镜像路径
不 build/pull。v0.3.2 只有在项目启用 schema 1.1 优化合同并单独确认后，才允许类型化、
绑定 Recipe 的构建。远程 Engine、Compose/Kubernetes、任意 Docker 参数和整容器 perf
聚合仍不受支持。

## 资源怎么选

- `perflens-{version}-py3-none-any.whl`：安装 CLI、MCP、Skill、Collector 和
  显式管理员部署入口；
- `perflens_{version}-{debian_revision}_amd64.deb`：Debian 13 普通用户主安装包；
- `perflens-collector_{version}-{debian_revision}_<架构>.deb`：可选 Collector 与 Rust
  Helper，必须与同版本主 DEB 一起安装；安装时不会自动启用服务；
- `perflens-{version}.tar.gz`：Python 源码发行包；
- `perflens-skill-{version}.zip`：只安装独立 Skill 时使用；
- `sbom.cdx.json`：CycloneDX 依赖清单；
- `SHA256SUMS`：六个正式发行产物的 SHA-256 校验。

## 下载后先验证

只下载了部分资源时可以忽略缺失项，但自己下载的每个文件都必须显示 `OK`：

```bash
sha256sum --ignore-missing --check SHA256SUMS
```

安装了 GitHub CLI 时，建议再验证文件内容与官方 Release 工作流身份：

```bash
gh attestation verify ./perflens-{version}-py3-none-any.whl \
  --repo link0-o/PerfLens \
  --signer-workflow link0-o/PerfLens/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

DEB、源码包、Skill、SBOM 和 `SHA256SUMS` 也可以这样验证。校验失败时不要安装；GitHub
自动生成的两个 `Source code` 快照不属于 PerfLens 构建资产，不在证明范围内。

## 自动采集

分析已有 Profile 不需要 root。实时自动采集需要管理员审核并部署独立 Collector；
Agent 和 MCP 始终保持普通用户权限。检查引导生成的 `collector.toml` 后，可以先执行
`perflens-admin deploy --config <配置> --dry-run`，再由管理员执行一次
同样的命令（加 `sudo`、去掉 `--dry-run`）。之后用户可以直接说“优化当前项目的性能”，
确认具体程序和参数后由 PerfLens 自动取得新 PID。用户重新登录后可先运行
`perflens accept-collector --authorize-host-acceptance`，用内置负载完成无需 PID 的
真实短时验收。先运行 `perflens doctor`，再阅读
[产品部署指南](https://github.com/link0-o/PerfLens/blob/{tag}/docs/deployment.zh-CN.md)。
部署命令默认显示中文预检/成功摘要；自动化程序需要完整版本化结果时加 `--json`。

Collector 还会在启动 perf 前检查 spool 总字节数、文件数和文件系统空闲余量；达到
管理员配置的边界时拒绝新采集，但不会自动删除旧证据。
部署后运行 `perflens-admin spool-status` 可用中文只读检查存储余量；需要版本化机器
可读证据时加 `--json`。
每套 Collector 只允许一个普通用户 UID，避免共享 `perflens` 组导致 Profile 跨用户泄露。

旧证据不会按时间自动删除。管理员可先用 `archive-spool --dry-run` 审查选择结果，再创建
带版本化 manifest 与逐文件 SHA-256 的 root 管理 ZIP。可用 `verify-spool-archive`
完全只读地验证归档，加 `--verify-sources` 核对仍存在的原文件。只有完成独立备份、运行
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

## 卸载前

先对每个接入项目运行 `perflens detach --project <项目> --dry-run`，确认后去掉
`--dry-run`。它只移除经过所有权验证的 Codex/Claude MCP 配置和未修改 Skill，保留其他
客户端设置、引导文件和分析证据。需要保留 Skill 时加 `--keep-skills`。系统 Collector
还需要管理员另行执行 `perflens-admin undeploy`。

**Full Changelog**：https://github.com/link0-o/PerfLens/commits/{tag}
