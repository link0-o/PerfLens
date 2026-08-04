# PerfLens 安装与首次使用

简体中文 | [English](INSTALL.md)

## 先确认下载哪个文件

普通 Linux 用户应下载：

```text
perflens-0.1.1-py3-none-any.whl
```

`.whl` 是 Python 安装包，不是需要解压后点击运行的 ZIP。不要提取它。解压后看到的 `perflens/` 和 `perflens-0.1.1.dist-info/` 只是程序模块与安装元数据。

其他 Release 文件的用途：

- `perflens_0.1.1-1_amd64.deb`：Debian 13 普通用户主安装包；
- `perflens-collector_0.1.1-1_all.deb`：可选 Collector 管理入口，需配合同版本主包；
- `perflens-0.1.1.tar.gz`：源码发行包；
- `perflens-performance-analysis-0.1.1.zip`：只包含 Agent Skill；
- `sbom.cdx.json`：依赖安全清单；
- `SHA256SUMS`：下载校验和；
- `Source code`：GitHub 自动生成的源码快照。

Debian 13 `amd64` 用户推荐直接安装主 DEB，不需要 pipx：

```bash
sudo apt install ./perflens_0.1.1-1_amd64.deb
```

需要自动采集时再安装完全相同版本的 Collector DEB。安装软件包不会自动启动
特权服务，完整流程见[《Debian 安装包》](docs/debian-packages.zh-CN.md)。

## 第一步：安装 wheel（非 Debian 或不使用 DEB 时）

需要 Linux 和 Python 3.12 或 3.13。推荐使用 pipx 隔离安装：

```bash
cd ~/Downloads
pipx install ./perflens-0.1.1-py3-none-any.whl
```

如果浏览器下载到了其他目录，请先在文件管理器中进入该目录，右键空白处选择
“在终端中打开”，再运行 `pipx install`；也可以把命令中的文件名换成 wheel
的完整路径。不要先在文件管理器中提取 wheel。

如果系统没有 pipx，Debian/Ubuntu 用户可以先通过系统包管理器安装：

```bash
sudo apt install pipx
pipx ensurepath
```

然后重新打开终端，再执行 wheel 安装命令。也可以使用：

```bash
uv tool install ./perflens-0.1.1-py3-none-any.whl
```

验证安装：

```bash
perflens --version
perflens --help
```

## 第二步：运行安装后引导

选择需要使用 PerfLens 的项目目录：

```bash
perflens setup --project /绝对路径/你的项目
```

该命令只在所选项目内执行安全操作：

- 安装或识别 PerfLens Performance Analysis Skill；
- 生成 `perflens-setup/codex-mcp.toml`；
- 生成只读权限报告 `collection-capabilities.json`；
- 生成中文 `下一步.zh-CN.md`；
- 生成带 `schema_version` 的 `setup.json`。

它不会执行 sudo、修改 sysctl/capability、覆盖用户 Codex 配置或启动 Collector。完成后按照终端显示的“请继续阅读”路径操作。

如果需要分析 `perf.data` 或进行源码符号化，可以显式开启有界外部工具：

```bash
perflens setup \
  --project /绝对路径/你的项目 \
  --output-directory perflens-setup-with-symbols \
  --allow-process-execution
```

每次引导必须使用一个不存在的新输出目录，已有文件不会被覆盖。

运行统一的只读状态检查：

```bash
perflens status --project /绝对路径/你的项目
```

它会用中文指出引导、Skill、MCP、Collector 资产、Socket、用户组或 perf 权限中
尚未完成的部分，不会执行采样或修改系统。

## 第三步：开始分析

只使用 CLI 分析 folded Profile：

```bash
perflens analyze-folded \
  --input profile.folded \
  --output analysis.json
```

使用 Codex 时，打开引导生成的 `codex-mcp.toml`，把完整配置块复制到
Linux 用户配置 `~/.codex/config.toml`；也可以在项目已受信任时合并到
项目的 `.codex/config.toml`。不要覆盖其中已有内容。重启 Codex，执行
`codex mcp list` 确认 `perflens` 已加载，然后在项目中说：

```text
使用 $perflens-performance-analysis 分析这个项目的性能 Profile，
区分直接证据、候选原因和缺失证据。
```

## 可选：准备自动采集

分析已有 Profile 不需要 root 或 Collector。只有确实需要自动附加实时 PID 时，才运行：

```bash
perflens setup \
  --project /绝对路径/你的项目 \
  --output-directory perflens-collector-setup \
  --prepare-collector \
  --automatic-collection
```

这仍然只生成待检查资产，不会提权。检查生成的
`collector-assets/collector.toml` 后，管理员只需执行一次部署命令：

```bash
perflens-admin deploy \
  --config /绝对路径/perflens-collector-setup/collector-assets/collector.toml \
  --dry-run
sudo perflens-admin deploy \
  --config /绝对路径/perflens-collector-setup/collector-assets/collector.toml
```

上面的路径只是 DEB 示例。请直接复制生成的 `下一步.zh-CN.md` 中的命令：`setup` 会
安全识别 DEB 的 `/usr/bin` 入口；wheel 或源码布局默认生成 `/opt/perflens/bin` 入口。
如果系统包缺少配套 Collector，`setup` 会直接告诉你应安装哪个包，不会生成错误引导。

第一条只校验并显示计划；第二条才写入系统、添加授权用户组并启动服务，通常只需输入
一次 root 密码。部署命令默认显示中文摘要：预检会明确写出“尚未修改系统”，正式部署
成功时会写出健康握手结论和下一步。脚本需要完整版本化结果时加 `--json`。入口必须
来自系统包或 `/opt/perflens` 中的受信任
副本，不要用 `sudo` 运行用户家目录里可修改的脚本。完整内核权限和真实短时验收步骤见
[《产品部署指南》](docs/deployment.zh-CN.md)。不要让 MCP 或 Agent 以 root 运行。

完成验收和 MCP 配置后，用户不需要查询 PID，可以直接对 Codex 说：

```text
使用 $perflens-performance-analysis 优化当前项目的运行性能。
允许运行我确认的项目可执行文件并采集最多 10 秒，不要附加其他已有进程。
```

Skill 会先识别构建产物和启动参数并向用户确认；PerfLens 再以普通用户启动程序，
自动取得本次进程 PID 并交给 Collector。它不会随意执行仓库里的脚本，也不会让
Collector 以特权启动用户程序。

实时采集并非固定 10 秒：自动计划默认 10 秒，用户可以在请求中调整，
但默认安全上限是 30 秒。部署后以普通用户运行
`perflens accept-collector --authorize-host-acceptance`，无需输入 PID；该验收默认
1 秒、最多 5 秒，并默认输出带结论边界的中文摘要。自动化程序加 `--json`；需要留档时
加 `--output ./collector-acceptance.json`。管理员也可以通过 Collector 独立策略进一步
降低允许的模式、事件、时长和输出大小。

## 升级

只调整采集模式、时长、事件或配额时，无需重新部署或升级软件包。复制当前配置并编辑
独立候选文件，然后执行：

```bash
cp /etc/perflens/collector.toml ./collector.next.toml
chmod 600 ./collector.next.toml
perflens-admin update-policy --config "$PWD/collector.next.toml" --dry-run
sudo perflens-admin update-policy --config "$PWD/collector.next.toml"
```

它会自动重启、健康检查并在失败时恢复原配置，但拒绝改变授权 UID 和固定 spool。

长期使用后需要释放采集目录空间时，不要手工按文件时间直接删除。使用
`perflens-admin archive-spool` 先生成带哈希 manifest 的 root 管理归档，再通过
`verify-spool-archive --verify-sources` 只读核对归档和仍存在的原文件，然后运行
`prune-archived-spool --dry-run` 审查清理计划，最后输入独立的显式授权短语。完整步骤和
默认“7 天前、保留最新 20 份”的边界见[《产品部署指南》](docs/deployment.zh-CN.md)。

先安装新 wheel 或同版本配套的两个新 DEB，再由管理员运行：

```bash
sudo perflens-admin upgrade --dry-run
sudo perflens-admin upgrade
```

该流程保留 `/etc/perflens/collector.toml` 和历史采集证据，只更新可信的托管 unit 并
重启新程序，失败时尝试恢复旧 unit。完成后以普通用户重新运行
`perflens accept-collector --authorize-host-acceptance`。完整边界见
[《产品部署指南》](docs/deployment.zh-CN.md)。

## 卸载

pipx 安装的普通用户程序可以这样卸载：

```bash
pipx uninstall perflens
```

项目内的 Skill、`perflens-setup` 目录、Collector 服务和历史采集数据不会被静默删除，应由用户或管理员检查后分别处理。

## 常见问题

### 解压 wheel 后没有可执行文件

这是正常的，因为 wheel 应交给 pipx、uv 或 pip 安装，而不是手工解压。

### `perflens: command not found`

重新打开终端，执行 `pipx ensurepath`，并用 `pipx list` 确认安装状态。

### `doctor` 显示 blocked

普通 Profile 分析仍可使用。实时采集需要管理员部署受限 Collector 并审核主机 perf 策略。
