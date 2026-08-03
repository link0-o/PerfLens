# PerfLens 安装与首次使用

简体中文 | [English](INSTALL.md)

## 先确认下载哪个文件

普通 Linux 用户应下载：

```text
perflens-0.1.0-py3-none-any.whl
```

`.whl` 是 Python 安装包，不是需要解压后点击运行的 ZIP。不要提取它。解压后看到的 `perflens/` 和 `perflens-0.1.0.dist-info/` 只是程序模块与安装元数据。

其他 Release 文件的用途：

- `perflens-0.1.0.tar.gz`：源码发行包；
- `perflens-performance-analysis-0.1.0.zip`：只包含 Agent Skill；
- `sbom.cdx.json`：依赖安全清单；
- `SHA256SUMS`：下载校验和；
- `Source code`：GitHub 自动生成的源码快照。

## 第一步：安装 wheel

需要 Linux 和 Python 3.12 或 3.13。推荐使用 pipx 隔离安装：

```bash
cd ~/Downloads
pipx install ./perflens-0.1.0-py3-none-any.whl
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
uv tool install ./perflens-0.1.0-py3-none-any.whl
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
  --prepare-collector
```

这仍然只生成待检查资产，不会提权。管理员安装、内核权限和真实短时验收步骤见[《产品部署指南》](docs/deployment.zh-CN.md)。不要让 MCP 或 Agent 以 root 运行。

实时采集并非固定 10 秒：自动计划默认 10 秒，用户可以在请求中调整，
但默认安全上限是 30 秒。部署验收命令 `verify-collector` 默认 1 秒、最多
5 秒。管理员也可以通过 Collector 独立策略进一步降低允许的模式、事件、
时长和输出大小。

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
