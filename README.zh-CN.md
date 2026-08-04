# PerfLens

> 基于证据的 Linux 性能分析工具，集成 CLI、MCP Server 与 Codex Skill。
> Evidence-driven Linux performance analysis with a CLI, MCP Server, and Codex Skill.

[![CI](https://github.com/link0-o/PerfLens/actions/workflows/ci.yml/badge.svg)](https://github.com/link0-o/PerfLens/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

简体中文 | [English](README.md)

**第一次安装：请先看[《安装与首次使用》](INSTALL.zh-CN.md)。`.whl` 不要解压，应使用 pipx 或 uv 安装。**

PerfLens 是一个面向 Linux 应用和编码 Agent 的、基于证据的性能分析工具包。它把 Profile 解析、热点计算、源码定位和诊断规则做成确定性工具，再由 Skill 约束 Agent 如何解释这些证据。

## 它是 MCP 还是 Skill？

两者都有，但它们不是同一个东西。完整项目分为三层：

```text
PerfLens Core + CLI（真正执行确定性分析）
├── MCP Server（让 Codex 等客户端调用分析工具）
└── Skill（告诉 Agent 按什么流程分析、如何避免过度下结论）
```

- **Core + CLI**：可以单独使用，不需要 MCP，也不会调用任何 LLM API。
- **MCP Server**：本地 stdio 服务，把 Core 能力暴露为有类型、有权限边界的工具。
- **Skill**：仓库中的 Agent 工作说明。它会引导 Agent 先看元数据和热点，再看调用路径、源码和缺失证据。

最简单的选择：

- 只想在终端生成 JSON/Markdown：使用 CLI。
- 想让 Codex 自动调用工具并解释结果：配置 MCP，再使用 Skill。
- 已经有分析产物，只想按严谨流程解读：也可以只引用 Skill，但同时配置 MCP 效果最好。

PerfLens 不包含 LLM API、Web UI、自动修改源码功能、Benchmark 执行器或自研 Agent 框架。

## 安装

需要 Python 3.12 或更高版本。

从 GitHub Releases 下载 wheel 后，推荐作为独立工具安装：

```bash
pipx install ./perflens-0.1.1-py3-none-any.whl
# 或者
uv tool install ./perflens-0.1.1-py3-none-any.whl
```

不要手工提取 wheel。安装成功后运行项目引导：

```bash
perflens setup \
  --project /绝对路径/你的项目 \
  --prepare-collector \
  --automatic-collection
```

然后打开命令显示的 `下一步.zh-CN.md`。完整新手流程见[《安装与首次使用》](INSTALL.zh-CN.md)。

Debian 13 用户也可以直接安装原生 `.deb`，不需要自己创建 Python 环境。主包与
可选 Collector 包的选择、安装和安全卸载见[《Debian 安装包》](docs/debian-packages.zh-CN.md)。

随时可以运行只读状态检查，不需要记住多条排错命令：

```bash
perflens status --project /绝对路径/你的项目
```

自动采集已配置且本地访问条件满足时，这条命令还会执行一次有界、只读的健康握手，
通过内核 peer credentials 复核 Collector 的 PID/UID。遗留 Socket、无响应服务或错误
身份进程会明确显示为不可用，不再被误报为“可验收”。

管理员完成 Collector 部署、用户重新登录后，只需一条命令做真实验收，不必查 PID：

```bash
perflens accept-collector --authorize-host-acceptance
```

默认输出简洁中文结果，包括证据路径、哈希、指标数量和结论边界。自动化程序使用
`--json` 获取完整机器可读结果；需要留档时使用
`--output ./collector-acceptance.json` 写入一个新的版本化证据文件。

上面的 wheel 安装方式会安装 `perflens`、`perflens-mcp`、可选的 `perflens-collector`
和管理员入口 `perflens-admin`。可以这样确认版本：

```bash
perflens --version
perflens-mcp --version
perflens-collector --version
perflens-admin --version
```

也支持直接安装源码目录：

```bash
python -m pip install .
```

开发环境推荐使用：

```bash
uv sync --all-groups
```

下面的命令默认已经激活虚拟环境；未激活时可把 `perflens` 换成 `.venv/bin/perflens`。

## 用 CLI 分析 Profile

### FlameGraph folded 文本

```bash
perflens analyze-folded \
  --input tests/fixtures/folded/normal.folded \
  --output build/analysis.json
```

folded 输入示例：

```text
main;worker;parse;malloc 182
main;worker;compute 271
```

栈顺序统一为 `根 → 叶子`。最后一帧计入 self 权重；样本中每个唯一的 `(符号, DSO)` 只计算一次 inclusive 权重，递归调用不会使函数级 inclusive 百分比超过 100%。

标准 folded 文本不包含 DSO、PID/TID、CPU、时间戳、事件和源码信息。PerfLens 会明确把这些字段记录为 `unknown`，不会根据函数名猜测。

### perf script 文本

先生成 PerfLens 支持的稳定字段：

```bash
perf script --ns \
  -F comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline \
  -i perf.data > profile.perf-script

perflens analyze-perf-script \
  --input profile.perf-script \
  --output build/analysis.json
```

### perf.data

也可以让 PerfLens 调用系统 `perf` 做只读转换：

```bash
perflens analyze-perf-data \
  --input perf.data \
  --output build/analysis.json
```

这条命令不会采样、不会附加到进程、不会请求 sudo。它只调用绝对路径且在允许列表中的 `perf`。多版本并存时可用 `--perf-path` 指定版本。

### 符号、源码和诊断报告

```bash
perflens inspect-elf --input build/app --output build/elf.json

perflens resolve-source \
  --binary build/app \
  --module-offset 0x1234 \
  --output build/source.json

perflens classify \
  --analysis build/analysis.json \
  --output build/diagnosis.json

perflens report \
  --analysis build/analysis.json \
  --problem "吞吐量回退" \
  --metric "requests/second" \
  --output build/report.md
```

源码定位必须使用已经验证的模块相对偏移。PerfLens 不会根据运行时地址猜测 ASLR/PIE 基址。分类规则产生的是“待调查候选”，不是已经确认的根因。

## 比较优化前后

```bash
perflens compare-profiles \
  --baseline build/baseline-analysis.json \
  --candidate build/candidate-analysis.json \
  --output build/profile-comparison.json \
  --markdown-output build/profile-comparison.md

perflens normalize-benchmark \
  --input benchmark-hyperfine.json \
  --output build/benchmark.json

perflens compare-benchmarks \
  --baseline build/baseline-benchmark.json \
  --candidate build/candidate-benchmark.json \
  --output build/benchmark-comparison.json
```

Profile 百分比变化只表示所选事件的分布变化，不等于耗时变化。只有工作负载可比、Benchmark 有重复样本且效果达到实际意义阈值时，才能把结果升级为更强的改进或回退结论。

## 配置 MCP + Skill

正式安装包已经携带 Skill。先把它安装到需要分析的项目中：

```bash
perflens install-skill --project /absolute/path/to/workspace
```

该命令会创建 `.agents/skills/perflens-performance-analysis`，如果目标已经存在则拒绝覆盖。然后生成项目级 MCP 配置：

```bash
perflens codex-config --workspace /absolute/path/to/workspace
```

检查输出的 TOML，再将它加入项目的 `.codex/config.toml`。需要直接分析 `perf.data` 或调用源码符号化程序时，才增加：

```text
--allow-process-execution
```

下面是从源码仓库直接注册 MCP 的方式。

先安装依赖并创建产物目录：

```bash
uv sync --all-groups
mkdir -p perflens-results
```

在仓库根目录注册本地 MCP：

```bash
codex mcp add perflens -- \
  "$PWD/.venv/bin/perflens-mcp" \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes
```

重启 Codex，然后用 `/mcp` 或下面的命令确认服务存在：

```bash
codex mcp list
```

之后可以直接对 Codex 说：

```text
使用 $perflens-performance-analysis 分析 ./profile.folded，
告诉我最主要的热点、直接证据、候选原因、缺失证据和下一步验证办法。
```

Skill 位于 `.agents/skills/perflens-performance-analysis`。`$perflens-performance-analysis` 是 Skill 名称；`perflens` 是 MCP Server 名称。

完整权限说明和项目级配置见[《MCP 与 Skill 使用指南》](docs/mcp-and-skill.zh-CN.md)。

如果希望 Skill 面向已授权实时 PID 自动完成“权限检查 → 计划 → 采集 → 分析”，请看[《自动采集与 Collector Broker》](docs/automatic-collection.zh-CN.md)。MCP 和 Agent 不以 root 运行；可选 Collector 通过独立策略持有最小 perf capability。

完成一次管理员部署后，用户不必自己找 PID。可以直接说：

```text
使用 $perflens-performance-analysis 优化当前项目的运行性能。
允许运行我确认的项目可执行文件并采集最多 10 秒，不要附加其他已有进程。
```

Skill 会先确认具体可执行文件、参数和工作负载；普通用户启动器取得新 PID，
Collector 只接收绑定该 PID 的短期采集计划。项目程序不会以 root 运行。

面向其他用户安装系统 Collector、执行真实验收和后续升级时，请看[《产品部署指南》](docs/deployment.zh-CN.md)。

## 主动采样

主动采样默认关闭，而且必须明确授权。CLI 示例：

```bash
perflens collect-profile \
  --mode record \
  --executable /absolute/path/to/app \
  --target-arg=--workload \
  --data-output build/profile.data \
  --metadata-output build/collection.json \
  --authorize-target \
  --authorization I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING
```

支持 `record`、`stat`、`sched`、`lock` 和 `off_cpu` 模式。附加到已有 PID 还需要独立开关、有限时长以及授权短语 `I_EXPLICITLY_AUTHORIZE_PID_ATTACH`。

PerfLens 永远不会自行执行 sudo、修改内核策略或降低主机安全限制。若系统的 `perf_event_paranoid`、容器策略或能力设置不允许采样，应由系统管理员提供经过批准的采样环境或 Profile 文件。

## 权限和安全边界

运行 `perflens doctor` 可以在不采样、不附加 PID 的情况下检查当前五种采集模式。Agent 自动采集使用短期、单次、绑定 PID 所有者和启动时间的计划，并由 Unix Socket Collector 再次检查调用 UID、目标、模式、单次资源上限、spool 累计配额和磁盘空闲余量。达到存储边界时只拒绝新采集，不自动删除旧证据。Skill 本身不是授权。

当前每套 Collector 只允许一个普通用户 UID；不要让多个用户共享同一个 `perflens`
组和 spool，否则组可读 Profile 会跨用户泄露。

部署后只需运行 `perflens-admin spool-status`，即可用中文查看 spool 文件数、逻辑大小、
磁盘保留余量和当前最多可采集数据量；该命令只读，不删除旧证据。机器可读输出使用
`perflens-admin spool-status --json`。

旧证据不会自动轮转。管理员可以先用 `perflens-admin archive-spool --dry-run` 生成精确
计划，再创建带版本化 manifest 和逐文件 SHA-256 的只读 ZIP；源文件此时仍全部保留。
使用 `verify-spool-archive` 可以完全只读地验证归档；加 `--verify-sources` 还会核对仍
存在的原文件。只有把归档放到独立存储、运行 `prune-archived-spool --dry-run` 并逐项
审查后，才能输入 `I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE` 清理完全匹配的
原文件。完整命令见
[《产品部署指南》](docs/deployment.zh-CN.md)。Agent 不应自动执行该清理流程。

首次部署和后续升级都会完成只读健康协议往返，并通过内核凭据复核服务 PID/UID；仅
存在 Socket 文件不会被当作成功，因此旧文件、错误身份或未监听服务会在自动采集前
暴露出来。`perflens-admin deploy` 默认显示中文预检/成功摘要；自动化程序加 `--json`
可获得完整版本化结果。

安装新版本后使用 `sudo perflens-admin upgrade --dry-run` 预检，再运行
`sudo perflens-admin upgrade`。它保留管理员策略和历史证据，只更新可信托管 unit，失败
时尝试恢复；升级后应重新运行普通用户真实验收。

- 所有用户路径都会被规范化，并限制在配置的 allowed root 内。
- 输入 Profile 不会被覆盖。
- 产物使用原子写入，并且只能写入指定 artifact root。
- 外部命令不经过 shell，输出、错误和超时都有上限。
- 实时采样和 PID 附加默认关闭，且采用多重授权。
- 解析失败时保留有限诊断，不返回无限量原始数据。

## 退出码

| 代码 | 含义 |
|---:|---|
| 0 | 成功 |
| 2 | CLI 用法或输入无效 |
| 3 | Profile 不支持或格式错误 |
| 4 | 超出资源限制 |
| 5 | 输出或路径安全检查失败 |
| 6 | 外部工具失败或超时 |
| 70 | 未预期的内部错误 |

## 开发验证

第一次维护项目时，建议先阅读[《中文开发指南》](docs/development.zh-CN.md)和
[《架构说明》](docs/architecture.zh-CN.md)。

```bash
uv run ruff check .
uv run pyright
uv run pytest --cov=perflens
uv build
uv run pip-audit
```

## 已知限制

- folded 格式没有 DSO 信息，无法区分不同 DSO 中的同名函数。
- Profile 百分比表示事件权重，不是墙钟时间。
- 热点是直接观察结果，不等于已确认根因。
- `perf.data` 能否迁移分析取决于本机 `perf` 版本和匹配的 DSO/调试符号。
- 主动采样取决于 Linux 内核权限；权限不足时 PerfLens 会返回有界的结构化错误。
- `off_cpu` 只采集 `sched:sched_switch` 栈证据，仍需结合工作负载才能判断阻塞时间。

更多中文资料：

- [中文开发指南](docs/development.zh-CN.md)
- [架构说明](docs/architecture.zh-CN.md)
- [兼容范围](docs/compatibility.zh-CN.md)
- [已知限制与结论边界](docs/limitations.zh-CN.md)
- [真实世界 Profile 验收记录](docs/real-world-acceptance.zh-CN.md)
- [Folded Profile 数据模型](docs/profile-model.zh-CN.md)
- [性能预算与已记录基线](docs/performance-budget.zh-CN.md)
- [产物 Schema 兼容与迁移](docs/schema-migrations.zh-CN.md)
- [自研与依赖复用决策](docs/dependency-decisions.zh-CN.md)
- [MCP 与 Skill 使用指南](docs/mcp-and-skill.zh-CN.md)
- [自动采集与 Collector Broker](docs/automatic-collection.zh-CN.md)
- [产品部署、验收、升级与卸载](docs/deployment.zh-CN.md)
- [安全策略](SECURITY.zh-CN.md)
- [发布就绪检查](docs/release-readiness.zh-CN.md)
- [发布流程](docs/releasing.zh-CN.md)
- [故障排查](docs/troubleshooting.zh-CN.md)
