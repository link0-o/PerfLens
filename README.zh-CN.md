# PerfLens

> 基于证据的 Linux 性能分析工具，集成 CLI、MCP Server 与 Codex Skill。
> Evidence-driven Linux performance analysis with a CLI, MCP Server, and Codex Skill.

[![CI](https://github.com/link0-o/PerfLens/actions/workflows/ci.yml/badge.svg)](https://github.com/link0-o/PerfLens/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

简体中文 | [English](README.md)

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
pipx install ./perflens-0.1.0-py3-none-any.whl
# 或者
uv tool install ./perflens-0.1.0-py3-none-any.whl
```

两种方式都会安装 `perflens` 和 `perflens-mcp`。可以这样确认版本：

```bash
perflens --version
perflens-mcp --version
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
- [MCP 与 Skill 使用指南](docs/mcp-and-skill.zh-CN.md)
- [安全策略](SECURITY.zh-CN.md)
- [发布就绪检查](docs/release-readiness.zh-CN.md)
- [发布流程](docs/releasing.zh-CN.md)
- [故障排查](docs/troubleshooting.zh-CN.md)
