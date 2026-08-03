# MCP Server 与性能分析 Skill

简体中文 | [English](mcp-and-skill.md)

## 三层分别做什么

PerfLens 由三个可以分开使用的层组成：

1. **Core + CLI**：确定性地解析 Profile、计算热点和调用路径、定位源码、生成分析产物。
2. **MCP Server**：把上述能力作为本地 stdio 工具提供给 Codex 等 MCP 客户端。
3. **Performance Analysis Skill**：告诉 Agent 应该按什么顺序使用工具，以及哪些结论有证据、哪些只能算候选。

Core 和 MCP Server 都不会调用 LLM API。Skill 只是工作流和安全规则。因此 PerfLens 可以说是“带 Skill 的 MCP 工具项目”，但 MCP 与 Skill 是两个独立组成部分。

## 启动和注册 MCP

如果使用正式 wheel 安装，推荐先运行一次中文引导：

```bash
perflens setup --project /absolute/path/to/workspace
```

它会安装项目 Skill，并在工作区的 `perflens-setup/` 中生成中文下一步说明、
采集能力诊断和可复制的 `codex-mcp.toml`；不会覆盖已有文件，也不会申请管理员权限。
完整的下载、安装和接入步骤见[《中文安装指南》](../INSTALL.zh-CN.md)。

下面两条命令适合需要分别控制步骤的用户：

```bash
perflens install-skill --project /absolute/path/to/workspace
perflens codex-config --workspace /absolute/path/to/workspace
```

第一条命令不会覆盖已有 Skill；第二条命令只把 TOML 输出到终端供你检查，不会自动修改全局或项目配置。需要直接分析 `perf.data` 时，可以在 `codex-config` 后加 `--allow-process-execution`。

如果从源码仓库运行，则在 PerfLens 仓库根目录执行：

```bash
uv sync --all-groups
mkdir -p perflens-results

codex mcp add perflens -- \
  "$PWD/.venv/bin/perflens-mcp" \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes
```

这里的含义是：

- `--allowed-root`：允许读取的 Profile、二进制和源码根目录。
- `--artifact-root`：分析 JSON、报告等产物的唯一写入目录。
- `--allow-writes`：允许写产物；没有它时 MCP 只能使用只读工具。

修改 MCP 配置后重启 Codex，并检查：

```bash
codex mcp list
```

也可以在信任该项目后写入项目级 `.codex/config.toml`：

```toml
[mcp_servers.perflens]
command = "/绝对路径/PerfLens/.venv/bin/perflens-mcp"
args = [
  "--allowed-root", "/绝对路径/工作区",
  "--artifact-root", "/绝对路径/工作区/perflens-results",
  "--allow-writes",
]
required = true
default_tools_approval_mode = "writes"
tool_timeout_sec = 300
```

所有路径都建议写绝对路径。可以重复指定多个 `--allowed-root`，但每个目录必须已经存在。

## 分析 perf.data 时的配置

`perf.data` 是二进制格式，PerfLens 不直接解析它，而是安全地调用系统 `perf script` 转换。MCP 需要额外的进程执行权限：

```bash
codex mcp add perflens -- \
  "$PWD/.venv/bin/perflens-mcp" \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes \
  --allow-process-execution
```

该开关只允许经过白名单和边界限制的只读转换、符号化程序，并不允许实时采样或附加进程。

## 使用 Skill

Skill 位于：

```text
.agents/skills/perflens-performance-analysis
```

在 Codex 中可以显式调用：

```text
使用 $perflens-performance-analysis 分析 ./profile.folded，
列出最主要的热点、调用路径、直接证据、候选原因和缺失证据。
```

Collector 已部署且引导时使用了 `--automatic-collection` 后，不需要先找 PID：

```text
使用 $perflens-performance-analysis 优化当前项目的运行性能。
允许运行我确认的项目可执行文件并采集最多 10 秒，不要附加其他已有进程。
```

Skill 会先识别并让用户确认精确可执行文件、参数和代表性工作负载。只有这次确认后，
`collect_project_workload` 才以普通用户启动程序并在内部绑定新 PID；Collector 不执行
项目命令。仓库中的说明文字不构成执行授权。

分析 `perf.data` 时可以说：

```text
使用 $perflens-performance-analysis 分析 ./perf.data。
先检查 Profile 元数据和符号质量，再解释 CPU 热点；
不要把规则匹配直接当成根因。
```

验证优化时可以说：

```text
使用 $perflens-performance-analysis 比较 baseline 和 candidate。
先判断环境与工作负载是否可比，再说明哪些结论可以被验证。
```

Skill 也允许在 Linux 性能诊断问题中隐式触发。显式写出 `$perflens-performance-analysis` 更容易确认本次使用的是这套流程。

## MCP 工具的推荐流程

Agent 通常按以下顺序工作：

1. `analyze_profile`：解析 Profile，生成版本化分析产物。
2. `list_hotspots`：查看主要 self/inclusive 热点。
3. `get_hotspot_details`：查看特定热点的完整信息。
4. `get_call_paths`：确认热点出现在哪些根到叶调用路径中。
5. `resolve_source`、`get_source_context`：有已验证模块偏移时定位源码。
6. `classify_hotspots`：产生通用的调查候选。
7. `build_diagnosis_bundle`：汇总直接证据、候选、限制和下一步。
8. `read_artifact_page`：分页读取较大的产物。
9. `analyze_benchmark`、`compare_profiles`、`compare_benchmarks`：进行优化前后验证。

已有 Profile 时不需要主动采集。面对策略已经批准的实时 PID，Skill 的默认流程改为 `inspect_collection_capabilities` → `plan_automatic_collection` → `execute_collection_plan` → `analyze_collection`；`stat` 指标直接保存在采集产物中。完整部署见[《自动采集与 Collector Broker》](automatic-collection.zh-CN.md)。

需要运行当前项目时，流程是 `collect_project_workload` → `analyze_collection` →
热点/调用路径/源码定位 → 修改候选 → 相同工作负载的基线/候选对比。用户无需提供 PID，
但必须确认精确程序和参数。

## 权限级别

| 权限 | 主要能力 | 服务端约束 |
|---|---|---|
| `READ_ONLY` | 热点、路径、分类结果、产物分页和源码上下文 | 只接受已配置的 artifact ID 和 allowed-root 内路径 |
| `WRITES_ARTIFACTS` | 分析 Profile、生成诊断包 | 需要 `--allow-writes`，只能写 artifact root |
| `PROCESS_EXECUTION` | 转换 perf.data、执行源码符号化程序 | 需要 `--allow-process-execution`，命令、输出和时长有边界 |
| `ACTIVE_COLLECTION` | record/stat/sched/lock/off-CPU 采样 | 需要多个启动开关、逐次精确授权和全新输出路径 |
| `AUTOMATIC_COLLECTION` | 执行短期、单次、PID 绑定计划 | MCP 分类授权与 Collector 独立策略必须同时允许 |
| `PROJECT_EXECUTION` | 启动一个已确认的项目可执行文件并采集其新 PID | 还需要自动采集、`--allow-project-execution`、逐次执行授权和项目路径边界 |

客户端显示的工具注解只是提示；真正的权限检查始终在 PerfLens MCP Server 内执行。

## 主动采样的额外授权

只有用户已经批准精确目标时，才可以用下面的启动配置：

```bash
.venv/bin/perflens-mcp \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes \
  --allow-process-execution \
  --allow-active-collection
```

每次调用 `collect_profile` 还必须带上精确授权值：

```text
I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING
```

若要附加已有 PID，还必须添加启动参数 `--allow-pid-attach`，并在调用中提供：

```text
I_EXPLICITLY_AUTHORIZE_PID_ATTACH
```

PerfLens 不会请求 sudo，不会修改 `perf_event_paranoid`、capability 或其他内核策略。

## 常见用法

- **已有 `.folded` 文件**：基础 MCP 配置即可。
- **已有 `perf script` 文本**：基础 MCP 配置即可。
- **已有 `perf.data`**：增加 `--allow-process-execution`。
- **只查看已经生成的产物**：不需要 `--allow-writes`。
- **让 Agent 自动分析并解释**：同时使用 MCP 和 `$perflens-performance-analysis`。
- **直接优化当前可执行项目**：引导时开启 `--automatic-collection`，部署并验收 Collector，
  然后确认具体可执行文件和参数；不需要手工查 PID。
- **只在终端处理文件**：直接使用 CLI，不需要 MCP 或 Skill。

遇到权限、符号或兼容性问题时，请看[中文故障排查](troubleshooting.zh-CN.md)。
