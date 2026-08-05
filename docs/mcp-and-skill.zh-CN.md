# MCP Server 与性能分析 Skill

简体中文 | [English](mcp-and-skill.md)

## 三层分别做什么

PerfLens 由三个可以分开使用的层组成：

1. **Core + CLI**：确定性地解析 Profile、计算热点和调用路径、定位源码、生成分析产物。
2. **MCP Server**：把上述能力作为本地 stdio 工具提供给 Codex、Claude Code 等客户端。
3. **Performance Analysis Skill**：告诉 Agent 应该按什么顺序使用工具，以及哪些结论有证据、哪些只能算候选。

Core 和 MCP Server 都不会调用 LLM API。Skill 只是工作流和安全规则。因此 PerfLens 可以说是“带 Skill 的 MCP 工具项目”，但 MCP 与 Skill 是两个独立组成部分。

## 启动和注册 MCP

如果使用正式安装包，推荐只在确实需要 PerfLens 的项目中运行一次：

```bash
cd /absolute/path/to/workspace
perflens init
```

它默认同时激活 Codex 和 Claude Code。Codex 使用项目 `.agents/skills` 和
`.codex/config.toml`；Claude Code 使用项目 `.claude/skills` 和 `.mcp.json`。
未运行 `init` 的其他项目没有这些入口，因此客户端不会认为 PerfLens 在那里可用。
使用 `--client codex`、`--client claude-code` 或 `--read-only` 可以缩小范围。
冲突的用户手写配置会被拒绝覆盖，也不会申请管理员权限。
升级接入或调整权限开关时使用 `perflens init --update`。普通重复初始化不会覆盖已有
引导目录；更新模式也只更新所有权记录匹配的 MCP 配置和未修改 Skill。要停用已有客户端，
先执行对应客户端的 `detach`，再用新的客户端范围更新。`perflens-setup` 是托管生成目录；
额外用户文件会阻止更新，已有 Collector 暂存资产在未要求重新生成时保留。
完整的下载、安装和接入步骤见[《中文安装指南》](../INSTALL.zh-CN.md)。

下面两条命令适合需要分别控制步骤的用户：

```bash
perflens install-skill --project /absolute/path/to/workspace
perflens codex-config --workspace /absolute/path/to/workspace
perflens install-skill --client claude-code --project /absolute/path/to/workspace
perflens claude-config --workspace /absolute/path/to/workspace
```

第一条命令不会覆盖已有 Skill；第二条命令只把 TOML 输出到终端供你检查，不会自动修改
全局或项目配置。日常首次接入优先使用 `init`，不需要手工复制。需要直接分析
`perf.data` 时，可以在 `codex-config` 后加 `--allow-process-execution`。

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

产物会原子发布且不覆盖已有路径；同一产物 ID 只有字节完全相同时才是幂等成功。
读取会拒绝 FIFO、软链接、额外硬链接、不安全权限以及根目录/文件身份变化。不可信的
同 UID 项目仍应使用操作系统沙箱隔离。

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

## 连接 Claude Code

`perflens init` 会把同一份 Agent Skill 安装到
`.claude/skills/perflens-performance-analysis`，并把下面这种标准 stdio 服务安全合并到
项目 `.mcp.json`：

```json
{
  "mcpServers": {
    "perflens": {
      "type": "stdio",
      "command": "/usr/bin/perflens-mcp",
      "args": ["--allowed-root", "/绝对路径/项目", "--allow-writes"],
      "env": {}
    }
  }
}
```

PerfLens 保留其他 `mcpServers`，但拒绝覆盖名称相同且内容不同的用户配置。Claude Code
首次使用项目级 MCP 时会要求用户信任。首次创建顶层 `.claude/skills` 时如果 Claude Code
已经运行，需要重启一次。显式调用方式为：

```text
使用 /perflens-performance-analysis 分析并优化当前项目。
```

对应机制见 Claude Code 官方的
[Skill 文档](https://code.claude.com/docs/en/slash-commands)和
[MCP 项目级配置文档](https://code.claude.com/docs/en/mcp)。

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
.claude/skills/perflens-performance-analysis
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

## 解除项目接入

卸载 PerfLens 前，对每个接入过的项目先预演再移除：

```bash
perflens detach --project /绝对路径/项目 --dry-run
perflens detach --project /绝对路径/项目
```

默认同时处理 Codex 和 Claude Code，并删除经过验证的 MCP 条目和未修改托管 Skill。
Codex 只删除带完整托管标记且只包含 `mcp_servers.perflens` 的块；Claude 只删除与引导目录
`claude-mcp.json` 完全一致的 `perflens` 条目。引导文件、分析产物和 Collector 数据保留；
用户修改或无法验证所有权的内容拒绝自动删除。使用 `--client codex|claude-code` 只处理
一个客户端，使用 `--keep-skills` 保留 Skill，自定义引导目录使用 `--setup-directory`。
保留的 Skill 仍可被客户端发现，所以 `--keep-skills` 不是彻底停用。
