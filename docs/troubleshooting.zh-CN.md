# 故障排查

简体中文 | [English](troubleshooting.md)

## 主动 perf 采样被拒绝

PerfLens 会把 `perf` 的有限 stderr 作为 `EXTERNAL_TOOL_FAILED` 返回。请检查：

- `/proc/sys/kernel/perf_event_paranoid`
- 当前用户的 capability
- 容器安全策略
- tracepoint 和 debugfs/tracefs 的访问权限

PerfLens 不会执行 sudo、修改 sysctl、授予 capability、挂载 tracefs 或降低主机安全策略。请让系统管理员提供经过批准的采样环境，或在有权限的机器上采集 Profile 后交给 PerfLens 分析。

## 无法解析已有 perf.data

`perf.data` 往往依赖采集机器的 `perf` 版本、内核和二进制环境。优先使用与采集端兼容的 `perf`，并通过 `--perf-path` 传入它的绝对路径。

如果仍不兼容，请在采集机器上导出文本：

```bash
perf script --ns \
  -F comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline \
  -i perf.data > profile.perf-script
```

然后使用：

```bash
perflens analyze-perf-script \
  --input profile.perf-script \
  --output build/analysis.json
```

PerfLens 不直接解析 `perf.data` 二进制格式。

## MCP 分析 perf.data 提示没有进程执行权限

在 `perflens-mcp` 的参数中加入：

```text
--allow-process-execution
```

修改配置后需要重启 MCP 客户端。对于 Codex，可用 `codex mcp list` 或 `/mcp` 确认新的配置已经生效。

## 找不到符号或源码行

请检查：

- Profile 对应的 DSO 是否存在。
- Build ID 是否匹配。
- 独立调试文件和 debug link 是否可用。
- 容器路径、构建路径和本地源码路径是否正确映射。
- 是否安装了 `llvm-symbolizer` 或 `addr2line`。

源码定位只接受已验证的模块相对偏移。PerfLens 不会根据单独的运行时 IP 猜测 ASLR 或 PIE 基址。缺失的符号会保留为 unknown，而不会被伪造。

## MCP 拒绝读取路径

输入 Profile、二进制、调试文件和源码工作区都必须位于某个 `--allowed-root` 之下。服务启动时会规范化路径并检查真实位置，符号链接也不能绕过边界。

为新的工作区增加一个明确的 allowed root：

```text
--allowed-root /absolute/path/to/workspace
```

不要为了省事把 `/` 或用户主目录整体设为 allowed root。

## MCP 拒绝写入产物

确认服务参数中包含 `--allow-writes`，且目标位于 `--artifact-root` 下。目标文件必须是新文件；PerfLens 不覆盖已有分析产物，也不会覆盖源 Profile。

可以换一个新文件名，或先确认旧文件是否还需要保留。

## 只有部分分析结果

单条坏记录会被跳过并写入有界诊断。结构性资源限制则会使分析失败，避免静默丢失精确数据。

请检查分析 JSON 中的：

- warnings 和诊断摘要
- 已解析与跳过的记录数
- unknown symbol/DSO/source 的数量
- 是否触发输入大小、行长、栈深、唯一帧或调用路径上限

不要只根据一个热点百分比下结论。

## Benchmark 比较结果是“不确定”

常见原因包括：

- baseline 与 candidate 的机器、内核、CPU、频率策略或工作负载不同。
- 重复样本不足。
- 波动太大。
- 实际效果没有达到配置的意义阈值。
- 只有 Profile 百分比变化，没有吞吐量或延迟等外部指标。

这不是工具失败，而是现有证据不足以证明改进或回退。

## Codex 没有发现 Skill

Skill 位于仓库的：

```text
.agents/skills/perflens-performance-analysis
```

请确认从 PerfLens 仓库或包含该目录的工作区启动 Codex，然后显式输入：

```text
使用 $perflens-performance-analysis 分析这个 Linux Profile。
```

Skill 和 MCP 是独立组件。发现 Skill 不代表 MCP 已经连接；请另外用 `codex mcp list` 检查名为 `perflens` 的 MCP Server。

